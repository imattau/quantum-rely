package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	json "github.com/goccy/go-json"
	"github.com/pippellia-btc/rely/v2/auth"
	"github.com/pippellia-btc/rely/v2/internal/consensus"
	"github.com/pippellia-btc/rely/v2/internal/p2p"
	"github.com/pippellia-btc/rely/v2/internal/quantum"
)

//go:embed web/mesh.html web/mesh.js web/mesh.css
var dashboardAssets embed.FS

const dashboardSessionCookie = "quantum_relay_mesh_session"

type dashboardSession struct {
	Pubkey  string
	Expires time.Time
}

type dashboardHistory struct {
	At              time.Time `json:"at"`
	ConnectedPeers  int       `json:"connected_peers"`
	ConfiguredPeers int       `json:"configured_peers"`
	GraphNodes      int       `json:"graph_nodes"`
	GraphEdges      int       `json:"graph_edges"`
	ConsensusRound  int64     `json:"consensus_round"`
}

type dashboardStatus struct {
	GeneratedAt    time.Time          `json:"generated_at"`
	PollIntervalMs int                `json:"poll_interval_ms"`
	Self           dashboardSelf      `json:"self"`
	Summary        dashboardSummary   `json:"summary"`
	Peers          []p2p.PeerSnapshot `json:"peers"`
	Topology       quantum.Snapshot   `json:"topology"`
	Consensus      consensus.Metrics  `json:"consensus"`
	History        []dashboardHistory `json:"history"`
}

type dashboardSelf struct {
	URL           string  `json:"url"`
	UptimeSeconds float64 `json:"uptime_seconds"`
}

type dashboardSummary struct {
	ConfiguredPeers int   `json:"configured_peers"`
	ConnectedPeers  int   `json:"connected_peers"`
	Disconnected    int   `json:"disconnected_peers"`
	GraphNodes      int   `json:"graph_nodes"`
	GraphEdges      int   `json:"graph_edges"`
	ConsensusRound  int64 `json:"consensus_round"`
}

type dashboardHandler struct {
	cfg       DashboardConfig
	relayURL  string
	peerMgr   *p2p.PeerManager
	graph     *quantum.GraphState
	diffuser  *consensus.Diffuser
	startedAt time.Time

	authState *auth.State
	authMu    sync.Mutex
	sessions  map[string]dashboardSession

	historyMu  sync.Mutex
	history    []dashboardHistory
	lastSample time.Time
}

func newDashboardHandler(cfg DashboardConfig, relayURL string, pm *p2p.PeerManager, graph *quantum.GraphState, diffuser *consensus.Diffuser) (*dashboardHandler, error) {
	canonical, err := auth.CanonicalURL(relayURL)
	if err != nil {
		return nil, fmt.Errorf("dashboard relay URL: %w", err)
	}
	authCfg := auth.NewConfig()
	authCfg.URL = canonical
	return &dashboardHandler{
		cfg: cfg, relayURL: relayURL, peerMgr: pm, graph: graph, diffuser: diffuser,
		startedAt: time.Now(), authState: auth.NewState(authCfg), sessions: make(map[string]dashboardSession),
	}, nil
}

func (h *dashboardHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	switch {
	case req.Method == http.MethodGet && req.URL.Path == "/mesh":
		h.serveAsset(w, "web/mesh.html", "text/html; charset=utf-8")
	case req.Method == http.MethodGet && req.URL.Path == "/mesh/app.js":
		h.serveAsset(w, "web/mesh.js", "text/javascript; charset=utf-8")
	case req.Method == http.MethodGet && req.URL.Path == "/mesh/app.css":
		h.serveAsset(w, "web/mesh.css", "text/css; charset=utf-8")
	case req.Method == http.MethodGet && req.URL.Path == "/mesh/auth/challenge":
		h.issueChallenge(w)
	case req.Method == http.MethodPost && req.URL.Path == "/mesh/auth":
		h.authenticate(w, req)
	case req.Method == http.MethodGet && req.URL.Path == "/api/mesh/status":
		h.status(w, req)
	default:
		http.NotFound(w, req)
	}
}

func (h *dashboardHandler) serveAsset(w http.ResponseWriter, name, contentType string) {
	data, err := dashboardAssets.ReadFile(name)
	if err != nil {
		http.Error(w, "dashboard asset unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}

func (h *dashboardHandler) issueChallenge(w http.ResponseWriter) {
	var challenge string
	h.authState.Reset(func(value string) { challenge = value })
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]string{"challenge": challenge})
}

func (h *dashboardHandler) authenticate(w http.ResponseWriter, req *http.Request) {
	if origin := req.Header.Get("Origin"); origin != "" && origin != requestOrigin(req) {
		http.Error(w, "cross-origin authentication rejected", http.StatusForbidden)
		return
	}
	var envelope []json.RawMessage
	if err := json.NewDecoder(http.MaxBytesReader(w, req.Body, 64*1024)).Decode(&envelope); err != nil || len(envelope) != 2 {
		http.Error(w, "invalid NIP-42 authentication", http.StatusUnauthorized)
		return
	}
	var label string
	if err := json.Unmarshal(envelope[0], &label); err != nil || label != "AUTH" {
		http.Error(w, "invalid NIP-42 authentication", http.StatusUnauthorized)
		return
	}
	request, err := auth.Parse(json.NewDecoder(bytes.NewReader(envelope[1])))
	if err != nil {
		http.Error(w, "invalid NIP-42 authentication", http.StatusUnauthorized)
		return
	}
	if err := h.authState.Validate(request); err != nil {
		http.Error(w, "authentication rejected", http.StatusUnauthorized)
		return
	}
	if !allowedPubkey(h.cfg.AdminPubkeys, request.Pubkey) {
		http.Error(w, "dashboard administrator access required", http.StatusForbidden)
		return
	}

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		http.Error(w, "could not create session", http.StatusInternalServerError)
		return
	}
	token := hex.EncodeToString(tokenBytes)
	h.authMu.Lock()
	h.sessions[token] = dashboardSession{Pubkey: request.Pubkey, Expires: time.Now().Add(15 * time.Minute)}
	h.authMu.Unlock()
	h.pruneSessions()
	http.SetCookie(w, &http.Cookie{Name: dashboardSessionCookie, Value: token, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode, MaxAge: 15 * 60})
	writeJSON(w, http.StatusOK, map[string]string{"status": "authenticated"})
}

func (h *dashboardHandler) authenticated(req *http.Request) bool {
	cookie, err := req.Cookie(dashboardSessionCookie)
	if err != nil || cookie.Value == "" {
		return false
	}
	h.authMu.Lock()
	session, ok := h.sessions[cookie.Value]
	if ok && time.Now().After(session.Expires) {
		delete(h.sessions, cookie.Value)
		ok = false
	}
	if ok {
		session.Expires = time.Now().Add(15 * time.Minute)
		h.sessions[cookie.Value] = session
	}
	h.authMu.Unlock()
	return ok
}

func (h *dashboardHandler) pruneSessions() {
	now := time.Now()
	h.authMu.Lock()
	defer h.authMu.Unlock()
	for token, session := range h.sessions {
		if now.After(session.Expires) {
			delete(h.sessions, token)
		}
	}
}

func (h *dashboardHandler) status(w http.ResponseWriter, req *http.Request) {
	if !h.authenticated(req) {
		http.Error(w, "dashboard authentication required", http.StatusUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, h.snapshot())
}

func (h *dashboardHandler) snapshot() dashboardStatus {
	peers := h.peerMgr.Snapshot()
	topology := h.graph.Snapshot()
	metrics := h.diffuser.Metrics()
	connected := 0
	for _, peer := range peers {
		if peer.Connected {
			connected++
		}
	}
	now := time.Now()
	status := dashboardStatus{
		GeneratedAt: now, PollIntervalMs: h.cfg.PollIntervalMs, Self: dashboardSelf{URL: h.relayURL, UptimeSeconds: now.Sub(h.startedAt).Seconds()},
		Summary: dashboardSummary{ConfiguredPeers: len(peers), ConnectedPeers: connected, Disconnected: len(peers) - connected, GraphNodes: len(topology.Relays), GraphEdges: len(topology.Edges), ConsensusRound: metrics.Round},
		Peers:   peers, Topology: topology, Consensus: metrics,
	}
	h.historyMu.Lock()
	if h.lastSample.IsZero() || now.Sub(h.lastSample) >= 5*time.Second {
		h.history = append(h.history, dashboardHistory{At: now, ConnectedPeers: connected, ConfiguredPeers: len(peers), GraphNodes: len(topology.Relays), GraphEdges: len(topology.Edges), ConsensusRound: metrics.Round})
		h.lastSample = now
		cutoff := now.Add(-time.Duration(h.cfg.HistorySeconds) * time.Second)
		keep := 0
		for keep < len(h.history) && h.history[keep].At.Before(cutoff) {
			keep++
		}
		if keep > 0 {
			h.history = append([]dashboardHistory(nil), h.history[keep:]...)
		}
	}
	status.History = append([]dashboardHistory(nil), h.history...)
	h.historyMu.Unlock()
	return status
}

func requestOrigin(req *http.Request) string {
	scheme := "http"
	if req.TLS != nil {
		scheme = "https"
	}
	if forwarded := strings.ToLower(strings.TrimSpace(strings.Split(req.Header.Get("X-Forwarded-Proto"), ",")[0])); forwarded == "http" || forwarded == "https" {
		scheme = forwarded
	}
	host := strings.TrimSpace(strings.Split(req.Header.Get("X-Forwarded-Host"), ",")[0])
	if host == "" {
		host = req.Host
	}
	return scheme + "://" + host
}

func writeJSON(w http.ResponseWriter, code int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(value)
}

// serveRelayEndpoint adds dashboard routes while leaving all other paths to
// the relay's normal Nostr WebSocket/NIP-11 handler.
func serveRelayEndpoint(ctx context.Context, relay http.Handler, dashboard http.Handler, listen string) error {
	mux := http.NewServeMux()
	if dashboard != nil {
		mux.Handle("/mesh", dashboard)
		mux.Handle("/mesh/", dashboard)
		mux.Handle("/api/mesh/", dashboard)
	}
	mux.Handle("/", relay)
	server := &http.Server{Addr: listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 120 * time.Second}
	errCh := make(chan error, 1)
	if starter, ok := relay.(interface{ Start(context.Context) }); ok {
		starter.Start(ctx)
	}
	go func() {
		if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := server.Shutdown(shutdownCtx)
		if waiter, ok := relay.(interface{ Wait() }); ok {
			waiter.Wait()
		}
		return err
	case err := <-errCh:
		return err
	}
}
