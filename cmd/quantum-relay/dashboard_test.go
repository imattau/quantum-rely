package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pippellia-btc/rely/v2/internal/consensus"
	"github.com/pippellia-btc/rely/v2/internal/p2p"
	"github.com/pippellia-btc/rely/v2/internal/quantum"
)

func TestDashboardUnauthenticatedStatus(t *testing.T) {
	h, err := newDashboardHandler(DashboardConfig{
		Enabled: true, AdminPubkeys: []string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		PollIntervalMs: 3000, HistorySeconds: 300,
	}, "wss://relay.example.com/", p2p.NewPeerManager(nil), quantum.NewGraphState(), consensus.NewDiffuser(nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	h.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/mesh/status", nil))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
}

func TestDashboardServesShell(t *testing.T) {
	h, err := newDashboardHandler(DashboardConfig{
		Enabled: true, AdminPubkeys: []string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	}, "wss://relay.example.com/", p2p.NewPeerManager(nil), quantum.NewGraphState(), consensus.NewDiffuser(nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	h.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/mesh", nil))
	if recorder.Code != http.StatusOK || recorder.Body.Len() == 0 {
		t.Fatalf("dashboard response = %d with %d bytes", recorder.Code, recorder.Body.Len())
	}
}
