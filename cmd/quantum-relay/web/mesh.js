(() => {
  const login = document.querySelector('#login');
  const dashboard = document.querySelector('#dashboard');
  const error = document.querySelector('#login-error');
  const short = (value) => value.length > 34 ? `${value.slice(0, 16)}…${value.slice(-12)}` : value;
  const api = (path, options) => fetch(path, { credentials: 'same-origin', ...options });
  async function authenticate() {
    error.textContent = '';
    if (!window.nostr) { error.textContent = 'No NIP-07 browser extension was found.'; return; }
    try {
      const challenge = await (await api('/mesh/auth/challenge')).json();
      const event = await window.nostr.signEvent({ kind: 22242, created_at: Math.floor(Date.now() / 1000), tags: [['relay', location.origin.replace(/^http/, 'ws') + '/'], ['challenge', challenge.challenge]], content: '' });
      const response = await api('/mesh/auth', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(['AUTH', event]) });
      if (!response.ok) throw new Error(await response.text());
      login.hidden = true; dashboard.hidden = false; document.querySelector('#auth').textContent = 'Authenticated administrator'; poll();
    } catch (e) { error.textContent = e.message || 'Authentication failed.'; }
  }
  function render(data) {
    const s = data.summary;
    const health = document.querySelector('#health'); health.classList.toggle('warn', s.disconnected > 0); health.innerHTML = `<h2>${s.disconnected ? 'Mesh needs attention' : 'Mesh healthy'}</h2><span class="muted">${s.connected_peers} of ${s.configured_peers} configured peers connected</span>`;
    document.querySelector('#metrics').innerHTML = [['Connected peers', s.connected_peers], ['Graph nodes', s.graph_nodes], ['Graph edges', s.graph_edges], ['Consensus round', s.consensus_round]].map(([label, value]) => `<div class="card metric"><span class="muted">${label}</span><strong>${value}</strong></div>`).join('');
    document.querySelector('#consensus').innerHTML = `<p>Round <strong>${data.consensus.round}</strong></p><p class="muted">${data.consensus.reputations} tracked reputation entries<br>${data.consensus.dirty} pending reputation changes</p>`;
    document.querySelector('#peers').innerHTML = data.peers.length ? data.peers.map(p => `<tr><td title="${p.url}">${short(p.url)}</td><td><span class="status"><i class="dot ${p.connected ? 'up' : ''}"></i>${p.connected ? 'Connected' : 'Offline'}</span></td><td>${p.trust || 1}</td><td>${p.queue}/${p.capacity}</td><td>${p.reconnect ? 'Enabled' : 'Stopped'}</td></tr>`).join('') : '<tr><td colspan="5" class="muted">No configured peers</td></tr>';
    const graph = document.querySelector('#graph'), width = 640, height = 300, nodes = data.topology.relays;
    const positions = nodes.map((_, i) => { const a = (Math.PI * 2 * i / Math.max(nodes.length, 1)) - Math.PI / 2; return [width / 2 + Math.cos(a) * Math.min(220, 35 * nodes.length), height / 2 + Math.sin(a) * Math.min(100, 24 * nodes.length)]; });
    graph.innerHTML = `<svg viewBox="0 0 ${width} ${height}" role="img" aria-label="Relay mesh topology">${data.topology.edges.map(e => `<line class="edge" x1="${positions[e[0]][0]}" y1="${positions[e[0]][1]}" x2="${positions[e[1]][0]}" y2="${positions[e[1]][1]}"/>`).join('')}${nodes.map((n, i) => `<circle class="node ${i === 0 ? 'self' : ''}" cx="${positions[i][0]}" cy="${positions[i][1]}" r="12"/><text class="node-label" x="${positions[i][0] + 16}" y="${positions[i][1] + 4}">${short(n)}</text>`).join('')}</svg>`;
    document.querySelector('#updated').textContent = `Updated ${new Date(data.generated_at).toLocaleTimeString()}`;
  }
  async function poll() { let delay = 3000; try { const response = await api('/api/mesh/status'); if (response.status === 401) { login.hidden = false; dashboard.hidden = true; return; } if (!response.ok) throw new Error(await response.text()); const data = await response.json(); delay = data.poll_interval_ms || delay; render(data); document.querySelector('#status-error').textContent = ''; } catch (e) { document.querySelector('#status-error').textContent = `Status unavailable: ${e.message}`; } setTimeout(poll, delay); }
  document.querySelector('#login-button').addEventListener('click', authenticate);
})();
