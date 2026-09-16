const API = '/api/v1';
let events = [];
let system = {};
let stream = null;
let reconnectTimer = null;
let authToken = sessionStorage.getItem('privashield.authToken') || '';

const $ = id => document.getElementById(id);
const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
}[c]));

function toast(message) {
  const el = $('toast');
  el.textContent = message;
  el.classList.add('show');
  setTimeout(() => el.classList.remove('show'), 2400);
}

function authHeaders() {
  return authToken ? { Authorization: `Bearer ${authToken}` } : {};
}

async function request(path, options = {}) {
  const response = await fetch(API + path, {
    headers: {
      'Content-Type': 'application/json',
      ...authHeaders(),
      ...(options.headers || {})
    },
    ...options
  });
  if (!response.ok) {
    let detail = `HTTP ${response.status}`;
    try { detail = (await response.json()).detail || detail; } catch {}
    if (response.status === 401) {
      detail = 'Authentication required. Enter a local bearer token.';
    }
    throw new Error(detail);
  }
  return response.json();
}

function severityBadge(level) {
  return `<span class="severity ${esc(level)}">${esc(level)}</span>`;
}

function eventRow(event) {
  return `<tr data-event-id="${esc(event.id)}"><td>${new Date(event.timestamp).toLocaleTimeString()}</td><td>${severityBadge(event.severity)}</td><td>${esc(event.source)}</td><td>${esc(event.event_type)}</td><td>${esc(event.summary)}</td><td>${esc(event.src_ip || '')}</td><td>${esc(event.dst_ip || '')}</td></tr>`;
}

function feedItem(event) {
  return `<div class="feed-item"><span class="time">${new Date(event.timestamp).toLocaleTimeString()}</span><span class="source">${esc(event.source)}</span><span>${severityBadge(event.severity)}${esc(event.summary)}</span></div>`;
}

function renderEvents() {
  const rows = events.slice(0, 100);
  $('eventTable').innerHTML = rows.map(eventRow).join('') || '<tr><td colspan="7">No events received yet.</td></tr>';
  $('liveFeed').innerHTML = rows.slice(0, 30).map(feedItem).join('') || '<p class="muted">Waiting for local telemetry.</p>';
  $('metricEvents').textContent = events.length;
  const high = events.filter(e => ['high', 'critical'].includes(e.severity)).length;
  $('metricHigh').textContent = high;
  if (events[0] && !$('analysisEventId').value) $('analysisEventId').value = events[0].id;
}

function renderSystem() {
  const components = [
    ['Database', system.database],
    ['Event bus', system.event_bus],
    ['Local AI', system.ai],
    ['Enforcement', 'inactive']
  ];
  $('componentList').innerHTML = components.map(([name, value]) =>
    `<div class="component"><strong>${esc(name)}</strong><span class="${['enabled', 'connected', 'inactive'].includes(value) ? 'ok-text' : 'warn-text'}">${esc(value || 'unknown')}</span></div>`
  ).join('');
  $('systemMode').textContent = (system.enforcement_mode || 'observe').toUpperCase();
  $('componentState').textContent = `Database ${system.database || 'unknown'} · Event bus ${system.event_bus || 'unknown'} · AI ${system.ai || 'unknown'}`;
}

function renderIdentity(identity) {
  const verified = identity.credential_verified ? 'VERIFIED' : 'UNVERIFIED DEV';
  $('authIdentity').textContent = `${identity.name} · ${identity.role} · ${verified}`;
}

async function refresh() {
  try {
    const [identity, status, stats, recent, sensors, audit, firewall, ai] = await Promise.all([
      request('/auth/me'),
      request('/system/status'),
      request('/events/stats'),
      request('/events?limit=100'),
      request('/sensors'),
      request('/audit/verify'),
      request('/firewall/config'),
      request('/ai/status')
    ]);
    renderIdentity(identity);
    system = status;
    events = recent;
    renderEvents();
    renderSystem();
    $('metricEvents').textContent = stats.total;
    $('metricHigh').textContent = (stats.by_severity?.high || 0) + (stats.by_severity?.critical || 0);
    renderSensors(sensors);
    renderAudit(audit);
    $('firewallMode').value = firewall.mode;
    $('firewallThreshold').value = firewall.threshold;
    $('thresholdValue').textContent = Number(firewall.threshold).toFixed(2);
    $('aiState').textContent = ai.enabled ? `${ai.provider} · ${ai.model} · ${ai.authority}` : `Local AI disabled · ${ai.model}`;
    $('connectionDot').className = 'dot ok';
    $('connectionText').textContent = 'API connected';
    connectStream();
  } catch (error) {
    $('connectionDot').className = 'dot bad';
    $('connectionText').textContent = 'API unavailable';
    $('authIdentity').textContent = error.message;
    toast(error.message);
  }
}

function renderSensors(sensors) {
  const active = sensors.filter(s => s.active).length;
  $('metricSensors').textContent = active;
  $('sensorTotal').textContent = `${sensors.length} registered`;
  $('sensorCards').innerHTML = sensors.map(s =>
    `<div class="sensor-card"><header><strong>${esc(s.name)}</strong><span class="${s.active ? 'ok-text' : 'warn-text'}">${s.active ? 'ACTIVE' : 'STALE'}</span></header><p>${esc(s.sensor_type)} · ${esc(s.hostname)}</p><p>Interface ${esc(s.interface || 'n/a')} · Last seen ${new Date(s.last_seen).toLocaleString()}</p></div>`
  ).join('') || '<p class="muted">No collector heartbeats have been received.</p>';
}

async function renderAudit(verification) {
  $('metricAudit').textContent = verification.valid ? 'VALID' : 'INVALID';
  $('metricAudit').className = verification.valid ? 'ok-text' : 'warn-text';
  $('auditCount').textContent = `${verification.entries} entries`;
  $('auditVerification').innerHTML = `<p class="${verification.valid ? 'ok-text' : 'warn-text'}"><strong>${verification.valid ? 'Hash chain verified' : 'Integrity failure detected'}</strong></p><p class="muted">Entries checked: ${verification.entries}</p>`;
  try {
    const entries = await request('/audit?limit=30');
    $('auditEntries').innerHTML = entries.reverse().map(e =>
      `<div class="audit-entry"><strong>#${e.sequence} ${esc(e.action)}</strong><p>${esc(e.actor)} · ${esc(e.resource_type)}</p><p>${new Date(e.timestamp).toLocaleString()}</p></div>`
    ).join('') || '<p class="muted">No audit entries yet.</p>';
  } catch {}
}

function disconnectStream() {
  if (reconnectTimer) {
    clearTimeout(reconnectTimer);
    reconnectTimer = null;
  }
  if (stream) {
    stream.onclose = null;
    stream.close();
    stream = null;
  }
}

function connectStream() {
  if (stream && [WebSocket.OPEN, WebSocket.CONNECTING].includes(stream.readyState)) return;
  const scheme = location.protocol === 'https:' ? 'wss' : 'ws';
  const protocols = ['privashield'];
  if (authToken) protocols.push(`privashield.bearer.${authToken}`);
  stream = new WebSocket(`${scheme}://${location.host}${API}/ws/events`, protocols);
  stream.onopen = () => {
    $('connectionDot').className = 'dot ok';
    $('connectionText').textContent = 'Live stream connected';
  };
  stream.onmessage = message => {
    const payload = JSON.parse(message.data);
    if (payload.type === 'security.event') {
      events.unshift(payload.data);
      events = events.slice(0, 200);
      renderEvents();
    }
  };
  stream.onclose = event => {
    stream = null;
    if (event.code === 4401 || event.code === 4403) {
      $('connectionDot').className = 'dot bad';
      $('connectionText').textContent = 'Live stream unauthorized';
      return;
    }
    reconnectTimer = setTimeout(connectStream, 2500);
  };
  stream.onerror = () => stream?.close();
}

async function saveFirewall() {
  try {
    const result = await request('/firewall/config', {
      method: 'PATCH',
      body: JSON.stringify({
        mode: $('firewallMode').value,
        threshold: Number($('firewallThreshold').value)
      })
    });
    $('systemMode').textContent = result.mode.toUpperCase();
    toast('Firewall simulation policy saved');
  } catch (error) { toast(error.message); }
}

async function evaluateFirewall() {
  try {
    const result = await request('/firewall/evaluate', {
      method: 'POST',
      body: JSON.stringify({
        risk_score: Number($('riskScore').value),
        reason: $('riskReason').value
      })
    });
    $('firewallResult').textContent = JSON.stringify(result, null, 2);
    toast('Simulation completed');
  } catch (error) { toast(error.message); }
}

async function analyzeThreat() {
  const id = $('analysisEventId').value.trim() || (events[0]?.id || '');
  if (!id) { toast('No event selected'); return; }
  $('analysisResult').textContent = 'Analyzing locally...';
  try {
    const result = await request('/ai/analyze', {
      method: 'POST',
      body: JSON.stringify({
        event_ids: [id],
        question: $('analysisQuestion').value.trim() || null
      })
    });
    $('analysisResult').innerHTML = `<div class="analysis-card"><p>${severityBadge(result.risk_level)} confidence ${Math.round(result.confidence * 100)}%</p><strong>Summary</strong><p>${esc(result.summary)}</p><strong>Evidence</strong><ul>${result.evidence.map(v => `<li>${esc(v)}</li>`).join('')}</ul><strong>Recommended actions</strong><ul>${result.recommended_actions.map(v => `<li>${esc(v)}</li>`).join('')}</ul></div>`;
  } catch (error) {
    $('analysisResult').textContent = error.message;
    toast(error.message);
  }
}

function saveAuthToken() {
  authToken = $('authToken').value.trim();
  if (authToken) sessionStorage.setItem('privashield.authToken', authToken);
  else sessionStorage.removeItem('privashield.authToken');
  $('authToken').value = '';
  disconnectStream();
  refresh();
}

function clearAuthToken() {
  authToken = '';
  sessionStorage.removeItem('privashield.authToken');
  $('authToken').value = '';
  disconnectStream();
  refresh();
}

document.querySelectorAll('.nav').forEach(button => button.addEventListener('click', () => {
  document.querySelectorAll('.nav,.view').forEach(el => el.classList.remove('active'));
  button.classList.add('active');
  $(button.dataset.view).classList.add('active');
}));
$('refreshButton').addEventListener('click', refresh);
$('saveAuthToken').addEventListener('click', saveAuthToken);
$('clearAuthToken').addEventListener('click', clearAuthToken);
$('authToken').addEventListener('keydown', event => { if (event.key === 'Enter') saveAuthToken(); });
$('firewallThreshold').addEventListener('input', event => $('thresholdValue').textContent = Number(event.target.value).toFixed(2));
$('saveFirewall').addEventListener('click', saveFirewall);
$('evaluateFirewall').addEventListener('click', evaluateFirewall);
$('analyzeThreat').addEventListener('click', analyzeThreat);
document.addEventListener('click', event => {
  const row = event.target.closest('tr[data-event-id]');
  if (row) {
    $('analysisEventId').value = row.dataset.eventId;
    document.querySelector('[data-view="interpreter"]').click();
  }
});
refresh();
setInterval(refresh, 15000);
