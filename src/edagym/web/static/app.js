const state = { tasks: [], runs: [], selectedRun: null };
const panels = [...document.querySelectorAll('[data-panel]')];
let token = '';

function headers(extra = {}) { return { Authorization: `Bearer ${token || ''}`, ...extra }; }
async function request(path, options = {}) {
  const response = await fetch(path, { cache: 'no-store', ...options, headers: headers(options.headers) });
  if (!response.ok) throw new Error((await response.json().catch(() => ({}))).error || `HTTP ${response.status}`);
  return response.json();
}
function showToast(message) {
  const toast = document.querySelector('#toast'); toast.textContent = message; toast.hidden = false;
  window.clearTimeout(showToast.timer); showToast.timer = window.setTimeout(() => { toast.hidden = true; }, 4200);
}
function setView(name) {
  for (const panel of panels) panel.hidden = panel.id !== name;
  for (const tab of document.querySelectorAll('[data-view]')) tab.classList.toggle('active', tab.dataset.view === name);
  if (name === 'runs') refreshRuns();
}
for (const tab of document.querySelectorAll('[data-view]')) tab.addEventListener('click', () => setView(tab.dataset.view));
document.querySelector('#task-filter').addEventListener('input', renderTasks);
document.querySelector('#refresh-runs').addEventListener('click', refreshRuns);
document.querySelector('#connect').addEventListener('click', () => { token = document.querySelector('#token-input').value.trim(); boot(); });
document.querySelector('#token-input').addEventListener('keydown', event => { if (event.key === 'Enter') document.querySelector('#connect').click(); });

async function boot() {
  try {
    const session = await request('/api/session'); document.querySelector('#principal').textContent = session.principal_id;
    state.tasks = (await request('/api/tasks')).families; renderTasks();
  } catch (error) {
    document.querySelector('#principal').textContent = 'Unavailable';
    document.querySelector('#task-list').innerHTML = `<div class="empty">${escapeHtml(error.message)}. Check the authenticated local session.</div>`;
  }
}
function renderTasks() {
  const filter = document.querySelector('#task-filter').value.toLowerCase().trim();
  const tasks = state.tasks.filter(task => JSON.stringify(task).toLowerCase().includes(filter)); const target = document.querySelector('#task-list');
  if (!tasks.length) { target.innerHTML = '<div class="empty">No task family matches this filter.</div>'; return; }
  target.innerHTML = tasks.map(task => `<article class="task-card"><div><p class="eyebrow">${escapeHtml(task.root)}</p><h3>${escapeHtml(task.family)}</h3><p class="contract">${escapeHtml(task.contract || 'Task contract available from the authenticated catalog.')}</p><div class="tags">${(task.capabilities || []).map(cap => `<span class="tag">${escapeHtml(cap)}</span>`).join('')}</div></div><button class="button" data-start-family="${escapeAttr(task.family)}" type="button">Start controlled run</button></article>`).join('');
  for (const button of target.querySelectorAll('[data-start-family]')) button.addEventListener('click', () => startRun(button.dataset.startFamily));
}
async function startRun(family) {
  try {
    const result = await request('/api/runs', { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: window.location.origin, 'Idempotency-Key': `web-${crypto.randomUUID()}` }, body: JSON.stringify({ family, difficulty: 'base', session_id: 'human' }) });
    showToast(`Run ${result.run_id} created: ${result.phase}`); setView('runs');
  } catch (error) { showToast(`Run could not start: ${error.message}`); }
}
async function refreshRuns() {
  try { state.runs = (await request('/api/runs')).runs; renderRuns(); }
  catch (error) { document.querySelector('#run-list').innerHTML = `<div class="empty">${escapeHtml(error.message)}</div>`; }
}
function renderRuns() {
  const root = document.querySelector('#run-list'); if (!state.runs.length) { root.innerHTML = '<div class="empty">No runs yet. Start one from the task catalog.</div>'; return; }
  const selected = state.selectedRun || state.runs[0].run_id; state.selectedRun = selected;
  root.innerHTML = `<div class="run-list">${state.runs.map(run => `<button class="run-card ${run.run_id === selected ? 'selected' : ''}" data-run-id="${escapeAttr(run.run_id)}" type="button"><span class="run-id">${escapeHtml(run.run_id)}</span><span class="run-meta"><span>${escapeHtml(run.phase)}</span><span>${escapeHtml(run.terminal_reason || run.unavailable_reason || 'active')}</span></span></button>`).join('')}</div><div id="run-detail" class="run-detail"></div>`;
  for (const button of root.querySelectorAll('[data-run-id]')) button.addEventListener('click', () => { state.selectedRun = button.dataset.runId; renderRuns(); });
  renderRunDetail(state.runs.find(item => item.run_id === selected));
}
async function renderRunDetail(run) {
  const detail = document.querySelector('#run-detail'); if (!run) { detail.innerHTML = '<div class="empty">Select a run.</div>'; return; }
  const events = await request(`/api/runs/${encodeURIComponent(run.run_id)}/events?cursor=0`).catch(error => ({ events: [{ kind: 'error', payload: { message: error.message } }], cursor: { sequence: 0 } }));
  detail.innerHTML = `<div class="status-row"><div><p class="eyebrow">Selected run</p><h3>${escapeHtml(run.run_id)}</h3></div><span class="status ${escapeAttr(run.phase)}">${escapeHtml(run.phase)}</span></div><dl class="detail-grid"><div class="metric"><dt>Control owner</dt><dd>${escapeHtml(run.control_owner)}</dd></div><div class="metric"><dt>Next event</dt><dd>${run.next_sequence}</dd></div><div class="metric"><dt>Manifest</dt><dd>${escapeHtml(run.manifest_digest)}</dd></div><div class="metric"><dt>Reason</dt><dd>${escapeHtml(run.unavailable_reason || run.terminal_reason || 'Awaiting action')}</dd></div></dl><div class="action-row"><button class="button secondary" data-evidence="${escapeAttr(run.run_id)}" type="button">Open evidence</button><button class="button secondary" data-cancel="${escapeAttr(run.run_id)}" type="button" ${run.phase === 'terminal' || run.phase === 'unavailable' ? 'disabled' : ''}>Cancel run</button></div><div class="event-log" aria-label="Run events">${(events.events || []).map(event => `<div class="event-line">#${event.sequence} ${escapeHtml(event.kind)} ${escapeHtml(JSON.stringify(event.payload || {}))}</div>`).join('') || '<div class="event-line">No visible events.</div>'}</div>`;
  detail.querySelector('[data-evidence]').addEventListener('click', () => { setView('evidence'); renderEvidence(run, events); }); detail.querySelector('[data-cancel]').addEventListener('click', () => cancelRun(run.run_id));
}
async function cancelRun(runId) {
  try { await request(`/api/runs/${encodeURIComponent(runId)}/intents`, { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: window.location.origin, 'Idempotency-Key': `web-cancel-${crypto.randomUUID()}` }, body: JSON.stringify({ kind: 'cancel', payload: {} }) }); showToast('Cancel intent recorded'); await refreshRuns(); }
  catch (error) { showToast(`Cancel rejected: ${error.message}`); }
}
function renderEvidence(run, events) {
  document.querySelector('#evidence-view').innerHTML = `<article class="evidence-panel"><p class="eyebrow">Run journal projection</p><h3>${escapeHtml(run.run_id)}</h3><pre>${escapeHtml(JSON.stringify({ manifest_digest: run.manifest_digest, phase: run.phase, events: events.events || [] }, null, 2))}</pre></article><article class="evidence-panel"><p class="eyebrow">Access boundary</p><h3>Participant view</h3><pre>${escapeHtml(JSON.stringify({ visible_event_count: (events.events || []).length, cursor: events.cursor || {}, terminal: events.terminal }, null, 2))}</pre></article>`;
}
function escapeHtml(value) { return String(value ?? '').replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#039;'); }
function escapeAttr(value) { return escapeHtml(value).replaceAll('`', '&#096;'); }
boot();
