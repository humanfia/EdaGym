const state = { tasks: [], runs: [], selectedRun: null };
const panels = [...document.querySelectorAll('[data-panel]')];
let token = '';

function headers(extra = {}) { return { Authorization: `Bearer ${token || ''}`, ...extra }; }
async function request(path, options = {}, asText = false) {
  const response = await fetch(path, { cache: 'no-store', ...options, headers: headers(options.headers) });
  if (!response.ok) throw new Error((await response.json().catch(() => ({}))).error || `HTTP ${response.status}`);
  return asText ? response.text() : response.json();
}
async function readEvents(runId, cursor = 0) {
  const body = await request(`/api/runs/${encodeURIComponent(runId)}/events?cursor=${cursor}`, {}, true);
  const events = []; let next = cursor;
  for (const block of body.split('\n\n')) {
    const lines = block.split('\n');
    const data = lines.filter(line => line.startsWith('data: ')).map(line => line.slice(6)).join('\n');
    if (!data) continue;
    if (lines.includes('event: cursor')) next = Number(data);
    else events.push(JSON.parse(data));
  }
  return { events, cursor: { sequence: next } };
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
document.querySelector('#open-instance').addEventListener('submit', event => { event.preventDefault(); startRun(null, document.querySelector('#instance-id').value.trim()); });
document.querySelector('#connect').addEventListener('click', () => { token = document.querySelector('#token-input').value.trim(); boot(); });
document.querySelector('#token-input').addEventListener('keydown', event => { if (event.key === 'Enter') document.querySelector('#connect').click(); });

async function boot() {
  try {
    const session = await request('/api/session'); document.querySelector('#principal').textContent = session.principal_id;
    for (const [id, values] of [['profile-id', session.profiles], ['session-id', session.sessions]]) document.querySelector(`#${id}`).innerHTML = values.map(value => `<option value="${escapeAttr(value)}">${escapeHtml(value)}</option>`).join('');
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
  target.innerHTML = tasks.map(task => `<article class="task-card"><div><p class="eyebrow">${escapeHtml(task.root)}</p><h3>${escapeHtml(task.family)}</h3><p class="contract">${escapeHtml(task.contract || 'Task contract available from the authenticated catalog.')}</p><div class="tags">${(task.capabilities || []).map(cap => `<span class="tag">${escapeHtml(cap)}</span>`).join('')}</div></div><button class="button" data-start-family="${escapeAttr(task.family)}" type="button" ${task.generator_available ? '' : 'disabled'}>Create task run</button></article>`).join('');
  for (const button of target.querySelectorAll('[data-start-family]')) button.addEventListener('click', () => startRun(button.dataset.startFamily));
}
async function startRun(family, instanceId = null) {
  try {
    const result = await request('/api/runs', { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: window.location.origin, 'Idempotency-Key': `web-${crypto.randomUUID()}` }, body: JSON.stringify({ ...(instanceId ? { instance_id: instanceId } : { family }), profile_id: document.querySelector('#profile-id').value, session_id: document.querySelector('#session-id').value }) });
    state.selectedRun = result.run_id; showToast(`Run ${result.run_id} created: ${result.phase}`); setView('runs');
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
  const events = await readEvents(run.run_id).catch(error => ({ events: [{ kind: 'error', payload: { message: error.message } }], cursor: { sequence: 0 } }));
  if (state.selectedRun !== run.run_id) return;
  detail.innerHTML = `<div class="status-row"><div><p class="eyebrow">Selected run</p><h3>${escapeHtml(run.run_id)}</h3></div><span class="status ${escapeAttr(run.phase)}">${escapeHtml(run.phase)}</span></div><dl class="detail-grid"><div class="metric"><dt>Control owner</dt><dd>${escapeHtml(run.control_owner)}</dd></div><div class="metric"><dt>Next event</dt><dd>${run.next_sequence}</dd></div><div class="metric"><dt>Manifest</dt><dd>${escapeHtml(run.manifest_digest)}</dd></div><div class="metric"><dt>Reason</dt><dd>${escapeHtml(run.unavailable_reason || run.terminal_reason || 'Awaiting action')}</dd></div></dl><div class="action-row"><button class="button secondary" data-evidence="${escapeAttr(run.run_id)}" type="button">Open evidence</button><button class="button secondary" data-cancel="${escapeAttr(run.run_id)}" type="button" ${run.phase === 'terminal' || run.phase === 'unavailable' ? 'disabled' : ''}>Cancel run</button></div><div id="workspace-actions"></div><div class="event-log" aria-label="Run events">${(events.events || []).map(event => `<div class="event-line">#${event.sequence} ${escapeHtml(event.kind)} ${escapeHtml(JSON.stringify(event.payload || {}))}</div>`).join('') || '<div class="event-line">No visible events.</div>'}</div>`;
  detail.querySelector('[data-evidence]').addEventListener('click', () => { setView('evidence'); renderEvidence(run, events); }); detail.querySelector('[data-cancel]').addEventListener('click', () => cancelRun(run.run_id));
  await renderWorkspace(run);
}
async function cancelRun(runId) {
  try { await request(`/api/runs/${encodeURIComponent(runId)}/intents`, { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: window.location.origin, 'Idempotency-Key': `web-cancel-${crypto.randomUUID()}` }, body: JSON.stringify({ kind: 'cancel', payload: {} }) }); showToast('Cancel intent recorded'); await refreshRuns(); }
  catch (error) { showToast(`Cancel rejected: ${error.message}`); }
}
async function sendIntent(runId, kind, payload) {
  return request(`/api/runs/${encodeURIComponent(runId)}/intents`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'Idempotency-Key': `web-${crypto.randomUUID()}` }, body: JSON.stringify({ kind, payload }) });
}
async function renderWorkspace(run) {
  const contract = await request(`/api/runs/${encodeURIComponent(run.run_id)}/interface`).catch(() => null);
  const target = document.querySelector('#workspace-actions');
  if (!contract || !target || state.selectedRun !== run.run_id) return;
  const disabled = contract.writable ? '' : 'disabled';
  target.innerHTML = `<form id="edit-workspace" class="workspace-form"><label>Submission file<select id="workspace-path">${contract.submission_paths.map(path => `<option value="${escapeAttr(path)}">${escapeHtml(path)}</option>`).join('')}</select></label><label>Source<textarea id="workspace-content" spellcheck="false" ${disabled}></textarea></label><button class="button" type="submit" ${disabled}>Save edit</button></form><form id="invoke-tool" class="workspace-form"><label>Participant tool<select id="tool-id">${contract.tool_ids.map(id => `<option value="${escapeAttr(id)}">${escapeHtml(id)}</option>`).join('')}</select></label><label>Arguments (JSON array)<textarea id="tool-arguments" class="arguments" spellcheck="false">["-V"]</textarea></label><button class="button" type="submit" ${disabled}>Run tool</button></form><div class="workspace-form"><div class="action-row"><button class="button" id="submit-candidate" type="button" ${disabled}>Submit for evaluation</button><button class="button secondary" id="checkpoint" type="button" ${disabled}>Save checkpoint</button><button class="button secondary" id="resume-run" type="button">Resume run</button></div><form id="transfer-control"><label>Next control owner<input id="next-writer" required></label><button class="button secondary" type="submit" ${disabled}>Transfer control</button></form></div>`;
  async function loadSource() {
    const path = document.querySelector('#workspace-path').value;
    if (!path) return;
    try { document.querySelector('#workspace-content').value = await request(`/api/runs/${encodeURIComponent(run.run_id)}/file?path=${encodeURIComponent('workspace/' + path)}`, {}, true); }
    catch (error) { showToast(error.message); }
  }
  async function action(button, operation) {
    button.disabled = true;
    try { await operation(); showToast('Action recorded'); await refreshRuns(); }
    catch (error) { showToast(error.message); button.disabled = !contract.writable; }
  }
  target.querySelector('#workspace-path').addEventListener('change', loadSource);
  target.querySelector('#edit-workspace').addEventListener('submit', event => { event.preventDefault(); action(event.submitter, () => sendIntent(run.run_id, 'edit', { path: target.querySelector('#workspace-path').value, content: target.querySelector('#workspace-content').value })); });
  target.querySelector('#invoke-tool').addEventListener('submit', event => { event.preventDefault(); action(event.submitter, () => sendIntent(run.run_id, 'tool', { tool_id: target.querySelector('#tool-id').value, arguments: JSON.parse(target.querySelector('#tool-arguments').value) })); });
  target.querySelector('#submit-candidate').addEventListener('click', event => action(event.currentTarget, () => sendIntent(run.run_id, 'submit', { candidate_id: `candidate_${crypto.randomUUID()}` })));
  target.querySelector('#checkpoint').addEventListener('click', event => action(event.currentTarget, () => sendIntent(run.run_id, 'checkpoint', { checkpoint_id: `checkpoint_${crypto.randomUUID()}` })));
  target.querySelector('#resume-run').addEventListener('click', event => action(event.currentTarget, () => request(`/api/runs/${encodeURIComponent(run.run_id)}/resume`, { method: 'POST', headers: { 'Idempotency-Key': `resume-${crypto.randomUUID()}` } })));
  target.querySelector('#transfer-control').addEventListener('submit', event => { event.preventDefault(); action(event.submitter, () => sendIntent(run.run_id, 'transfer_control', { next_writer: target.querySelector('#next-writer').value })); });
  await loadSource();
}
function renderEvidence(run, events) {
  document.querySelector('#evidence-view').innerHTML = `<article class="evidence-panel"><p class="eyebrow">Run journal projection</p><h3>${escapeHtml(run.run_id)}</h3><pre>${escapeHtml(JSON.stringify({ manifest_digest: run.manifest_digest, phase: run.phase, events: events.events || [] }, null, 2))}</pre></article><article class="evidence-panel"><p class="eyebrow">Access boundary</p><h3>Participant view</h3><pre>${escapeHtml(JSON.stringify({ visible_event_count: (events.events || []).length, cursor: events.cursor || {}, terminal: run.phase === 'terminal' || run.phase === 'unavailable' }, null, 2))}</pre></article>`;
}
function escapeHtml(value) { return String(value ?? '').replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#039;'); }
function escapeAttr(value) { return escapeHtml(value).replaceAll('`', '&#096;'); }
boot();
