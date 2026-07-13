const threats = [
  {
    id: 'TC-DEMO-024', severity: 'critical', type: 'CLOUD IDENTITY CAMPAIGN', title: 'Glass Meridian targets fictional cloud sign-in flows',
    summary: 'Synthetic reports describe token replay and consent-grant abuse patterns affecting collaboration tenants.', relevance: 'Potential relevance: identity providers', confidence: 'HIGH', sourceCount: 3,
    tags: ['T1078 Valid Accounts', 'T1528 Token Theft'], action: 'Review identity telemetry coverage', source: 'Northstar Research (fictional)', date: 'Jul 12, 2026', bullets: ['Confirm authorization before reviewing any production tenant logs.', 'Validate sign-in and OAuth application audit telemetry is retained.', 'Use the Detection Studio draft as a human-review starting point.']
  },
  {
    id: 'TC-DEMO-017', severity: 'high', type: 'RANSOMWARE PRECURSOR', title: 'Copper Vale uses staged remote-access tooling',
    summary: 'Fictional incident reporting suggests credential access followed by remote service creation in lab environments.', relevance: 'Potential relevance: Windows endpoints', confidence: 'MEDIUM', sourceCount: 2,
    tags: ['T1021 Remote Services', 'T1569 System Services'], action: 'Review remote service detection draft', source: 'Demo CERT bulletin', date: 'Jul 11, 2026', bullets: ['Review the synthetic Sigma draft for expected administrative activity.', 'Confirm required Windows service creation telemetry before tuning.', 'Do not treat this demo item as evidence of compromise.']
  },
  {
    id: 'TC-DEMO-031', severity: 'high', type: 'PHISHING CAMPAIGN', title: 'Harbor Lantern lures mimic document-share notices',
    summary: 'Fictional phishing content uses collaboration-themed landing pages and example-only indicator patterns.', relevance: 'Potential relevance: collaboration tools', confidence: 'HIGH', sourceCount: 4,
    tags: ['T1566 Phishing', 'T1204 User Execution'], action: 'Brief users on document-share lures', source: 'ThreatCommand demo feed', date: 'Jul 11, 2026', bullets: ['Use only approved awareness channels and example indicators.', 'Validate email gateway logging is available for authorized review.', 'Add the draft to a local briefing after human review.']
  },
  {
    id: 'TC-DEMO-009', severity: 'high', type: 'VULNERABILITY SIGNAL', title: 'CVE-2026-00042 gains synthetic KEV designation',
    summary: 'A fictional public-facing appliance issue is modeled as actively exploited for prioritization practice.', relevance: 'Potential relevance: confirm product inventory', confidence: 'HIGH', sourceCount: 2,
    tags: ['CVE-2026-00042', 'Patch priority'], action: 'Assess affected product inventory', source: 'Demo KEV catalog', date: 'Jul 10, 2026', bullets: ['Confirm whether the fictional product is present before taking action.', 'Use local vulnerability workflow to record assessment evidence.', 'No exploit details are included in this defensive prototype.']
  }
];

const actions = [
  { text: 'Review cloud identity detection gap', meta: 'Linked: TC-DEMO-024 · Today', priority: 'HIGH' },
  { text: 'Assess CVE-2026-00042 potential relevance', meta: 'Linked: TC-DEMO-009 · Due Jul 15', priority: 'HIGH' },
  { text: 'Add phishing campaign to weekly brief', meta: 'Linked: TC-DEMO-031 · This week', priority: 'MEDIUM' }
];

const workspaceContent = {
  priority: { eyebrow: 'LOCAL TRIAGE QUEUE', title: 'Priority Threats', description: 'Review fictional intelligence records with evidence, confidence labels, and human-approved next actions.', note: 'All threat records shown in this Phase 1 workspace are synthetic. They do not describe live activity, exposure, or compromise.' },
  explorer: { eyebrow: 'LOCAL ENTITY EXPLORATION', title: 'Intelligence Explorer', description: 'Find reports, CVEs, indicators, ATT&CK techniques, actors, malware, and locally saved notes.', note: 'Search is intentionally restricted to the locally bundled demo dataset in this prototype.' },
  vulnerabilities: { eyebrow: 'VULNERABILITY PRIORITIZATION', title: 'Vulnerabilities', description: 'Prioritize potential relevance without asserting affected versions, exposure, or patch status.', note: 'Potential technology matches are not proof of vulnerability or exposure.' },
  actors: { eyebrow: 'ENTITY INTELLIGENCE', title: 'Threat Actors & Malware', description: 'Explore fictional actor, campaign, and malware profiles with explicit attribution uncertainty.', note: 'Attribution shown here is fictional and modeled only for UI review.' },
  iocs: { eyebrow: 'INDICATOR WORKSPACE', title: 'IOC Intelligence', description: 'Track source provenance, confidence, staleness, and relationships for locally held indicators.', note: 'Demo IOCs use RFC-safe example data and are never queried externally.' },
  detection: { eyebrow: 'HUMAN-REVIEW REQUIRED', title: 'Detection Studio', description: 'Draft, review, explain, and export defensive detections—never auto-deploy them.', note: 'Every generated or sample detection is a DRAFT — HUMAN REVIEW REQUIRED.' },
  hunting: { eyebrow: 'AUTHORIZED DEFENSIVE HUNTING', title: 'Threat Hunting', description: 'Develop hypotheses and review only the systems and logs you are authorized to access.', note: 'This visual prototype contains no active scanning, system access, or query execution.' },
  knowledge: { eyebrow: 'LOCAL KNOWLEDGE VAULT', title: 'Knowledge Base', description: 'Build a private, source-linked record of research, notes, playbooks, and lessons learned.', note: 'Phase 1 demonstrates a local workspace only; no documents are imported or indexed.' },
  digest: { eyebrow: 'LOCAL-ONLY REPORTING', title: 'Digest Studio', description: 'Build local executive, analyst, and technical briefs from selected evidence.', note: 'Exports and email delivery are intentionally not enabled in this Phase 1 visual prototype.' },
  feeds: { eyebrow: 'NETWORK & PRIVACY', title: 'Feed Sources', description: 'See every enabled connector, the requested data, network mode, and complete local request history.', note: 'No connectors are enabled. This prototype makes zero external requests.' },
  copilot: { eyebrow: 'OLLAMA-ONLY LOCAL AI', title: 'Local AI Copilot', description: 'Ground analysis in permitted local records with citations and explicit uncertainty.', note: 'Ollama is not connected in this visual prototype, and no remote AI fallback exists.' },
  settings: { eyebrow: 'LOCAL CONTROL PLANE', title: 'Settings & Privacy', description: 'Control local-only storage, network behavior, model connections, exports, and privacy warnings.', note: 'Default network mode is Manual Sync. External requests are disabled in this Phase 1 build.' },
  backup: { eyebrow: 'DATA PORTABILITY', title: 'Backup & Restore', description: 'Prepare local-only backups and transparent restore workflows with destructive-operation warnings.', note: 'Backup is represented as a visual workflow only in Phase 1; no data is written or overwritten.' }
};

let currentView = 'command';
let networkMode = 'MANUAL SYNC';
let toastTimer;

const $ = (selector, parent = document) => parent.querySelector(selector);
const $$ = (selector, parent = document) => [...parent.querySelectorAll(selector)];

function renderThreatCards() {
  $('#threat-grid').innerHTML = threats.map((threat, index) => `
    <article class="threat-card panel ${threat.severity}">
      <div class="threat-card-top"><span class="type-label">${threat.type}</span><span class="severity ${threat.severity}">${threat.severity.toUpperCase()}</span></div>
      <h3>${threat.title}</h3><p>${threat.summary}</p>
      <div class="threat-tags">${threat.tags.map(tag => `<span>${tag}</span>`).join('')}</div>
      <div class="threat-meta"><span>Confidence <b>${threat.confidence}</b></span><span>${threat.sourceCount} sources</span></div>
      <div class="card-actions"><button data-threat="${index}">Review record →</button><button class="watch" data-toast="Added ${threat.id} to a local demo watchlist.">☆ Watch</button></div>
    </article>`).join('');
}

function renderActionQueue() {
  $('#action-queue').innerHTML = actions.map((action, index) => `
    <div class="action-item"><i></i><div><strong>${action.text}</strong><span>${action.meta}</span></div><button class="${action.priority === 'HIGH' ? 'high' : ''}" data-complete-action="${index}">${action.priority}</button></div>`).join('');
}

function openThreat(index) {
  const threat = threats[index];
  $('#modal-content').innerHTML = `
    <p class="eyebrow">${threat.type} · ${threat.id}</p><h2 id="modal-title">${threat.title}</h2>
    <div class="modal-meta"><span class="severity ${threat.severity}">${threat.severity.toUpperCase()}</span><span>Confidence: ${threat.confidence}</span><span>${threat.date}</span></div>
    <p>${threat.summary}</p>
    <div class="modal-section"><h3>WHY IT MATTERS</h3><p>${threat.relevance}. This is a local, synthetic relevance assessment and must be validated before action.</p></div>
    <div class="modal-section"><h3>EVIDENCE IN LOCAL KNOWLEDGE BASE</h3><p>${threat.source} (fictional), ${threat.sourceCount} synthetic source record${threat.sourceCount > 1 ? 's' : ''}; local processing timestamp: Jul 12, 2026, 09:42 EDT.</p></div>
    <div class="modal-section"><h3>RECOMMENDED NEXT STEPS</h3><ul class="modal-list">${threat.bullets.map(bullet => `<li>${bullet}</li>`).join('')}</ul></div>
    <div class="modal-section"><h3>LIMITATIONS</h3><p>Demo data — not live threat intelligence. This record makes no claim about an actual environment, organization, victim, or system.</p></div>`;
  $('#modal-backdrop').classList.remove('hidden');
  $('#threat-modal').classList.remove('hidden');
}

function closeModal() {
  $('#modal-backdrop').classList.add('hidden');
  $('#threat-modal').classList.add('hidden');
}

function toast(message) {
  const el = $('#toast');
  el.textContent = message;
  el.classList.remove('hidden');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.add('hidden'), 3100);
}

function setMode(mode) {
  networkMode = mode;
  $('#mode-text').textContent = networkMode;
  const sync = $('#sync-button');
  if (mode === 'OFFLINE') {
    sync.disabled = true;
    sync.style.opacity = '.46';
    sync.title = 'Sync disabled in Offline Mode';
  } else {
    sync.disabled = false;
    sync.style.opacity = '1';
    sync.title = 'Visual-only sync action';
  }
  toast(mode === 'OFFLINE' ? 'Offline Mode enabled. No external requests are permitted.' : `${mode} mode enabled. Connectors remain disabled in Phase 1.`);
}

function genericRows(view) {
  if (view === 'priority') return threats.map((t, index) => `<div class="placeholder-row"><i style="background:${t.severity === 'critical' ? 'var(--red)' : 'var(--amber)'}"></i><div><b>${t.title}</b><span>${t.id} · ${t.relevance} · ${t.sourceCount} source records</span></div><button class="linkish" data-threat="${index}">Review →</button></div>`).join('');
  if (view === 'feeds') return `<table class="feed-table"><thead><tr><th>CONNECTOR</th><th>STATUS</th><th>REQUESTED DATA</th><th>LAST SYNC</th></tr></thead><tbody><tr><td><b>CISA KEV catalog</b><small>Government vulnerability catalog</small></td><td><span class="badge-offline">DISABLED</span></td><td>None</td><td>Never</td></tr><tr><td><b>MITRE ATT&CK STIX</b><small>ATT&CK technique data</small></td><td><span class="badge-offline">DISABLED</span></td><td>None</td><td>Never</td></tr><tr><td><b>Advisory RSS template</b><small>Public source template</small></td><td><span class="badge-offline">DISABLED</span></td><td>None</td><td>Never</td></tr></tbody></table>`;
  if (view === 'detection') return `<div class="placeholder-row"><i style="background:var(--amber)"></i><div><b>Suspicious OAuth consent grant patterns</b><span>Sigma · T1078 · Draft · Required telemetry: identity audit logs</span></div><em>DRAFT</em></div><div class="placeholder-row"><i style="background:var(--green)"></i><div><b>Encoded PowerShell review</b><span>Sigma · T1059.001 · Validated demo content</span></div><em style="color:var(--green)">VALIDATED</em></div><div class="placeholder-row"><i style="background:var(--amber)"></i><div><b>Remote service creation review</b><span>Microsoft Sentinel KQL · T1569 · Needs tuning</span></div><em>REVIEW</em></div>`;
  if (view === 'vulnerabilities') return `<div class="placeholder-row"><i style="background:var(--red)"></i><div><b>CVE-2026-00042 — fictional appliance issue</b><span>Simulated KEV · Potential relevance requires inventory confirmation</span></div><em style="color:var(--red)">CRITICAL</em></div><div class="placeholder-row"><i style="background:var(--amber)"></i><div><b>CVE-2026-00118 — fictional identity library issue</b><span>Potential relevance: cloud identity profile match</span></div><em>HIGH</em></div><div class="placeholder-row"><i></i><div><b>CVE-2026-00171 — fictional collaboration component</b><span>No public exploitation evidence in demo dataset</span></div><em>MEDIUM</em></div>`;
  if (view === 'copilot') return `<div class="workspace-input"><span style="color:var(--purple)">✦</span><input aria-label="Copilot prompt" placeholder="Ask about the local demo knowledge base..."><button data-toast="Connect a local Ollama model in Phase 2 to begin grounded analysis.">Analyze locally</button></div><div class="prototype-note" style="margin-top:14px">Ollama status: not connected. No remote model, API key, or cloud fallback is available. Any future answer will cite exact local source items and clearly state limitations.</div>`;
  if (view === 'settings') return `<div class="setting-line"><b>Network mode</b><small>${networkMode} · zero active connectors</small></div><div class="setting-line"><b>External requests</b><small>Blocked in prototype</small></div><div class="setting-line"><b>Local AI endpoint</b><small>Not connected</small></div><div class="setting-line"><b>Demo data</b><small>248 fictional local records</small></div><div class="setting-line"><b>Telemetry & analytics</b><small>Disabled · none collected</small></div>`;
  if (view === 'backup') return `<div class="setting-line"><b>Application database</b><small>Visual prototype — no database created</small></div><div class="setting-line"><b>Configuration export</b><small>Planned for Phase 2</small></div><div class="setting-line"><b>Backup verification</b><small>Planned for Phase 2</small></div><div class="prototype-note" style="margin-top:14px">Future restores will always show a destructive-operation warning and require explicit user confirmation.</div>`;
  if (view === 'hunting') return `<div class="placeholder-row"><i style="background:var(--amber)"></i><div><b>Review suspicious cloud sign-in patterns</b><span>Planned · T1078 · Human-review query template</span></div><em>PLANNED</em></div><div class="placeholder-row"><i></i><div><b>Investigate staged remote service creation</b><span>Draft hypothesis · T1021, T1569</span></div><em>PLANNED</em></div>`;
  return `<div class="placeholder-row"><i></i><div><b>Welcome to the local ${workspaceContent[view].title} workspace</b><span>This section is visually complete for Phase 1 and ready for local data wiring in Phase 2.</span></div><em>LOCAL</em></div><div class="placeholder-row"><i style="background:var(--purple)"></i><div><b>Synthetic reference record</b><span>Demo data · no external service, credential, or upload is used</span></div><em>DEMO</em></div>`;
}

function switchView(view) {
  currentView = view;
  $$('.nav-item').forEach(item => item.classList.toggle('active', item.dataset.view === view));
  $('#view-command').classList.toggle('hidden', view !== 'command');
  const generic = $('#view-generic');
  generic.classList.toggle('hidden', view === 'command');
  if (view !== 'command') {
    const info = workspaceContent[view];
    generic.className = 'content generic-view';
    generic.innerHTML = `<div class="crumb"><span>LOCAL WORKSPACE</span><i>/</i> ${info.title.toUpperCase()} <b>DEMO DATA — NOT LIVE THREAT INTELLIGENCE</b></div><div class="generic-hero"><p class="eyebrow">${info.eyebrow}</p><h1>${info.title}</h1><p>${info.description}</p></div><div class="generic-grid"><article class="panel"><div class="panel-heading" style="padding:16px 16px 4px"><div><p class="micro-label">PHASE 1 VISUAL PROTOTYPE</p><h2>${view === 'feeds' ? 'Connector transparency' : 'Local workspace records'}</h2></div><button class="tiny-button" data-toast="This is a visual-only Phase 1 control.">+ New local item</button></div><div class="placeholder-list">${genericRows(view)}</div></article><aside class="panel generic-side"><p class="micro-label">SAFETY & PRIVACY</p><h2>Designed for authorized defensive work</h2><p>${info.note}</p><div class="prototype-note">LOCAL ONLY<br><span style="color:#879ba4">No cloud services · no external requests · no telemetry</span></div><button class="queue-button" style="margin-top:14px" data-view="command">Return to Command Center</button></aside></div>`;
  }
  closePalette();
  $('#sidebar').classList.remove('open');
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

function openPalette() {
  $('#modal-backdrop').classList.remove('hidden');
  $('#command-palette').classList.remove('hidden');
  renderPalette('');
  setTimeout(() => $('#palette-input').focus(), 10);
}
function closePalette() { $('#command-palette').classList.add('hidden'); if ($('#threat-modal').classList.contains('hidden')) $('#modal-backdrop').classList.add('hidden'); }
function renderPalette(query) {
  const quick = [{ view: 'command', icon: '⌘', title: 'Command Center', detail: 'Local operational overview' }, ...Object.entries(workspaceContent).map(([view, item]) => ({ view, icon: view === 'copilot' ? '✦' : '◇', title: item.title, detail: item.eyebrow }))];
  const matches = quick.filter(item => `${item.title} ${item.detail}`.toLowerCase().includes(query.toLowerCase())).slice(0, 7);
  $('#palette-options').innerHTML = matches.length ? matches.map(item => `<button class="palette-option" data-view="${item.view}"><i>${item.icon}</i><span>${item.title}<small>${item.detail}</small></span></button>`).join('') : '<p style="padding:9px 15px 15px;color:#81939b;font-size:11px">No local matching workspace found.</p>';
}

function bindEvents() {
  document.addEventListener('click', event => {
    const viewButton = event.target.closest('[data-view]');
    if (viewButton) { switchView(viewButton.dataset.view); return; }
    const threatButton = event.target.closest('[data-threat]');
    if (threatButton) { openThreat(Number(threatButton.dataset.threat)); return; }
    const toastButton = event.target.closest('[data-toast]');
    if (toastButton) { toast(toastButton.dataset.toast); return; }
    const complete = event.target.closest('[data-complete-action]');
    if (complete) { const index = Number(complete.dataset.completeAction); const done = actions.splice(index, 1)[0]; renderActionQueue(); toast(`Marked “${done.text}” as complete in this local demo session.`); return; }
    if (event.target.closest('[data-close-modal]') || event.target === $('#modal-backdrop')) { closeModal(); closePalette(); }
  });
  $('#mode-toggle').addEventListener('click', () => setMode(networkMode === 'OFFLINE' ? 'MANUAL SYNC' : 'OFFLINE'));
  $('#sync-button').addEventListener('click', () => toast('Visual prototype: no sync occurs. No external request was made.'));
  $('#add-action').addEventListener('click', () => { actions.unshift({ text: 'New local analyst action', meta: 'Created now · unlinked demo item', priority: 'MEDIUM' }); renderActionQueue(); toast('Local demo action added.'); });
  $('#search-button').addEventListener('click', openPalette);
  $('#menu-button').addEventListener('click', () => $('#sidebar').classList.add('open'));
  $('#mobile-close').addEventListener('click', () => $('#sidebar').classList.remove('open'));
  $('#notification-button').addEventListener('click', () => toast('3 demo notifications: one detection draft, two priority review items.'));
  $('#palette-input').addEventListener('input', event => renderPalette(event.target.value));
  document.addEventListener('keydown', event => {
    if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') { event.preventDefault(); openPalette(); }
    if (event.key === 'Escape') { closeModal(); closePalette(); $('#sidebar').classList.remove('open'); }
  });
}

renderThreatCards();
renderActionQueue();
bindEvents();
