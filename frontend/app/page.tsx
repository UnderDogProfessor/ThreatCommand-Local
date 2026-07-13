"use client";

import { ChangeEvent, FormEvent, useEffect, useMemo, useRef, useState } from "react";

type Threat = { reference_id: string; title: string; category: string; severity: string; confidence: string; summary: string; potential_relevance: string; source_count: number; tags: string[]; attack_techniques: string[]; demo: boolean };
type Action = { id: string; title: string; action_type: string; priority: string; linked_reference?: string; created_at: string };
type Detection = { id: string; title: string; description: string; rule_format: string; status: string; maturity?: string; telemetry_state?: string; attack_techniques: string[]; required_telemetry: string[]; segment?: string; learning_purpose?: boolean; library_rank?: number };
type Dashboard = { demo_notice: string; network_mode: string; posture: { score: number; label: string; inputs: string[]; limitation: string }; threats: Threat[]; actions: Action[]; coverage: { technique: string; status: string; count: number }[]; vulnerabilities: { cve_id: string; title: string; severity: string; kev: boolean; potential_relevance: string; recommended_action: string }[] };
type DashboardWithStatus = Dashboard & { data_status?: { notice: string; total: number; live_count: number; demo_count: number; live_kev_count: number } };
type LiveOverview = { new_kev_7d: number; recent_kevs: { cve_id: string; title: string; severity: string; potential_relevance: string; source_url: string; published_at?: string }[]; live_news: { reference_id: string; title: string; summary: string; severity: string; tags: string[]; published_at?: string; source_url: string; connector_key: string }[]; zero_day_watch: { reference_id: string; title: string; summary: string; severity: string; published_at?: string; source_url: string; connector_key: string }[]; feed_health: { key: string; name: string; enabled: boolean; last_status: string; last_sync_at?: string; records_added: number; records_updated: number; records_failed: number }[]; learning_library: { segment: string; count: number }[] };
type LiveDashboard = Dashboard & { live_overview: LiveOverview };
type Connector = { key: string; name: string; description: string; source_url: string; data_type: string; enabled: boolean; last_status: string; last_sync_at?: string; last_content_at?: string; next_sync_at?: string; schedule_hours?: number; retention_days?: number; credential_required: boolean; records_failed?: number; parser_available?: boolean };
type SearchItem = { reference_id: string; title: string; summary: string; kind: string };
type Vulnerability = { cve_id: string; title: string; description: string; severity: string; cvss?: number; kev: boolean; exploitation_evidence?: string; potential_relevance: string; recommended_action: string; source_url?: string; published_at?: string; demo: boolean };
type VulnerabilityPage = { items: Vulnerability[]; total: number; offset: number; limit: number; counts: { total: number; live_count: number; demo_count: number; live_kev_count: number } };
type ConnectorLog = { id: string; connector_key?: string; requested_at: string; request_method: string; destination: string; outcome: string; status_code?: number; records_added: number; records_updated: number; records_skipped: number; records_failed: number; detail?: string };
type DetailResponse = { kind: "vulnerability" | "threat" | "detection"; record: Record<string, any>; limitations?: string; learning_steps?: string[]; revisions?: { version: number; change_summary: string; created_at: string }[]; validation_results?: { fixture_name: string; outcome: string; evidence: string; created_at: string }[]; learning?: { what_to_learn: string; why_it_matters: string; technical_explanation: string; kill_chain: { phase: string; explanation: string }[]; detection_logic: string; false_positives: string; tuning: string; how_to_use: string; validation: string; limitations: string } };
type NewsItem = { reference_id: string; title: string; summary: string; severity: string; tags: string[]; published_at?: string; confidence: string; connector_key: string; source_url: string };
type NewsPage = { items: NewsItem[]; total: number; offset: number; limit: number };
type Watchlist = { id: string; name: string; description: string; color: "cyan" | "amber" | "purple" | "red"; item_count: number; created_at: string; updated_at: string };
type HuntCase = { id: string; name: string; objective: string; hypothesis: string; scope: string; status: "planned" | "active" | "complete" | "escalated"; attack_techniques: string[]; required_telemetry: string[]; linked_reference?: string; notes: string; created_at: string; updated_at: string };
type IncidentCase = { id: string; title: string; summary: string; severity: "critical" | "high" | "medium" | "low"; status: "open" | "investigating" | "contained" | "closed"; linked_reference?: string; notes: string; tags: string[]; created_at: string; updated_at: string };
type LocalSettings = { network_mode: string; profile: Record<string, unknown>; external_ai_enabled: boolean; external_ai_configured: boolean; available_ai_providers: string[]; local_access_configured?: boolean; local_access_required?: boolean };
type AiStatus = { provider: string; model: string; endpoint: string; external: boolean; configured: boolean; external_ai_enabled: boolean; network_mode: string; key_stored_in?: string; cloud_fallback: boolean };
type IntelligenceItem = { reference_id: string; kind: "news" | "vulnerability"; detail_kind: "threat" | "vulnerability"; title: string; summary: string; severity: string; tags: string[]; published_at?: string; confidence: string; source: string; source_url?: string };
type IntelligenceResult = { items: IntelligenceItem[]; total: number; sources: string[]; tags: string[]; local_only: boolean };
type ImportReview = { id: string; filename: string; content_type: string; content_hash: string; local_path: string; preview: string; candidate_entities: { cves?: string[]; ips?: string[]; urls?: string[]; hashes?: string[] }; status: "pending" | "approved" | "rejected"; created_at: string; reviewed_at?: string };
type StorageOverview = { database: number; raw_feed_content: number; knowledge_content: number; imports: number; exports: number; logs: number; local_only: boolean };
type LocalExport = { filename: string; bytes: number; modified_at: string };
type SourceLifecycle = { key: string; name: string; enabled: boolean; retention_days?: number; source_owner: string; terms_url?: string; license_version?: string; reliability_tier: string; permitted_use: string; policy_verified_at?: string; last_sync_at?: string; last_content_at?: string; last_status: string; failure_count: number; retry_after_at?: string; document_count: number; raw_content_bytes: number; latest_retrieved_at?: string };
type AccessStatus = { configured: boolean; required: boolean; unlocked: boolean; scope: string };
type CopilotCitation = { reference_id: string; title: string; source_url?: string; published_at?: string; retrieved_at?: string; connector_key?: string };
type SemanticStatus = { knowledge_items: number; chunks: number; indexed_chunks: number; stale_chunks: number; unindexed_items: number; configured: boolean; embedding_model?: string; dimension: number; semantic_ready: boolean; automatic_indexing: boolean; local_only: boolean; retrieval_fallback: string };
type KnowledgeRetrieval = { mode: string; items: { knowledge_item_id: string; chunk_index: number; title: string; content: string; score: number }[]; warning: string; status: SemanticStatus };

const api = process.env.NEXT_PUBLIC_API_URL ?? "http://127.0.0.1:8000";
const nav = ["Command Center", "Review Queue", "Live Cybernews", "Intelligence Explorer", "Vulnerabilities", "Technology Profile", "IOC Lifecycle", "Watchlists", "Detection Studio", "Detection Lifecycle", "Threat Hunting", "Incident Notes", "Evidence Ledger", "Knowledge Base", "Digest Studio", "Feed Sources", "Data Lifecycle", "Audit Trail", "Local AI Copilot", "Settings"];

async function apiFetch(path: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  if (["POST", "PUT", "PATCH", "DELETE"].includes((init.method ?? "GET").toUpperCase())) {
    const csrf = typeof window === "undefined" ? "" : window.sessionStorage.getItem("threatcommand_csrf") ?? "";
    if (csrf) headers.set("X-CSRF-Token", csrf);
  }
  return fetch(`${api}${path}`, { ...init, headers, credentials: "include" });
}

async function getJson<T>(path: string): Promise<T> {
  const response = await apiFetch(path, { cache: "no-store" });
  if (!response.ok) throw new Error(await response.text());
  return response.json() as Promise<T>;
}

export default function Home() {
  const [active, setActive] = useState("Command Center");
  const [dashboard, setDashboard] = useState<Dashboard | null>(null);
  const [detections, setDetections] = useState<Detection[]>([]);
  const [connectors, setConnectors] = useState<Connector[]>([]);
  const [connectorLog, setConnectorLog] = useState<ConnectorLog[]>([]);
  const [vulnerabilityPage, setVulnerabilityPage] = useState<VulnerabilityPage | null>(null);
  const [newsPage, setNewsPage] = useState<NewsPage | null>(null);
  const [watchlists, setWatchlists] = useState<Watchlist[]>([]);
  const [hunts, setHunts] = useState<HuntCase[]>([]);
  const [incidents, setIncidents] = useState<IncidentCase[]>([]);
  const [importReviews, setImportReviews] = useState<ImportReview[]>([]);
  const [search, setSearch] = useState("");
  const [searchResult, setSearchResult] = useState<{ threats: SearchItem[]; vulnerabilities: SearchItem[]; knowledge: SearchItem[] } | null>(null);
  const [notice, setNotice] = useState("Loading local workspace…");
  const [copilotQuestion, setCopilotQuestion] = useState("");
  const [copilotAnswer, setCopilotAnswer] = useState("");
  const [copilotCitations, setCopilotCitations] = useState<CopilotCitation[]>([]);
  const [detail, setDetail] = useState<DetailResponse | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [access, setAccess] = useState<AccessStatus | null>(null);

  const refresh = async () => {
    try {
      const [nextDashboard, nextDetections, nextConnectors, nextVulnerabilities, nextNews, nextWatchlists, nextHunts, nextIncidents, nextImportReviews] = await Promise.all([getJson<DashboardWithStatus>("/api/dashboard"), getJson<Detection[]>("/api/detections"), getJson<{ connectors: Connector[]; request_log: ConnectorLog[] }>("/api/connectors"), getJson<VulnerabilityPage>("/api/vulnerabilities?limit=50"), getJson<NewsPage>("/api/news?limit=100"), getJson<Watchlist[]>("/api/watchlists"), getJson<HuntCase[]>("/api/hunts"), getJson<IncidentCase[]>("/api/incidents"), getJson<ImportReview[]>("/api/imports/review")]);
      setDashboard(nextDashboard); setDetections(nextDetections); setConnectors(nextConnectors.connectors); setConnectorLog(nextConnectors.request_log); setVulnerabilityPage(nextVulnerabilities); setNewsPage(nextNews); setWatchlists(nextWatchlists); setHunts(nextHunts); setIncidents(nextIncidents); setImportReviews(nextImportReviews); setNotice(nextDashboard.data_status?.notice ?? "Local data loaded. No external request was made.");
    } catch { setNotice("The local API is unavailable. Start ThreatCommand Local with Docker Desktop running."); }
  };
  useEffect(() => { apiFetch("/api/access/status").then((response) => response.json()).then(setAccess).catch(() => setNotice("The local API is unavailable. Start ThreatCommand Local with Docker Desktop running.")); }, []);
  useEffect(() => { if (access?.unlocked) refresh(); }, [access]);

  const mode = dashboard?.network_mode ?? "manual";
  const critical = dashboard?.threats.filter((item) => item.severity === "critical").length ?? 0;
  const filteredThreats = useMemo(() => dashboard?.threats.filter((item) => `${item.title} ${item.summary} ${item.reference_id}`.toLowerCase().includes(search.toLowerCase())) ?? [], [dashboard, search]);

  const runSearch = async (event: FormEvent) => {
    event.preventDefault(); if (search.trim().length < 2) return setSearchResult(null);
    try { setSearchResult(await getJson(`/api/search?q=${encodeURIComponent(search)}`)); } catch { setNotice("Local search needs at least two characters and a running local database."); }
  };
  const completeAction = async (id: string) => { await apiFetch(`/api/actions/${id}/complete`, { method: "POST" }); refresh(); };
  const createAction = async () => { const title = window.prompt("New local analyst action"); if (!title) return; await apiFetch("/api/actions", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ title, action_type: "Investigate", priority: "medium" }) }); refresh(); };
  const changeMode = async () => { const next = mode === "offline" ? "manual" : "offline"; const current = await getJson<LocalSettings>("/api/settings"); await apiFetch("/api/settings", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ network_mode: next, profile: current.profile }) }); refresh(); };
  const enableConnector = async (connector: Connector) => {
    const acknowledgement = window.confirm(`Enable ${connector.name}?\n\nThe provider can observe this device's public IP when you later initiate a manual sync. Source terms and rate limits apply. No request will be made by enabling.`);
    if (!acknowledgement) return;
    const response = await apiFetch(`/api/connectors/${connector.key}`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ enabled: !connector.enabled, acknowledged_network_disclosure: !connector.enabled }) });
    if (!response.ok) setNotice("Connector setting was not changed."); else { setNotice(`${connector.name} updated. A separate Manual Sync confirmation is required before any request.`); refresh(); }
  };
  const toggleAllConnectors = async () => {
    const enable = connectors.some((connector) => !connector.enabled);
    const message = enable ? `Enable all ${connectors.length} feed sources?\n\nThis does not make a request now. Each provider can observe your public IP only when you later use Manual Sync.` : "Disable every feed source? This stops future Manual Sync requests but preserves locally imported records.";
    if (!window.confirm(message)) return;
    const response = await apiFetch("/api/connectors", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ enabled: enable, acknowledged_network_disclosure: enable }) });
    const data = await response.json(); setNotice(response.ok ? `${data.affected_connectors} feed sources are now ${enable ? "enabled" : "disabled"}.` : (data.detail ?? "Feed sources were not updated.")); refresh();
  };
  const syncConnector = async (connector: Connector) => {
    if (!window.confirm(`Manually sync ${connector.name} from ${connector.source_url}? This creates an outbound request visible to the provider.`)) return;
    const response = await apiFetch(`/api/connectors/${connector.key}/sync`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ confirmed: true }) });
    const data = await response.json(); setNotice(response.ok ? `Manual sync finished: ${data.added} added, ${data.updated} updated.` : (data.detail ?? "Manual sync did not run.")); refresh();
  };
  const syncAllEnabled = async () => {
    const enabled = connectors.filter((connector) => connector.enabled);
    if (!enabled.length) return setNotice("Enable at least one feed source before syncing.");
    if (!window.confirm(`Manually sync all ${enabled.length} enabled sources now?\n\nThis creates one outbound request per enabled source. Each request is logged locally, and unavailable or unsupported sources will be reported without stopping the rest.`)) return;
    const response = await apiFetch("/api/connectors/sync-enabled", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ confirmed: true }) });
    const data = await response.json(); const successful = data.results?.filter((result: { outcome: string }) => result.outcome === "success").length ?? 0; setNotice(response.ok ? `Sync enabled completed: ${successful} succeeded out of ${data.attempted}. Review the local request log for details.` : (data.detail ?? "Sync enabled did not run.")); refresh();
  };
  const updateConnectorSchedule = async (connector: Connector, schedule_hours: number) => { const response = await apiFetch(`/api/connectors/${connector.key}`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ enabled: connector.enabled, schedule_hours }) }); setNotice(response.ok ? `${connector.name} will use a ${schedule_hours}-hour local schedule when Scheduled Sync is active.` : "Schedule was not updated."); if (response.ok) refresh(); };
  const askCopilot = async (event: FormEvent, approveExternal = false) => { event.preventDefault(); setCopilotAnswer("Checking the selected AI provider…"); setCopilotCitations([]); const response = await apiFetch("/api/copilot", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ question: copilotQuestion, approve_external: approveExternal }) }); const data = await response.json(); if (response.ok) { setCopilotAnswer(`${data.answer}\n\n${data.warning ?? ""}`.trim()); setCopilotCitations(data.citations ?? []); } else setCopilotAnswer(data.detail ?? "Select a configured provider before using the Copilot."); };
  const importFile = async (event: ChangeEvent<HTMLInputElement>) => { const file = event.target.files?.[0]; if (!file) return; const data = new FormData(); data.append("file", file); const response = await apiFetch("/api/imports", { method: "POST", body: data }); const result = await response.json(); event.target.value = ""; setNotice(response.ok ? `${result.status === "duplicate" ? "Already staged locally" : "Queued locally for review"}: ${file.name}. ${result.warning}` : (result.detail ?? "Local import failed.")); if (response.ok) refresh(); };
  const decideImport = async (id: string, decision: "approve" | "reject") => { const response = await apiFetch(`/api/imports/review/${id}/${decision}`, { method: "POST" }); const result = await response.json(); setNotice(response.ok ? `Local import ${decision === "approve" ? "approved" : "rejected"}. ${result.warning}` : (result.detail ?? "The import review decision was not saved.")); if (response.ok) refresh(); };
  const deleteImport = async (id: string, filename: string) => { if (window.prompt(`This permanently deletes ${filename}, its review record, and any searchable knowledge created from it on this device. Type DELETE to continue.`) !== "DELETE") return; const response = await apiFetch(`/api/imports/review/${id}`, { method: "DELETE", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ confirmation: "DELETE" }) }); const result = await response.json(); setNotice(response.ok ? result.warning : (result.detail ?? "The local import could not be deleted.")); if (response.ok) refresh(); };
  const openDetail = async (kind: DetailResponse["kind"], id: string) => { setDetailLoading(true); setDetail(null); try { setDetail(await getJson<DetailResponse>(`/api/${kind === "vulnerability" ? "vulnerabilities" : kind === "threat" ? "threats" : "detections"}/${encodeURIComponent(id)}`)); } catch { setNotice("The selected local record could not be loaded."); } finally { setDetailLoading(false); } };
  const loadMoreNews = async () => { if (!newsPage || newsPage.items.length >= newsPage.total) return; try { const next = await getJson<NewsPage>(`/api/news?limit=100&offset=${newsPage.items.length}`); setNewsPage({ ...next, items: [...newsPage.items, ...next.items], offset: 0, limit: newsPage.items.length + next.items.length }); } catch { setNotice("More local cybernews could not be loaded."); } };
  const createWatchlist = async (payload: { name: string; description: string; color: string }) => { const response = await apiFetch("/api/watchlists", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) }); const data = await response.json(); setNotice(response.ok ? `Local watchlist created: ${data.name}.` : (data.detail ?? "Watchlist was not created.")); if (response.ok) refresh(); };
  const createHunt = async (payload: Record<string, unknown>) => { const response = await apiFetch("/api/hunts", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) }); const data = await response.json(); setNotice(response.ok ? `Local hunt created: ${data.name}.` : (data.detail ?? "Hunt was not created.")); if (response.ok) refresh(); };
  const updateHuntStatus = async (id: string, status: HuntCase["status"]) => { const response = await apiFetch(`/api/hunts/${id}/status`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ status }) }); if (response.ok) refresh(); else setNotice("Hunt status was not updated."); };
  const createIncident = async (payload: Record<string, unknown>) => { const response = await apiFetch("/api/incidents", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) }); const data = await response.json(); setNotice(response.ok ? `Local incident case created: ${data.title}.` : (data.detail ?? "Incident case was not created.")); if (response.ok) refresh(); };
  const updateIncidentStatus = async (id: string, status: IncidentCase["status"]) => { const response = await apiFetch(`/api/incidents/${id}/status`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ status }) }); if (response.ok) refresh(); else setNotice("Incident status was not updated."); };
  const addWatchlistItem = async (watchlistId: string, payload: { entity_type: string; reference_id: string; title: string }) => { const response = await apiFetch(`/api/watchlists/${watchlistId}/items`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) }); const data = await response.json(); setNotice(response.ok ? `Added to your local watchlist: ${data.title || payload.reference_id}.` : (data.detail ?? "The item was not added to the watchlist.")); if (response.ok) refresh(); };

  if (!access) return <main className="access-gate"><section className="panel access-card"><p>THREATCOMMAND LOCAL</p><h1>Checking local access…</h1><span>The dashboard is waiting for the localhost API.</span></section></main>;
  if (!access.unlocked) return <LocalAccessGate configured={access.configured} onUnlocked={(status) => setAccess(status)} />;

  return <div className="shell">
    <aside className="rail"><div className="brand"><span className="brand-mark">◈</span><div><strong>THREAT<span>COMMAND</span></strong><small>LOCAL INTELLIGENCE HUB</small></div></div><p className="rail-label">OPERATIONS</p>{nav.map((item) => <button key={item} className={active === item ? "nav active" : "nav"} onClick={() => setActive(item)}><i>{item === "Command Center" ? "⌘" : item === "Local AI Copilot" ? "✦" : "◇"}</i>{item}</button>)}<div className="rail-bottom"><span className="dot"/> LOCAL DATA VAULT<br/><small>Database and imports remain on this device.</small></div></aside>
    <main><header><form onSubmit={runSearch} className="search"><span>⌕</span><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search local intelligence, CVEs, IOCs…"/><kbd>ENTER</kbd></form><div className="header-actions"><span className="badge local">● LOCAL FIRST</span><button className={`badge mode ${mode}`} onClick={changeMode}>● {mode.toUpperCase()}</button><span className="ollama">✦ AI PROVIDER <small>see Settings</small></span></div></header>
      <section className="workspace"><div className="notice"><b>DEMO DATA — NOT LIVE THREAT INTELLIGENCE</b><span>{notice}</span></div>
        <div className="data-status"><b>{vulnerabilityPage?.counts.live_count ? "LOCAL DATA — LIVE + DEMO" : "DEMO DATA — NOT LIVE THREAT INTELLIGENCE"}</b><span>{notice}</span></div>
        {searchResult && <section className="search-results panel"><div className="section-top"><h2>Local search results</h2><button onClick={() => setSearchResult(null)}>Clear</button></div>{[...searchResult.threats, ...searchResult.vulnerabilities, ...searchResult.knowledge].map((item) => <article key={`${item.kind}-${item.reference_id}`}><b>{item.reference_id}</b><div><strong>{item.title}</strong><p>{item.summary}</p></div><em>{item.kind}</em></article>)}</section>}
        {active === "Command Center" && dashboard && <InteractiveCommandCenter dashboard={dashboard as LiveDashboard} setActive={setActive} openDetail={openDetail} />}
        {active === "Review Queue" && <ReviewQueueWorkspace openDetail={openDetail} />}
        {active === "Live Cybernews" && <LiveCybernewsWorkspace page={newsPage} openDetail={openDetail} loadMore={loadMoreNews} />}
        {active === "Intelligence Explorer" && <IntelligenceExplorer openDetail={openDetail} />}
        {active === "Vulnerabilities" && <InteractiveVulnerabilities page={vulnerabilityPage} openDetail={openDetail} />}
        {active === "Technology Profile" && <TechnologyProfileWorkspace />}
        {active === "IOC Lifecycle" && <IocLifecycleWorkspace />}
        {active === "Watchlists" && <WatchlistsWorkspace watchlists={watchlists} createWatchlist={createWatchlist} />}
        {active === "Detection Studio" && <InteractiveLearningLibrary detections={detections} openDetail={openDetail} />}
        {active === "Detection Lifecycle" && <DetectionLifecycleWorkspace detections={detections} />}
        {active === "Threat Hunting" && <ThreatHuntingWorkspace hunts={hunts} createHunt={createHunt} updateStatus={updateHuntStatus} />}
        {active === "Incident Notes" && <IncidentNotesWorkspace incidents={incidents} createIncident={createIncident} updateStatus={updateIncidentStatus} />}
        {active === "Evidence Ledger" && <CaseEvidenceWorkspace hunts={hunts} incidents={incidents} />}
        {active === "Feed Sources" && <ResilientFeedsView connectors={connectors} logs={connectorLog} mode={mode} enableConnector={enableConnector} syncConnector={syncConnector} updateSchedule={updateConnectorSchedule} toggleAll={toggleAllConnectors} syncAll={syncAllEnabled} />}
        {active === "Data Lifecycle" && <DataLifecycleWorkspace />}
        {active === "Audit Trail" && <AuditTrailWorkspace />}
        {active === "Local AI Copilot" && <CopilotView question={copilotQuestion} setQuestion={setCopilotQuestion} answer={copilotAnswer} citations={copilotCitations} submit={askCopilot} />}
        {active === "Knowledge Base" && <KnowledgeReviewWorkspace reviews={importReviews} importFile={importFile} decideImport={decideImport} deleteImport={deleteImport} />}
        {active === "Digest Studio" && <DigestView setNotice={setNotice} />}
        {active === "Settings" && <AiProviderSettings />}
      </section>
      {(detail || detailLoading) && <RecordModal detail={detail} loading={detailLoading} watchlists={watchlists} addWatchlistItem={addWatchlistItem} close={() => { setDetail(null); setDetailLoading(false); }} />}
    </main>
  </div>;
}

function CommandCenter({ dashboard, threats, critical, completeAction, createAction }: { dashboard: Dashboard; threats: Threat[]; critical: number; completeAction: (id: string) => void; createAction: () => void }) { return <><div className="title"><div><p>SITUATIONAL AWARENESS</p><h1>Command Center</h1><span>Evidence-led intelligence for your local defensive workflow.</span></div><div className="live"><i/> LOCAL DATABASE CONNECTED</div></div><div className="privacy"><b>Private by design.</b> This system is bound to localhost. Connectors are disabled by default and every external request requires confirmation.</div><section className="stats"><article className="panel posture"><span>LOCAL THREAT POSTURE</span><div><strong>{dashboard.posture.score}</strong><b>{dashboard.posture.label.toUpperCase()}</b></div><p>{dashboard.posture.limitation}</p></article><article className="panel"><span>PRIORITY ITEMS</span><strong>{threats.length}</strong><p>{critical} critical demo item{critical === 1 ? "" : "s"} · human review required</p></article><article className="panel"><span>DETECTION COVERAGE</span><strong>{dashboard.coverage.length}<small> techniques</small></strong><p>Draft and validated local detection content</p></article><article className="panel"><span>VULNERABILITIES</span><strong>{dashboard.vulnerabilities.length}</strong><p>Potential relevance only until you validate inventory</p></article></section><section className="grid"><article className="panel analyst"><div className="section-top"><div><p>WHAT CHANGED</p><h2>Local analyst brief</h2></div><span>Manual Sync Mode</span></div><div className="brief">✦ <p><b>Local records are ready for review.</b> The database is seeded with fictional content until you explicitly import or synchronize an approved source.</p></div><div className="coverage">{dashboard.coverage.map((item) => <span key={`${item.technique}-${item.status}`}><b>{item.technique}</b>{item.status}</span>)}</div></article><article className="panel queue"><div className="section-top"><div><p>PERSONAL ACTION QUEUE</p><h2>Next best actions</h2></div><button onClick={createAction}>+ Add</button></div>{dashboard.actions.map((action) => <div className="action" key={action.id}><i/><div><strong>{action.title}</strong><small>{action.action_type} · {action.linked_reference ?? "local task"}</small></div><button onClick={() => completeAction(action.id)}>Complete</button></div>)}</article></section><div className="section-top list-title"><div><p>EVIDENCE-LED TRIAGE</p><h2>Priority threats</h2></div><span>All items are fictional demo data</span></div><ThreatsView threats={threats}/></> }
function ThreatsView({ threats }: { threats: Threat[] }) { return <section className="cards">{threats.map((item) => <article className={`panel threat ${item.severity}`} key={item.reference_id}><div><span>{item.category}</span><b>{item.severity.toUpperCase()}</b></div><h3>{item.title}</h3><p>{item.summary}</p><div className="tags">{item.attack_techniques.map((tag) => <i key={tag}>{tag}</i>)}</div><footer>{item.reference_id}<em>{item.confidence}</em></footer></article>)}</section> }
function VulnerabilitiesView({ items }: { items: Dashboard["vulnerabilities"] }) { return <GenericView title="Vulnerability Workspace" copy="Vulnerability records are prioritized for potential relevance. The workspace never claims actual vulnerability, exposure, compromise, or patch status without validated user evidence." children={<div className="table">{items.map((item) => <article key={item.cve_id}><b>{item.cve_id}</b><div><strong>{item.title}</strong><p>{item.potential_relevance}</p></div><span className={item.kev ? "kev" : ""}>{item.kev ? "DEMO KEV" : item.severity.toUpperCase()}</span><em>{item.recommended_action}</em></article>)}</div>}/> }
function DetectionView({ detections }: { detections: Detection[] }) { return <GenericView title="Detection Studio" copy="All saved detection content is DRAFT — HUMAN REVIEW REQUIRED unless explicitly validated in your authorized environment." children={<div className="table">{detections.map((item) => <article key={item.id}><b>{item.rule_format}</b><div><strong>{item.title}</strong><p>{item.description} · {item.attack_techniques.join(", ")}</p></div><span className={item.status}>{item.status.toUpperCase()}</span><em>{item.required_telemetry.join(", ")}</em></article>)}</div>}/> }
function FeedsView({ connectors, mode, enableConnector, syncConnector }: { connectors: Connector[]; mode: string; enableConnector: (connector: Connector) => void; syncConnector: (connector: Connector) => void }) { return <GenericView title="Feed Sources & Network Transparency" copy={`Current mode: ${mode}. No source makes a request until it is enabled, its disclosure is acknowledged, and you separately confirm Manual Sync.`} children={<div className="table">{connectors.map((item) => <article key={item.key}><b>{item.enabled ? "ENABLED" : "DISABLED"}</b><div><strong>{item.name}</strong><p>{item.description}<br/><code>{item.source_url}</code></p></div><span>{item.data_type}</span><div className="row-buttons"><button onClick={() => enableConnector(item)}>{item.enabled ? "Disable" : "Enable"}</button><button disabled={!item.enabled || mode === "offline"} onClick={() => syncConnector(item)}>Sync now</button></div></article>)}</div>}/> }
function CopilotView({ question, setQuestion, answer, citations, submit }: { question: string; setQuestion: (value: string) => void; answer: string; citations: CopilotCitation[]; submit: (event: FormEvent, approveExternal?: boolean) => void }) {
  const [ai, setAi] = useState<AiStatus | null>(null);
  const [approveExternal, setApproveExternal] = useState(false);
  useEffect(() => { getJson<AiStatus>("/api/ai/status").then(setAi).catch(() => setAi(null)); }, []);
  const external = Boolean(ai?.external);
  return <GenericView title="Local AI Copilot" copy="Answers are grounded in a bounded local evidence set. Feed text is treated as untrusted data; the Copilot cannot run tools, change settings, or take response actions." children={<form className="copilot" onSubmit={(event) => submit(event, approveExternal)}>
    <textarea value={question} onChange={(event) => setQuestion(event.target.value)} placeholder="Ask about local intelligence, a CVE, a detection, or a hunt hypothesis…"/>
    <p className="page-note">Provider: <b>{ai?.provider === "ollama" ? "Local Ollama" : ai?.provider ?? "loading"}</b>. The response will include only citations selected from local records.</p>
    {external && <label className="external-ai-consent"><input type="checkbox" checked={approveExternal} onChange={(event) => setApproveExternal(event.target.checked)}/> I approve this one external request. My question and the local citation set selected for it will be sent to the configured provider; a local audit keeps only a question fingerprint and citation IDs.</label>}
    <button disabled={external && !approveExternal}>{external ? "Analyze with approved external AI" : "Analyze with local Ollama"}</button>
    {answer && <pre>{answer}</pre>}
    {citations.length > 0 && <section className="panel copilot-citations"><h2>Local evidence cited</h2>{citations.map((citation) => <article key={citation.reference_id}><b>{citation.reference_id}</b><span>{citation.title}</span>{citation.source_url && <a href={citation.source_url} target="_blank" rel="noreferrer">Original source ↗</a>}<small>Published {citation.published_at ? new Date(citation.published_at).toLocaleString() : "not supplied"} · Retrieved {citation.retrieved_at ? new Date(citation.retrieved_at).toLocaleString() : "not recorded"}</small></article>)}</section>}
  </form>}/>;
}
function DigestView({ setNotice }: { setNotice: (value: string) => void }) { const create = async () => { const response = await apiFetch("/api/digests", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ audience: "Analyst" }) }); const data = await response.json(); setNotice(response.ok ? `Local digest created: ${data.title}` : "Could not create local digest."); }; return <GenericView title="Digest Studio" copy="Generate an editable local Markdown briefing from selected database records. It is never automatically emailed, published, or uploaded." action={<button className="button" onClick={create}>Create local analyst digest</button>}/> }
function GenericView({ title, copy, children, action }: { title: string; copy: string; children?: React.ReactNode; action?: React.ReactNode }) { return <section className="generic"><div className="title"><div><p>LOCAL-ONLY WORKSPACE</p><h1>{title}</h1><span>{copy}</span></div>{action}</div>{children ?? <div className="panel empty"><b>Phase 2 local core</b><p>This workspace is connected to the local API and database foundation. More advanced capability follows in Phase 3.</p></div>}</section> }

function ReviewQueueWorkspace({ openDetail }: { openDetail: (kind: DetailResponse["kind"], id: string) => void }) { const [queue, setQueue] = useState<any>(null); const load = () => getJson<any>("/api/review-queue").then(setQueue); useEffect(() => { load(); }, []); const assess = async (item: any, status: string) => { const evidence = window.prompt("Local evidence or decision note (optional)") ?? ""; const response = await apiFetch("/api/relevance", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ entity_type: "vulnerability", reference_id: item.cve_id, status, evidence }) }); if (response.ok) load(); }; return <GenericView title="Evidence Review Queue" copy="Transparent vulnerability intelligence ordered by exploitation evidence, recorded technology context, criticality, exposure, CVSS, and source recency. Unknown inputs add no points and never mean you are affected." children={<>{queue && <div className="explorer-summary"><span><b>{queue.total}</b> local items awaiting relevance review</span><span>{queue.explanation}</span></div>}<section className="case-list">{queue?.items.map((item: any) => <article className="panel case-card" key={item.cve_id}><div className="case-meta"><span>PRIORITY {item.priority.score}/100</span><select value={item.priority.relevance.status} onChange={(event) => assess(item, event.target.value)}><option value="unknown">Unknown</option><option value="potential">Potential</option><option value="confirmed">Confirmed relevance</option><option value="not_applicable">Not applicable</option></select></div><h2>{item.cve_id} — {item.title}</h2><p>{item.priority.matching_profiles.length ? `Matched local profile: ${item.priority.matching_profiles.map((profile: any) => profile.name).join(", ")}` : "No local technology profile matched this record."}</p><footer>{item.priority.factors.filter((factor: any) => factor.points).map((factor: any) => <i key={factor.name}>+{factor.points} {factor.name}</i>)}<button onClick={() => openDetail("vulnerability", item.cve_id)}>Read local record →</button></footer></article>)}</section>{queue && !queue.items.length && <div className="panel empty"><b>No local vulnerabilities are awaiting relevance review.</b><p>Add technology context, then review new intelligence as it arrives.</p></div>}</>}/>; }

function TechnologyProfileWorkspace() { const [items, setItems] = useState<any[]>([]); const [form, setForm] = useState({ name: "", vendor: "", product: "", version: "", criticality: "medium", internet_exposed: false, notes: "" }); const load = () => getJson<any[]>("/api/technology-profiles").then(setItems); useEffect(() => { load(); }, []); const submit = async (event: FormEvent) => { event.preventDefault(); const response = await apiFetch("/api/technology-profiles", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(form) }); if (response.ok) { setForm({ name: "", vendor: "", product: "", version: "", criticality: "medium", internet_exposed: false, notes: "" }); load(); } }; return <GenericView title="Technology Profile" copy="Record only the technology context you choose. It is used locally to explain potential relevance; it never proves an asset is vulnerable or exposed." children={<><form className="phase-form panel" onSubmit={submit}><label>Name<input required value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} placeholder="Public-facing application"/></label><label>Vendor / product<input value={form.vendor} onChange={(event) => setForm({ ...form, vendor: event.target.value })} placeholder="Vendor"/><input value={form.product} onChange={(event) => setForm({ ...form, product: event.target.value })} placeholder="Product"/></label><label>Criticality<select value={form.criticality} onChange={(event) => setForm({ ...form, criticality: event.target.value })}><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select><label><input type="checkbox" checked={form.internet_exposed} onChange={(event) => setForm({ ...form, internet_exposed: event.target.checked })}/> Internet exposed (validated)</label></label><button>Add local profile</button></form><div className="case-list">{items.map((item) => <article className="panel case-card" key={item.id}><div className="case-meta"><span>{item.criticality}</span><span>{item.internet_exposed ? "validated internet exposure" : "exposure not recorded"}</span></div><h2>{item.name}</h2><p>{[item.vendor, item.product, item.version].filter(Boolean).join(" · ") || "No vendor/product detail recorded."}</p></article>)}</div></>}/>; }

function IocLifecycleWorkspace() { const [items, setItems] = useState<any[]>([]); const [value, setValue] = useState(""); const [indicator_type, setType] = useState("domain"); const load = () => getJson<any[]>("/api/iocs").then(setItems); useEffect(() => { load(); }, []); const submit = async (event: FormEvent) => { event.preventDefault(); const response = await apiFetch("/api/iocs", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ indicator_type, value }) }); if (response.ok) { setValue(""); load(); } }; return <GenericView title="IOC Lifecycle" copy="Track locally added indicators with an explicit lifecycle. An observed or source-reported indicator is not automatically malicious, blocked, or queried externally." children={<><form className="phase-form compact" onSubmit={submit}><label>Type<select value={indicator_type} onChange={(event) => setType(event.target.value)}><option value="domain">Domain</option><option value="ip">IP</option><option value="url">URL</option><option value="hash">Hash</option><option value="email">Email</option></select></label><label>Indicator<input required value={value} onChange={(event) => setValue(event.target.value)} placeholder="example.org"/></label><button>Add local indicator</button></form><div className="table">{items.map((item) => <article key={item.id}><b>{item.indicator_type.toUpperCase()}</b><div><strong>{item.value}</strong><p>{item.confidence}</p></div><span>{item.lifecycle_status}</span><em>{item.valid_until ? `Valid until ${new Date(item.valid_until).toLocaleDateString()}` : "No expiry recorded"}</em></article>)}</div></>}/>; }

function KnowledgeReviewWorkspace({ reviews, importFile, decideImport, deleteImport }: { reviews: ImportReview[]; importFile: (event: ChangeEvent<HTMLInputElement>) => Promise<void>; decideImport: (id: string, decision: "approve" | "reject") => Promise<void>; deleteImport: (id: string, filename: string) => Promise<void> }) {
  const pending = reviews.filter((item) => item.status === "pending");
  const decided = reviews.filter((item) => item.status !== "pending");
  const entityLabels: Record<string, string> = { cves: "CVE", ips: "IP", urls: "URL", hashes: "SHA-256" };
  return <GenericView title="Knowledge Base & Import Review" copy="Stage Markdown, text, CSV, STIX, or MISP JSON locally. Nothing becomes searchable until you inspect and approve it; files and candidate entities remain on this device." action={<label className="button">Stage local file<input type="file" accept=".txt,.md,.csv,.json,.stix,.misp" onChange={importFile}/></label>} children={<>
    <SemanticKnowledgePanel />
    <section className="import-summary panel"><div><p>LOCAL REVIEW QUEUE</p><h2>{pending.length} awaiting decision</h2><span>Candidate CVEs, IPs, URLs, and hashes are extracted locally for review only.</span></div><b>NO EXTERNAL UPLOAD</b></section>
    {pending.length ? <section className="import-review-list">{pending.map((item) => { const entities = Object.entries(item.candidate_entities).flatMap(([kind, values]) => Array.isArray(values) ? values.map((value) => ({ kind, value })) : []); return <article className="panel import-review-card" key={item.id}><div className="import-review-meta"><b>PENDING REVIEW</b><span>{item.content_type.toUpperCase()} · {new Date(item.created_at).toLocaleString()}</span></div><h2>{item.filename}</h2><p className="import-hash">SHA-256 {item.content_hash}</p>{entities.length ? <div className="candidate-entities">{entities.map(({ kind, value }) => <i key={`${kind}-${value}`}>{entityLabels[kind] ?? kind}: {value}</i>)}</div> : <p className="page-note">No common CVE, IP, URL, or SHA-256 candidate was found in the first local pass.</p>}<pre>{item.preview || "The file contained no readable preview text."}</pre><footer><button className="approve-import" onClick={() => decideImport(item.id, "approve")}>Approve into knowledge base</button><button className="reject-import" onClick={() => decideImport(item.id, "reject")}>Reject import</button><button onClick={() => deleteImport(item.id, item.filename)}>Delete local file</button></footer></article>; })}</section> : <div className="panel empty"><b>No imports are waiting for review.</b><p>Stage a supported local file when you want to inspect it before adding it to the searchable knowledge base.</p></div>}
    {decided.length > 0 && <section className="import-history panel"><div className="section-top"><div><p>LOCAL REVIEW HISTORY</p><h2>Recent decisions</h2></div><span>{decided.length} recorded</span></div>{decided.slice(0, 12).map((item) => <article key={item.id}><b className={item.status}>{item.status.toUpperCase()}</b><div><strong>{item.filename}</strong><p>{item.status === "approved" ? "Added to the local knowledge base after review." : "Not added to the local knowledge base; source file remains in local imports."}</p></div><button onClick={() => deleteImport(item.id, item.filename)}>Erase local data</button><time>{new Date(item.reviewed_at ?? item.created_at).toLocaleString()}</time></article>)}</section>}
  </>}/>;
}

function SemanticKnowledgePanel() {
  const [status, setStatus] = useState<SemanticStatus | null>(null);
  const [query, setQuery] = useState("");
  const [result, setResult] = useState<KnowledgeRetrieval | null>(null);
  const [notice, setNotice] = useState("");
  const load = async () => { try { setStatus(await getJson<SemanticStatus>("/api/knowledge/semantic-status")); } catch { setNotice("Could not read the local semantic-index status."); } };
  useEffect(() => { load(); }, []);
  const reindex = async () => {
    if (!status?.configured) return setNotice("Set OLLAMA_EMBEDDING_MODEL in .env, restart ThreatCommand, then rebuild the index.");
    if (window.prompt("This sends reviewed local knowledge only to your configured localhost Ollama endpoint. Type REINDEX to rebuild the local semantic index.") !== "REINDEX") return;
    setNotice("Building the local semantic index. This can take a little while for large reviewed documents…");
    const response = await apiFetch("/api/knowledge/reindex", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ confirmation: "REINDEX" }) });
    const data = await response.json();
    setNotice(response.ok ? `${data.indexed_chunks} chunks indexed locally. ${data.warning}` : (data.detail ?? "The local semantic index was not rebuilt."));
    if (response.ok) { setStatus(data.status); setResult(null); }
  };
  const search = async (event: FormEvent) => {
    event.preventDefault(); if (query.trim().length < 3) return setNotice("Enter at least three characters to search reviewed local knowledge.");
    try { const data = await getJson<KnowledgeRetrieval>(`/api/knowledge/retrieve?q=${encodeURIComponent(query)}`); setResult(data); setNotice(data.warning); setStatus(data.status); } catch { setNotice("Local knowledge search could not be completed."); }
  };
  const summary = !status ? "Checking local semantic-index status…" : status.semantic_ready ? `Ready: ${status.indexed_chunks} local chunks use ${status.embedding_model}.` : status.configured ? `${status.knowledge_items} reviewed item(s), ${status.chunks} chunk(s); rebuild required before semantic retrieval is complete.` : "Keyword search is available. Configure a local Ollama embedding model to enable semantic retrieval.";
  return <section className="panel semantic-panel"><div className="section-top"><div><p>LOCAL SEMANTIC RETRIEVAL</p><h2>Grounded knowledge search</h2></div><button onClick={reindex} disabled={!status?.configured}>Rebuild local index</button></div><p>{summary}</p><small>Indexing is never automatic. It uses only the configured localhost Ollama endpoint, stores vectors in this local PostgreSQL database, and never sends reviewed knowledge to an external AI provider.</small><form className="phase-form compact" onSubmit={search}><label>Search reviewed local knowledge<input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Technique, CVE, product, or investigation question"/></label><button>Search local knowledge</button></form>{notice && <p className="page-note">{notice}</p>}{result && <div className="semantic-results">{result.items.length ? result.items.map((item) => <article key={`${item.knowledge_item_id}-${item.chunk_index}`}><b>{result.mode === "local-semantic" ? `${Math.round(item.score * 100)}% match` : "KEYWORD MATCH"}</b><div><strong>{item.title}</strong><p>{item.content}</p></div><span>Local knowledge</span></article>) : <p className="page-note">No reviewed local knowledge matched that search.</p>}</div>}</section>;
}

function LiveVulnerabilitiesView({ page }: { page: VulnerabilityPage | null }) {
  const [filter, setFilter] = useState<"all" | "live" | "demo">("all");
  if (!page) return <GenericView title="Vulnerability Workspace" copy="Loading locally stored vulnerability records…" />;
  const visible = page.items.filter((item) => filter === "all" || (filter === "live" ? !item.demo : item.demo));
  return <GenericView title="Vulnerability Workspace" copy="Live feed records and synthetic demo records are separated below. A live record is still intelligence, not proof of local exposure, compromise, or patch status." children={<>
    <div className="data-totals"><span><b>{page.counts.total.toLocaleString()}</b> local CVE records</span><span><b>{page.counts.live_count.toLocaleString()}</b> live CISA KEV</span><span><b>{page.counts.demo_count}</b> demo records</span><div className="filter-buttons"><button className={filter === "all" ? "selected" : ""} onClick={() => setFilter("all")}>All</button><button className={filter === "live" ? "selected" : ""} onClick={() => setFilter("live")}>Live CISA</button><button className={filter === "demo" ? "selected" : ""} onClick={() => setFilter("demo")}>Demo</button></div></div>
    <div className="table vulnerability-table">{visible.map((item) => <article key={item.cve_id}><b>{item.cve_id}</b><div><strong>{item.title}</strong><p>{item.description}</p><small>{item.source_url ?? "local synthetic source"}</small></div><span className={item.demo ? "demo" : "live"}>{item.demo ? "DEMO" : item.kev ? "LIVE KEV" : "LIVE"}</span><em>{item.recommended_action}<small>{item.potential_relevance}</small></em></article>)}</div>
    <p className="page-note">Showing {visible.length.toLocaleString()} records from the first {page.items.length.toLocaleString()} locally indexed results. Use global search to find a specific CVE.</p>
  </>}/>;
}

function LiveFeedsView({ connectors, logs, mode, enableConnector, syncConnector }: { connectors: Connector[]; logs: ConnectorLog[]; mode: string; enableConnector: (connector: Connector) => void; syncConnector: (connector: Connector) => void }) {
  return <GenericView title="Feed Sources & Network Transparency" copy={`Current mode: ${mode}. Each source is independently controlled; enabling a source never syncs it automatically.`} children={<>
    <div className="table feed-table-live">{connectors.map((item) => <article key={item.key}><b className={item.enabled ? "enabled" : "disabled"}>{item.enabled ? "ENABLED" : "DISABLED"}</b><div><strong>{item.name}</strong><p>{item.description}</p><code>{item.source_url}</code><small>Status: {item.last_status}{item.last_sync_at ? ` · Last sync ${new Date(item.last_sync_at).toLocaleString()}` : ""}</small></div><span>{item.data_type}</span><div className="row-buttons"><button onClick={() => enableConnector(item)}>{item.enabled ? "Disable" : "Enable"}</button><button disabled={!item.enabled || mode === "offline"} onClick={() => syncConnector(item)}>Sync now</button></div></article>)}</div>
    <section className="network-log panel"><div className="section-top"><div><p>LOCAL OUTBOUND REQUEST LOG</p><h2>Network transparency</h2></div><span>{logs.length} request{logs.length === 1 ? "" : "s"} recorded</span></div>{logs.length ? logs.slice(0, 10).map((log) => <article key={log.id}><b>{log.outcome.toUpperCase()}</b><div><strong>{log.connector_key}</strong><p>{log.destination}</p></div><span>{new Date(log.requested_at).toLocaleString()}</span><em>HTTP {log.status_code ?? "—"} · +{log.records_added} added · {log.records_failed} failed</em></article>) : <p>No outbound connector request has been made from this local database.</p>}</section>
    <section className="candidate-feeds panel"><p>FREE-SOURCE ROADMAP</p><h2>Additional disabled sources being prepared</h2><div><span>NVD CVE API</span><span>CISA Cybersecurity Advisories RSS</span><span>MITRE ATT&amp;CK STIX</span></div><small>These sources remain disabled until their current official endpoints, terms, and parsers are verified. No request is made by listing them here.</small></section>
  </>}/>;
}

function InteractiveFeedsView({ connectors, logs, mode, enableConnector, syncConnector, toggleAll, syncAll }: { connectors: Connector[]; logs: ConnectorLog[]; mode: string; enableConnector: (connector: Connector) => void; syncConnector: (connector: Connector) => void; toggleAll: () => void; syncAll: () => void }) {
  const enabledCount = connectors.filter((connector) => connector.enabled).length;
  const allEnabled = connectors.length > 0 && enabledCount === connectors.length;
  return <GenericView title="Feed Sources & Network Transparency" copy={`Current mode: ${mode}. Switches enable or disable a source only; they do not make network requests. Every Sync action remains separately confirmed and logged.`} children={<>
    <section className="feed-toolbar panel"><div><p>CONNECTOR CONTROLS</p><h2>{enabledCount} of {connectors.length} sources enabled</h2><small>All sources remain local until you explicitly initiate a Manual Sync.</small></div><div className="toolbar-actions"><button className="switch-control" role="switch" aria-checked={allEnabled} onClick={toggleAll}><i/><span>{allEnabled ? "Disable all" : "Enable all"}</span></button><button className="sync-all" disabled={!enabledCount || mode === "offline"} onClick={syncAll}>↻ Sync enabled now</button></div></section>
    <div className="table feed-table-live">{connectors.map((item) => <article key={item.key}><button className={`feed-switch ${item.enabled ? "on" : ""}`} role="switch" aria-checked={item.enabled} aria-label={`${item.enabled ? "Disable" : "Enable"} ${item.name}`} onClick={() => enableConnector(item)}><i/></button><div><strong>{item.name}</strong><p>{item.description}</p><code>{item.source_url}</code><small>Status: {item.last_status}{item.last_sync_at ? ` · Last sync ${new Date(item.last_sync_at).toLocaleString()}` : ""}</small></div><span>{item.data_type}</span><div className="row-buttons"><button disabled={!item.enabled || mode === "offline"} onClick={() => syncConnector(item)}>Sync now</button></div></article>)}</div>
    <section className="network-log panel"><div className="section-top"><div><p>LOCAL OUTBOUND REQUEST LOG</p><h2>Network transparency</h2></div><span>{logs.length} request{logs.length === 1 ? "" : "s"} recorded</span></div>{logs.length ? logs.slice(0, 10).map((log) => <article key={log.id}><b>{log.outcome.toUpperCase()}</b><div><strong>{log.connector_key}</strong><p>{log.destination}</p></div><span>{new Date(log.requested_at).toLocaleString()}</span><em>HTTP {log.status_code ?? "—"} · +{log.records_added} added · {log.records_failed} failed</em></article>) : <p>No outbound connector request has been made from this local database.</p>}</section>
    <section className="candidate-feeds panel"><p>MANUAL SYNC SAFEGUARD</p><h2>Why Sync enabled now is a button—not a persistent switch</h2><small>A one-time sync is explicit and logged. Recurring synchronization needs a separate schedule, source-by-source rate limits, and your approval because it produces ongoing outbound traffic.</small></section>
  </>}/>;
}

function ResilientFeedsView({ connectors, logs, mode, enableConnector, syncConnector, updateSchedule, toggleAll, syncAll }: { connectors: Connector[]; logs: ConnectorLog[]; mode: string; enableConnector: (connector: Connector) => void; syncConnector: (connector: Connector) => void; updateSchedule: (connector: Connector, hours: number) => void; toggleAll: () => void; syncAll: () => void }) {
  const [filter, setFilter] = useState<"all" | "enabled" | "attention">("all");
  const enabledCount = connectors.filter((connector) => connector.enabled).length;
  const allEnabled = connectors.length > 0 && enabledCount === connectors.length;
  const latestLogByKey = new Map<string, ConnectorLog>();
  logs.forEach((log) => { if (log.connector_key && !latestLogByKey.has(log.connector_key)) latestLogByKey.set(log.connector_key, log); });
  const failedByKey = new Map([...latestLogByKey.entries()].filter(([, log]) => log.outcome === "failed"));
  const visible = connectors.filter((connector) => filter === "all" || (filter === "enabled" ? connector.enabled : failedByKey.has(connector.key) || connector.last_status.startsWith("failed:")));
  return <GenericView title="Feed Sources & Network Transparency" copy={`Current mode: ${mode}. Enable switches do not make requests. Use filters to isolate failed sources, inspect the error, then Retry with a separate Manual Sync confirmation.`} children={<>
    <section className="feed-toolbar panel"><div><p>CONNECTOR CONTROLS</p><h2>{enabledCount} of {connectors.length} sources enabled</h2><small>{mode === "scheduled" ? "Scheduled Sync is active. Each enabled source uses its displayed local interval." : "All sources remain local until you explicitly initiate a Manual Sync or select Scheduled Sync in Settings."}</small></div><div className="toolbar-actions"><button className="switch-control" role="switch" aria-checked={allEnabled} onClick={toggleAll}><i/><span>{allEnabled ? "Disable all" : "Enable all"}</span></button><button className="sync-all" disabled={!enabledCount || mode === "offline"} onClick={syncAll}>↻ Sync enabled now</button></div></section>
    <div className="feed-filter-bar"><button className={filter === "all" ? "selected" : ""} onClick={() => setFilter("all")}>All <b>{connectors.length}</b></button><button className={filter === "enabled" ? "selected" : ""} onClick={() => setFilter("enabled")}>Enabled <b>{enabledCount}</b></button><button className={filter === "attention" ? "selected attention" : "attention"} onClick={() => setFilter("attention")}>Needs attention <b>{failedByKey.size}</b></button></div>
    <div className="table feed-table-live">{visible.map((item) => { const failure = failedByKey.get(item.key); const unavailable = item.parser_available === false; return <article className={failure ? "has-failure" : ""} key={item.key}><button className={`feed-switch ${item.enabled ? "on" : ""}`} role="switch" aria-checked={item.enabled} aria-label={`${item.enabled ? "Disable" : "Enable"} ${item.name}`} disabled={unavailable} onClick={() => enableConnector(item)}><i/></button><div><strong>{item.name}</strong><p>{item.description}</p><code>{item.source_url}</code><small>Status: {unavailable ? "Parser not implemented; source cannot be enabled." : item.last_status}{item.last_sync_at ? ` · Last sync ${new Date(item.last_sync_at).toLocaleString()}` : ""}{item.last_content_at ? ` · Content changed ${new Date(item.last_content_at).toLocaleString()}` : ""}{item.next_sync_at ? ` · Next ${new Date(item.next_sync_at).toLocaleString()}` : ""}</small>{failure && <small className="failure-detail"><b>Last issue:</b> {failure.detail}</small>}</div><span>{unavailable ? "NOT AVAILABLE" : failure ? "NEEDS ATTENTION" : item.data_type}</span><div className="row-buttons"><label className="schedule-select">Every <select value={item.schedule_hours ?? 6} onChange={(event) => updateSchedule(item, Number(event.target.value))} disabled={!item.enabled || unavailable}><option value="1">1 h</option><option value="3">3 h</option><option value="6">6 h</option><option value="12">12 h</option><option value="24">24 h</option><option value="168">7 d</option></select></label><button disabled={!item.enabled || unavailable || mode === "offline"} onClick={() => syncConnector(item)}>{failure ? "Retry" : "Sync now"}</button></div></article>; })}</div>
    {!visible.length && <div className="panel empty"><b>No sources match this filter.</b><p>Use All to return to the full local connector catalog.</p></div>}
    <section className="network-log panel"><div className="section-top"><div><p>LOCAL OUTBOUND REQUEST LOG</p><h2>Network transparency</h2></div><span>{logs.length} request{logs.length === 1 ? "" : "s"} recorded</span></div>{logs.length ? logs.slice(0, 20).map((log) => <article className={log.outcome === "failed" ? "log-failure" : ""} key={log.id}><b>{log.outcome.toUpperCase()}</b><div><strong>{log.connector_key}</strong><p>{log.destination}</p>{log.detail && <small>{log.detail}</small>}</div><span>{new Date(log.requested_at).toLocaleString()}</span><em>HTTP {log.status_code ?? "—"} · +{log.records_added} added · {log.records_failed} failed</em></article>) : <p>No outbound connector request has been made from this local database.</p>}</section>
    <section className="candidate-feeds panel"><p>REPAIR WORKFLOW</p><h2>Fix a failed source safely</h2><small>Open Needs attention, read the local error, correct the source configuration if necessary, then use Retry. Redirects and malformed XML are handled more tolerantly after this update; the NVD entry now uses the NVD CVE API rather than the retired RSS URL. A retry still requires your confirmation and is logged.</small></section>
  </>}/>;
}

function LiveCommandCenter({ dashboard, setActive }: { dashboard: LiveDashboard; setActive: (view: string) => void }) {
  const live = dashboard.live_overview;
  const enabledFeeds = live.feed_health.filter((feed) => feed.enabled).length;
  return <>
    <div className="title"><div><p>LIVE INTELLIGENCE MONITOR</p><h1>Command Center</h1><span>What changed in locally synchronized sources, what is being discussed, and what deserves human review.</span></div><div className="live"><i/> {enabledFeeds} ENABLED LOCAL SOURCE{enabledFeeds === 1 ? "" : "S"}</div></div>
    <section className="live-metrics"><article className="panel"><span>NEW CISA KEVs · 7 DAYS</span><strong>{live.new_kev_7d.toLocaleString()}</strong><p>Live CISA records added or dated in the last seven days. Validate inventory before action.</p><button onClick={() => setActive("Vulnerabilities")}>Review vulnerabilities →</button></article><article className="panel"><span>LIVE CYBERNEWS</span><strong>{live.live_news.length}</strong><p>{live.live_news.length ? "Source-reported news items are stored locally." : "No RSS source has been synced yet."}</p><button onClick={() => setActive("Live Cybernews")}>Review all cybernews →</button></article><article className="panel"><span>ZERO-DAY WATCH</span><strong>{live.zero_day_watch.length}</strong><p>{live.zero_day_watch.length ? "Source-reported zero-day mentions require corroboration." : "No locally synchronized source has flagged a zero-day mention."}</p><button onClick={() => setActive("Feed Sources")}>Manage sources →</button></article><article className="panel"><span>LEARNING DETECTIONS</span><strong>{live.learning_library.reduce((total, item) => total + item.count, 0)}</strong><p>Curated defensive learning templates, never auto-deployed.</p><button onClick={() => setActive("Detection Studio")}>Open library →</button></article></section>
    <section className="live-grid"><article className="panel intelligence-list"><div className="section-top"><div><p>NEW CISA KEVS</p><h2>Latest local vulnerability intelligence</h2></div><button onClick={() => setActive("Vulnerabilities")}>View all →</button></div>{live.recent_kevs.slice(0, 6).map((item) => <article key={item.cve_id}><b>{item.cve_id}</b><div><strong>{item.title}</strong><small>{item.potential_relevance}</small></div><span>LIVE KEV</span></article>)}</article><article className="panel intelligence-list"><div className="section-top"><div><p>LIVE CYBERNEWS</p><h2>Source-reported intelligence stream</h2></div><button onClick={() => setActive("Live Cybernews")}>All cybernews →</button></div>{live.live_news.length ? live.live_news.slice(0, 6).map((item) => <article key={item.reference_id}><b>{item.connector_key}</b><div><strong>{item.title}</strong><small>{item.summary}</small></div><span>{item.severity}</span></article>) : <div className="empty-live">Enable and manually sync an approved RSS source to populate this local stream. Feed claims remain source-reported until corroborated.</div>}</article></section>
    <section className="live-grid lower"><article className="panel intelligence-list"><div className="section-top"><div><p>ZERO-DAY WATCH</p><h2>Local source signals</h2></div></div>{live.zero_day_watch.length ? live.zero_day_watch.map((item) => <article key={item.reference_id}><b>{item.connector_key}</b><div><strong>{item.title}</strong><small>{item.summary}</small></div><span>REVIEW</span></article>) : <div className="empty-live">No zero-day keyword signal has been synchronized locally. This is not a claim that no zero-days exist.</div>}</article><article className="panel feed-health"><div className="section-top"><div><p>FEED HEALTH</p><h2>Network transparency</h2></div><button onClick={() => setActive("Feed Sources")}>Full log →</button></div>{live.feed_health.map((feed) => <article key={feed.key}><i className={feed.enabled ? "good" : "off"}/><div><strong>{feed.name}</strong><small>{feed.last_status}{feed.last_sync_at ? ` · ${new Date(feed.last_sync_at).toLocaleString()}` : ""}</small></div><span>{feed.enabled ? "enabled" : "disabled"}</span></article>)}</article></section>
  </>;
}

function LearningDetectionView({ detections }: { detections: Detection[] }) {
  const segments = ["On-Prem", "Cloud", "Incident Response"];
  const [segment, setSegment] = useState("On-Prem");
  const library = detections.filter((item) => item.learning_purpose);
  const visible = library.filter((item) => item.segment === segment).sort((a, b) => (a.library_rank ?? 999) - (b.library_rank ?? 999));
  return <GenericView title="Detection Learning Library" copy="Curated defensive learning templates. Every item is a DRAFT — HUMAN REVIEW REQUIRED and must be validated and tuned only in systems you are authorized to access." children={<>
    <div className="library-summary">{segments.map((name) => <button key={name} className={segment === name ? "selected" : ""} onClick={() => setSegment(name)}><b>{library.filter((item) => item.segment === name).length}</b>{name}</button>)}</div>
    <div className="table learning-table">{visible.map((item) => <article key={item.id}><b>#{item.library_rank}</b><div><strong>{item.title}</strong><p>{item.description}</p><small>{item.attack_techniques.join(", ")} · Required telemetry: {item.required_telemetry.join(", ")}</small></div><span>{item.rule_format}</span><em>LEARNING DRAFT</em></article>)}</div>
    <p className="page-note">Showing all {visible.length} curated {segment.toLowerCase()} templates. They are educational references, not claims of production coverage.</p>
  </>}/>;
}

function InteractiveCommandCenter({ dashboard, setActive, openDetail }: { dashboard: LiveDashboard; setActive: (view: string) => void; openDetail: (kind: DetailResponse["kind"], id: string) => void }) {
  const live = dashboard.live_overview;
  const enabledFeeds = live.feed_health.filter((feed) => feed.enabled).length;
  return <>
    <div className="title"><div><p>LIVE INTELLIGENCE MONITOR</p><h1>Command Center</h1><span>New local KEVs, source-reported cybernews, and an opt-in global attack map. Select a record to read its local evidence.</span></div><div className="live"><i/> {enabledFeeds} ENABLED LOCAL SOURCE{enabledFeeds === 1 ? "" : "S"}</div></div>
    <section className="live-metrics"><article className="panel"><span>NEW CISA KEVs · 7 DAYS</span><strong>{live.new_kev_7d.toLocaleString()}</strong><p>Live CISA records added or dated in the last seven days. Validate inventory before action.</p><button onClick={() => setActive("Vulnerabilities")}>Review vulnerabilities →</button></article><article className="panel"><span>LIVE CYBERNEWS</span><strong>{live.live_news.length}</strong><p>{live.live_news.length ? "Select an item to read the locally stored feed content; an original reference remains available." : "No RSS source has been synced yet."}</p><button onClick={() => setActive("Live Cybernews")}>Review all cybernews →</button></article><article className="panel"><span>LEARNING DETECTIONS</span><strong>{live.learning_library.reduce((total, item) => total + item.count, 0)}</strong><p>Click a template to study telemetry, ATT&amp;CK mapping, and draft content.</p><button onClick={() => setActive("Detection Studio")}>Open library →</button></article></section>
    <section className="live-grid"><article className="panel intelligence-list"><div className="section-top"><div><p>NEW CISA KEVS</p><h2>Latest local vulnerability intelligence</h2></div><button onClick={() => setActive("Vulnerabilities")}>View all →</button></div>{live.recent_kevs.slice(0, 6).map((item) => <button className="record-row" key={item.cve_id} onClick={() => openDetail("vulnerability", item.cve_id)}><b>{item.cve_id}</b><div><strong>{item.title}</strong><small>{item.potential_relevance}</small></div><span>Read →</span></button>)}</article><article className="panel intelligence-list"><div className="section-top"><div><p>LIVE CYBERNEWS</p><h2>Source-reported intelligence stream</h2></div><button onClick={() => setActive("Live Cybernews")}>All cybernews →</button></div>{live.live_news.length ? live.live_news.slice(0, 6).map((item) => <button className="record-row" key={item.reference_id} onClick={() => openDetail("threat", item.reference_id)}><b>{item.connector_key}</b><div><strong>{item.title}</strong><small>{item.summary}</small></div><span>Read →</span></button>) : <div className="empty-live">Enable and manually sync an approved RSS source to populate this local stream. Feed claims remain source-reported until corroborated.</div>}</article></section>
    <section className="external-tracker-row"><ExternalLiveAttackTracker mode={dashboard.network_mode} /></section>
  </>;
}

function ExternalLiveAttackTracker({ mode }: { mode: string }) {
  const [connected, setConnected] = useState(false);
  useEffect(() => { if (mode === "offline") setConnected(false); }, [mode]);
  const connect = () => {
    if (mode === "offline") return;
    if (window.confirm("Load Radware's external live threat map? Your browser will connect directly to livethreatmap.radware.com and disclose its IP address and standard browser metadata to that provider.")) setConnected(true);
  };
  return <article className="panel external-attack-tracker"><div className="section-top"><div><p>GLOBAL ATTACK TRACKER</p><h2>External near-real-time telemetry</h2></div>{connected && <button onClick={() => setConnected(false)}>Disconnect</button>}</div>{connected ? <><iframe title="Radware Live Threat Map" src="https://livethreatmap.radware.com/" loading="lazy" referrerPolicy="strict-origin" sandbox="allow-scripts allow-same-origin allow-popups"/><p className="external-map-note">Connected directly to Radware. This visualization reflects sampled, anonymized network and application attack telemetry—not confirmed incidents, attribution, or exposure of your systems.</p></> : <div className="external-map-intro"><b>{mode === "offline" ? "Offline Mode blocks the external map" : "External map is disconnected"}</b><p>{mode === "offline" ? "This browser-direct visualization is unavailable while Offline Mode is active. Switch to Manual or Scheduled Sync first, then review the network disclosure before loading it." : "Load Radware’s official Live Threat Map to view its global, near-real-time sampled attack telemetry here. Nothing is sent to Radware until you choose Load live map."}</p>{mode !== "offline" && <div><button className="load-external-map" onClick={connect}>Load live map</button><a href="https://livethreatmap.radware.com/" target="_blank" rel="noreferrer">Open Radware map ↗</a></div>}</div>}</article>;
}

function LiveCybernewsWorkspace({ page, openDetail, loadMore }: { page: NewsPage | null; openDetail: (kind: DetailResponse["kind"], id: string) => void; loadMore: () => void }) {
  const [filter, setFilter] = useState("all");
  if (!page) return <GenericView title="Live Cybernews" copy="Loading locally synchronized RSS items…" />;
  const sources = [...new Set(page.items.map((item) => item.connector_key))].sort();
  const visible = page.items.filter((item) => filter === "all" || item.connector_key === filter);
  return <GenericView title="Live Cybernews" copy="All items shown here are stored locally from enabled RSS sources. Select an item to read the full feed content saved locally; the original source remains available as a reference link." children={<>
    <div className="news-summary"><span><b>{page.total.toLocaleString()}</b> locally stored news items</span><span><b>{sources.length}</b> contributing sources loaded</span><div className="news-filters"><button className={filter === "all" ? "selected" : ""} onClick={() => setFilter("all")}>All</button>{sources.map((source) => <button className={filter === source ? "selected" : ""} key={source} onClick={() => setFilter(source)}>{source}</button>)}</div></div>
    <div className="news-list">{visible.map((item) => <button className="news-card panel" key={item.reference_id} onClick={() => openDetail("threat", item.reference_id)}><div className="news-card-meta"><span>{item.connector_key}</span><span>{item.published_at ? new Date(item.published_at).toLocaleString() : "date not supplied"}</span><b>{item.severity}</b></div><h2>{item.title}</h2><p>{item.summary}</p><footer>{item.tags.map((tag) => <i key={tag}>{tag}</i>)}<em>Read local copy →</em></footer></button>)}</div>
    {page.items.length < page.total && <button className="load-more" onClick={loadMore}>Load next locally stored items ({page.total - page.items.length} remaining)</button>}
    {!visible.length && <div className="panel empty"><b>No locally stored cybernews matches this filter.</b><p>Sync an enabled source or choose a different local source filter.</p></div>}
  </>}/>;
}

function IntelligenceExplorer({ openDetail }: { openDetail: (kind: DetailResponse["kind"], id: string) => void }) {
  const [filters, setFilters] = useState({ q: "", kind: "all", severity: "all", source: "all", tag: "all", days: "30" });
  const [result, setResult] = useState<IntelligenceResult | null>(null);
  const [loading, setLoading] = useState(true);
  useEffect(() => { const params = new URLSearchParams(filters); setLoading(true); getJson<IntelligenceResult>(`/api/intelligence?${params.toString()}`).then(setResult).finally(() => setLoading(false)); }, [filters]);
  const update = (key: keyof typeof filters, value: string) => setFilters({ ...filters, [key]: value });
  return <GenericView title="Intelligence Explorer" copy="Search and filter your locally stored cybernews and vulnerability intelligence. These filters never contact a feed, enrichment provider, or external search service." children={<>
    <section className="explorer-filters panel"><label>Find local intelligence<input value={filters.q} onChange={(event) => update("q", event.target.value)} placeholder="CVE, product, technique, keyword, source…"/></label><label>Data<select value={filters.kind} onChange={(event) => update("kind", event.target.value)}><option value="all">All records</option><option value="news">Cybernews</option><option value="vulnerability">Vulnerabilities</option></select></label><label>Severity<select value={filters.severity} onChange={(event) => update("severity", event.target.value)}><option value="all">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></label><label>Source<select value={filters.source} onChange={(event) => update("source", event.target.value)}><option value="all">All local sources</option>{result?.sources.map((source) => <option key={source} value={source}>{source}</option>)}</select></label><label>Tag<select value={filters.tag} onChange={(event) => update("tag", event.target.value)}><option value="all">All tags</option>{result?.tags.map((tag) => <option key={tag} value={tag}>{tag}</option>)}</select></label><label>Recency<select value={filters.days} onChange={(event) => update("days", event.target.value)}><option value="1">Last 24 hours</option><option value="7">Last 7 days</option><option value="30">Last 30 days</option><option value="90">Last 90 days</option><option value="0">All local history</option></select></label></section>
    <div className="explorer-summary"><span><b>{result?.total ?? 0}</b> matching local records</span><span>{loading ? "Filtering local database…" : "No external request made"}</span><button onClick={() => setFilters({ q: "", kind: "all", severity: "all", source: "all", tag: "all", days: "30" })}>Reset filters</button></div>
    <section className="explorer-list">{result?.items.map((item) => <button className={`panel explorer-record ${item.severity}`} key={`${item.kind}-${item.reference_id}`} onClick={() => openDetail(item.detail_kind, item.reference_id)}><div className="explorer-record-meta"><span>{item.kind === "vulnerability" ? "VULNERABILITY" : item.source}</span><b>{item.severity}</b><time>{item.published_at ? new Date(item.published_at).toLocaleString() : "date unavailable"}</time></div><h2>{item.title}</h2><p>{item.summary}</p><footer>{item.tags.map((tag) => <i key={tag}>{tag}</i>)}<em>{item.confidence} · Open →</em></footer></button>)}</section>
    {!loading && !result?.items.length && <div className="panel empty"><b>No local records match these filters.</b><p>Broaden the date range, clear a filter, or manually synchronize an enabled source.</p></div>}
  </>}/>;
}

function InteractiveVulnerabilities({ page, openDetail }: { page: VulnerabilityPage | null; openDetail: (kind: DetailResponse["kind"], id: string) => void }) {
  const [filter, setFilter] = useState<"all" | "live" | "demo">("all");
  if (!page) return <GenericView title="Vulnerability Workspace" copy="Loading locally stored vulnerability records…" />;
  const visible = page.items.filter((item) => filter === "all" || (filter === "live" ? !item.demo : item.demo));
  return <GenericView title="Vulnerability Workspace" copy="Select any CVE to read its locally stored description, source link, affected products, recommended action, and limitations." children={<>
    <div className="data-totals"><span><b>{page.counts.total.toLocaleString()}</b> local CVE records</span><span><b>{page.counts.live_count.toLocaleString()}</b> live CISA KEV</span><span><b>{page.counts.demo_count}</b> demo records</span><div className="filter-buttons"><button className={filter === "all" ? "selected" : ""} onClick={() => setFilter("all")}>All</button><button className={filter === "live" ? "selected" : ""} onClick={() => setFilter("live")}>Live CISA</button><button className={filter === "demo" ? "selected" : ""} onClick={() => setFilter("demo")}>Demo</button></div></div>
    <div className="table vulnerability-table">{visible.map((item) => <button className="detail-row" key={item.cve_id} onClick={() => openDetail("vulnerability", item.cve_id)}><b>{item.cve_id}</b><div><strong>{item.title}</strong><p>{item.description}</p><small>{item.source_url ?? "local synthetic source"}</small></div><span className={item.demo ? "demo" : "live"}>{item.demo ? "DEMO" : item.kev ? "LIVE KEV" : "LIVE"}</span><em>{item.recommended_action}<small>{item.potential_relevance}</small></em></button>)}</div>
    <p className="page-note">Select a record to expand it. Showing {visible.length.toLocaleString()} records from the first {page.items.length.toLocaleString()} locally indexed results.</p>
  </>}/>;
}

function InteractiveLearningLibrary({ detections, openDetail }: { detections: Detection[]; openDetail: (kind: DetailResponse["kind"], id: string) => void }) {
  const segments = ["On-Prem", "Cloud", "Incident Response"];
  const [segment, setSegment] = useState("On-Prem");
  const library = detections.filter((item) => item.learning_purpose);
  const visible = library.filter((item) => item.segment === segment).sort((a, b) => (a.library_rank ?? 999) - (b.library_rank ?? 999));
  return <GenericView title="Detection Learning Library" copy="Select a template to learn the behavior, ATT&CK mapping, telemetry requirement, draft rule or query, safe validation approach, and limitations." children={<>
    <div className="library-summary">{segments.map((name) => <button key={name} className={segment === name ? "selected" : ""} onClick={() => setSegment(name)}><b>{library.filter((item) => item.segment === name).length}</b>{name}</button>)}</div>
    <div className="table learning-table">{visible.map((item) => <button className="detail-row" key={item.id} onClick={() => openDetail("detection", item.id)}><b>#{item.library_rank}</b><div><strong>{item.title}</strong><p>{item.description}</p><small>{item.attack_techniques.join(", ")} · Required telemetry: {item.required_telemetry.join(", ")}</small></div><span>{item.rule_format}</span><em>Study →</em></button>)}</div>
    <p className="page-note">Showing all {visible.length} curated {segment.toLowerCase()} templates. They are educational references, not claims of production coverage.</p>
  </>}/>;
}

type WatchlistItem = { id: string; entity_type: string; reference_id: string; title: string; notes: string; created_at: string };
type WatchlistDetail = Watchlist & { items: WatchlistItem[] };

function WatchlistsWorkspace({ watchlists, createWatchlist }: { watchlists: Watchlist[]; createWatchlist: (payload: { name: string; description: string; color: string }) => Promise<void> }) {
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<WatchlistDetail | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState({ name: "", description: "", color: "cyan" });
  const [itemForm, setItemForm] = useState({ entity_type: "threat", reference_id: "", title: "", notes: "" });
  useEffect(() => { if (!selectedId) { setDetail(null); return; } getJson<WatchlistDetail>(`/api/watchlists/${selectedId}`).then(setDetail).catch(() => setDetail(null)); }, [selectedId, watchlists]);
  const submitWatchlist = async (event: FormEvent) => { event.preventDefault(); await createWatchlist(form); setForm({ name: "", description: "", color: "cyan" }); setShowCreate(false); };
  const submitItem = async (event: FormEvent) => { event.preventDefault(); if (!selectedId) return; const response = await apiFetch(`/api/watchlists/${selectedId}/items`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(itemForm) }); if (response.ok) { setItemForm({ entity_type: "threat", reference_id: "", title: "", notes: "" }); setDetail(await getJson<WatchlistDetail>(`/api/watchlists/${selectedId}`)); } };
  return <GenericView title="Watchlists" copy="Keep an intentional local set of threats, CVEs, indicators, or detections that deserve continued review. Watchlists never make external requests." action={<button className="button" onClick={() => setShowCreate(!showCreate)}>{showCreate ? "Close" : "+ New watchlist"}</button>} children={<>
    {showCreate && <form className="phase-form panel" onSubmit={submitWatchlist}><label>Name<input required value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} placeholder="e.g., Identity and cloud priority"/></label><label>Purpose<input value={form.description} onChange={(event) => setForm({ ...form, description: event.target.value })} placeholder="What should this list help you monitor?"/></label><label>Accent<select value={form.color} onChange={(event) => setForm({ ...form, color: event.target.value })}><option value="cyan">Cyan</option><option value="amber">Amber</option><option value="purple">Purple</option><option value="red">Red</option></select></label><button>Create local watchlist</button></form>}
    <div className="watchlist-grid">{watchlists.map((watchlist) => <button className={`watchlist-card panel ${watchlist.color} ${selectedId === watchlist.id ? "selected" : ""}`} key={watchlist.id} onClick={() => setSelectedId(watchlist.id)}><span>{watchlist.item_count} tracked</span><h2>{watchlist.name}</h2><p>{watchlist.description || "No purpose recorded yet."}</p><em>Open watchlist →</em></button>)}</div>
    {!watchlists.length && <div className="panel empty"><b>No local watchlists yet.</b><p>Create one for technologies, threat themes, CVEs, or defensive work you want to revisit.</p></div>}
    {detail && <section className="watchlist-detail panel"><div className="section-top"><div><p>LOCAL WATCHLIST</p><h2>{detail.name}</h2></div><span>{detail.items.length} items</span></div><form className="phase-form compact" onSubmit={submitItem}><label>Type<select value={itemForm.entity_type} onChange={(event) => setItemForm({ ...itemForm, entity_type: event.target.value })}><option value="threat">Threat</option><option value="vulnerability">Vulnerability</option><option value="ioc">IOC</option><option value="detection">Detection</option></select></label><label>Reference<input required value={itemForm.reference_id} onChange={(event) => setItemForm({ ...itemForm, reference_id: event.target.value })} placeholder="CVE, threat ID, IOC, or detection ID"/></label><label>Label<input value={itemForm.title} onChange={(event) => setItemForm({ ...itemForm, title: event.target.value })} placeholder="Optional readable label"/></label><button>Add local item</button></form><div className="watchlist-items">{detail.items.map((item) => <article key={item.id}><b>{item.entity_type.toUpperCase()}</b><div><strong>{item.title || item.reference_id}</strong><small>{item.reference_id}{item.notes ? ` · ${item.notes}` : ""}</small></div></article>)}{!detail.items.length && <p className="page-note">Add a local reference above. This does not query the Internet or any external enrichment service.</p>}</div></section>}
  </>}/>;
}

function ThreatHuntingWorkspace({ hunts, createHunt, updateStatus }: { hunts: HuntCase[]; createHunt: (payload: Record<string, unknown>) => Promise<void>; updateStatus: (id: string, status: HuntCase["status"]) => Promise<void> }) {
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState({ name: "", objective: "", hypothesis: "", scope: "", attack_techniques: "", required_telemetry: "", linked_reference: "", notes: "" });
  const submit = async (event: FormEvent) => { event.preventDefault(); await createHunt({ ...form, attack_techniques: form.attack_techniques.split(",").map((item) => item.trim()).filter(Boolean), required_telemetry: form.required_telemetry.split(",").map((item) => item.trim()).filter(Boolean), status: "planned" }); setForm({ name: "", objective: "", hypothesis: "", scope: "", attack_techniques: "", required_telemetry: "", linked_reference: "", notes: "" }); setShowCreate(false); };
  return <GenericView title="Threat Hunting" copy="Create safe, locally stored hunt hypotheses for systems and logs you are authorized to access. Queries and actions remain human-review-required drafts." action={<button className="button" onClick={() => setShowCreate(!showCreate)}>{showCreate ? "Close" : "+ New hunt"}</button>} children={<>
    {showCreate && <form className="phase-form panel" onSubmit={submit}><label>Hunt name<input required value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} placeholder="Suspicious cloud token review"/></label><label>Objective<textarea required value={form.objective} onChange={(event) => setForm({ ...form, objective: event.target.value })} placeholder="What are you trying to learn or validate?"/></label><label>Hypothesis<textarea required value={form.hypothesis} onChange={(event) => setForm({ ...form, hypothesis: event.target.value })} placeholder="State a defensible hypothesis, not a conclusion."/></label><label>Authorized scope<input value={form.scope} onChange={(event) => setForm({ ...form, scope: event.target.value })} placeholder="Logs, accounts, systems, or date range you are authorized to review"/></label><label>ATT&CK techniques<input value={form.attack_techniques} onChange={(event) => setForm({ ...form, attack_techniques: event.target.value })} placeholder="T1528, T1078"/></label><label>Required telemetry<input value={form.required_telemetry} onChange={(event) => setForm({ ...form, required_telemetry: event.target.value })} placeholder="Identity audit logs, cloud activity logs"/></label><button>Create local hunt</button></form>}
    <div className="case-list">{hunts.map((hunt) => <article className="panel case-card" key={hunt.id}><div className="case-meta"><span>{hunt.status}</span><select value={hunt.status} onChange={(event) => updateStatus(hunt.id, event.target.value as HuntCase["status"])}><option value="planned">Planned</option><option value="active">Active</option><option value="complete">Complete</option><option value="escalated">Escalated</option></select></div><h2>{hunt.name}</h2><p><b>Objective:</b> {hunt.objective}</p><p><b>Hypothesis:</b> {hunt.hypothesis}</p><footer>{hunt.attack_techniques.map((technique) => <i key={technique}>{technique}</i>)}<em>{hunt.required_telemetry.join(", ") || "Telemetry not recorded"}</em></footer></article>)}</div>{!hunts.length && <div className="panel empty"><b>No local hunt cases yet.</b><p>Start with a question you can answer using authorized telemetry—never an assumption of compromise.</p></div>}
  </>}/>;
}

function IncidentNotesWorkspace({ incidents, createIncident, updateStatus }: { incidents: IncidentCase[]; createIncident: (payload: Record<string, unknown>) => Promise<void>; updateStatus: (id: string, status: IncidentCase["status"]) => Promise<void> }) {
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState({ title: "", summary: "", severity: "medium", linked_reference: "", notes: "", tags: "" });
  const submit = async (event: FormEvent) => { event.preventDefault(); await createIncident({ ...form, status: "open", tags: form.tags.split(",").map((item) => item.trim()).filter(Boolean) }); setForm({ title: "", summary: "", severity: "medium", linked_reference: "", notes: "", tags: "" }); setShowCreate(false); };
  return <GenericView title="Incident Notes" copy="Maintain a private local record of authorized investigations. This workspace does not connect to, contain, or remediate any production environment." action={<button className="button" onClick={() => setShowCreate(!showCreate)}>{showCreate ? "Close" : "+ New case"}</button>} children={<>
    {showCreate && <form className="phase-form panel" onSubmit={submit}><label>Case title<input required value={form.title} onChange={(event) => setForm({ ...form, title: event.target.value })} placeholder="Authorized investigation — initial review"/></label><label>Summary<textarea required value={form.summary} onChange={(event) => setForm({ ...form, summary: event.target.value })} placeholder="What is known, what is uncertain, and what needs validation?"/></label><label>Severity<select value={form.severity} onChange={(event) => setForm({ ...form, severity: event.target.value })}><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></label><label>Local notes<textarea value={form.notes} onChange={(event) => setForm({ ...form, notes: event.target.value })} placeholder="Evidence, decisions, timeline notes, or next steps"/></label><label>Tags<input value={form.tags} onChange={(event) => setForm({ ...form, tags: event.target.value })} placeholder="identity, cloud, phishing"/></label><button>Create local case</button></form>}
    <div className="case-list">{incidents.map((incident) => <article className={`panel case-card severity-${incident.severity}`} key={incident.id}><div className="case-meta"><span>{incident.severity}</span><select value={incident.status} onChange={(event) => updateStatus(incident.id, event.target.value as IncidentCase["status"])}><option value="open">Open</option><option value="investigating">Investigating</option><option value="contained">Contained</option><option value="closed">Closed</option></select></div><h2>{incident.title}</h2><p>{incident.summary}</p><p className="case-notes">{incident.notes || "No further local notes recorded."}</p><footer>{incident.tags.map((tag) => <i key={tag}>{tag}</i>)}<em>{incident.linked_reference ?? "Unlinked local case"}</em></footer></article>)}</div>{!incidents.length && <div className="panel empty"><b>No local incident cases yet.</b><p>Create a private case when you need a durable timeline, notes, and follow-up state for an authorized investigation.</p></div>}
  </>}/>;
}

function formatBytes(bytes: number) { if (!bytes) return "0 B"; const units = ["B", "KB", "MB", "GB", "TB"]; const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1); return `${(bytes / 1024 ** index).toFixed(index ? 1 : 0)} ${units[index]}`; }

function DataLifecycleWorkspace() {
  const [sources, setSources] = useState<SourceLifecycle[]>([]);
  const [exports, setExports] = useState<LocalExport[]>([]);
  const [retentionBehavior, setRetentionBehavior] = useState("");
  const [notice, setNotice] = useState("");
  const load = async () => { try { const [data, nextExports] = await Promise.all([getJson<{ sources: SourceLifecycle[]; retention_behavior: string }>("/api/data-lifecycle"), getJson<LocalExport[]>("/api/exports")]); setSources(data.sources); setExports(nextExports); setRetentionBehavior(data.retention_behavior); setNotice(""); } catch { setNotice("Could not read local source lifecycle information."); } };
  useEffect(() => { load(); }, []);
  const purge = async (source: SourceLifecycle) => {
    const confirmation = window.prompt(`This removes only locally stored raw body text for ${source.name}. Normalized intelligence and analyst records remain. Type PURGE to continue.`);
    if (confirmation !== "PURGE") return;
    const response = await apiFetch(`/api/connectors/${source.key}/purge-raw`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ confirmation }) });
    const result = await response.json();
    setNotice(response.ok ? `${result.connector}: removed ${formatBytes(result.bytes_removed)} from ${result.documents_changed} raw source records.` : (result.detail ?? "Raw content was not removed."));
    if (response.ok) load();
  };
  const eraseExport = async (item: LocalExport) => {
    if (window.prompt(`This permanently deletes ${item.filename} from this device. Type DELETE to continue.`) !== "DELETE") return;
    const response = await apiFetch(`/api/exports/${encodeURIComponent(item.filename)}`, { method: "DELETE", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ confirmation: "DELETE" }) });
    const result = await response.json();
    setNotice(response.ok ? result.warning : (result.detail ?? "The local export could not be deleted."));
    if (response.ok) load();
  };
  return <GenericView title="Data Lifecycle & Source Governance" copy="Review what is retained locally, source provenance, freshness, retry backoff, and approved terms context. This screen makes no external request." children={<>
    <section className="storage-panel panel"><p>RETENTION BEHAVIOR</p><h2>Raw feed content is managed per source</h2><span>{retentionBehavior || "Loading local retention policy…"}</span></section>
    <section className="case-list">{sources.map((source) => <article className="panel case-card" key={source.key}><div className="case-meta"><span>{source.reliability_tier}</span><span>{source.enabled ? "enabled" : "disabled"}</span></div><h2>{source.name}</h2><p><b>Owner:</b> {source.source_owner || "Not recorded"}<br/><b>Use guidance:</b> {source.permitted_use}<br/><b>Retention:</b> {source.retention_days ? `${source.retention_days} days for raw body text` : "Raw content retention not configured"}</p><p><b>Local raw content:</b> {formatBytes(source.raw_content_bytes)} across {source.document_count} source records.<br/><b>Last retrieved:</b> {source.latest_retrieved_at ? new Date(source.latest_retrieved_at).toLocaleString() : "never"}<br/><b>Last changed:</b> {source.last_content_at ? new Date(source.last_content_at).toLocaleString() : "not recorded"}</p><p><b>Health:</b> {source.last_status}{source.retry_after_at ? ` · retry held until ${new Date(source.retry_after_at).toLocaleString()}` : ""}</p>{source.terms_url && <a className="source-link" href={source.terms_url} target="_blank" rel="noreferrer">Source terms ↗</a>}<button onClick={() => purge(source)} disabled={!source.raw_content_bytes}>Purge local raw content</button></article>)}</section>
    <section className="import-history panel"><div className="section-top"><div><p>LOCAL EXPORTS</p><h2>Delete handovers you no longer need</h2></div><span>{exports.length} local file{exports.length === 1 ? "" : "s"}</span></div>{exports.length ? exports.map((item) => <article key={item.filename}><b>LOCAL JSON</b><div><strong>{item.filename}</strong><p>{formatBytes(item.bytes)} · created or changed {new Date(item.modified_at).toLocaleString()}</p></div><button onClick={() => eraseExport(item)}>Erase export</button></article>) : <p className="page-note">No local handover exports are stored.</p>}</section>
    {notice && <p className="page-note">{notice}</p>}
  </>}/>;
}

function AuditTrailWorkspace() {
  const [events, setEvents] = useState<{ id: string; event_type: string; detail: Record<string, unknown>; created_at: string }[]>([]);
  const [notice, setNotice] = useState("");
  const load = async () => { try { setEvents(await getJson<{ id: string; event_type: string; detail: Record<string, unknown>; created_at: string }[]>("/api/audit-events?limit=100")); setNotice(""); } catch { setNotice("Could not read the local audit trail."); } };
  useEffect(() => { load(); }, []);
  return <GenericView title="Local Audit Trail" copy="A local event log records security-sensitive settings, source, evidence, detection, and external-AI decisions. It is not sent anywhere." action={<button className="button" onClick={load}>Refresh</button>} children={<><section className="panel storage-panel"><p>ACCOUNTABILITY</p><h2>{events.length} recent local events</h2><span>For external AI, the trail stores a question fingerprint and citation IDs rather than the question or answer.</span></section><section className="audit-list panel">{events.map((event) => <article key={event.id}><div><b>{event.event_type.replaceAll("_", " ")}</b><small>{new Date(event.created_at).toLocaleString()}</small></div><pre>{JSON.stringify(event.detail, null, 2)}</pre></article>)}{!events.length && <p>{notice || "No audit events recorded yet."}</p>}</section>{notice && <p className="page-note">{notice}</p>}</>}/>;
}

function StorageRetentionPanel() {
  const [storage, setStorage] = useState<StorageOverview | null>(null);
  const [error, setError] = useState("");
  const load = async () => { try { setStorage(await getJson<StorageOverview>("/api/storage")); setError(""); } catch { setError("Could not read the local storage overview."); } };
  useEffect(() => { load(); }, []);
  const categories = storage ? [["Local database", storage.database], ["Raw feed content", storage.raw_feed_content], ["Knowledge content", storage.knowledge_content], ["Staged imports", storage.imports], ["Exports", storage.exports], ["Logs", storage.logs]] as [string, number][] : [];
  return <section className="storage-panel panel"><div className="section-top"><div><p>LOCAL STORAGE & RETENTION</p><h2>Storage overview</h2></div><button onClick={load}>Refresh</button></div><p>Raw feed text is pruned automatically using each source's local retention period. Normalized intelligence and reviewed knowledge remain unless you remove them locally.</p>{storage ? <div className="storage-grid">{categories.map(([label, bytes]) => <div key={label}><span>{label}</span><b>{formatBytes(bytes)}</b></div>)}</div> : <span>{error || "Loading local storage totals…"}</span>}<small>{storage?.local_only ? "Calculated from this device only. This overview makes no external request." : "Storage source could not be verified."}</small></section>;
}

function LocalAccessGate({ configured, onUnlocked }: { configured: boolean; onUnlocked: (status: AccessStatus) => void }) {
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [notice, setNotice] = useState("");
  const submit = async (event: FormEvent) => { event.preventDefault(); if (!configured && password !== confirm) return setNotice("The two passphrases do not match."); const response = await apiFetch(configured ? "/api/access/unlock" : "/api/access/setup", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ password }) }); const result = await response.json(); if (!response.ok) return setNotice(result.detail ?? "Local access setup failed."); window.sessionStorage.setItem("threatcommand_csrf", result.csrf_token); setPassword(""); setConfirm(""); setNotice(""); onUnlocked({ configured: true, required: true, unlocked: true, scope: "local-only" }); };
  return <main className="access-gate"><section className="panel access-card"><p>THREATCOMMAND LOCAL</p><h1>{configured ? "Unlock your local workspace" : "Protect your local workspace"}</h1><span>{configured ? "This passphrase protects the local API in this browser. It is not sent to any external service." : "Before any intelligence is shown, create a 12-character or longer passphrase. Only a slow salted verifier is stored locally; it cannot be recovered by the dashboard."}</span><form onSubmit={submit}><label>Local passphrase<input type="password" autoFocus required minLength={12} value={password} onChange={(event) => setPassword(event.target.value)} autoComplete={configured ? "current-password" : "new-password"}/></label>{!configured && <label>Confirm passphrase<input type="password" required minLength={12} value={confirm} onChange={(event) => setConfirm(event.target.value)} autoComplete="new-password"/></label>}<button>{configured ? "Unlock local workspace" : "Create protected workspace"}</button></form>{notice && <small>{notice}</small>}</section></main>;
}

function LocalAccessSettings({ configured }: { configured: boolean }) {
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [notice, setNotice] = useState("");
  const setup = async (event: FormEvent) => { event.preventDefault(); if (password !== confirm) return setNotice("The two passphrases do not match."); const response = await apiFetch("/api/access/setup", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ password }) }); const result = await response.json(); if (!response.ok) return setNotice(result.detail ?? "Local access protection was not configured."); window.sessionStorage.setItem("threatcommand_csrf", result.csrf_token); window.location.reload(); };
  const lock = async () => { const response = await apiFetch("/api/access/lock", { method: "POST" }); if (!response.ok) return setNotice("The local workspace could not be locked."); window.sessionStorage.removeItem("threatcommand_csrf"); window.location.reload(); };
  return <section className="local-access-panel panel"><div><p>LOCAL ACCESS PROTECTION</p><h2>{configured ? "Local passphrase protection is enabled" : "Add a local workspace passphrase"}</h2><span>{configured ? "This browser can be locked without stopping the containers. The passphrase is stored only as a slow salted verifier in the local database." : "Create a 12-character or longer passphrase to protect state-changing local API requests with an HTTP-only session and CSRF checks."}</span></div>{configured ? <button onClick={lock}>Lock this browser</button> : <form onSubmit={setup}><label>Passphrase<input type="password" required minLength={12} value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="new-password"/></label><label>Confirm<input type="password" required minLength={12} value={confirm} onChange={(event) => setConfirm(event.target.value)} autoComplete="new-password"/></label><button>Enable local protection</button></form>}{notice && <small>{notice}</small>}</section>;
}

function AccessibilityPreferences() {
  const [fontScale, setFontScale] = useState("standard");
  const [contrast, setContrast] = useState(false);
  const [reducedMotion, setReducedMotion] = useState(false);
  useEffect(() => {
    try {
      const stored = JSON.parse(window.localStorage.getItem("threatcommand_accessibility") ?? "{}");
      setFontScale(stored.fontScale === "large" ? "large" : "standard"); setContrast(Boolean(stored.contrast)); setReducedMotion(Boolean(stored.reducedMotion));
    } catch { /* Keep accessible defaults when a local browser value is malformed. */ }
  }, []);
  useEffect(() => {
    document.documentElement.dataset.fontScale = fontScale;
    document.documentElement.dataset.contrast = contrast ? "high" : "standard";
    document.documentElement.dataset.reducedMotion = reducedMotion ? "true" : "false";
    window.localStorage.setItem("threatcommand_accessibility", JSON.stringify({ fontScale, contrast, reducedMotion }));
  }, [fontScale, contrast, reducedMotion]);
  return <section className="local-access-panel panel"><div><p>ACCESSIBILITY PREFERENCES</p><h2>Adjust this browser’s local view</h2><span>Preferences stay in this browser only. They do not alter stored intelligence or make any network request.</span></div><form><label>Text scale<select value={fontScale} onChange={(event) => setFontScale(event.target.value)}><option value="standard">Standard</option><option value="large">Large</option></select></label><label><input type="checkbox" checked={contrast} onChange={(event) => setContrast(event.target.checked)}/> High contrast</label><label><input type="checkbox" checked={reducedMotion} onChange={(event) => setReducedMotion(event.target.checked)}/> Reduce motion</label></form></section>;
}

function AiProviderSettings() {
  const [settings, setSettings] = useState<LocalSettings | null>(null);
  const [ai, setAi] = useState<AiStatus | null>(null);
  const [notice, setNotice] = useState("");
  const load = async () => { try { const [nextSettings, nextAi] = await Promise.all([getJson<LocalSettings>("/api/settings"), getJson<AiStatus>("/api/ai/status")]); setSettings(nextSettings); setAi(nextAi); } catch { setNotice("Could not read the local AI configuration."); } };
  useEffect(() => { load(); }, []);
  const selectProvider = async (provider: string) => {
    if (!settings) return;
    if (provider !== "ollama" && !window.confirm("Use an external AI provider? When you submit a Copilot request, your question and the local evidence selected for that request will leave this device. API keys remain only in your local .env file.")) return;
    const response = await apiFetch("/api/settings", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ network_mode: settings.network_mode, profile: { ...settings.profile, ai_provider: provider } }) });
    setNotice(response.ok ? `${provider === "ollama" ? "Local Ollama" : provider} selected. ${provider === "ollama" ? "No cloud fallback is used." : "External calls remain blocked until your local .env enables and configures this provider."}` : "AI provider selection was not saved.");
    if (response.ok) load();
  };
  const selectNetworkMode = async (network_mode: string) => {
    if (!settings || network_mode === settings.network_mode) return;
    if (network_mode === "scheduled" && !window.confirm("Enable Scheduled Sync for all currently enabled connectors? They will use their displayed per-source intervals and every outbound request will be recorded locally.")) return;
    const response = await apiFetch("/api/settings", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ network_mode, profile: settings.profile }) });
    setNotice(response.ok ? `Network mode changed to ${network_mode}.` : "Network mode was not updated.");
    if (response.ok) load();
  };
  return <GenericView title="Settings & AI Providers" copy="Ollama is the private default. External AI is optional, off by default, and never receives data unless you deliberately select it and submit a Copilot request." children={<>
    <section className="ai-provider-status panel"><div><p>ACTIVE ANALYSIS PROVIDER</p><h2>{ai?.provider === "ollama" ? "Local Ollama" : ai?.provider ?? "Loading…"}</h2><span>{ai?.model || "No model configured"}</span></div><b className={ai?.external ? "external" : "local"}>{ai?.external ? "EXTERNAL" : "LOCAL ONLY"}</b></section>
    <section className="network-mode-panel panel"><div><p>NETWORK MODE</p><h2>{settings?.network_mode?.toUpperCase() ?? "LOADING…"}</h2><span>Scheduled Sync affects only enabled connectors; each source keeps its own local interval and retention policy.</span></div><select value={settings?.network_mode ?? "manual"} onChange={(event) => selectNetworkMode(event.target.value)}><option value="offline">Offline — block all external requests</option><option value="manual">Manual — user-confirmed sync only</option><option value="scheduled">Scheduled — enabled sources sync automatically</option></select></section>
    <LocalAccessSettings configured={Boolean(settings?.local_access_configured)} />
    <AccessibilityPreferences />
    <StorageRetentionPanel />
    <section className="provider-grid">{["ollama", "openai", "openai-compatible"].map((provider) => <button className={`provider-card panel ${ai?.provider === provider ? "selected" : ""}`} key={provider} onClick={() => selectProvider(provider)}><b>{provider === "ollama" ? "OLLAMA" : provider === "openai" ? "OPENAI API" : "OPENAI-COMPATIBLE"}</b><h2>{provider === "ollama" ? "Private local models" : provider === "openai" ? "OpenAI cloud models" : "Your provider endpoint"}</h2><p>{provider === "ollama" ? "Runs locally through Ollama. Prompts and evidence stay on this device." : provider === "openai" ? "Uses your own OpenAI API key and configured cloud model." : "Supports a user-supplied Chat Completions-compatible endpoint and key."}</p><em>{ai?.provider === provider ? "Selected" : "Select provider"}</em></button>)}</section>
    {ai?.external && <section className="external-ai-warning panel"><p>EXTERNAL AI PRIVACY WARNING</p><h2>Cloud analysis is configured as an explicit exception</h2><ul><li>Only the Copilot question and the locally selected evidence for that request are sent.</li><li>Your API key is read only from <code>.env</code>; it is never entered, displayed, or stored by the dashboard.</li><li>Offline Mode blocks the request completely. There is no silent fallback between providers.</li></ul><pre>{`AI_PROVIDER=${ai.provider}\nEXTERNAL_AI_ENABLED=true\nEXTERNAL_AI_BASE_URL=${ai.provider === "openai" ? "https://api.openai.com/v1" : "https://your-provider.example/v1"}\nEXTERNAL_AI_API_KEY=your_key_here\nEXTERNAL_AI_MODEL=your_model_here`}</pre></section>}
    {ai?.external && !ai.configured && <div className="panel empty"><b>Finish local configuration before use.</b><p>Add the shown variables to the project’s local <code>.env</code> file, then restart ThreatCommand. The UI will not accept or retain your provider key.</p></div>}
    {notice && <p className="page-note">{notice}</p>}
  </>}/>;
}

function DetectionLifecycleWorkspace({ detections }: { detections: Detection[] }) {
  const [selectedId, setSelectedId] = useState("");
  const [detail, setDetail] = useState<DetailResponse | null>(null);
  const [maturity, setMaturity] = useState("draft");
  const [owner, setOwner] = useState("");
  const [telemetryState, setTelemetryState] = useState("unknown");
  const [validationNotes, setValidationNotes] = useState("");
  const [fixture, setFixture] = useState("");
  const [outcome, setOutcome] = useState("not_run");
  const [validationEvidence, setValidationEvidence] = useState("");
  const [notice, setNotice] = useState("");
  const load = async (id: string) => {
    if (!id) { setDetail(null); return; }
    try {
      const next = await getJson<DetailResponse>(`/api/detections/${encodeURIComponent(id)}`);
      setDetail(next);
      setMaturity(next.record.maturity ?? "draft");
      setOwner(next.record.owner ?? "");
      setTelemetryState(next.record.telemetry_state ?? "unknown");
      setValidationNotes(next.record.validation_notes ?? "");
      setNotice("");
    } catch { setNotice("The selected local detection could not be loaded."); }
  };
  useEffect(() => { if (!selectedId && detections[0]) setSelectedId(detections[0].id); }, [detections, selectedId]);
  useEffect(() => { load(selectedId); }, [selectedId]);
  const saveMaturity = async (event: FormEvent) => {
    event.preventDefault(); if (!selectedId) return;
    const response = await apiFetch(`/api/detections/${selectedId}/maturity`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ maturity, owner, telemetry_state: telemetryState, validation_notes: validationNotes }) });
    const result = await response.json();
    if (!response.ok) return setNotice(result.detail ?? "The lifecycle state was not saved.");
    setNotice("Lifecycle state saved locally. A revision snapshot was recorded when values changed.");
    load(selectedId);
  };
  const recordValidation = async (event: FormEvent) => {
    event.preventDefault(); if (!selectedId) return;
    const response = await apiFetch(`/api/detections/${selectedId}/validation`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ fixture_name: fixture, outcome, evidence: validationEvidence }) });
    const result = await response.json();
    if (!response.ok) return setNotice(result.detail ?? "The validation result was not saved.");
    setFixture(""); setOutcome("not_run"); setValidationEvidence(""); setNotice("Validation result saved locally. It does not claim deployment or production coverage."); load(selectedId);
  };
  const runStaticLint = async () => {
    if (!selectedId) return;
    const response = await apiFetch(`/api/detections/${selectedId}/lint`, { method: "POST" });
    const result = await response.json();
    setNotice(response.ok ? `Static advisory recorded as ${String(result.outcome).toUpperCase()}. It did not execute a query or prove platform compatibility.` : (result.detail ?? "The static advisory could not be recorded."));
    if (response.ok) load(selectedId);
  };
  return <GenericView title="Detection Lifecycle" copy="Track learning detections through review and safe validation. These records remain local and never deploy, query, block, or modify another system." children={<>
    {!detections.length ? <div className="panel empty"><b>No detections are available.</b><p>Open Detection Studio after the local library has loaded.</p></div> : <>
      <section className="panel"><label>Detection<select value={selectedId} onChange={(event) => setSelectedId(event.target.value)}>{detections.map((item) => <option key={item.id} value={item.id}>{item.title}</option>)}</select></label><p className="page-note">Maturity is a local governance label, not proof that a rule is deployed or effective.</p></section>
      {detail && <section className="case-list"><article className="panel case-card"><div className="case-meta"><span>{detail.record.maturity ?? "draft"}</span><span>{detail.record.telemetry_state ?? "unknown"} telemetry</span></div><h2>{detail.record.title}</h2><p>{detail.record.description}</p><button onClick={runStaticLint}>Run built-in static advisory</button><p className="page-note">This only checks basic rule structure. It does not execute the rule, validate a vendor parser, or establish detection coverage.</p><form className="phase-form" onSubmit={saveMaturity}><label>Maturity<select value={maturity} onChange={(event) => setMaturity(event.target.value)}><option value="draft">Draft</option><option value="reviewed">Reviewed</option><option value="tested">Tested</option><option value="validated">Validated</option><option value="deployed">Deployed</option><option value="tuned">Tuned</option><option value="monitored">Monitored</option><option value="retired">Retired</option></select></label><label>Owner / reviewer<input value={owner} onChange={(event) => setOwner(event.target.value)} placeholder="Local team or reviewer"/></label><label>Telemetry state<select value={telemetryState} onChange={(event) => setTelemetryState(event.target.value)}><option value="unknown">Unknown</option><option value="unavailable">Unavailable</option><option value="available">Available</option><option value="normalized">Normalized</option></select></label><label>Validation or review notes<textarea value={validationNotes} onChange={(event) => setValidationNotes(event.target.value)} placeholder="What was reviewed, tested, or still needs verification?"/></label><button>Save local lifecycle</button></form></article>
        <article className="panel case-card"><h2>Record a safe validation result</h2><p>Use an authorized fixture, saved event, or review scenario. Do not execute adversary behavior from this workspace.</p><form className="phase-form" onSubmit={recordValidation}><label>Fixture / scenario<input required minLength={2} value={fixture} onChange={(event) => setFixture(event.target.value)} placeholder="Saved identity sign-in fixture"/></label><label>Outcome<select value={outcome} onChange={(event) => setOutcome(event.target.value)}><option value="not_run">Not run</option><option value="pass">Pass</option><option value="fail">Fail</option></select></label><label>Local evidence / notes<textarea value={validationEvidence} onChange={(event) => setValidationEvidence(event.target.value)} placeholder="Expected vs. observed result, timestamp, and safe reference"/></label><button>Save validation result</button></form></article></section>}
      {detail && <section className="case-list"><article className="panel case-card"><h2>Revision history</h2>{detail.revisions?.length ? <div className="evidence-list">{detail.revisions.map((revision) => <p key={`${revision.version}-${revision.created_at}`}><b>v{revision.version}</b> {revision.change_summary} <em>{new Date(revision.created_at).toLocaleString()}</em></p>)}</div> : <p>No local lifecycle revisions recorded yet.</p>}</article><article className="panel case-card"><h2>Validation history</h2>{detail.validation_results?.length ? <div className="evidence-list">{detail.validation_results.map((result) => <p key={`${result.fixture_name}-${result.created_at}`}><b>{result.outcome.toUpperCase()}</b> {result.fixture_name}{result.evidence ? ` — ${result.evidence}` : ""} <em>{new Date(result.created_at).toLocaleString()}</em></p>)}</div> : <p>No validation result recorded yet.</p>}</article></section>}
    </>}{notice && <p className="page-note">{notice}</p>}</>}/>;
}

function CaseEvidenceWorkspace({ hunts, incidents }: { hunts: HuntCase[]; incidents: IncidentCase[] }) {
  const [caseType, setCaseType] = useState<"hunt" | "incident">("hunt");
  const [caseId, setCaseId] = useState("");
  const [evidence, setEvidence] = useState<any[]>([]);
  const [findings, setFindings] = useState<any[]>([]);
  const [evidenceType, setEvidenceType] = useState("fact");
  const [content, setContent] = useState("");
  const [sourceUrl, setSourceUrl] = useState("");
  const [classification, setClassification] = useState("no_finding");
  const [findingSummary, setFindingSummary] = useState("");
  const [notice, setNotice] = useState("");
  const cases = caseType === "hunt" ? hunts : incidents;
  useEffect(() => { if (!cases.some((item) => item.id === caseId)) setCaseId(cases[0]?.id ?? ""); }, [caseType, hunts, incidents, caseId]);
  const load = async () => {
    if (!caseId) { setEvidence([]); setFindings([]); return; }
    try {
      const result = await getJson<any>(`/api/${caseType === "hunt" ? "hunts" : "incidents"}/${caseId}/evidence`);
      setEvidence(caseType === "hunt" ? result.evidence : result);
      setFindings(caseType === "hunt" ? result.findings : []);
      setNotice("");
    } catch { setNotice("The local evidence record could not be loaded."); }
  };
  useEffect(() => { load(); }, [caseId, caseType]);
  const addEvidence = async (event: FormEvent) => {
    event.preventDefault(); if (!caseId) return;
    const response = await apiFetch(`/api/${caseType === "hunt" ? "hunts" : "incidents"}/${caseId}/evidence`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ evidence_type: evidenceType, content, source_url: sourceUrl || null }) });
    const result = await response.json();
    if (!response.ok) return setNotice(result.detail ?? "Evidence was not saved.");
    setContent(""); setSourceUrl(""); setNotice("Evidence saved locally with a content fingerprint to prevent accidental duplicates."); load();
  };
  const addFinding = async (event: FormEvent) => {
    event.preventDefault(); if (!caseId || caseType !== "hunt") return;
    const response = await apiFetch(`/api/hunts/${caseId}/findings`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ classification, summary: findingSummary }) });
    const result = await response.json();
    if (!response.ok) return setNotice(result.detail ?? "Hunt finding was not saved.");
    setFindingSummary(""); setNotice("Hunt finding saved locally. It has not triggered a response action."); load();
  };
  const exportHandover = async () => {
    if (!caseId) return;
    const response = await apiFetch(`/api/cases/${caseType}/${caseId}/handover-export`, { method: "POST" });
    const result = await response.json();
    if (!response.ok) return setNotice(result.detail ?? "The local handover export could not be created.");
    const file = await apiFetch(result.download_path);
    if (!file.ok) return setNotice("The local handover was created but could not be downloaded.");
    const objectUrl = URL.createObjectURL(await file.blob()); const anchor = document.createElement("a"); anchor.href = objectUrl; anchor.download = result.filename; anchor.click(); URL.revokeObjectURL(objectUrl);
    setNotice(`Local handover exported with ${result.provenance_manifest.evidence_count} evidence hashes. Review it before sharing.`);
  };
  return <GenericView title="Evidence Ledger" copy="Separate local facts, source claims, analyst inferences, artifacts, and decisions for authorized hunts and incident cases. This workspace makes no external request." action={<button className="button" disabled={!caseId} onClick={exportHandover}>Export local handover</button>} children={<>
    <section className="panel phase-form compact"><label>Case type<select value={caseType} onChange={(event) => setCaseType(event.target.value as "hunt" | "incident")}><option value="hunt">Threat hunt</option><option value="incident">Incident case</option></select></label><label>Local case<select value={caseId} onChange={(event) => setCaseId(event.target.value)}>{cases.map((item) => <option key={item.id} value={item.id}>{caseType === "hunt" ? (item as HuntCase).name : (item as IncidentCase).title}</option>)}</select></label></section>
    {!cases.length ? <div className="panel empty"><b>No {caseType === "hunt" ? "hunt cases" : "incident cases"} yet.</b><p>Create one in its workspace before adding evidence.</p></div> : <><section className="case-list"><article className="panel case-card"><h2>Add evidence</h2><form className="phase-form" onSubmit={addEvidence}><label>Record type<select value={evidenceType} onChange={(event) => setEvidenceType(event.target.value)}><option value="fact">Fact</option><option value="claim">Source claim</option><option value="inference">Analyst inference</option><option value="artifact">Artifact</option><option value="decision">Decision</option></select></label><label>Local record<textarea required minLength={2} value={content} onChange={(event) => setContent(event.target.value)} placeholder="State what is known, reported, inferred, or decided — and retain uncertainty."/></label><label>Optional reference URL<input type="url" value={sourceUrl} onChange={(event) => setSourceUrl(event.target.value)} placeholder="https://local-or-approved-reference"/></label><button>Save local evidence</button></form></article>{caseType === "hunt" && <article className="panel case-card"><h2>Record hunt finding</h2><form className="phase-form" onSubmit={addFinding}><label>Classification<select value={classification} onChange={(event) => setClassification(event.target.value)}><option value="no_finding">No finding</option><option value="benign">Benign</option><option value="suspicious">Suspicious</option><option value="confirmed">Confirmed</option><option value="detection_candidate">Detection candidate</option></select></label><label>Summary<textarea required minLength={2} value={findingSummary} onChange={(event) => setFindingSummary(event.target.value)} placeholder="Describe the result and what would be needed to validate it."/></label><button>Save local finding</button></form></article>}</section>
      <section className="case-list"><article className="panel case-card"><h2>Evidence timeline</h2>{evidence.length ? <div className="evidence-list">{evidence.map((item) => <p key={item.id}><b>{item.evidence_type.toUpperCase()}</b> {item.content} {item.source_url && <a href={item.source_url} target="_blank" rel="noreferrer">reference ↗</a>} <em>{new Date(item.created_at).toLocaleString()}</em></p>)}</div> : <p>No evidence recorded for this local case.</p>}</article>{caseType === "hunt" && <article className="panel case-card"><h2>Hunt findings</h2>{findings.length ? <div className="evidence-list">{findings.map((item) => <p key={item.id}><b>{item.classification.toUpperCase()}</b> {item.summary} <em>{new Date(item.created_at).toLocaleString()}</em></p>)}</div> : <p>No hunt finding recorded yet.</p>}</article>}</section></>}{notice && <p className="page-note">{notice}</p>}</>}/>;
}

function RecordModal({ detail, loading, watchlists, addWatchlistItem, close }: { detail: DetailResponse | null; loading: boolean; watchlists: Watchlist[]; addWatchlistItem: (watchlistId: string, payload: { entity_type: string; reference_id: string; title: string }) => Promise<void>; close: () => void }) {
  const [selectedWatchlist, setSelectedWatchlist] = useState("");
  const dialogRef = useRef<HTMLElement>(null);
  useEffect(() => {
    const previouslyFocused = document.activeElement as HTMLElement | null;
    const focusFirst = () => { dialogRef.current = document.querySelector<HTMLElement>(".record-modal"); dialogRef.current?.querySelector<HTMLElement>("button:not([disabled]), a[href], input:not([disabled]), select:not([disabled]), textarea:not([disabled])")?.focus(); };
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") { close(); return; }
      if (event.key !== "Tab" || !dialogRef.current) return;
      const focusable = Array.from(dialogRef.current.querySelectorAll<HTMLElement>("button:not([disabled]), a[href], input:not([disabled]), select:not([disabled]), textarea:not([disabled])"));
      if (!focusable.length) return;
      const first = focusable[0]; const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
      if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    };
    const timer = window.setTimeout(focusFirst, 0);
    window.addEventListener("keydown", closeOnEscape);
    return () => { window.clearTimeout(timer); window.removeEventListener("keydown", closeOnEscape); previouslyFocused?.focus(); };
  }, [close, detail, loading]);
  if (loading) return <div className="modal-backdrop"><section className="record-modal"><button className="modal-close" onClick={close}>×</button><p>Loading the local record…</p></section></div>;
  if (!detail) return null;
  const record = detail.record;
  const title = record.title ?? record.cve_id ?? "Local record";
  const source = record.source_url as string | undefined;
  const isDetection = detail.kind === "detection";
  return <div className="modal-backdrop" role="presentation" onMouseDown={close}><section className="record-modal" role="dialog" aria-modal="true" aria-labelledby="record-title" onMouseDown={(event) => event.stopPropagation()}><button className="modal-close" onClick={close} aria-label="Close details">×</button><p className="modal-label">{detail.kind === "vulnerability" ? "LOCAL VULNERABILITY DETAIL" : detail.kind === "threat" ? "SOURCE-REPORTED INTELLIGENCE" : "DETECTION LEARNING DETAIL"}</p><h2 id="record-title">{title}</h2><div className="modal-meta"><span>{record.cve_id ?? record.reference_id ?? record.segment}</span><span>{record.severity ?? record.rule_format}</span><span>{detail.kind === "detection" ? "LOCAL LEARNING LIBRARY" : record.demo ? "DEMO" : "LOCAL LIVE DATA"}</span></div><p className="modal-summary">{record.description ?? record.summary}</p>{source && <a className="source-link" href={source} target="_blank" rel="noreferrer">Open original source ↗</a>}
    {detail.kind === "vulnerability" && <><ModalSection title="Why it matters"><p>KEV status: <b>{record.kev ? "Known Exploited Vulnerability" : "Not marked KEV"}</b>. Exploitation evidence: {record.exploitation_evidence ?? "No source-specific evidence stored."}</p><p>Affected products: {(record.affected_products ?? []).join(", ") || "Not supplied"}</p></ModalSection><ModalSection title="Potential relevance"><p>{record.potential_relevance}</p><p>Recommended action: <b>{record.recommended_action}</b></p></ModalSection></>}
    {detail.kind === "threat" && <ModalSection title="Full locally stored feed content"><p>This is the complete content supplied by the synchronized RSS or Atom feed. Some publishers provide excerpts rather than full articles in their feed.</p><pre>{record.raw_content || "This feed item did not include additional content."}</pre></ModalSection>}
    {isDetection && detail.learning && <><ModalSection title="What you learn"><p>{detail.learning.what_to_learn}</p><p>{detail.learning.how_to_use}</p></ModalSection><ModalSection title="Why it matters"><p>{detail.learning.why_it_matters}</p></ModalSection><ModalSection title="Technical explanation"><p>{detail.learning.technical_explanation}</p></ModalSection><ModalSection title="Cyber Kill Chain & ATT&CK context"><ul>{detail.learning.kill_chain.map((item) => <li key={item.phase}><b>{item.phase}:</b> {item.explanation}</li>)}</ul></ModalSection><ModalSection title="Detection logic"><p>{detail.learning.detection_logic}</p></ModalSection><ModalSection title="Required telemetry"><p>{(record.required_telemetry ?? []).join(", ")}</p></ModalSection><ModalSection title="Draft rule or query"><pre>{record.rule_content}</pre></ModalSection><ModalSection title="False positives to consider"><p>{detail.learning.false_positives}</p></ModalSection><ModalSection title="Tuning approach"><p>{detail.learning.tuning}</p></ModalSection><ModalSection title="Safe validation"><p>{detail.learning.validation}</p><p>{detail.learning.limitations}</p></ModalSection></>}
    {watchlists.length > 0 && <ModalSection title="Add to local watchlist"><div className="watchlist-quick-add"><select value={selectedWatchlist} onChange={(event) => setSelectedWatchlist(event.target.value)}><option value="">Choose a watchlist…</option>{watchlists.map((watchlist) => <option key={watchlist.id} value={watchlist.id}>{watchlist.name}</option>)}</select><button disabled={!selectedWatchlist} onClick={() => addWatchlistItem(selectedWatchlist, { entity_type: detail.kind === "vulnerability" ? "vulnerability" : detail.kind === "detection" ? "detection" : "threat", reference_id: String(record.cve_id ?? record.reference_id ?? record.id), title })}>Add record</button></div></ModalSection>}
    <ModalSection title="Confidence and limitations"><p>{detail.limitations ?? detail.learning?.limitations}</p>{detail.learning_steps && <ul>{detail.learning_steps.map((step) => <li key={step}>{step}</li>)}</ul>}</ModalSection></section></div>;
}

function ModalSection({ title, children }: { title: string; children: React.ReactNode }) { return <section className="modal-section"><h3>{title}</h3>{children}</section>; }
