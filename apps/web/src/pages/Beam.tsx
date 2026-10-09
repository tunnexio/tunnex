import "../beam-workspace.css";
import "../app-access-workspace.css";
import { Icon } from "../components/Icon";
import AppAccessPagination from "../components/AppAccessPagination";
import AppAccessRowMenu from "../components/AppAccessRowMenu";
import AppAccessEmptyState from "../components/AppAccessEmptyState";
import { lazy, Suspense, useEffect, useRef, useState } from "react";
import { Link, Navigate, useLocation, useParams, useSearchParams } from "react-router-dom";
import { Button, Card, ErrorText, Field, Input, Loading, Modal, PageHeader, Select, RefreshButton } from "../components/ui";
import { Logo } from "../brand";
import { AudiencePicker } from "../components/BeamAudiencePicker";
import { BeamCliPublisher } from "../components/BeamCliPublisher";
import { BeamRooms } from "../components/BeamRooms";
import { BeamFeedback, BeamNotifications } from "../components/BeamFeedback";
import { BeamShareMobile } from "../components/BeamShareMobile";
import { BeamDiagnostics } from "../components/BeamDiagnostics";
import { ResourceSummary } from "../components/ResourceSummary";
import { BeamEvents } from "../components/BeamEvents";
import { BeamCompatibilityHelp } from "../components/BeamCompatibilityHelp";
import { beamRoomsApi } from "../lib/beam-rooms";
import { useBeamClock, beamCountdown } from "../lib/beam-clock";
import { useAuth } from "../lib/auth";
import { useOrg } from "../lib/useOrg";
import { api, apiErrorMessage } from "../lib/api";
import { beamApi, beamHandoffURL, beamCanOpen, beamIsTerminal, beamLaunchURL, beamStatus, type BeamAudience, type BeamGrantsImpact, type BeamShareFilters, type BeamGrant, type BeamPage, type BeamPolicy, type BeamShare } from "../lib/beam";

// This import is removed entirely from production bundles by Vite.
const BeamUIPreview = import.meta.env.DEV ? lazy(() => import("../components/BeamUIPreview")) : null;

export default function Beam() {
  const { org, failed } = useOrg();
  const { state } = useAuth();
  const location = useLocation();
  const { shareId } = useParams();
  if (failed) return <Card><ErrorText>Could not load your organization.</ErrorText></Card>;
  if (!org || state.status !== "authed") return <Card><Loading label="Loading Local Sharing…" /></Card>;
  return <BeamWorkspace key={`${org.id}:${state.user.id}:${location.pathname}`} orgId={org.id} shareId={shareId} />;
}
function BeamWorkspace({ orgId, shareId }: { orgId: string; shareId?: string }) {
  const location = useLocation();
  const { state } = useAuth();
  const canOperate = state.status === "authed" && Boolean(state.user.cp_admin);
  const [params] = useSearchParams();
  const sampleId = import.meta.env.DEV && import.meta.env.VITE_BEAM_UI_FIXTURES === "1" && location.pathname === "/beam/my-shares" && !shareId ? params.get("sample") : null;
  const [policy, setPolicy] = useState<BeamPolicy | null>(null);
  const [error, setError] = useState("");
  const [reload, setReload] = useState(0);
  const [ownedHistory, setOwnedHistory] = useState<"checking" | "present" | "empty" | "failed">("checking");
  useEffect(() => {
    let current = true; setPolicy(null); setError(""); setOwnedHistory("checking");
    void beamApi.policy(orgId).then(async result => {
      if (!current) return;
      if (!result.ok) { setError(result.error); return; }
      setPolicy(result.data);
      if (result.data.can_publish || result.data.can_manage_policy) { setOwnedHistory("present"); return; }
      // A former publisher retains access to their own share history and Stop.
      const owned = await beamApi.shares(orgId, false);
      if (!current) return;
      if (!owned.ok) { setOwnedHistory("failed"); return; }
      if (owned.data.items.length || (owned.data.quota?.active_shares ?? 0) > 0) { setOwnedHistory("present"); return; }
      const projects = await beamRoomsApi.projects(orgId);
      if (current) setOwnedHistory(projects.ok ? projects.data.items.length ? "present" : "empty" : "failed");
    });
    return () => { current = false; };
  }, [orgId, reload]);
  if (policy && location.pathname === "/beam") return <Navigate replace to={policy.can_publish || policy.can_manage_policy ? "/beam/my-shares" : "/beam/shared-with-me"} />;
  if (policy?.can_publish && !policy.open_for_all_users && !policy.can_manage_policy && location.pathname === "/beam/shared-with-me") return <Navigate replace to="/beam/my-shares" />;
  if (policy && !policy.can_publish && !policy.can_manage_policy && location.pathname === "/beam/my-shares") {
    if (ownedHistory === "checking") return <Card><Loading label="Checking your share history…" /></Card>;
    if (ownedHistory === "empty") return <Navigate replace to="/beam/shared-with-me" />;
    if (ownedHistory === "failed") return <Card><ErrorText>Could not check your share history.</ErrorText><Button onClick={() => setReload(n => n + 1)}>Retry Local Sharing</Button></Card>;
  }
  const shared = location.pathname === "/beam/shared-with-me";
  const events = location.pathname === "/beam/events";
  return <div className="beam-workspace network-management space-y-5">
    {!shareId && !sampleId && <PageHeader navigationTitle title="Local Sharing" actions={policy?.can_manage_policy ? <Link className="beam-inline-link" to="/settings?section=beam">Sharing policy</Link> : undefined} />}
    {!shareId && !sampleId && <nav aria-label="Local Sharing workspaces" className="workspace-tabs">
      {policy && (policy.can_publish || policy.can_manage_policy || ownedHistory === "present") && <Link aria-current={!shared && !events ? "page" : undefined} to="/beam/my-shares">My shares</Link>}
      {policy && (!policy.can_publish || policy.open_for_all_users || policy.can_manage_policy) && <Link aria-current={shared ? "page" : undefined} to="/beam/shared-with-me">Shared with me</Link>}
      {policy?.can_manage_policy && <Link aria-current={events ? "page" : undefined} to="/beam/events">Events</Link>}
    </nav>}
    {error ? <Card><ErrorText>{error}</ErrorText><Button onClick={() => setReload(n => n + 1)}>Retry Local Sharing</Button></Card> : !policy ? <Card><Loading label="Checking Local Sharing availability…" /></Card> : <>
      {(!policy.enabled || !policy.domain_ready) && <div className="beam-setup-notice"><Icon name="circle-alert" size={14} /><p role="status">{!policy.enabled ? "Local sharing is off." : "Serving setup incomplete."}</p>{!policy.enabled && policy.can_manage_policy ? <Link className="beam-inline-link" to="/settings?section=features&feature=local-sharing">Open feature settings</Link> : !policy.domain_ready && canOperate ? <Link className="beam-inline-link" to="/settings?section=beam-serving">Configure serving setup</Link> : <span className="beam-setup-owner">{!policy.enabled ? "Contact your organization administrator." : "Contact your installation operator."}</span>}</div>}
      {sampleId && BeamUIPreview ? <Suspense fallback={<Loading label="Loading local preview…" />}><BeamUIPreview orgId={orgId} sampleId={sampleId} now={Date.now()} /></Suspense> : shareId ? <ShareDetail orgId={orgId} shareId={shareId} policy={policy} /> : events ? <BeamEvents orgId={orgId} permitted={policy.can_manage_policy} /> : <ShareInventory orgId={orgId} shared={shared} policy={policy} />}
    </>}
  </div>;
}
function localDateTime(date: Date) { return new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0,16); }
function statusTone(label: string) {
  return label === "Live" ? "live" : ["Publisher offline", "Reconnecting", "Refresh required", "Starting"].includes(label) ? "warning" : ["Local app unavailable", "Unavailable"].includes(label) ? "danger" : "neutral";
}
function Status({ share, uncertain = false, now }: { share: BeamShare; uncertain?: boolean; now?: number }) {
  const label = uncertain ? "Refresh required" : beamStatus(share, now);
  return <span className="beam-status" data-tone={statusTone(label)}>{label}</span>;
}
function ShareAvatar({ share }: { share: BeamShare }) {
  const color = Array.from(share.name).reduce((sum, character) => sum + character.charCodeAt(0), 0) % 4;
  const initials = share.name.trim().split(/\s+/).slice(0, 2).map(word => word[0]).join("").toUpperCase();
  return <span className="beam-app-icon" data-color={color} aria-hidden="true">{initials || <Icon name="local-sharing" size={19} />}</span>;
}
function OpenShare({ share, now }: { share: BeamShare; now?: number }) {
  const url = beamLaunchURL(share.url, share.hostname);
  return beamCanOpen(share, now) && url ? <a className="beam-open-link" aria-label={`Open ${share.name}`} href={url} target="_blank" rel="noopener noreferrer">Open app<Icon name="chevron-right" size={15} /></a> : <span className="beam-unavailable">{!share.can_open ? "Access is not currently granted" : beamStatus(share, now)}</span>;
}
function ShareInventory({ orgId, shared, policy }: { orgId: string; shared: boolean; policy: BeamPolicy }) {
  const [workspace, setWorkspace] = useState<"projects" | "active" | "history">("active");
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(20);
  const [query, setQuery] = useState("");
  const [search, setSearch] = useState("");
  const [health, setHealth] = useState<BeamShareFilters>({});
  const [healthDraft, setHealthDraft] = useState<BeamShareFilters>({});
  const clock = useBeamClock();
  const [data, setData] = useState<BeamPage<BeamShare> | null>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [reload, setReload] = useState(0);
  const [, setClock] = useState(0);
  useEffect(() => { if (!shared && workspace === "projects") return; let current = true; setData(null); setError(""); void beamApi.shares(orgId, shared, page * pageSize, search || undefined, shared ? health : { ...health, scope: workspace === "history" ? "history" : "active" }, pageSize).then(result => { if (!current) return; if (result.ok) { clock.synchronize(result.data.server_time ?? result.server_time); setData(result.data); } else setError(result.error); }); return () => { current = false; }; }, [orgId, shared, page, pageSize, reload, search, health, workspace]);
  useEffect(() => { const timer = window.setInterval(() => setClock(n => n + 1), 1000); const poll = window.setInterval(() => setReload(n => n + 1), 30000); const focus = () => setReload(n => n + 1); window.addEventListener("focus", focus); return () => { window.clearInterval(timer); window.clearInterval(poll); window.removeEventListener("focus", focus); }; }, []);
  const visibleShares = data?.items.filter(share => shared ? (["active", "paused"].includes(share.state) && !beamIsTerminal(share, clock.now())) : workspace === "history" ? beamIsTerminal(share, clock.now()) : !beamIsTerminal(share, clock.now())) ?? [];
  const filtered = Boolean(search || health.state || health.connectivity);
  const [previewAvailable, setPreviewAvailable] = useState(false);
  const showPreview = import.meta.env.DEV && import.meta.env.VITE_BEAM_UI_FIXTURES === "1" && !shared && workspace !== "history";
  const emptyTitle = filtered ? "No shares match this search." : shared ? "No apps are currently shared with you." : workspace === "history" ? "No ended sessions yet." : "No active shares";
  const emptyDescription = filtered ? "Try another name or clear the filters." : shared ? "Shared apps appear here when a publisher gives your account access." : workspace === "history" ? `Ended previews stay here for reference.${policy.can_publish ? " Start a new session from a saved project." : ""}` : policy.can_publish ? policy.enabled && policy.domain_ready ? "Share a saved project or local app using the CLI or desktop client." : "Publishing becomes available when sharing is enabled and serving setup is complete." : "Your previous shares and saved projects stay available. Publishing permission is required to start another preview.";
  function clear() { setQuery(""); setSearch(""); setHealth({}); setHealthDraft({}); setPage(0); }
  async function copy(share: BeamShare) {
    const url = beamLaunchURL(share.url, share.hostname);
    if (!url) { setError("This share does not have a valid link. Refresh to check its current state."); return; }
    try { await navigator.clipboard.writeText(url); setNotice("Link copied. Reviewers still need current access and sign-in."); }
    catch { setError("Could not copy the link. Open its details to select and copy it."); }
  }
  return <section aria-label={shared ? "Shared with me" : "My shares"} className="beam-inventory">
    <div className="beam-workspace-bar">
      {!shared && <div role="group" aria-label="My share views" className="beam-view-tabs">{([ ["active", "Active"], ["projects", "Saved projects"], ["history", "History"] ] as const).map(([value, label]) => <button type="button" key={value} aria-pressed={workspace === value} onClick={() => { setWorkspace(value); clear(); }}>{label}</button>)}</div>}
      <div className="beam-workspace-tools"><BeamNotifications orgId={orgId} />{!shared && policy.can_publish && <BeamCliPublisher orgId={orgId} policy={policy} label="Share a local app" />}</div>
    </div>
    {!shared && workspace === "projects" ? <BeamRooms orgId={orgId} policy={policy} /> : <>
      <form className="beam-toolbar" onSubmit={event => { event.preventDefault(); setPage(0); setSearch(query.trim()); setHealth(healthDraft); }}>
        <div className="beam-search"><Icon name="search" size={17} /><Input type="search" aria-label="Search shares" maxLength={200} placeholder="Search apps or hostnames…" value={query} onChange={event => setQuery(event.target.value)} /></div>
        {!shared && <Select className="beam-state-filter" aria-label="Share state" width="auto" value={healthDraft.state ?? ""} onChange={event => setHealthDraft(d => ({ ...d, state: (event.target.value || undefined) as BeamShareFilters["state"] }))}><option value="">All states</option>{(workspace === "history" ? ["stopped", "expired", "revoked"] : ["starting", "active", "paused"]).map(state => <option key={state} value={state}>{state.charAt(0).toUpperCase() + state.slice(1)}</option>)}</Select>}
        <Select className="beam-connectivity-filter" aria-label="Share connectivity" width="auto" value={healthDraft.connectivity ?? ""} onChange={event => setHealthDraft(d => ({ ...d, connectivity: (event.target.value || undefined) as BeamShareFilters["connectivity"] }))}><option value="">All connectivity</option><option value="online">Online</option><option value="offline">Offline or reconnecting</option><option value="origin_unavailable">Local app unavailable</option></Select>
        <Button type="submit" variant="ghost" size="sm" aria-label="Search shares">Search</Button>
        <RefreshButton label="Refresh shares" type="button" className="beam-refresh" onClick={() => setReload(n => n + 1)} />
        {filtered && <Button type="button" variant="ghost" size="sm" onClick={clear}>Clear share search</Button>}
      </form>
      {notice && <p role="status" className="beam-notice">{notice}</p>}
      {!shared && data?.quota && <p className="beam-list-summary" title="Starting and paused shares use a share slot.">{data.quota.active_shares} of {data.quota.max_shares} share slots in use</p>}
      {error ? <div className="beam-error"><ErrorText>{error}</ErrorText><Button onClick={() => setReload(n => n + 1)}>Retry shares</Button></div> : !data ? <Loading label="Loading shares…" /> : !visibleShares.length ? showPreview && previewAvailable ? <div className="beam-empty-inline"><span className="beam-empty-mark" aria-hidden="true"><Icon name="local-sharing" size={23} /></span><div><p role="status">{emptyTitle}</p><span>{filtered ? "Try another name or clear the filters." : !policy.enabled ? "Enable sharing to publish your first app." : !policy.domain_ready ? "Finish serving setup to share your first app." : "Your next local app can have a private link."}</span></div>{filtered && <button type="button" className="beam-inline-link" onClick={clear}>Clear filters</button>}</div> : <AppAccessEmptyState icon="globe"
        title={emptyTitle}
        description={emptyDescription}
        action={filtered ? <Button variant="ghost" size="sm" onClick={clear}>Clear filters</Button> : !shared && workspace === "active" ? <button type="button" className="beam-inline-link" onClick={() => { setWorkspace("projects"); clear(); }}>View saved projects</button> : undefined}
      /> : <div className="beam-table-wrap"><table className="beam-inventory-table"><caption className="sr-only">{shared ? "Apps shared with me" : workspace === "history" ? "Ended shares" : "Active shares"}</caption><thead><tr><th>Application</th><th>Status</th><th>{shared ? "Publisher" : "Reviewers"}</th><th>Expires</th><th><span className="sr-only">Actions</span></th></tr></thead><tbody>{visibleShares.map(share => {
        const path = `/beam/shares/${encodeURIComponent(share.id)}`;
        const actionLabel = shared ? `Review ${share.name}` : workspace === "history" ? `View ${share.name}` : `Manage ${share.name}`;
        return <tr key={share.id}><td><div className="beam-app-identity"><ShareAvatar share={share} /><div><h2 aria-label={share.name}><Link to={path} aria-label={actionLabel}>{share.name}</Link></h2><p className="beam-url">{share.hostname}</p></div></div></td><td><Status share={share} now={clock.now()} /></td><td>{shared ? share.publisher_name || "Publisher" : share.grants ? `${share.grants.length} ${share.grants.length === 1 ? "selection" : "selections"}` : "Not reported"}</td><td><span className="beam-expiry">{new Date(share.expires_at).toLocaleString()}</span><span className="beam-countdown">{beamCountdown(share.expires_at, clock.now())}</span></td><td><div className="beam-row-actions"><OpenShare share={share} now={clock.now()} /><AppAccessRowMenu label={`Actions for ${share.name}`} actions={[{ key: "details", label: "View share details", href: path }, { key: "copy", label: "Copy link", disabledReason: beamIsTerminal(share, clock.now()) ? "This share has ended." : null, onSelect: () => void copy(share) }]} /></div></td></tr>;
      })}</tbody></table></div>}
      {data && (data.items.length > 0 || page > 0) && <AppAccessPagination page={page + 1} pageSize={pageSize} count={visibleShares.length} hasNext={data.items.length >= pageSize} previousLabel="Previous shares" nextLabel="Next shares" onPageChange={next => setPage(next - 1)} onPageSizeChange={size => { setPageSize(size); setPage(0); }} />}
      {showPreview && BeamUIPreview && <Suspense fallback={null}><BeamUIPreview orgId={orgId} search={search || undefined} filters={health} now={clock.now()} onAvailable={setPreviewAvailable} /></Suspense>}
    </>}
    {!shared && <details className="beam-disclosure beam-publishing-help"><summary>Publishing help</summary><div><p>Run your local app and publish from the CLI or desktop client. Keep both running while reviewers use the shared browser link.</p>{!policy.can_publish && <p>Your account is not permitted to publish. An administrator can update the sharing policy.</p>}<Link className="beam-inline-link" to="/connect">Get the desktop client<Icon name="chevron-right" size={14} /></Link><BeamCompatibilityHelp /></div></details>}
  </section>;
}
function ShareDetail({ orgId, shareId, policy }: { orgId: string; shareId: string; policy: BeamPolicy }) {
  const [share, setShare] = useState<BeamShare | null>(null);
  const [audience, setAudience] = useState<BeamAudience | null>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [uncertain, setUncertain] = useState(false);
  const clock = useBeamClock();
  const grantOpener = useRef<HTMLElement | null>(null);
  const [grantImpact, setGrantImpact] = useState<BeamGrantsImpact | null>(null);
  const [grantConfirmation, setGrantConfirmation] = useState(false);
  const [confirmStop, setConfirmStop] = useState(false);
  const [expires, setExpires] = useState("");
  const [grants, setGrants] = useState<BeamGrant[]>([]);
  const [reload, setReload] = useState(0);
  const alive = useRef(true);
  const lock = useRef(false);
  const projection = useRef<BeamShare | null>(null);
  projection.current = share;
  const [, setClock] = useState(0);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  useEffect(() => { const clock = window.setInterval(() => setClock(n => n + 1), 1000); return () => window.clearInterval(clock); }, []);
  useEffect(() => {
    let current = true;
    const poll = window.setInterval(() => {
      if (lock.current || !projection.current) return;
      void beamApi.share(orgId, shareId).then(result => {
        if (!current || lock.current || !projection.current) return;
        const saved = projection.current;
        if (!result.ok) {
          setShare({ ...saved, can_open: false }); setUncertain(true);
          setError(`${result.error} Current share access could not be checked. Refresh before another change; your edits are still shown.`);
        } else if (result.data.version < saved.version) {
          // A read begun before a successful mutation may finish afterwards.
          // Keep the newer saved result rather than restoring an older projection.
          return;
        } else if (result.data.version > saved.version) {
          setShare({ ...result.data, version: saved.version, can_open: false }); setUncertain(true);
          setError("This share changed on the server. Refresh before another change; your edits are still shown.");
        } else { clock.synchronize(result.server_time); setShare(result.data); }
      });
    }, 5000);
    return () => { current = false; window.clearInterval(poll); };
  }, [orgId, shareId, reload]);
  useEffect(() => { let current = true; setShare(null); setAudience(null); setError(""); setNotice(""); setUncertain(false); void beamApi.share(orgId, shareId).then(async result => {
    if (!current) return;
    if (!result.ok) { setError(result.error); return; }
    clock.synchronize(result.server_time); setGrantImpact(null); setGrantConfirmation(false); setShare(result.data); setGrants(result.data.grants ?? []); setExpires("");
    if (result.data.can_manage) { const subjects = await beamApi.audience(orgId); if (!current) return; if (subjects.ok) setAudience(subjects.data); else setError(`Share loaded. Reviewer choices could not be loaded: ${subjects.error}`); }
  }); return () => { current = false; }; }, [orgId, shareId, reload]);
  async function mutate(operation: () => ReturnType<typeof beamApi.share>, success: string) {
    if (!share || lock.current || uncertain) return; lock.current = true; setBusy(true); setError(""); setNotice("");
    try { const result = await operation(); if (!alive.current) return; if (!result.ok) { setGrantImpact(null); setConfirmStop(false); setError(`${result.error} Refresh the share before another change. Your edits are still shown.`); setUncertain(true); } else { clock.synchronize(result.server_time); setGrantImpact(null); setGrantConfirmation(false); setShare(result.data); setGrants(result.data.grants ?? []); setNotice(success); setConfirmStop(false); } }
    finally { lock.current = false; if (alive.current) setBusy(false); }
  }
  async function reviewGrants(opener: HTMLElement) {
    if (!share || busy || uncertain || lock.current) return;
    grantOpener.current = opener; lock.current = true; setBusy(true); setError("");
    try { const result = await beamApi.grantsImpact(orgId, share, grants); if (!alive.current) return;
      if (!result.ok) { if (result.code === "beam_version_conflict") setUncertain(true); setError(`${result.error} Reviewer access was not changed.${result.code === "beam_version_conflict" ? " Refresh before another change; your edits are still shown." : ""}`); return; }
      if (result.data.share_version !== share.version) { setUncertain(true); setError("This share changed. Refresh before saving reviewer access; your edits are still shown."); return; }
      setGrantConfirmation(false); setGrantImpact(result.data);
    } finally { lock.current = false; if (alive.current) setBusy(false); }
  }
  const terminal = share ? beamIsTerminal(share, clock.now()) : false;
  const manage = Boolean(share?.can_manage && !terminal);
  const disabled = busy || uncertain || !manage;
  return <section className="beam-detail space-y-4" aria-label="Share management">
    <div className="beam-detail-toolbar"><nav aria-label="Breadcrumb" className="beam-breadcrumb"><Link to="/beam/my-shares">My shares</Link><span aria-hidden> / </span><span>{share?.name ?? "Share"}</span></nav><RefreshButton label="Refresh share" type="button" disabled={busy} onClick={() => setReload(n => n + 1)} /></div>
    <ErrorText>{error}</ErrorText>{notice && <p role="status">{notice}</p>}
    {!share ? !error && <Loading label="Loading share…" /> : <div className="beam-detail-grid">
      <section className="beam-detail-main space-y-5"><PageHeader title={share.name} actions={<Status share={share} uncertain={uncertain} now={clock.now()} />} />
        <ResourceSummary title="Share settings" headingLevel={2} footer={<div className="beam-actions"><OpenShare share={share} now={clock.now()} /><BeamShareMobile share={share} now={clock.now()} /><Button variant="ghost" onClick={() => { void navigator.clipboard.writeText(share.url).then(() => { if (alive.current) setNotice("Link copied. Reviewers still need current access and sign-in."); }).catch(() => { if (alive.current) setError("Could not copy. Select and copy the link above."); }); }}>Copy link</Button></div>}>
          <dl className="beam-facts tnx-resource-facts"><div className="tnx-resource-fact-wide"><dt>Browser link</dt><dd className="beam-url">{share.url}</dd></div><div><dt>Created</dt><dd>{new Date(share.created_at).toLocaleString()}</dd></div><div><dt>Expires</dt><dd>{new Date(share.expires_at).toLocaleString()}<span className="block text-xs">{beamCountdown(share.expires_at, clock.now())}</span></dd></div>{share.can_manage && <div className="tnx-resource-fact-wide"><dt>Audience</dt><dd>{share.grants?.length ?? 0} selected {(share.grants?.length ?? 0) === 1 ? "user or group" : "users or groups"}</dd></div>}</dl>
        </ResourceSummary>
        <ResourceSummary title={share.can_manage ? "Manage sharing" : "Sharing status"} headingLevel={2} className="beam-management-summary"><div className="space-y-5">
        {terminal ? <p role="status">This share has ended. Create a new share using the CLI or desktop client to publish again.</p> : share.can_manage ? <>
          <div className="beam-actions">{share.state === "paused" ? <Button disabled={disabled || !policy.enabled || !policy.domain_ready} onClick={() => void mutate(() => beamApi.action(orgId, share, "resume"), "Share resumed. Its original expiry is preserved.")}>Resume share</Button> : <Button disabled={disabled} onClick={() => void mutate(() => beamApi.action(orgId, share, "pause"), "Share paused. Reviewer access is ending.")}>Pause share</Button>}<Button variant="danger" disabled={disabled} onClick={() => setConfirmStop(true)}>Stop share</Button></div>
          {confirmStop && <Modal title="Stop this share" danger onDismiss={() => { if (!busy) setConfirmStop(false); }} actions={<><Button variant="ghost" disabled={busy} onClick={() => setConfirmStop(false)}>Keep sharing</Button><Button variant="danger" disabled={disabled} onClick={() => void mutate(() => beamApi.action(orgId, share, "stop"), "Share stopped permanently.")}>Confirm stop</Button></>}><p>Stop this share permanently? This link cannot be resumed and open reviewer access will end.</p></Modal>}
          <form className="beam-expiry-form space-y-3" onSubmit={event => { event.preventDefault(); if (expires && Number.isFinite(Date.parse(expires)) && Date.parse(expires) > Date.parse(share.expires_at)) void mutate(() => beamApi.action(orgId, share, "extend", new Date(expires).toISOString()), "Share expiry updated."); }}><Field label="New expiry"><Input type="datetime-local" disabled={disabled} value={expires} min={localDateTime(new Date(Date.parse(share.expires_at) + 60000))} max={localDateTime(new Date(Date.parse(share.created_at) + policy.max_duration_seconds * 1000))} onChange={event => setExpires(event.target.value)} required /></Field><p className="text-xs text-ink-secondary">Maximum lifetime is {policy.max_duration_seconds / 3600} hours from creation. Reconnecting never extends it.</p><Button disabled={disabled || !policy.enabled || !policy.domain_ready || !expires || !Number.isFinite(Date.parse(expires))}>Extend expiry</Button></form>
        </> : <p>You do not have permission to manage this share.</p>}
        {share.can_manage && <BeamCompatibilityHelp share={share} />}
        </div></ResourceSummary>
      </section>
      {share.can_manage && <ResourceSummary title="Reviewers" headingLevel={2} className="beam-reviewers"><div className="space-y-4"><p className="text-sm text-ink-secondary">Only the people and groups permitted by your organization can receive access. Removing the last matching grant ends that reviewer's access.</p>{!audience ? <p>Reviewer choices are unavailable. Refresh to retry.</p> : <><AudiencePicker audience={audience} grants={grants} onChange={setGrants} disabled={disabled} /><Button disabled={disabled} onClick={event => void reviewGrants(event.currentTarget)}>Review reviewer access</Button></>}</div></ResourceSummary>}
    </div>}
    {share && <BeamFeedback key={share.id} orgId={orgId} share={share} uncertain={uncertain} />}
    {share?.can_manage && <details className="beam-disclosure"><summary>Diagnostics &amp; event history</summary><div className="beam-support"><BeamDiagnostics orgId={orgId} shareId={share.id} revision={`${share.authority_version}:${share.state}:${share.connectivity}`} /><BeamEvents orgId={orgId} shareId={share.id} revision={`${share.authority_version}:${share.state}`} permitted /></div></details>}
    {share && grantImpact && <Modal returnFocusTo={grantOpener.current} title="Review reviewer access" onDismiss={() => { if (!busy) setGrantImpact(null); }} actions={<><Button variant="ghost" disabled={busy} onClick={() => setGrantImpact(null)}>Keep editing reviewers</Button><Button disabled={disabled || (grantImpact.requires_confirmation && !grantConfirmation)} onClick={() => void mutate(() => beamApi.grants(orgId, share, grants, grantConfirmation), "Reviewer access saved.")}>Confirm reviewer access</Button></>}>
      <p>{grantImpact.removed_grant_count} grants removed; {grantImpact.affected_reviewer_count} reviewers lose their last matching grant; {grantImpact.affected_reviewer_session_count} current reviewer sessions affected.</p><p className="text-sm text-ink-secondary">Counts reflect the checked share version. The server checks current authority again when saving.</p>{grantImpact.requires_confirmation && <label className="flex items-center gap-3"><input type="checkbox" checked={grantConfirmation} disabled={busy} onChange={event => setGrantConfirmation(event.target.checked)} /><span>Confirm removal of these reviewer grants</span></label>}
    </Modal>}
  </section>;
}
export function BeamLaunch() {
  return <div className="beam-workspace beam-review-launch space-y-6"><Logo size={42} wordmarkOnly /><BeamLaunchContent /></div>;
}
function BeamLaunchContent() {
  const [params] = useSearchParams(); const { org } = useOrg(); const { state } = useAuth();
  const requestedOrg = params.get("orgId") ?? ""; const id = params.get("shareId") ?? ""; const nonce = params.get("nonce_hash") ?? ""; const target = params.get("target") ?? "/";
  const valid = /^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(requestedOrg) && /^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(id) && /^[a-f0-9]{64}$/.test(nonce) && target.startsWith("/") && !target.startsWith("//") && !/[\\\r\n\u0000#]/.test(target) && target.length <= 2048;
  if (!valid) return <Card><ErrorText>This sharing link is invalid. Reopen the original shared URL.</ErrorText></Card>;
  if (!org || state.status !== "authed") return <Loading label="Checking reviewer sign-in…" />;
  if (org.id !== requestedOrg) return <Card><ErrorText>This link belongs to a different organization. Switch to its organization, then reopen the shared URL.</ErrorText><Link className="text-brand" to="/dashboard">Return to your organization</Link></Card>;
  return <ReviewerLaunch key={`${org.id}:${state.user.id}:${id}:${nonce}`} orgId={org.id} id={id} nonce={nonce} target={target} />;
}
function ReviewerLaunch({ orgId, id, nonce, target }: { orgId: string; id: string; nonce: string; target: string }) {
  const clock = useBeamClock();
  const [, tick] = useState(0);
  useEffect(() => { const timer = window.setInterval(() => tick(n => n + 1), 1000); return () => window.clearInterval(timer); }, []);
  const [share, setShare] = useState<BeamShare | null>(null); const [error, setError] = useState(""); const [busy, setBusy] = useState(false); const [mfa, setMfa] = useState(false); const [code, setCode] = useState(""); const [consumed, setConsumed] = useState(false); const [expired, setExpired] = useState(false); const [reload, setReload] = useState(0); const alive = useRef(true); const locked = useRef(false);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  useEffect(() => { let current = true; setShare(null); setError(""); void beamApi.share(orgId, id).then(result => { if (current) { if (result.ok) { clock.synchronize(result.server_time); setShare(result.data); } else setError(result.error); } }); return () => { current = false; }; }, [orgId, id, reload]);
  async function launch() {
    if (!share || !beamCanOpen(share, clock.now()) || consumed || locked.current) return; locked.current = true; setBusy(true); setError("");
    try { const result = await beamApi.launch(orgId, id, nonce, target); if (!alive.current) return; if (!result.ok) { if (["beam_mfa_required", "mfa_required", "mfa_step_up_required"].includes(result.code ?? "")) setMfa(true); else { setConsumed(true); setExpired(result.code === "beam_launch_expired"); setError(result.code === "beam_launch_expired" ? result.error : `${result.error} Reopen the original shared URL to try again.`); } return; } const url = beamHandoffURL(result.data.redirect_url, share.hostname); setConsumed(true); if (!url) { setError("The server returned an invalid sharing destination. Reopen the original shared URL."); return; } window.location.replace(url); }
    finally { locked.current = false; if (alive.current) setBusy(false); }
  }
  const freshURL = share && beamCanOpen(share, clock.now()) ? beamLaunchURL(`https://${share.hostname}/_beam/start?target=${encodeURIComponent(target)}`, share.hostname) : null;
  async function verify(event: React.FormEvent) { event.preventDefault(); if (locked.current || !code.trim()) return; locked.current = true; setBusy(true); setError(""); try { const result = await api.POST("/api/v1/auth/mfa/step-up", { body: { code: code.trim() } }); if (!alive.current) return; setCode(""); if (result.error || !result.data) setError(apiErrorMessage(result.error, "Could not verify MFA.")); else { setMfa(false); locked.current = false; setBusy(false); await launch(); } } catch { if (alive.current) setError("Could not confirm MFA. Try a fresh code."); } finally { locked.current = false; if (alive.current) setBusy(false); } }
  return <div className="space-y-4"><PageHeader title="Open shared app" /><Link className="text-brand text-sm" to={`/beam/shares/${encodeURIComponent(id)}`}>Review feedback</Link><Card className="space-y-4"><ErrorText>{error}</ErrorText>{!share ? error ? <Button onClick={() => setReload(n => n + 1)}>Retry share</Button> : <Loading label="Checking share access…" /> : <><h2 className="font-semibold">{share.name}</h2><p className="beam-url">{share.hostname}</p><Status share={share} now={clock.now()} /><p className="text-sm">Your current sign-in and reviewer grant are checked before app access begins.</p>{mfa ? <form onSubmit={event => void verify(event)} className="space-y-3"><Field label="Authenticator or recovery code"><Input required autoComplete="one-time-code" value={code} disabled={busy} onChange={event => setCode(event.target.value)} /></Field><Button disabled={busy || !code.trim()}>Verify MFA</Button><Link className="text-brand" to="/settings?section=authentication">Set up account MFA</Link></form> : <Button disabled={busy || consumed || !beamCanOpen(share, clock.now())} onClick={() => void launch()}>{busy ? "Opening…" : `Continue to ${share.name}`}</Button>}{expired && freshURL && <a className="text-brand block w-fit py-2" href={freshURL} referrerPolicy="no-referrer">Open fresh link</a>}</>}</Card></div>;
}
