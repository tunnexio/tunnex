import "../beam-workspace.css";
import { useEffect, useRef, useState } from "react";
import { Link, Navigate, useLocation, useParams, useSearchParams } from "react-router-dom";
import { Button, Card, EmptyState, ErrorText, Field, Input, Loading, Modal, PageHeader } from "../components/ui";
import { Logo } from "../brand";
import { AudiencePicker } from "../components/BeamAudiencePicker";
import { BeamCliPublisher } from "../components/BeamCliPublisher";
import { BeamRooms } from "../components/BeamRooms";
import { BeamFeedback, BeamNotifications } from "../components/BeamFeedback";
import { BeamShareMobile } from "../components/BeamShareMobile";
import { BeamDiagnostics } from "../components/BeamDiagnostics";
import { BeamEvents } from "../components/BeamEvents";
import { BeamCompatibilityHelp } from "../components/BeamCompatibilityHelp";
import { beamRoomsApi } from "../lib/beam-rooms";
import { useBeamClock, beamCountdown } from "../lib/beam-clock";
import { useAuth } from "../lib/auth";
import { useOrg } from "../lib/useOrg";
import { api, apiErrorMessage } from "../lib/api";
import { beamApi, beamHandoffURL, beamCanOpen, beamIsTerminal, beamLaunchURL, beamStatus, type BeamAudience, type BeamGrantsImpact, type BeamShareFilters, type BeamGrant, type BeamPage, type BeamPolicy, type BeamShare } from "../lib/beam";

export default function Beam() {
  const { org, failed } = useOrg();
  const { state } = useAuth();
  const location = useLocation();
  const { shareId } = useParams();
  if (failed) return <Card><ErrorText>Could not load your organization.</ErrorText></Card>;
  if (!org || state.status !== "authed") return <Card><Loading label="Loading Beam…" /></Card>;
  return <BeamWorkspace key={`${org.id}:${state.user.id}:${location.pathname}`} orgId={org.id} shareId={shareId} />;
}
function BeamWorkspace({ orgId, shareId }: { orgId: string; shareId?: string }) {
  const location = useLocation();
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
    if (ownedHistory === "failed") return <Card><ErrorText>Could not check your share history.</ErrorText><Button onClick={() => setReload(n => n + 1)}>Retry Beam</Button></Card>;
  }
  const shared = location.pathname === "/beam/shared-with-me";
  const events = location.pathname === "/beam/events";
  return <div className="beam-workspace space-y-5">
    <PageHeader title="Tunnex Beam" subtitle="Share a local web app through a secure link" actions={policy?.can_manage_policy ? <Link className="text-brand" to="/settings?section=beam">Sharing policy</Link> : undefined} />
    <nav aria-label="Beam workspaces" className="workspace-tabs">
      {policy && (policy.can_publish || policy.can_manage_policy || ownedHistory === "present") && <Link aria-current={!shared && !events ? "page" : undefined} to="/beam/my-shares">My shares</Link>}
      {policy && (!policy.can_publish || policy.open_for_all_users || policy.can_manage_policy) && <Link aria-current={shared ? "page" : undefined} to="/beam/shared-with-me">Shared with me</Link>}
      {policy?.can_manage_policy && <Link aria-current={events ? "page" : undefined} to="/beam/events">Events</Link>}
    </nav>
    {policy && !shareId && !events && <BeamNotifications orgId={orgId} />}
    {error ? <Card><ErrorText>{error}</ErrorText><Button onClick={() => setReload(n => n + 1)}>Retry Beam</Button></Card> : !policy ? <Card><Loading label="Checking Beam availability…" /></Card> : <>
      {(!policy.enabled || !policy.domain_ready) && <Card><p role="status">{!policy.enabled ? "Beam is off for this organization. An organization administrator can enable sharing." : "Beam serving setup is incomplete. An installation operator must configure its domain and HTTPS proxy."}</p>{policy.can_manage_policy && <Link className="text-brand" to="/settings?section=beam">Review sharing policy</Link>}</Card>}
      {shareId ? <ShareDetail orgId={orgId} shareId={shareId} policy={policy} /> : events ? <BeamEvents orgId={orgId} permitted={policy.can_manage_policy} /> : <ShareInventory orgId={orgId} shared={shared} policy={policy} />}
    </>}
  </div>;
}
function localDateTime(date: Date) { return new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0,16); }
function Status({ share, uncertain = false, now }: { share: BeamShare; uncertain?: boolean; now?: number }) { const label = uncertain ? "Refresh required" : beamStatus(share, now); return <span className={`beam-status ${label === "Live" ? "beam-status-live" : ""}`}>{label}</span>; }
function OpenShare({ share, now }: { share: BeamShare; now?: number }) {
  const url = beamLaunchURL(share.url, share.hostname);
  return beamCanOpen(share, now) && url ? <a className="text-brand text-sm font-medium" href={url} target="_blank" rel="noopener noreferrer">Open {share.name}</a> : <span className="text-sm text-ink-secondary">{!share.can_open ? "Access is not currently granted" : beamStatus(share, now)}</span>;
}
function ShareInventory({ orgId, shared, policy }: { orgId: string; shared: boolean; policy: BeamPolicy }) {
  const [workspace, setWorkspace] = useState<"projects" | "active" | "history">("active");
  const [page, setPage] = useState(0);
  const [query, setQuery] = useState("");
  const [search, setSearch] = useState("");
  const [health, setHealth] = useState<BeamShareFilters>({});
  const [healthDraft, setHealthDraft] = useState<BeamShareFilters>({});
  const clock = useBeamClock();
  const [data, setData] = useState<BeamPage<BeamShare> | null>(null);
  const [error, setError] = useState("");
  const [reload, setReload] = useState(0);
  const [, setClock] = useState(0);
  useEffect(() => { if (!shared && workspace === "projects") return; let current = true; setData(null); setError(""); void beamApi.shares(orgId, shared, page * 20, search || undefined, shared ? health : { ...health, scope: workspace === "history" ? "history" : "active" }).then(result => { if (!current) return; if (result.ok) { clock.synchronize(result.data.server_time ?? result.server_time); setData(result.data); } else setError(result.error); }); return () => { current = false; }; }, [orgId, shared, page, reload, search, health, workspace]);
  useEffect(() => { const timer = window.setInterval(() => setClock(n => n + 1), 1000); const poll = window.setInterval(() => setReload(n => n + 1), 30000); const focus = () => setReload(n => n + 1); window.addEventListener("focus", focus); return () => { window.clearInterval(timer); window.clearInterval(poll); window.removeEventListener("focus", focus); }; }, []);
  const visibleShares = data?.items.filter(share => shared ? (["active", "paused"].includes(share.state) && !beamIsTerminal(share, clock.now())) : workspace === "history" ? beamIsTerminal(share, clock.now()) : !beamIsTerminal(share, clock.now())) ?? [];
  return <section aria-label={shared ? "Shared with me" : "My shares"} className="space-y-4">
    {!shared && <div className="beam-intro"><div className="space-y-2"><h2 className="font-semibold">Your local apps, ready for review</h2><p className="text-sm text-ink-secondary">Publish from the Tunnex CLI or desktop client, then manage the link and reviewers here. Keep your local app and its publishing process running while reviewers use their browser.</p>{!policy.can_publish && <p className="text-sm">Your current account is not permitted to publish. An administrator can add your group to the sharing policy.</p>}</div><div className="beam-actions">{policy.can_publish && <BeamCliPublisher orgId={orgId} policy={policy} />}<Link className="text-brand text-sm" to="/connect">Get the desktop client</Link></div></div>}
    {!shared && <div role="group" aria-label="My share views" className="beam-actions">{([ ["projects", "Saved projects"], ["active", "Active"], ["history", "History"] ] as const).map(([value, label]) => <Button key={value} variant={workspace === value ? "primary" : "ghost"} aria-pressed={workspace === value} onClick={() => { setWorkspace(value); setPage(0); setHealth({}); setHealthDraft({}); setQuery(""); setSearch(""); }}>{label}</Button>)}</div>}
    {!shared && workspace === "projects" ? <BeamRooms orgId={orgId} policy={policy} /> : <>
    <div className="flex flex-wrap justify-between gap-3"><p className="text-sm text-ink-secondary">{shared ? "Active and paused apps shared with your account. Access is checked again when you open a link." : workspace === "history" ? "Ended sessions stay in History. Publish a saved project to start a new preview." : "Active and paused previews. Pausing and reconnecting keep the same link and expiry."}</p><Button variant="ghost" onClick={() => setReload(n => n + 1)}>Refresh shares</Button></div>
    <form className="flex flex-wrap items-end gap-3" onSubmit={event => { event.preventDefault(); setPage(0); setSearch(query.trim()); setHealth(healthDraft); }}><Field label="Search shares"><Input type="search" maxLength={200} placeholder="App name or hostname" value={query} onChange={event => setQuery(event.target.value)} /></Field>{!shared && <Field label="Share state"><select className="rounded border border-line bg-surface p-2" value={healthDraft.state ?? ""} onChange={event => setHealthDraft(d => ({ ...d, state: (event.target.value || undefined) as BeamShareFilters["state"] }))}><option value="">All states</option>{(workspace === "history" ? ["stopped", "expired", "revoked"] : ["starting", "active", "paused"]).map(state => <option key={state} value={state}>{state}</option>)}</select></Field>}<Field label="Share connectivity"><select className="rounded border border-line bg-surface p-2" value={healthDraft.connectivity ?? ""} onChange={event => setHealthDraft(d => ({ ...d, connectivity: (event.target.value || undefined) as BeamShareFilters["connectivity"] }))}><option value="">All connectivity</option><option value="online">Online</option><option value="offline">Offline or reconnecting</option><option value="origin_unavailable">Local app unavailable</option></select></Field><Button type="submit">Search shares</Button>{(search || health.state || health.connectivity) && <Button type="button" variant="ghost" onClick={() => { setQuery(""); setSearch(""); setHealth({}); setHealthDraft({}); setPage(0); }}>Clear share search</Button>}</form>
    {!shared && <BeamCompatibilityHelp />}
    {!shared && data?.quota && <p role="status" className="text-sm">{data.quota.active_shares} of {data.quota.max_shares} share slots in use. Paused and starting shares use a slot until they end or expire; search filters do not change this count.</p>}
    {error ? <Card><ErrorText>{error}</ErrorText><Button onClick={() => setReload(n => n + 1)}>Retry shares</Button></Card> : !data ? <Card><Loading label="Loading shares…" /></Card> : !visibleShares.length ? <Card><EmptyState>{(search || health.state || health.connectivity) ? "No shares match this search." : shared ? "No apps are currently shared with you." : workspace === "history" ? "No ended sessions yet." : "No active shares. Publish a saved project or your first local app using the CLI or desktop client."}</EmptyState></Card> : <div className="beam-share-grid">{visibleShares.map(share => <Card key={share.id} className="beam-share">
      <div className="beam-share-heading"><h2>{share.name}</h2><Status share={share} now={clock.now()} /></div>
      <p className="beam-url text-ink-secondary">{share.hostname}</p>
      <dl className="beam-meta"><div><dt>Expires</dt><dd>{new Date(share.expires_at).toLocaleString()}<span className="block text-xs">{beamCountdown(share.expires_at, clock.now())}</span></dd></div>{!shared && share.grants && <div><dt>Audience</dt><dd>{share.grants.length} selected {share.grants.length === 1 ? "user or group" : "users or groups"}</dd></div>}{shared && <div><dt>Publisher</dt><dd>{share.publisher_name || share.publisher_id.slice(0, 8)}</dd></div>}</dl>
      <div className="beam-actions"><OpenShare share={share} now={clock.now()} /><BeamShareMobile share={share} now={clock.now()} />{shared && <Link className="text-brand text-sm" to={`/beam/shares/${encodeURIComponent(share.id)}`}>Review {share.name}</Link>}{!shared && <Link className="text-brand text-sm" to={`/beam/shares/${encodeURIComponent(share.id)}`}>{workspace === "history" ? "View" : "Manage"} {share.name}</Link>}</div>
    </Card>)}</div>}
    {data && <div className="flex items-center gap-3"><Button variant="ghost" disabled={page === 0} onClick={() => setPage(n => n - 1)}>Previous shares</Button><span className="text-sm">Page {page + 1}</span><Button variant="ghost" disabled={data.items.length < data.limit || page >= 500} onClick={() => setPage(n => n + 1)}>Next shares</Button></div>}
    </>}
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
  return <section className="space-y-4" aria-label="Share management">
    <div className="flex flex-wrap items-center justify-between gap-3"><Link className="text-brand" to="/beam/my-shares">← My shares</Link><Button type="button" variant="ghost" disabled={busy} onClick={() => setReload(n => n + 1)}>Refresh share</Button></div>
    <ErrorText>{error}</ErrorText>{notice && <p role="status">{notice}</p>}
    {!share ? !error && <Loading label="Loading share…" /> : <div className="beam-detail-grid">
      <Card className="space-y-5"><div className="beam-share-heading"><h2>{share.name}</h2><Status share={share} uncertain={uncertain} now={clock.now()} /></div><p className="beam-url">{share.url}</p><dl className="beam-meta"><div><dt>Created</dt><dd>{new Date(share.created_at).toLocaleString()}</dd></div><div><dt>Expires</dt><dd>{new Date(share.expires_at).toLocaleString()}<span className="block text-xs">{beamCountdown(share.expires_at, clock.now())}</span></dd></div>{share.can_manage && <div><dt>Audience</dt><dd>{share.grants?.length ?? 0} selected {(share.grants?.length ?? 0) === 1 ? "user or group" : "users or groups"}</dd></div>}<div><dt>Saved version</dt><dd>{share.version}</dd></div></dl>
        <div className="beam-actions"><OpenShare share={share} now={clock.now()} /><BeamShareMobile share={share} now={clock.now()} /><Button variant="ghost" onClick={() => { void navigator.clipboard.writeText(share.url).then(() => { if (alive.current) setNotice("Link copied. Reviewers still need current access and sign-in."); }).catch(() => { if (alive.current) setError("Could not copy. Select and copy the link above."); }); }}>Copy link</Button></div>
        {terminal ? <p role="status">This share has ended. Create a new share using the CLI or desktop client to publish again.</p> : share.can_manage ? <>
          <div className="beam-actions">{share.state === "paused" ? <Button disabled={disabled || !policy.enabled || !policy.domain_ready} onClick={() => void mutate(() => beamApi.action(orgId, share, "resume"), "Share resumed. Its original expiry is preserved.")}>Resume share</Button> : <Button disabled={disabled} onClick={() => void mutate(() => beamApi.action(orgId, share, "pause"), "Share paused. Reviewer access is ending.")}>Pause share</Button>}<Button variant="danger" disabled={disabled} onClick={() => setConfirmStop(true)}>Stop share</Button></div>
          {confirmStop && <Modal title="Stop this share" danger onDismiss={() => { if (!busy) setConfirmStop(false); }} actions={<><Button variant="ghost" disabled={busy} onClick={() => setConfirmStop(false)}>Keep sharing</Button><Button variant="danger" disabled={disabled} onClick={() => void mutate(() => beamApi.action(orgId, share, "stop"), "Share stopped permanently.")}>Confirm stop</Button></>}><p>Stop this share permanently? This link cannot be resumed and open reviewer access will end.</p></Modal>}
          <form className="space-y-3 border-t border-line pt-4" onSubmit={event => { event.preventDefault(); if (expires && Number.isFinite(Date.parse(expires)) && Date.parse(expires) > Date.parse(share.expires_at)) void mutate(() => beamApi.action(orgId, share, "extend", new Date(expires).toISOString()), "Share expiry updated."); }}><Field label="New expiry"><Input type="datetime-local" disabled={disabled} value={expires} min={localDateTime(new Date(Date.parse(share.expires_at) + 60000))} max={localDateTime(new Date(Date.parse(share.created_at) + policy.max_duration_seconds * 1000))} onChange={event => setExpires(event.target.value)} required /></Field><p className="text-xs text-ink-secondary">Maximum lifetime is {policy.max_duration_seconds / 3600} hours from creation. Reconnecting never extends it.</p><Button disabled={disabled || !policy.enabled || !policy.domain_ready || !expires || !Number.isFinite(Date.parse(expires))}>Extend expiry</Button></form>
        </> : <p>You do not have permission to manage this share.</p>}
        {share.can_manage && <BeamCompatibilityHelp share={share} />}
      </Card>
      {share.can_manage && <Card className="space-y-4"><h2 className="font-semibold">Reviewers</h2><p className="text-sm text-ink-secondary">Only the people and groups permitted by your organization can receive access. Removing the last matching grant ends that reviewer's access.</p>{!audience ? <p>Reviewer choices are unavailable. Refresh to retry.</p> : <><AudiencePicker audience={audience} grants={grants} onChange={setGrants} disabled={disabled} /><Button disabled={disabled} onClick={event => void reviewGrants(event.currentTarget)}>Review reviewer access</Button></>}</Card>}
    </div>}
    {share && <BeamFeedback key={share.id} orgId={orgId} share={share} uncertain={uncertain} />}
    {share?.can_manage && <><BeamDiagnostics orgId={orgId} shareId={share.id} revision={`${share.authority_version}:${share.state}:${share.connectivity}`} /><BeamEvents orgId={orgId} shareId={share.id} revision={`${share.authority_version}:${share.state}`} permitted /></>}
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
  if (!valid) return <Card><ErrorText>This Beam link is invalid. Reopen the original shared URL.</ErrorText></Card>;
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
    try { const result = await beamApi.launch(orgId, id, nonce, target); if (!alive.current) return; if (!result.ok) { if (["beam_mfa_required", "mfa_required", "mfa_step_up_required"].includes(result.code ?? "")) setMfa(true); else { setConsumed(true); setExpired(result.code === "beam_launch_expired"); setError(result.code === "beam_launch_expired" ? result.error : `${result.error} Reopen the original shared URL to try again.`); } return; } const url = beamHandoffURL(result.data.redirect_url, share.hostname); setConsumed(true); if (!url) { setError("The server returned an invalid Beam destination. Reopen the original shared URL."); return; } window.location.replace(url); }
    finally { locked.current = false; if (alive.current) setBusy(false); }
  }
  const freshURL = share && beamCanOpen(share, clock.now()) ? beamLaunchURL(`https://${share.hostname}/_beam/start?target=${encodeURIComponent(target)}`, share.hostname) : null;
  async function verify(event: React.FormEvent) { event.preventDefault(); if (locked.current || !code.trim()) return; locked.current = true; setBusy(true); setError(""); try { const result = await api.POST("/api/v1/auth/mfa/step-up", { body: { code: code.trim() } }); if (!alive.current) return; setCode(""); if (result.error || !result.data) setError(apiErrorMessage(result.error, "Could not verify MFA.")); else { setMfa(false); locked.current = false; setBusy(false); await launch(); } } catch { if (alive.current) setError("Could not confirm MFA. Try a fresh code."); } finally { locked.current = false; if (alive.current) setBusy(false); } }
  return <div className="space-y-4"><PageHeader title="Open Beam app" /><Link className="text-brand text-sm" to={`/beam/shares/${encodeURIComponent(id)}`}>Review feedback</Link><Card className="space-y-4"><ErrorText>{error}</ErrorText>{!share ? error ? <Button onClick={() => setReload(n => n + 1)}>Retry share</Button> : <Loading label="Checking share access…" /> : <><h2 className="font-semibold">{share.name}</h2><p className="beam-url">{share.hostname}</p><Status share={share} now={clock.now()} /><p className="text-sm">Your current sign-in and reviewer grant are checked before app access begins.</p>{mfa ? <form onSubmit={event => void verify(event)} className="space-y-3"><Field label="Authenticator or recovery code"><Input required autoComplete="one-time-code" value={code} disabled={busy} onChange={event => setCode(event.target.value)} /></Field><Button disabled={busy || !code.trim()}>Verify MFA</Button><Link className="text-brand" to="/settings?section=authentication">Set up account MFA</Link></form> : <Button disabled={busy || consumed || !beamCanOpen(share, clock.now())} onClick={() => void launch()}>{busy ? "Opening…" : `Continue to ${share.name}`}</Button>}{expired && freshURL && <a className="text-brand block w-fit py-2" href={freshURL} referrerPolicy="no-referrer">Open fresh link</a>}</>}</Card></div>;
}
