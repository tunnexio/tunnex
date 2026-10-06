import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import type { components } from "@tunnex/shared";
import { api, apiErrorCode, apiErrorMessage, loadOne } from "../lib/api";
import { EntityPicker, type PickerOption } from "./EntityPicker";
import { AppAccessIcon } from "./AppAccessIcon";
import { Badge, Button, DataTable, ErrorText, Field, Input, Loading, Modal } from "./ui";

type Application = components["schemas"]["AppAccessApplication"];
type Publication = components["schemas"]["AppAccessPublicationState"];
type Action = "disable" | "delete";
type Review = { app: Application; publication?: Publication; error?: string };
type Outcome = { id: string; name: string; ok: boolean; message: string };

function deleteReason(app: Application, publication?: Publication) {
  if (app.publication_state !== "disabled") return "Disable the application before deleting it.";
  if (!publication) return "Waiting for current server withdrawal status.";
  if (publication.application_version !== app.version) return "Application changed. Refresh applications before continuing.";
  if (publication.active?.state !== "disabled") return "The server has not confirmed that the application is disabled.";
  if (!publication.active.withdrawal_confirmed) return "Waiting for server confirmation that routing and live streams have been withdrawn.";
  if (publication.pending_operation?.status === "queued" || publication.pending_operation?.status === "checking") return "A publication is pending. Disable it before deleting.";
  return null;
}
function failure(error: unknown) {
  return ["version_conflict", "stale_version"].includes(apiErrorCode(error) ?? "")
    ? "Application changed. Refresh applications and review its current state before trying again."
    : apiErrorMessage(error, "The outcome could not be confirmed. Refresh applications before trying again.");
}
function SelectedApplications({ applications }: { applications: Application[] }) {
  return <div className="space-y-2"><p className="font-medium">{applications.length} application{applications.length === 1 ? "" : "s"} selected</p><ul className="list-disc space-y-1 pl-5">{applications.map(app => <li key={app.id}>{app.draft.name}<span className="block text-xs text-ink-secondary">{app.draft.public_hostname}</span></li>)}</ul></div>;
}
function Outcomes({ outcomes }: { outcomes: Outcome[] }) {
  const succeeded = outcomes.filter(outcome => outcome.ok).length;
  return <div role="status" className="space-y-3"><p>{succeeded} succeeded · {outcomes.length - succeeded} not confirmed</p><ul className="space-y-2">{outcomes.map(outcome => <li key={outcome.id}><span className="font-medium">{outcome.name}: </span><span className={outcome.ok ? "" : "text-danger"}>{outcome.message}</span></li>)}</ul><p className="text-sm text-ink-secondary">Close to refresh applications before another action.</p></div>;
}

export default function AppAccessInventoryTable({ orgId, applications, manage, grant, canGrant, empty, onChanged }: {
  orgId: string; applications: Application[]; manage: boolean; grant: boolean; canGrant: boolean; empty: React.ReactNode; onChanged: () => void;
}) {
  const [publications, setPublications] = useState<Record<string, Publication>>({});
  const [readErrors, setReadErrors] = useState<Record<string, string>>({});
  const [dialog, setDialog] = useState<{ action: Action | "grant"; applications: Application[] } | null>(null);
  useEffect(() => {
    let cancelled = false;
    if (manage) void Promise.all(applications.filter(app => app.publication_state === "disabled").map(async app => {
      const result = await loadOne(() => api.GET("/api/v1/organizations/{orgId}/app-access/applications/{appId}/publication", { params: { path: { orgId, appId: app.id } } }));
      if (cancelled) return;
      if (result.ok) setPublications(current => ({ ...current, [app.id]: result.data }));
      else setReadErrors(current => ({ ...current, [app.id]: result.error }));
    }));
    return () => { cancelled = true; };
  }, [orgId, applications, manage]);
  const unavailableDelete = (app: Application) => readErrors[app.id] ? "Could not read withdrawal status. Refresh applications." : deleteReason(app, publications[app.id]);
  return <>
    <DataTable caption="Applications" failed={false} filterable={false} pageSize={0} rows={applications} rowKey={app => app.id} rowLabel={app => app.draft.name} empty={empty} rowActions={[
      ...(grant ? [{ key: "grant", label: "Grant access", unavailable: () => canGrant ? null : "Grants require an eligible license, Applications enabled and a configured domain.", run: (apps: Application[]) => setDialog({ action: "grant", applications: apps }) }] : []),
      ...(manage ? [
        { key: "disable", label: "Disable", run: (apps: Application[]) => setDialog({ action: "disable", applications: apps }) },
        { key: "delete", label: "Delete", danger: true, unavailable: unavailableDelete, run: (apps: Application[]) => setDialog({ action: "delete", applications: apps }) },
      ] : []),
    ]} columns={[
      { key: "application", header: "Application", cell: app => <div className="app-access-application-name"><span className="app-access-icon"><AppAccessIcon icon={app.draft.icon} image={app.draft.icon_data_url} size={18} /></span><div><Link to={`/app-access/applications/${app.id}`}>{app.draft.name}</Link><p>{app.draft.public_hostname}</p></div></div> },
      { key: "publication", header: "Publication", cell: app => <div className="space-y-1"><Badge tone={app.publication_state === "disabled" ? "warn" : "neutral"}>{app.publication_state === "published" ? `Published · Active revision ${app.active_revision}` : app.publication_state === "disabled" ? "Disabled · New browser access is denied" : "Draft · Browser traffic is not published"}</Badge>{manage && app.publication_state === "disabled" && <p className="text-xs text-ink-secondary">{unavailableDelete(app) ?? "Withdrawal confirmed · Ready to delete"}</p>}</div> },
      ...(manage || grant ? [{ key: "actions", header: "Actions", cell: (app: Application) => <div role="group" aria-label={`Actions for ${app.draft.name}`} className="flex flex-wrap gap-1">
        {grant && <Button size="sm" variant="ghost" disabled={!canGrant} onClick={() => setDialog({ action: "grant", applications: [app] })}>Grant access</Button>}
        {manage && <><Button size="sm" variant="ghost" onClick={() => setDialog({ action: "disable", applications: [app] })}>Disable</Button><Button size="sm" variant="ghost" disabled={!!unavailableDelete(app)} title={unavailableDelete(app) ?? undefined} onClick={() => setDialog({ action: "delete", applications: [app] })}>Delete</Button></>}
      </div> }] : []),
    ]} />
    {dialog?.action === "grant" && grant && <InventoryGrantDialog orgId={orgId} applications={dialog.applications} onClose={changed => { setDialog(null); if (changed) onChanged(); }} />}
    {dialog && dialog.action !== "grant" && manage && <InventoryActionDialog orgId={orgId} applications={dialog.applications} action={dialog.action} onClose={changed => { setDialog(null); if (changed) onChanged(); }} />}
  </>;
}

function InventoryActionDialog({ orgId, applications, action, onClose }: { orgId: string; applications: Application[]; action: Action; onClose: (changed: boolean) => void }) {
  const [reviews, setReviews] = useState<Review[] | null>(null);
  const [outcomes, setOutcomes] = useState<Outcome[] | null>(null);
  const [busy, setBusy] = useState(false);
  const alive = useRef(true);
  const inFlight = useRef(false);
  useEffect(() => {
    alive.current = true;
    void Promise.all(applications.map(async app => {
      const result = await loadOne(() => api.GET("/api/v1/organizations/{orgId}/app-access/applications/{appId}/publication", { params: { path: { orgId, appId: app.id } } }));
      if (!result.ok) return { app, error: result.error };
      const error = result.data.application_version !== app.version ? "Application changed. Close and refresh applications before confirming." : action === "delete" ? deleteReason(app, result.data) : null;
      return { app, publication: result.data, ...(error ? { error } : {}) };
    })).then(next => { if (alive.current) setReviews(next); });
    return () => { alive.current = false; };
  }, [orgId, applications, action]);
  async function apply() {
    if (!reviews || reviews.some(review => review.error) || inFlight.current || outcomes) return;
    inFlight.current = true; setBusy(true);
    const results: Outcome[] = [];
    // Bound the burst and stop starting more mutations if the user leaves this scope.
    for (const { app, publication } of reviews) {
      if (!alive.current) break;
      try {
        if (action === "disable") {
          const result = await api.POST("/api/v1/organizations/{orgId}/app-access/applications/{appId}/publication/disable", { params: { path: { orgId, appId: app.id } }, body: { expected_application_version: publication!.application_version, expected_authority_version: publication!.active?.authority_version ?? 0 } });
          results.push({ id: app.id, name: app.draft.name, ok: !result.error && !!result.data, message: result.error || !result.data ? failure(result.error) : result.data.active?.withdrawal_confirmed ? "Disabled. Routing and live stream withdrawal confirmed." : "Disabled. Waiting for server withdrawal confirmation before deletion." });
        } else {
          const result = await api.DELETE("/api/v1/organizations/{orgId}/app-access/applications/{appId}", { params: { path: { orgId, appId: app.id }, query: { expected_version: publication!.application_version } } });
          results.push({ id: app.id, name: app.draft.name, ok: !result.error, message: result.error ? failure(result.error) : "Removed from inventory. History and hostname reservation retained." });
        }
      } catch {
        results.push({ id: app.id, name: app.draft.name, ok: false, message: "Connection interrupted; outcome unknown. Refresh applications before trying again." });
      }
    }
    if (alive.current) { setOutcomes(results); setBusy(false); }
  }
  const blocked = !reviews || reviews.some(review => review.error);
  return <Modal title={action === "disable" ? "Disable applications" : "Delete applications"} danger onDismiss={() => { if (!inFlight.current || outcomes) onClose(!!outcomes || !!reviews?.some(review => review.error)); }} actions={<>
    <Button variant="ghost" disabled={busy} onClick={() => onClose(!!outcomes || !!reviews?.some(review => review.error))}>{outcomes ? "Close and refresh" : reviews?.some(review => review.error) ? "Close and refresh" : "Cancel"}</Button>
    {!outcomes && <Button variant="danger" disabled={busy || blocked} onClick={() => void apply()}>{busy ? "Applying changes…" : action === "disable" ? "Confirm disable" : "Confirm delete"}</Button>}
  </>}>
    <div className="space-y-4"><SelectedApplications applications={applications} />
      <p>Are you sure you want to {action} {applications.length === 1 ? "this application" : `these ${applications.length} applications`}?</p>
      <p>{action === "disable" ? "New access will be denied immediately, including for members with existing grants. Live connections may take a few seconds to close. Already delivered content cannot be removed. Existing grants are retained." : "These disabled applications will be removed from the inventory. Their history and hostname reservations are retained. This does not permanently erase their records."}</p>
      {outcomes ? <Outcomes outcomes={outcomes} /> : !reviews ? <Loading label="Checking current publication status…" /> : reviews.map(review => review.error && <ErrorText key={review.app.id}>{review.app.draft.name}: {review.error}</ErrorText>)}
    </div>
  </Modal>;
}

function InventoryGrantDialog({ orgId, applications, onClose }: { orgId: string; applications: Application[]; onClose: (changed: boolean) => void }) {
  const [options, setOptions] = useState<PickerOption[] | null>(null);
  const [subject, setSubject] = useState<PickerOption | null>(null);
  const [starts, setStarts] = useState("");
  const [expires, setExpires] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [outcomes, setOutcomes] = useState<Outcome[] | null>(null);
  const alive = useRef(true);
  const inFlight = useRef(false);
  useEffect(() => {
    alive.current = true;
    void Promise.all([
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/app-access/settings", { params: { path: { orgId } } })),
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/members", { params: { path: { orgId } } })),
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/groups", { params: { path: { orgId } } })),
    ]).then(([settings, members, groups]) => {
      if (!alive.current) return;
      if (!settings.ok || !members.ok || !groups.ok) { setError(!settings.ok ? settings.error : !members.ok ? members.error : !groups.ok ? groups.error : "Could not load grant subjects."); return; }
      if (!settings.data.entitlement_available || !settings.data.enabled || !settings.data.domain_ready) { setError("Grants require an eligible license, Applications enabled and a configured domain. Close and refresh applications."); return; }
      setOptions([
        ...members.data.filter(member => member.status === "active").map(member => ({ value: `user:${member.user_id}`, kind: "user", tag: "USER", label: member.name || member.email, detail: member.email, section: "People" })),
        ...groups.data.map(group => ({ value: `group:${group.id}`, kind: "group", tag: "GROUP", label: group.name, detail: `${group.member_count} members`, section: "Groups" })),
      ]);
    });
    return () => { alive.current = false; };
  }, [orgId]);
  async function save(event: React.FormEvent) {
    event.preventDefault();
    if (inFlight.current || !options || !subject || outcomes) return;
    let startsAt: string | null; let expiresAt: string | null;
    try { startsAt = starts ? new Date(starts).toISOString() : null; expiresAt = expires ? new Date(expires).toISOString() : null; } catch { setError("Enter a valid start and expiry date."); return; }
    if (startsAt && expiresAt && startsAt >= expiresAt) { setError("Expiry must be after the start time."); return; }
    inFlight.current = true; setBusy(true); setError("");
    const results: Outcome[] = [];
    for (const app of applications) {
      if (!alive.current) break;
      try {
        const result = await api.POST("/api/v1/organizations/{orgId}/app-access/grants", { params: { path: { orgId } }, body: { app_id: app.id, subject_kind: subject.kind as "user" | "group", subject_id: subject.value.slice(subject.value.indexOf(":") + 1), enabled: true, starts_at: startsAt, expires_at: expiresAt } });
        results.push({ id: app.id, name: app.draft.name, ok: !result.error && !!result.data, message: result.error || !result.data ? apiErrorMessage(result.error, "Grant outcome unknown. Review access grants before trying again.") : `Access granted to ${subject.label}.` });
      } catch { results.push({ id: app.id, name: app.draft.name, ok: false, message: "Connection interrupted; grant outcome unknown. Review access grants before trying again." }); }
    }
    if (alive.current) { setOutcomes(results); setBusy(false); }
  }
  return <Modal title="Grant application access" onDismiss={() => { if (!inFlight.current || outcomes) onClose(!!outcomes); }}>
    <form className="space-y-4" onSubmit={event => void save(event)}>
      <SelectedApplications applications={applications} />
      <p>Grant an explicit member or group access to each selected application. Grants do not publish applications or replace their own login and permissions.</p>
      {outcomes ? <Outcomes outcomes={outcomes} /> : <>{!options && !error ? <Loading label="Loading members and groups…" /> : options && <fieldset disabled={busy} className="space-y-4"><EntityPicker label="Grant subject" placeholder="Select a user or group explicitly" value={subject?.value ?? ""} options={options} onSelect={setSubject} /><p className="text-sm text-ink-secondary">Times use your local timezone and are saved as UTC. Empty fields leave that side of the validity window unbounded.</p><Field label="Starts at"><Input type="datetime-local" value={starts} onChange={event => setStarts(event.target.value)} /></Field><Field label="Expires at"><Input type="datetime-local" value={expires} onChange={event => setExpires(event.target.value)} /></Field></fieldset>}<ErrorText>{error}</ErrorText></>}
      <div className="flex flex-wrap gap-3">{!outcomes && <Button type="submit" disabled={busy || !options || !subject}>{busy ? "Saving grants…" : "Grant access to selected applications"}</Button>}<Button type="button" variant="ghost" disabled={busy} onClick={() => onClose(!!outcomes)}>{outcomes ? "Close and refresh" : "Cancel grant"}</Button></div>
    </form>
  </Modal>;
}
