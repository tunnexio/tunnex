import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent, type ReactNode, type Ref } from "react";
import { Link } from "react-router-dom";
import { api, apiErrorCode, apiErrorMessage, loadOne, type Device, type Member, type Role } from "../lib/api";
import { useOrg } from "../lib/useOrg";
import { useAuth } from "../lib/auth";
import { can, canManageMembership, HUMAN_ROLES } from "../lib/rbac";
import { deviceCountFor, deviceCountLabel, deactivationImpactCopy, rosterShape } from "../lib/usersview";
import { canResend, canRevoke, invitationState, inviteErrorCopy, inviteGate, inviterLabel, orderInvitations, outstandingCount, REVOKED_CAUSE_NOTE, stateLabel, type Invitation } from "../lib/invitationview";
import { Button, ErrorText, Field, Input, Loading, Modal, RefreshButton, Select } from "../components/ui";
import { UsersTabRail } from "../components/WorkspaceTabs";
import UsersInventory from "../components/UsersInventory";
import { ResourceSummary } from "../components/ResourceSummary";
import { LoadRetry } from "../components/LoadRetry";
import { OneTimeSecretModal } from "../components/OneTimeSecret";
import AppAccessPagination from "../components/AppAccessPagination";
import AppAccessRowMenu, { type AppAccessRowMenuAction } from "../components/AppAccessRowMenu";
import "../network-workspaces.css";
import "../app-access-workspace.css";
import "../users-workspace.css";
import "../user-detail-workspace.css";

type View = "users" | "roles" | "invitations";
type PersonAction = "deactivate" | "reactivate" | "reset";
type Stage = "overview" | "roles" | "devices";
const roleHelp: Record<string, string> = {
  owner: "Organization ownership and all administration.",
  admin: "Manage people and infrastructure, except ownership.",
  member: "Use resources allowed by access policies.",
  "ai-admin": "Manage AI models, credentials, and access.",
  "ai-view": "View AI configuration and usage.",
};
const memberRoles = (m: Member): Role[] => m.roles ?? [m.role];
const memberSignature = (m: Member) => `${m.user_id}:${m.status}:${memberRoles(m).join(",")}:${m.machine_credentials ?? "unknown"}:${m.managed_agent_delegations ?? "unknown"}`;
const memberState = (m: Member) => m.status === "deactivated" ? "Deactivated" : m.email_verified ? "Active" : "Email unverified";
const dateLabel = (date?: string | null) => date && Number.isFinite(new Date(date).getTime()) ? new Date(date).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" }) : "Not reported";

export default function Users({ view = "users" }: { view?: View }) {
  const { org } = useOrg();
  const { state } = useAuth();
  const actor = state.status === "authed" ? `${state.user.id}:${state.user.email_verified}` : state.status;
  return <UsersWorkspace key={`${org?.id ?? "no-organization"}:${actor}`} view={view} />;
}

function UsersWorkspace({ view }: { view: View }) {
  const { org, loading: orgLoading, failed: orgFailed } = useOrg();
  const { state } = useAuth();
  const actorId = state.status === "authed" ? state.user.id : "";
  const emailVerified = state.status === "authed" && state.user.email_verified;
  const [members, setMembers] = useState<Member[]>([]);
  const [membersState, setMembersState] = useState<"loading" | "ready" | "error">("loading");
  const [membersLoaded, setMembersLoaded] = useState(false);
  const [membersError, setMembersError] = useState("");
  const [devices, setDevices] = useState<Device[] | null>(null);
  const [deviceError, setDeviceError] = useState("");
  const [devicesLoading, setDevicesLoading] = useState(false);
  const [inspectedId, setInspectedId] = useState<string | null>(null);
  const [stage, setStage] = useState<Stage>("overview");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [confirmation, setConfirmation] = useState<{ kind: PersonAction; targets: Member[] } | null>(null);
  const [inviteOpen, setInviteOpen] = useState(false);
  const [invites, setInvites] = useState<Invitation[] | null>(null);
  const [inviteError, setInviteError] = useState("");
  const [invitesLoading, setInvitesLoading] = useState(false);
  const [inviteConfirmation, setInviteConfirmation] = useState<{ kind: "resend" | "revoke"; row: Invitation } | null>(null);
  const alive = useRef(true), rosterRequest = useRef(0), devicesRequest = useRef(0), invitesRequest = useRef(0), locked = useRef(false), ready = useRef(false), roster = useRef<Member[]>([]);
  const titleRef = useRef<HTMLHeadingElement>(null), stageRef = useRef<HTMLHeadingElement>(null);
  useEffect(() => { alive.current = true; return () => { alive.current = false; ready.current = false; rosterRequest.current++; devicesRequest.current++; invitesRequest.current++; }; }, []);
  const myRole = useMemo(() => {
    const mine = members.find(m => m.user_id === actorId);
    const roles = mine ? memberRoles(mine) : [];
    return roles.includes("owner") ? "owner" : roles.includes("admin") ? "admin" : mine?.role;
  }, [members, actorId]);
  // Mirrors the backend CountOwners contract, including deactivated owner rows.
  const ownerCount = members.filter(m => m.role === "owner").length;
  const shape = rosterShape({ role: myRole, isEnterprise: false });
  const loadMembers = useCallback(async () => {
    if (!org) return;
    const request = ++rosterRequest.current;
    ready.current = false; setMembersState("loading"); setMembersError("");
    const result = await loadOne(() => api.GET("/api/v1/organizations/{orgId}/members", { params: { path: { orgId: org.id } } }));
    if (!alive.current || request !== rosterRequest.current) return;
    if (!result.ok || !Array.isArray(result.data) || result.data.some(m => !m || typeof m.user_id !== "string" || typeof m.email !== "string") || new Set(result.data.map(m => m.user_id)).size !== result.data.length) {
      setMembersError(result.ok ? "Could not load members." : result.error); setMembersState("error"); return;
    }
    roster.current = result.data; setMembers(result.data); ready.current = true; setMembersLoaded(true); setMembersState("ready");
  }, [org?.id]);
  useEffect(() => { if (!orgLoading && org) void loadMembers(); }, [org?.id, orgLoading, loadMembers]);
  const loadDevices = useCallback(async () => {
    const request = ++devicesRequest.current;
    setDevices(null); setDeviceError("");
    if (!org || !can(myRole, "member:manage")) { setDevicesLoading(false); return; }
    setDevicesLoading(true);
    const result = await loadOne(() => api.GET("/api/v1/organizations/{orgId}/devices", { params: { path: { orgId: org.id } } }));
    if (!alive.current || request !== devicesRequest.current) return;
    setDevicesLoading(false);
    if (!result.ok || !Array.isArray(result.data)) { setDeviceError(result.ok ? "Could not load devices." : result.error); return; }
    setDevices(result.data);
  }, [org?.id, myRole]);
  useEffect(() => { void loadDevices(); }, [loadDevices]);
  const loadInvites = useCallback(async () => {
    const request = ++invitesRequest.current;
    if (!org || inviteGate(myRole).kind !== "ready") { setInvites(null); setInvitesLoading(false); return; }
    setInvitesLoading(true); setInviteError("");
    try {
      const { data, error: err } = await api.GET("/api/v1/organizations/{orgId}/invitations", { params: { path: { orgId: org.id } } });
      if (!alive.current || request !== invitesRequest.current) return;
      setInvitesLoading(false);
      if (err || !Array.isArray(data) || data.some(row => !row || typeof row.id !== "string" || !row.id || typeof row.email !== "string" || !HUMAN_ROLES.includes(row.role) || typeof row.created_at !== "string" || !Number.isFinite(Date.parse(row.created_at)) || typeof row.expires_at !== "string" || !Number.isFinite(Date.parse(row.expires_at))) || new Set(data.map(row => row.id)).size !== data.length) {
        setInviteError(err ? inviteErrorCopy(apiErrorCode(err)) : "Could not load invitations."); return;
      }
      setInvites(data as Invitation[]);
    } catch { if (alive.current && request === invitesRequest.current) { setInvitesLoading(false); setInviteError("Could not load invitations."); } }
  }, [org?.id, myRole]);
  useEffect(() => { void loadInvites(); }, [loadInvites]);
  useEffect(() => { setInspectedId(null); setConfirmation(null); setInviteConfirmation(null); setInviteOpen(false); }, [view]);
  useEffect(() => { if (inspectedId) titleRef.current?.focus(); }, [inspectedId]);
  const inspected = members.find(m => m.user_id === inspectedId);
  const inspectedDevices = devices?.filter(device => device.user_id === inspected?.user_id) ?? [];
  const blocked = busy || membersState !== "ready";
  function unavailable(kind: PersonAction, m: Member): string | null {
    if (!emailVerified) return "Verify your email to manage accounts.";
    if (!canManageMembership(myRole, m.role, "")) return "You cannot manage this member's role.";
    if (kind !== "reactivate" && m.user_id === actorId) return kind === "reset" ? "Reset your own 2FA from your account settings." : "You cannot deactivate your own account.";
    if (kind === "deactivate" && m.status !== "active") return "Already deactivated.";
    if (kind === "deactivate" && m.role === "owner" && ownerCount <= 1) return "An organization must always have at least one owner.";
    if (kind === "reactivate" && m.status === "active") return "Already active.";
    return null;
  }
  function requestAction(kind: PersonAction, targets: Member[]) {
    if (blocked || locked.current || !ready.current || !targets.length || (kind === "reset" && targets.length !== 1)) return;
    const current = targets.map(m => roster.current.find(row => row.user_id === m.user_id));
    if (current.some(m => !m || unavailable(kind, m))) return;
    setError(""); setNotice(""); setConfirmation({ kind, targets: current as Member[] });
  }
  async function decide() {
    if (!org || !confirmation || locked.current || !ready.current) return;
    const { kind, targets } = confirmation;
    if (targets.some(target => { const current = roster.current.find(m => m.user_id === target.user_id); return !current || memberSignature(current) !== memberSignature(target) || unavailable(kind, current); })) {
      setConfirmation(null); setError("The roster changed. Review the current accounts before continuing."); return;
    }
    locked.current = true; setBusy(true); setError("");
    const outcomes = await Promise.all(targets.map(async target => {
      try {
        const path = kind === "deactivate" ? "/api/v1/organizations/{orgId}/members/{userId}/deactivate" as const : kind === "reactivate" ? "/api/v1/organizations/{orgId}/members/{userId}/reactivate" as const : "/api/v1/organizations/{orgId}/members/{userId}/mfa-reset" as const;
        const result = await api.POST(path, { params: { path: { orgId: org.id, userId: target.user_id } } });
        return { target, error: result.error ? apiErrorMessage(result.error, "Could not update the account.") : "" };
      } catch { return { target, error: "Could not confirm the result. Refresh before trying again." }; }
    }));
    if (!alive.current) return;
    const failed = outcomes.filter(result => result.error);
    const succeeded = outcomes.length - failed.length;
    setConfirmation(null);
    setNotice(succeeded ? `${succeeded} ${succeeded === 1 ? "account" : "accounts"} ${kind === "reset" ? "had 2FA reset" : kind === "deactivate" ? "deactivated" : "reactivated"}.` : "");
    setError(failed.map(result => `${result.target.email}: ${result.error}`).join(" "));
    await loadMembers();
    if (alive.current) { locked.current = false; setBusy(false); }
  }
  async function changeRoles(target: Member, roles: Role[]) {
    const current = roster.current.find(m => m.user_id === target.user_id);
    if (!org || !current || locked.current || !ready.current || !emailVerified || memberSignature(current) !== memberSignature(target) || !roles.length || roles.some(role => !HUMAN_ROLES.includes(role) || !canManageMembership(myRole, current.role, role)) || (current.role === "owner" && ownerCount <= 1 && !roles.includes("owner"))) return;
    locked.current = true; setBusy(true); setError(""); setNotice("");
    try {
      const result = await api.PUT("/api/v1/organizations/{orgId}/members/{userId}/roles", { params: { path: { orgId: org.id, userId: current.user_id } }, body: { roles } });
      if (!alive.current) return;
      if (result.error) setError(apiErrorMessage(result.error, "Could not change the roles.")); else setNotice("Roles updated.");
    } catch { if (alive.current) setError("Could not confirm the role update. Refresh before trying again."); }
    if (!alive.current) return;
    await loadMembers();
    if (alive.current) { locked.current = false; setBusy(false); }
  }
  async function decideInvitation() {
    if (!org || !inviteConfirmation || locked.current || blocked || !emailVerified || invitesLoading || inviteError || inviteGate(myRole).kind !== "ready") return;
    const { kind, row } = inviteConfirmation;
    const current = invites?.find(inv => inv.id === row.id);
    if (!current || current.email !== row.email || current.role !== row.role || !(kind === "resend" ? canResend(invitationState(current, new Date())) && canManageMembership(myRole, "member", current.role) : canRevoke(invitationState(current, new Date())))) { setInviteConfirmation(null); setError("The invitation changed. Refresh before continuing."); return; }
    locked.current = true; setBusy(true); setInviteError(""); setNotice("");
    try {
      const result = await api.POST(kind === "resend" ? "/api/v1/organizations/{orgId}/invitations/resend" : "/api/v1/organizations/{orgId}/invitations/revoke", { params: { path: { orgId: org.id } }, body: { email: current.email } });
      if (!alive.current) return;
      if (result.error) setError(inviteErrorCopy(apiErrorCode(result.error))); else setNotice(kind === "resend" ? "Invitation renewed." : "Invitation revoked.");
    } catch { if (alive.current) setError("Could not confirm the result. Refresh before trying again."); }
    if (!alive.current) return;
    setInviteConfirmation(null); await loadInvites();
    if (alive.current) { locked.current = false; setBusy(false); }
  }
  const personActions = (m: Member): AppAccessRowMenuAction[] => !emailVerified || !canManageMembership(myRole, m.role, "") || m.user_id === actorId ? [] : [
    { key: m.status === "active" ? "deactivate" : "reactivate", label: m.status === "active" ? "Deactivate" : "Reactivate", danger: m.status === "active", disabledReason: blocked ? "Wait for the roster to finish loading." : unavailable(m.status === "active" ? "deactivate" : "reactivate", m), onSelect: () => requestAction(m.status === "active" ? "deactivate" : "reactivate", [m]) },
    { key: "reset", label: "Reset 2FA", disabledReason: blocked ? "Wait for the current operation." : unavailable("reset", m), onSelect: () => requestAction("reset", [m]) },
  ];
  const actions = <><RefreshButton label="Refresh" disabled={busy || orgLoading || !org || membersState === "loading"} onClick={() => { void loadMembers(); void loadDevices(); if (view === "invitations") void loadInvites(); }} />{emailVerified && can(myRole, "member:invite") && <Button disabled={blocked} onClick={() => setInviteOpen(true)}>Invite user</Button>}</>;
  function inspect(id: string, next?: "overview" | "roles") { if (blocked) return; setInspectedId(id); setStage(next ?? (view === "roles" ? "roles" : "overview")); }
  const changeStage = (next: Stage) => { setStage(next); queueMicrotask(() => stageRef.current?.focus()); };
  const backToPeople = <Button variant="ghost" disabled={busy} onClick={() => setInspectedId(null)}>Back to {view === "roles" ? "roles" : "users"}</Button>;
  return <div className="network-management users-workspace users-management">
    <UsersTabRail actions={actions} />
    <ErrorText>{error}</ErrorText>{notice && <p role="status" className="users-notice">{notice}</p>}
    {orgLoading ? <Loading label="Loading organization…" /> : !org ? <p role="alert">{orgFailed ? "Could not load your organizations." : "You are not a member of any organization yet."}</p> : membersState === "loading" ? <Loading label="Loading members…" /> : membersState === "error" ? <LoadRetry error={membersError} onRetry={() => void loadMembers()} /> : null}
    {membersLoaded && view !== "invitations" && <div hidden={membersState !== "ready" || inspectedId !== null}>
      <UsersInventory members={members} devices={devices} actorId={actorId} actorRole={myRole} emailVerified={emailVerified} busy={blocked} view={view} ownerCount={ownerCount} onInspect={inspect} onRequestAction={requestAction} />
    </div>}
    {membersState === "ready" && view !== "invitations" && inspectedId && (inspected ? <section className="user-detail" aria-label="Person details">
      <nav aria-label="Person breadcrumb" className="user-breadcrumb"><button type="button" disabled={busy} onClick={() => setInspectedId(null)}>{view === "roles" ? "Roles" : "Users"}</button><span aria-hidden="true">/</span><span>{inspected.name || inspected.email}</span></nav>
      <header className="user-detail-header"><div><h2 ref={titleRef} tabIndex={-1}>{inspected.name || inspected.email}</h2><p>{inspected.name && inspected.name !== inspected.email ? `${inspected.email} · ` : ""}{memberState(inspected)}{inspected.user_id === actorId ? " · You" : ""}</p></div><AppAccessRowMenu label={`Account actions for ${inspected.email}`} actions={personActions(inspected)} /></header>
      <div className="user-detail-layout"><nav aria-label="Person detail sections" className="user-detail-path">{(["overview", "roles", ...(shape.showDeviceCount ? ["devices"] : [])] as Stage[]).map(item => <button key={item} type="button" disabled={busy} aria-current={stage === item ? "step" : undefined} onClick={() => changeStage(item)}>{item[0].toUpperCase() + item.slice(1)}</button>)}</nav>
        <div className="user-detail-stage">
          {stage === "overview" && <ResourceSummary title="Account details" headingRef={stageRef} footer={backToPeople}><UserFacts summary rows={[["Email", inspected.email], ["Account", memberState(inspected)], ["Email verified", inspected.email_verified ? "Verified" : "Unverified"], ["Joined", dateLabel(inspected.joined_at)], ["Roles", memberRoles(inspected).join(" + ")]]} /></ResourceSummary>}
          {stage === "roles" && <PersonRoles key={inspected.user_id + ":" + memberRoles(inspected).join(",") + ":" + myRole + ":" + emailVerified} member={inspected} actorRole={myRole} editable={emailVerified && canManageMembership(myRole, inspected.role, "")} soleOwner={inspected.role === "owner" && ownerCount <= 1} busy={busy} headingRef={stageRef} backAction={backToPeople} onSave={roles => changeRoles(inspected, roles)} />}
          {stage === "devices" && shape.showDeviceCount && <ResourceSummary title="Devices" headingRef={stageRef} description="Devices enrolled by this person in this organization." footer={<>{backToPeople}{!devicesLoading && !deviceError && devices && <Link className="user-text-link" to="/devices">Open device inventory</Link>}</>}>
            {devicesLoading ? <Loading label="Loading devices…" /> : deviceError ? <LoadRetry error={deviceError} onRetry={() => void loadDevices()} /> : devices ? <><p className="user-stage-meta">{deviceCountLabel(deviceCountFor({ role: myRole, devices, userId: inspected.user_id }))}</p>{inspectedDevices.length ? <ul className="user-device-list" aria-label={`Devices for ${inspected.email}`}>{inspectedDevices.map(device => <li key={device.id}><span className="user-device-name">{device.name}</span><span className="user-device-state">{device.status}</span></li>)}</ul> : <div className="user-device-empty"><h4>No devices enrolled</h4><p>This person has no devices in this organization.</p></div>}</> : <p className="user-stage-meta" role="status">Device counts could not load.</p>}
          </ResourceSummary>}
        </div>
      </div>
    </section> : <div className="users-empty"><h3>Person no longer listed</h3><Button variant="ghost" onClick={() => setInspectedId(null)}>Back to users</Button></div>)}
    {membersState === "ready" && view === "invitations" && (inviteGate(myRole).kind !== "ready" ? <p role="alert">You do not have permission to manage invitations.</p> : <>
      {invitesLoading ? <Loading label="Loading invitations…" /> : inviteError ? <LoadRetry error={inviteError} onRetry={() => void loadInvites()} /> : invites && <InvitationsInventory rows={invites} busy={blocked} emailVerified={emailVerified} actorRole={myRole} onAction={(kind, row) => { if (!blocked && !locked.current) setInviteConfirmation({ kind, row }); }} onInvite={emailVerified ? () => setInviteOpen(true) : undefined} />}
    </>)}
    {inviteOpen && org && membersState === "ready" && emailVerified && can(myRole, "member:invite") && <InviteForm key={`${org.id}:${myRole}:${emailVerified}`} orgId={org.id} actorRole={myRole} onInvited={() => void loadInvites()} onDismiss={() => setInviteOpen(false)} />}
    {confirmation && <Modal title={confirmation.kind === "reset" ? "Reset two-factor authentication" : `${confirmation.kind === "deactivate" ? "Deactivate" : "Reactivate"} ${confirmation.targets.length === 1 ? "account" : "accounts"}?`} danger={confirmation.kind !== "reactivate"} placement="right" size="enrollment" onDismiss={() => { if (!busy) setConfirmation(null); }} actions={<><Button variant="ghost" disabled={busy} onClick={() => setConfirmation(null)}>Cancel</Button><Button variant={confirmation.kind === "reactivate" ? "primary" : "danger"} disabled={busy || !ready.current} onClick={() => void decide()}>{busy ? "Updating…" : confirmation.kind === "reset" ? "Reset 2FA" : confirmation.kind === "deactivate" ? "Deactivate" : "Reactivate"}</Button></>}><div className="user-account-confirm">
      <p>{confirmation.kind === "reset" ? "Clear this person's 2FA and recovery codes. They must enroll again if your organization requires MFA. Email notification is best effort." : confirmation.kind === "deactivate" ? "Prevent these accounts from signing in and using organization resources." : "Restore sign-in for these accounts. Existing organization roles remain."}</p>
      <ul>{confirmation.targets.map(m => <li key={m.user_id}><strong>{m.name || m.email}</strong>{m.name && <span>{m.email}</span>}<span>{memberState(m)} · {memberRoles(m).join(" + ")}</span></li>)}</ul>
      {confirmation.kind === "deactivate" && deactivationImpactCopy(confirmation.targets) && <div className="user-deactivation-impact" role="note"><strong>{confirmation.targets.reduce((n, m) => n + (m.machine_credentials ?? 0), 0)} machine credentials stop working. {confirmation.targets.reduce((n, m) => n + (m.managed_agent_delegations ?? 0), 0)} managed-agent delegations are withdrawn.</strong><p>This takes effect immediately across all organizations. Reactivating restores them; team assignments remain.</p></div>}
      {confirmation.kind === "reset" && <p>This resets enrollment only; it does not sign you in as them.</p>}
    </div></Modal>}
    {inviteConfirmation && <Modal title={inviteConfirmation.kind === "resend" ? "Renew invitation?" : "Revoke invitation?"} danger={inviteConfirmation.kind === "revoke"} placement="right" size="enrollment" onDismiss={() => { if (!busy) setInviteConfirmation(null); }} actions={<><Button variant="ghost" disabled={busy} onClick={() => setInviteConfirmation(null)}>Cancel</Button><Button variant={inviteConfirmation.kind === "revoke" ? "danger" : "primary"} disabled={busy} onClick={() => void decideInvitation()}>{busy ? "Updating…" : inviteConfirmation.kind === "resend" ? "Resend invitation" : "Revoke invitation"}</Button></>}><div className="user-account-confirm"><strong>{inviteConfirmation.row.email}</strong><UserFacts rows={[["Starting role", inviteConfirmation.row.role], ["Current state", stateLabel(invitationState(inviteConfirmation.row, new Date()))]]} /><p>{inviteConfirmation.kind === "resend" ? "Create a new invitation token and invalidate the previous link. Delivery follows this installation's email configuration." : "Invalidate the pending invitation link. An accepted membership is unaffected."}</p></div></Modal>}
  </div>;
}

function UserFacts({ rows, summary = false }: { rows: Array<[string, ReactNode]>; summary?: boolean }) { return <dl className={summary ? "user-facts tnx-resource-facts tnx-resource-facts-three" : "user-facts"}>{rows.map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value}</dd></div>)}</dl>; }

function PersonRoles({ member, actorRole, editable, soleOwner, busy, headingRef, backAction, onSave }: { member: Member; actorRole: Role | undefined; editable: boolean; soleOwner: boolean; busy: boolean; headingRef: Ref<HTMLHeadingElement>; backAction: ReactNode; onSave: (roles: Role[]) => Promise<void> }) {
  const saved = memberRoles(member), [selected, setSelected] = useState<Role[]>(saved);
  const options = editable ? HUMAN_ROLES.filter(role => canManageMembership(actorRole, member.role, role)) : saved;
  const unchanged = selected.length === saved.length && saved.every(role => selected.includes(role));
  return <ResourceSummary title="Roles" headingRef={headingRef} description="Roles control administration. Resource access comes from policies and group grants." footer={<>{backAction}{editable && <div className="user-role-actions">{!unchanged && <Button variant="ghost" disabled={busy} onClick={() => setSelected(saved)}>Discard changes</Button>}<Button disabled={busy || unchanged || !selected.length} onClick={() => void onSave(selected)}>{busy ? "Saving…" : "Save roles"}</Button></div>}</>}>
    <div className="user-role-editor" data-editable={editable}><fieldset disabled={busy}><legend className="sr-only">Roles for {member.email}</legend>{options.map(role => <label key={role} className="user-role-option" data-selected={selected.includes(role)}>{editable && <input type="checkbox" aria-label={role} checked={selected.includes(role)} disabled={soleOwner && role === "owner"} title={soleOwner && role === "owner" ? "An organization must always have at least one owner." : undefined} onChange={event => setSelected(current => event.target.checked ? [...current, role] : current.filter(value => value !== role))} />}<span><strong>{role}</strong><small>{roleHelp[role]}</small></span>{saved.includes(role) && <em>Assigned</em>}</label>)}</fieldset>{soleOwner && editable && <p className="user-role-note">Keep at least one owner.</p>}</div>
  </ResourceSummary>;
}

function InvitationsInventory({ rows, busy, emailVerified, actorRole, onAction, onInvite }: { rows: Invitation[]; busy: boolean; emailVerified: boolean; actorRole: Role | undefined; onAction: (kind: "resend" | "revoke", row: Invitation) => void; onInvite?: () => void }) {
  const [query, setQuery] = useState(""), [filter, setFilter] = useState<"all" | "outstanding" | "history">("all"), [page, setPage] = useState(1), [pageSize, setPageSize] = useState(20);
  const now = new Date(), outstanding = outstandingCount(rows, now);
  const visible = orderInvitations(rows, now).filter(row => (filter === "all" || (filter === "outstanding" ? canResend(invitationState(row, now)) : !canResend(invitationState(row, now)))) && `${row.email} ${row.role} ${inviterLabel(row)} ${stateLabel(invitationState(row, now))}`.toLowerCase().includes(query.toLowerCase()));
  const currentPage = Math.min(page, Math.max(1, Math.ceil(visible.length / pageSize))), shown = visible.slice((currentPage - 1) * pageSize, currentPage * pageSize);
  return <section className="users-invitations" aria-label="Invitation inventory"><div className="user-invitation-tools"><div className="user-invitation-filters">{(["all", "outstanding", "history"] as const).map(value => <button type="button" key={value} disabled={busy} aria-pressed={filter === value} onClick={() => { setFilter(value); setPage(1); }}>{value === "all" ? "All" : value === "outstanding" ? "Outstanding" : "History"}<span>({value === "all" ? rows.length : value === "outstanding" ? outstanding : rows.length - outstanding})</span></button>)}</div><span>{visible.length} invitations</span></div><Input type="search" aria-label="Search invitations" placeholder="Search invitations…" value={query} disabled={busy} onChange={event => { setQuery(event.target.value); setPage(1); }} />
    {shown.length ? <table className="users-native-table" aria-label="Invitation history"><thead><tr><th>Email</th><th>State</th><th>Roles</th><th>Invited by</th>{emailVerified && <th className="user-menu-column">Actions</th>}</tr></thead><tbody>{shown.map(row => { const status = invitationState(row, now); return <tr key={row.id} data-testid={`invite-${row.id}`} data-state={status}><td><span className="user-invitation-email">{row.email}</span><small>{status === "pending" ? `Expires ${dateLabel(row.expires_at)}` : `Created ${dateLabel(row.created_at)}`}</small></td><td><span className={`user-invitation-state is-${status}`}>{stateLabel(status)}</span></td><td>{row.role}</td><td>{inviterLabel(row)}</td>{emailVerified && <td className="user-menu-column">{canResend(status) && <AppAccessRowMenu label={`Invitation actions for ${row.email}`} actions={[
      { key: "resend", label: "Resend", disabledReason: busy ? "Wait for the current operation." : !canManageMembership(actorRole, "member", row.role) ? "Only an owner can resend an owner invitation." : !canResend(status) ? "Only pending or expired invitations can be renewed." : null, onSelect: () => onAction("resend", row) },
      { key: "revoke", label: "Revoke", danger: true, disabledReason: busy ? "Wait for the current operation." : !canRevoke(status) ? "Only pending or expired invitations can be revoked." : null, onSelect: () => onAction("revoke", row) },
    ]} />}</td>}</tr>; })}</tbody></table> : <div className="users-empty"><h3>{query || filter !== "all" ? "No matching invitations" : "No invitations yet"}</h3><p>{query || filter !== "all" ? "Try another search or view all invitations." : "Invite a person with the role they need to get started."}</p>{query || filter !== "all" ? <Button variant="ghost" onClick={() => { setQuery(""); setFilter("all"); setPage(1); }}>Clear filters</Button> : onInvite && <Button variant="ghost" onClick={onInvite}>Invite a person</Button>}</div>}
    <AppAccessPagination page={currentPage} pageSize={pageSize} count={shown.length} hasNext={currentPage * pageSize < visible.length} maxOffset={null} busy={busy} onPageChange={setPage} onPageSizeChange={size => { setPageSize(size); setPage(1); }} />
    {rows.some(row => row.revoked_at) && <details className="user-disclosure"><summary>About revoked invitations</summary><p>{REVOKED_CAUSE_NOTE}</p></details>}
  </section>;
}

// The API is enumeration-resistant: invite creation is never a claim that the address was a new account.
function InviteForm({ orgId, actorRole, onInvited, onDismiss }: { orgId: string; actorRole: Role | undefined; onInvited: () => void; onDismiss: () => void }) {
  const [email, setEmail] = useState(""), [role, setRole] = useState<Role>("member"), [busy, setBusy] = useState(false), [inviteLink, setInviteLink] = useState<string | null>(null), [err, setErr] = useState("");
  const [mailOn, setMailOn] = useState<boolean | null>(null), [delivered, setDelivered] = useState<boolean | null>(null);
  const alive = useRef(true), locked = useRef(false);
  useEffect(() => { alive.current = true; void api.GET("/api/v1/meta").then(({ data }) => { if (alive.current && typeof data?.smtp_configured === "boolean") setMailOn(data.smtp_configured); }).catch(() => {}); return () => { alive.current = false; }; }, []);
  async function submit(event: FormEvent) {
    event.preventDefault();
    if (locked.current || !canManageMembership(actorRole, "member", role) || !email.trim()) return;
    locked.current = true; setBusy(true); setErr("");
    try {
      const result = await api.POST("/api/v1/organizations/{orgId}/invitations", { params: { path: { orgId } }, body: { email, role } });
      if (!alive.current) return;
      if (result.error || !result.data || typeof result.data.invite_token !== "string" || !result.data.invite_token) { setErr(result.error ? apiErrorMessage(result.error, "Could not create the invitation.") : "Could not confirm the invitation link. Refresh the invitation list before trying again."); return; }
      setDelivered(typeof result.data.delivered === "boolean" ? result.data.delivered : null);
      setInviteLink(`${window.location.origin}/accept-invite?token=${result.data.invite_token}`); setEmail(""); onInvited();
    } catch { if (alive.current) setErr("Could not confirm the invitation. Refresh before trying again."); }
    finally { if (alive.current) { locked.current = false; setBusy(false); } }
  }
  if (inviteLink) return <OneTimeSecretModal title="Invitation link" caption={delivered === false ? "Email was not delivered. Copy this one-time link and share it securely." : delivered === true ? "An email was sent. You can also copy this one-time link and share it securely." : mailOn === false ? "Email delivery is not configured. Copy this one-time link and share it securely." : "Copy this one-time link and share it securely. Email delivery could not be confirmed."} secret={inviteLink} copyLabel="Copy link" onDismiss={() => { setInviteLink(null); onDismiss(); }} />;
  return <Modal title="Invite user" placement="right" size="enrollment" onDismiss={() => { if (!busy) onDismiss(); }} actions={<><Button variant="ghost" disabled={busy} onClick={onDismiss}>Cancel</Button><Button type="submit" form="invite-user-form" disabled={busy}>{busy ? "Creating…" : "Create invite"}</Button></>}><div className="user-invite-editor"><form id="invite-user-form" onSubmit={submit}><fieldset disabled={busy}><Field label="Email address"><Input type="email" value={email} onChange={event => setEmail(event.target.value)} required autoFocus placeholder="name@company.com" /></Field><Field label="Role"><Select aria-label="Role" value={role} onChange={event => setRole(event.target.value as Role)}>{HUMAN_ROLES.filter(value => canManageMembership(actorRole, "member", value)).map(value => <option key={value} value={value}>{value}</option>)}</Select></Field><p className="user-stage-meta">{roleHelp[role]}</p></fieldset></form>{mailOn === false && <p className="user-invite-warning">Email delivery is off. Copy the one-time link after creating the invitation.</p>}<ErrorText>{err}</ErrorText></div></Modal>;
}
