import "../network-workspaces.css";
import "../agents-workspace.css";
import "../agent-detail-workspace.css";
import { useEffect, useRef, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import type { components } from "@tunnex/shared";
import { Button, Field, Loading, Modal, RefreshButton, Select } from "../components/ui";
import AppAccessRowMenu, { type AppAccessRowMenuAction } from "../components/AppAccessRowMenu";
import { AgentProfileEditor, type AgentProfileEditorValue, type AgentProfileStatus } from "../components/AgentProfileEditor";
import { api, apiErrorCode, loadOne, type Member, type UserGroup } from "../lib/api";
import { useOrg } from "../lib/useOrg";
import { useAuth } from "../lib/auth";
import { can } from "../lib/rbac";
import { AgentMCPOAuthPanel, AgentMCPToolApprovalPanel, AgentMCPToolPolicyPanel } from "../components/AgentMCPControls";
import { AgentWorkflowProvenancePanel } from "../components/AgentWorkflowProvenance";
import { ResourceSummary } from "../components/ResourceSummary";

type AgentProfile = components["schemas"]["AgentProfile"];
type Runtime = components["schemas"]["AgentRuntimeStatus"];
type MCPInventory = components["schemas"]["AgentMCPInventory"];
type EffectiveMCP = components["schemas"]["AgentEffectiveMCPProfile"];
type Provenance = components["schemas"]["AgentWorkflowProvenanceRecord"];
type LicenceStatus = components["schemas"]["LicenseStatus"];
type CredentialRotation = components["schemas"]["AgentCredentialRotationStatus"];

const tabs = ["overview", "runtime", "mcp", "access", "activity"] as const;
type Tab = (typeof tabs)[number];
const tabLabel: Record<Tab, string> = {
  overview: "Overview", runtime: "Runtime", mcp: "MCP", access: "Access", activity: "Activity",
};

type State<T> = { kind: "loading" } | { kind: "ready"; data: T } | { kind: "error"; message: string; code?: string };
const loading = <T,>(): State<T> => ({ kind: "loading" });

/** Development-gallery input only. The route continues to own live reads. */
export type AgentDetailFixture = {
  profile: AgentProfile;
  runtime: Runtime;
  inventory: MCPInventory;
  provenance: Provenance[];
  effectiveMCP: EffectiveMCP;
  licence: LicenceStatus;
};

function readError(result: { ok: boolean; error?: string }): string {
  return result.ok ? "" : (result.error ?? "Could not load this information.");
}

function age(at?: string | null) {
  if (!at) return "never";
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(at).getTime()) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return <section className="agent-detail-panel"><h3>{title}</h3><div className="agent-detail-panel-body">{children}</div></section>;
}

function ReadState<T>({ state, children, onRetry, title = "Information unavailable", retryLabel = "Retry" }: { state: State<T>; children: (data: T) => React.ReactNode; onRetry?: () => void; title?: string; retryLabel?: string }) {
  if (state.kind === "loading") return <div className="agent-detail-read-state"><Loading label="Loading agent workspace…" /></div>;
  if (state.kind === "error") return <div className="agent-detail-read-state"><h3>{title}</h3><p role="alert">{state.message}</p><Button size="sm" variant="ghost" aria-label={retryLabel} onClick={onRetry ?? (() => window.location.reload())}>Retry</Button></div>;
  return <>{children(state.data)}</>;
}

function ObservedMCP({ data }: { data: MCPInventory }) {
  const servers = Array.isArray(data.snapshot.servers) ? data.snapshot.servers.map(value => value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {}) : undefined;
  return <Panel title="Observed MCP inventory"><p className="agent-detail-context">Observed {age(data.observed_at)} · secret-free shadow-mode inventory</p>
    {servers ? servers.length ? <ul className="agent-detail-observed-servers">{servers.map((server, index) => <li key={index}><div><strong>{typeof server.server_name === "string" && server.server_name ? server.server_name : "Unnamed server"}</strong>{typeof server.endpoint === "string" && server.endpoint && <small>{server.endpoint}</small>}</div><span>{Array.isArray(server.tools) ? `${server.tools.length} tool${server.tools.length === 1 ? "" : "s"}` : "Tools not reported"}</span></li>)}</ul> : <p className="agent-detail-context">No servers observed in this snapshot.</p> : <p className="agent-detail-context">Server inventory was not reported in this snapshot.</p>}
    <details className="agent-detail-disclosure"><summary>View inventory JSON</summary><pre>{JSON.stringify(data.snapshot, null, 2)}</pre></details>
  </Panel>;
}

function MCPAuthentication({ orgId, deviceId, inventory, canManage }: { orgId: string; deviceId: string; inventory: MCPInventory; canManage: boolean }) {
  const discovery = inventory.snapshot.oauth_discovery as { servers?: Array<{ status?: string }> } | undefined;
  const servers = Array.isArray(discovery?.servers) ? discovery.servers : undefined;
  const protectedReported = servers?.some(server => server?.status === "protected") ?? false;
  return <Panel title="MCP OAuth"><AgentMCPOAuthPanel orgId={orgId} deviceId={deviceId} inventory={inventory} canManage={canManage} />{!protectedReported && <p className="agent-detail-context" role="status">{servers ? "No OAuth-protected MCP server is reported in this inventory." : "OAuth discovery has not been reported in this inventory."}</p>}</Panel>;
}

function AgentAssignment({ profile, members, groups, busy, onSave }: { profile: AgentProfile; members: State<Member[]>; groups: State<UserGroup[]>; busy: boolean; onSave: (body: Record<string, unknown>) => void }) {
  const [ownerID, setOwnerID] = useState(profile.owner_id);
  const [groupID, setGroupID] = useState(profile.managing_group_id ?? "");
  if (members.kind === "loading" || groups.kind === "loading") return <Loading size="inline" label="Loading owners and groups…" />;
  if (members.kind === "error" || groups.kind === "error") return <p role="alert" className="text-cell text-danger">Ownership choices could not be loaded. No change can be submitted.</p>;
  const changed = ownerID !== profile.owner_id || (groupID || null) !== profile.managing_group_id;
  return <div className="agent-detail-assignment"><Field label="Accountable owner"><Select value={ownerID} disabled={busy} onChange={(event) => setOwnerID(event.target.value)}>{members.data.filter((member) => member.status === "active").map((member) => <option key={member.user_id} value={member.user_id}>{member.email}</option>)}</Select></Field><Field label="Managing group"><Select value={groupID} disabled={busy} onChange={(event) => setGroupID(event.target.value)}><option value="">No managing group</option>{groups.data.map((group) => <option key={group.id} value={group.id}>{group.name}</option>)}</Select></Field><p>Changing owner changes accountability only. A managing group may view and manage this agent, but does not gain access-grant or credential-rotation authority.</p><Button size="sm" disabled={busy || !ownerID || !changed} onClick={() => onSave({ ...(ownerID !== profile.owner_id ? { owner_id: ownerID } : {}), ...((groupID || null) !== profile.managing_group_id ? { managing_group_update: { group_id: groupID || null } } : {}) })}>Save ownership</Button></div>;
}

/** The key prevents a prior organization's agent state from rendering during an org switch. */
export default function AgentDetail(props: { fixture?: AgentDetailFixture; agentIdOverride?: string }) {
  const { org } = useOrg();
  const { state } = useAuth();
  const { agentId } = useParams();
  const actor = state.status === "authed" ? `${state.user.id}:${state.user.email_verified}` : state.status;
  return <AgentDetailWorkspace key={`${org?.id ?? "no-organization"}:${actor}:${props.agentIdOverride ?? agentId ?? ""}`} {...props} />;
}

/** Route workspace only. The index and router are intentionally owned by separate S18 workstreams. */
function AgentDetailWorkspace({ fixture, agentIdOverride }: { fixture?: AgentDetailFixture; agentIdOverride?: string }) {
  const { org } = useOrg();
  const { state: authState } = useAuth();
  const navigate = useNavigate();
  const { agentId: routeAgentId = "" } = useParams();
  const agentId = agentIdOverride ?? routeAgentId;
  const [search, setSearch] = useSearchParams();
  const rawTab = search.get("tab");
  const tab: Tab = tabs.includes(rawTab as Tab) ? rawTab as Tab : "overview";
  const [profile, setProfile] = useState<State<AgentProfile>>(loading);
  const [runtime, setRuntime] = useState<State<Runtime>>(loading);
  const [inventory, setInventory] = useState<State<MCPInventory>>(loading);
  const [provenance, setProvenance] = useState<State<Provenance[]>>(loading);
  const [effectiveMCP, setEffectiveMCP] = useState<State<EffectiveMCP>>(loading);
  const [licence, setLicence] = useState<State<LicenceStatus>>(loading);
  const [rotation, setRotation] = useState<State<CredentialRotation>>(loading);
  const [members, setMembers] = useState<State<Member[]>>(loading);
  const [groups, setGroups] = useState<State<UserGroup[]>>(loading);
  const [mutationError, setMutationError] = useState("");
  const [busy, setBusy] = useState(false);
  const [removeOpen, setRemoveOpen] = useState(false);
  const [profileEditorOpen, setProfileEditorOpen] = useState(false);
  const [assignmentOpen, setAssignmentOpen] = useState(false);
  const [readVersion, setReadVersion] = useState(0);
  const alive = useRef(true), mutationBusy = useRef(false);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  const myRole = members.kind === "ready" && authState.status === "authed"
    ? members.data.find((member) => member.user_id === authState.user.id)?.role
    : undefined;

  useEffect(() => {
    if (fixture) {
      setProfile({ kind: "ready", data: fixture.profile });
      setRuntime({ kind: "ready", data: fixture.runtime });
      setInventory({ kind: "ready", data: fixture.inventory });
      setProvenance({ kind: "ready", data: fixture.provenance });
      setEffectiveMCP({ kind: "ready", data: fixture.effectiveMCP });
      setLicence({ kind: "ready", data: fixture.licence });
      setRotation({ kind: "error", message: "Credential rotation is not supplied by this specimen." });
      setMembers({ kind: "ready", data: [] });
      setGroups({ kind: "ready", data: [] });
      return;
    }
    if (!org || !agentId) return;
    let cancelled = false;
    setProfile(loading()); setRuntime(loading()); setInventory(loading()); setProvenance(loading()); setEffectiveMCP(loading()); setLicence(loading()); setRotation(loading()); setMembers(loading()); setGroups(loading()); setMutationError("");
    const path = { orgId: org.id, deviceId: agentId };
    void loadOne(() => api.GET("/api/v1/organizations/{orgId}/agents/{deviceId}", { params: { path } })).then((r) => {
      if (cancelled) return;
      setProfile(r.ok ? { kind: "ready", data: r.data as AgentProfile } : { kind: "error", message: readError(r) });
      // Only an actor who can read the agent may receive deployment entitlement
      // details. The JIT capability is an additive Access-tab concern; it does
      // not gate the base agent workspace.
      if (r.ok) {
        void loadOne(() => api.GET("/api/v1/license")).then((licenceResult) => !cancelled && setLicence(licenceResult.ok ? { kind: "ready", data: licenceResult.data as LicenceStatus } : { kind: "error", message: readError(licenceResult) }));
        void loadOne(() => api.GET("/api/v1/organizations/{orgId}/members", { params: { path: { orgId: org.id } } })).then((result) => !cancelled && setMembers(result.ok ? { kind: "ready", data: result.data as Member[] } : { kind: "error", message: readError(result) }));
        void loadOne(() => api.GET("/api/v1/organizations/{orgId}/groups", { params: { path: { orgId: org.id } } })).then((result) => !cancelled && setGroups(result.ok ? { kind: "ready", data: result.data as UserGroup[] } : { kind: "error", message: readError(result) }));
        void loadOne(() => api.GET("/api/v1/organizations/{orgId}/agents/{deviceId}/runtime-status", { params: { path } })).then((result) => !cancelled && setRuntime(result.ok ? { kind: "ready", data: result.data as Runtime } : { kind: "error", message: readError(result) }));
        let inventoryCode: string | undefined;
        void loadOne(async () => { const result = await api.GET("/api/v1/organizations/{orgId}/agents/{deviceId}/mcp-inventory", { params: { path } }); inventoryCode = apiErrorCode(result.error); return result; }).then((result) => !cancelled && setInventory(result.ok ? { kind: "ready", data: result.data as MCPInventory } : { kind: "error", message: readError(result), code: inventoryCode }));
        void loadOne(() => api.GET("/api/v1/organizations/{orgId}/agents/{deviceId}/workflow-provenance", { params: { path } })).then((result) => !cancelled && setProvenance(result.ok ? { kind: "ready", data: result.data as Provenance[] } : { kind: "error", message: readError(result) }));
        void loadOne(() => api.GET("/api/v1/organizations/{orgId}/agents/{deviceId}/effective-mcp-profile", { params: { path } })).then((result) => !cancelled && setEffectiveMCP(result.ok ? { kind: "ready", data: result.data as EffectiveMCP } : { kind: "error", message: readError(result) }));
        void loadOne(() => api.GET("/api/v1/organizations/{orgId}/agents/{deviceId}/credential-rotation", { params: { path } })).then((result) => !cancelled && setRotation(result.ok ? { kind: "ready", data: result.data as CredentialRotation } : { kind: "error", message: readError(result) }));
      }
    });
    return () => { cancelled = true; };
  }, [fixture, org, agentId, readVersion]);

  const switchTab = (next: Tab) => { const nextSearch = new URLSearchParams(search); if (next === "overview") nextSearch.delete("tab"); else nextSearch.set("tab", next); setSearch(nextSearch); };
  function navigateTabs(event: React.KeyboardEvent<HTMLElement>) {
    if (!["ArrowDown", "ArrowUp", "Home", "End"].includes(event.key)) return;
    event.preventDefault();
    const index = event.key === "Home" ? 0 : event.key === "End" ? tabs.length - 1 : (tabs.indexOf(tab) + (event.key === "ArrowDown" ? 1 : -1) + tabs.length) % tabs.length;
    switchTab(tabs[index]);
    event.currentTarget.querySelectorAll<HTMLButtonElement>('[role="tab"]')[index]?.focus();
  }
  const refreshAgent = () => { if (!mutationBusy.current) setReadVersion(value => value + 1); };

  async function updateProfile(body: Record<string, unknown>, failure: string) {
    const assignment = "owner_id" in body || "managing_group_update" in body;
    if (!org || !agentId || mutationBusy.current || profile.kind !== "ready" || !(assignment ? profile.data.permissions.assign : profile.data.permissions.manage)) return false;
    mutationBusy.current = true; setBusy(true); setMutationError("");
    try {
      const result = await api.PATCH("/api/v1/organizations/{orgId}/agents/{deviceId}", { params: { path: { orgId: org.id, deviceId: agentId } }, body });
      if (!alive.current) return false;
      if (result.error || !result.data) { setMutationError(failure); return false; }
      setProfile({ kind: "ready", data: result.data as AgentProfile });
      return true;
    } catch {
      if (alive.current) setMutationError("Could not confirm the update. Refresh the agent before trying again.");
      return false;
    } finally { mutationBusy.current = false; if (alive.current) setBusy(false); }
  }
  async function rotateCredential() {
    if (!org || !agentId || mutationBusy.current || profile.kind !== "ready" || !profile.data.permissions.rotate_credentials || profile.data.status !== "active" || rotation.kind !== "ready" || rotation.data.state !== "current" || rotation.data.wireguard_state !== "current") return;
    mutationBusy.current = true; setBusy(true); setMutationError("");
    try {
      const requested = await api.POST("/api/v1/organizations/{orgId}/agents/{deviceId}/credential-rotation", { params: { path: { orgId: org.id, deviceId: agentId } } });
      if (!alive.current) return;
      if (requested.error) { setMutationError("Could not request credential rotation."); return; }
      const refreshed = await loadOne(() => api.GET("/api/v1/organizations/{orgId}/agents/{deviceId}/credential-rotation", { params: { path: { orgId: org.id, deviceId: agentId } } }));
      if (!alive.current) return;
      if (!refreshed.ok) { setMutationError("Rotation was requested but its status could not be refreshed."); return; }
      setRotation({ kind: "ready", data: refreshed.data as CredentialRotation });
    } catch { if (alive.current) setMutationError("Could not confirm credential rotation. Refresh the agent before trying again."); }
    finally { mutationBusy.current = false; if (alive.current) setBusy(false); }
  }
  async function removeAgent() {
    if (!org || !agentId || mutationBusy.current || profile.kind !== "ready" || !profile.data.permissions.revoke) return;
    mutationBusy.current = true; setBusy(true); setMutationError("");
    let revoked = false;
    try {
      const result = await api.POST("/api/v1/organizations/{orgId}/devices/{deviceId}/revoke", { params: { path: { orgId: org.id, deviceId: agentId } } });
      if (!alive.current) return;
      if (result.error) { setMutationError("Could not revoke the agent."); return; }
      revoked = true;
      const removed = await api.DELETE("/api/v1/organizations/{orgId}/devices/{deviceId}", { params: { path: { orgId: org.id, deviceId: agentId } } });
      if (!alive.current) return;
      if (removed.error) { setMutationError("The agent was revoked but could not be removed from the roster."); return; }
      setRemoveOpen(false);
      navigate("/agents");
    } catch { if (alive.current) setMutationError(revoked ? "The agent was revoked. Could not confirm removal; refresh the roster before trying again." : "Could not confirm revocation. Refresh the agent before trying again."); }
    finally { mutationBusy.current = false; if (alive.current) setBusy(false); }
  }

  if (!org) return <Loading label="Loading organization…" />;
  const data = profile.kind === "ready" ? profile.data : null;
  const detailSubtitle = data ? [data.environment, data.runtime].filter(Boolean).join(" · ") : "";
  const actionBlock = busy ? "An update is in progress." : null;
  const actions: AppAccessRowMenuAction[] = data ? [
    ...(data.permissions.manage ? [{ key: "profile", label: "Edit profile", disabledReason: actionBlock, onSelect: () => { setMutationError(""); setProfileEditorOpen(true); } }] : []),
    ...(data.permissions.assign ? [{ key: "assignment", label: "Change ownership", disabledReason: actionBlock, onSelect: () => { setMutationError(""); setAssignmentOpen(true); } }] : []),
    ...(data.permissions.revoke ? [{ key: "remove", label: "Remove agent", danger: true, disabledReason: actionBlock, onSelect: () => { setMutationError(""); setRemoveOpen(true); } }] : []),
  ] : [];
  const tabIndex = tabs.indexOf(tab);
  return <div className="agent-detail-workspace">
    <nav className="agent-detail-breadcrumb" aria-label="AI Agent breadcrumb"><Link to="/agents">AI Agents</Link><span aria-hidden="true">/</span><span aria-current="page">{data?.name ?? "Agent"}</span></nav>
    {data && <header className="agent-detail-header"><div><h1>{data.name}</h1>{detailSubtitle && <p>{detailSubtitle}</p>}</div><span className={`agent-detail-status agent-detail-status-${data.status}`}>{data.status}</span><RefreshButton label="Refresh agent" disabled={busy} onClick={refreshAgent} /><AppAccessRowMenu label={`Agent actions for ${data.name}`} actions={actions} /></header>}
    <ReadState state={profile} onRetry={refreshAgent} title="Agent unavailable" retryLabel="Retry agent">{(agent) => <div className="agent-detail-layout">
      <nav role="tablist" aria-label="Agent workspace" aria-orientation="vertical" className="agent-detail-rail" onKeyDown={navigateTabs}>{tabs.map(item => <button key={item} type="button" role="tab" tabIndex={tab === item ? 0 : -1} aria-selected={tab === item} aria-current={tab === item ? "page" : undefined} aria-controls="agent-detail-stage" onClick={() => switchTab(item)}>{tabLabel[item]}</button>)}</nav>
      <section id="agent-detail-stage" className="agent-detail-stage" role="tabpanel" aria-label={tabLabel[tab]}>
        <ResourceSummary title={tabLabel[tab]} headingLevel={2} className={`agent-detail-summary agent-detail-summary-${tab}`} footer={<>
          {tabIndex > 0 ? <Button variant="ghost" onClick={() => switchTab(tabs[tabIndex - 1])}>Back to {tabLabel[tabs[tabIndex - 1]].toLowerCase()}</Button> : <Link className="agent-detail-text-link" to="/agents">All agents</Link>}
          {tabIndex < tabs.length - 1 && <Button variant="ghost" onClick={() => switchTab(tabs[tabIndex + 1])}>View {tabLabel[tabs[tabIndex + 1]].toLowerCase()}</Button>}
        </>}>
        {tab === "overview" && <>
          <dl className="agent-detail-facts tnx-resource-facts tnx-resource-facts-three">
            <div><dt>Accountable owner</dt><dd>{agent.owner_email || "Unassigned"}</dd></div>
            <div><dt>Managing group</dt><dd>{agent.managing_group_name || "None"}</dd></div>
            <div><dt>Last handshake</dt><dd title={agent.last_handshake_at ?? undefined}>{agent.last_handshake_at ? age(agent.last_handshake_at) : "Never reported"}</dd></div>
            <div><dt>Environment</dt><dd>{agent.environment || "Not supplied"}</dd></div>
            <div><dt>Runtime</dt><dd>{agent.runtime || "Not supplied"}</dd></div>
          </dl>
          <p className="sr-only">Lifecycle comes from the agent profile. Handshake freshness is reported separately.</p>
          <details className="agent-detail-disclosure"><summary>Identity &amp; labels</summary><dl className="agent-detail-facts tnx-resource-facts"><div className="tnx-resource-fact-wide"><dt>Agent ID</dt><dd><code>{agent.device_id}</code></dd></div>{Object.entries(agent.labels).map(([key, value]) => <div key={key}><dt>{key}</dt><dd>{value}</dd></div>)}{Object.keys(agent.labels).length === 0 && <div><dt>Labels</dt><dd>None</dd></div>}</dl></details>
        </>}
        {tab === "runtime" && <>
          {org.managed_agent_runtime_enabled === false ? <div className="agent-detail-notice" role="status"><h3>Runtime synchronization off</h3><p>Enable synchronization to receive managed runtime reports.</p><Link className="agent-detail-text-link" to="/settings?section=features&feature=agent-runtime">Review runtime settings</Link></div> : <ReadState state={runtime} onRetry={refreshAgent} title="Runtime unavailable" retryLabel="Retry runtime">{(value) => <Panel title="Managed runtime"><dl className="agent-detail-facts tnx-resource-facts">
            <div><dt>Connectivity</dt><dd>{value.connectivity}</dd></div>
            <div><dt>Health</dt><dd>{value.health === "last_good" ? "Last good" : value.health === "ready" ? "Ready" : "Inconclusive"}</dd></div>
            <div><dt>Last report</dt><dd title={value.last_seen_at ?? undefined}>{value.last_seen_at ? `${age(value.last_seen_at)}${value.stale ? " (stale)" : ""}` : "Never reported"}</dd></div>
            <div><dt>Revision</dt><dd>{value.applied_revision} applied / {value.desired_revision} desired</dd></div>
            {value.client_version && <div><dt>Client version</dt><dd>{value.client_version}</dd></div>}
            {value.last_error_code && <div><dt>Last apply error</dt><dd>{value.last_error_code}{value.last_error_revision != null && <small>Revision {value.last_error_revision}</small>}</dd></div>}
          </dl><p className="agent-detail-context">Source: agent runtime report. {value.stale ? "The server marks this report stale." : "The server considers this report fresh."}</p></Panel>}</ReadState>}
          <ReadState state={rotation} onRetry={refreshAgent} title="Credential status unavailable" retryLabel="Retry credentials">{(value) => <Panel title="Credential rotation"><dl className="agent-detail-facts tnx-resource-facts"><div><dt>Runtime credential</dt><dd>Revision {value.current_revision} · {value.state}</dd></div><div><dt>WireGuard key</dt><dd>Revision {value.wireguard_current_revision} · {value.wireguard_state}</dd></div>{value.deadline && <div><dt>Deadline</dt><dd>{value.deadline}</dd></div>}</dl>{agent.permissions.rotate_credentials && <div className="agent-detail-panel-actions"><Button variant="ghost" size="sm" disabled={busy || agent.status !== "active" || value.state !== "current" || value.wireguard_state !== "current"} onClick={() => void rotateCredential()}>Rotate credential</Button></div>}</Panel>}</ReadState>
        </>}
        {tab === "mcp" && <>
          <ReadState state={effectiveMCP} onRetry={refreshAgent} title="MCP profile unavailable" retryLabel="Retry MCP profile">{(value) => <Panel title="Effective MCP profile">{value.assigned ? <><dl className="agent-detail-facts tnx-resource-facts"><div><dt>Profile</dt><dd>{value.profile_name ?? "MCP profile"}</dd></div><div><dt>Inherited from</dt><dd>{value.group_name ?? "Source group"}</dd></div>{value.endpoint && <div className="tnx-resource-fact-wide"><dt>Endpoint</dt><dd><code>{value.endpoint}</code></dd></div>}</dl><p className="agent-detail-context">Changing the shared group profile affects every member of that group.</p></> : <p className="agent-detail-context">No MCP profile is inherited through this agent’s groups.</p>}<Link className="agent-detail-text-link" to={`/mcp${value.group_id ? `?group=${value.group_id}` : ""}`}>Manage MCP profiles</Link></Panel>}</ReadState>
          {inventory.kind === "error" && inventory.code === "mcp_inventory_not_found" ? <div className="agent-detail-empty" role="status"><h3>No MCP inventory reported yet.</h3><p>Tool policy and OAuth controls require a reported inventory.</p></div> : <ReadState state={inventory} onRetry={refreshAgent} title="MCP inventory unavailable" retryLabel="Retry MCP inventory">{(value) => <>
            <ObservedMCP data={value} />
            <Panel title="MCP tool policy"><AgentMCPToolPolicyPanel orgId={org.id} deviceId={agentId} inventory={value} canManage={can(myRole, "agent_mcp_tool_policy:manage")} /></Panel>
            <MCPAuthentication orgId={org.id} deviceId={agentId} inventory={value} canManage={agent.permissions.manage} />
            <Panel title="Step-up approvals"><AgentMCPToolApprovalPanel orgId={org.id} deviceId={agentId} canApprove={can(myRole, "agent_mcp_tool_approval:approve")} /></Panel>
          </>}</ReadState>}
        </>}
        {tab === "access" && <>
          <div className="agent-detail-access-links"><Link className="agent-detail-text-link" to="/access">Open Access Policies</Link><p className="sr-only">Access is evaluated by organization policy.</p></div>
          <Panel title="Just-in-time access"><ReadState state={licence} onRetry={refreshAgent} title="Licence status unavailable" retryLabel="Retry licence status">{(status) => status.features.includes("agent_jit_access") ? org.agent_jit_access_enabled ? <><p className="agent-detail-context">Request temporary access, then track approval and expiry.</p><Link className="agent-detail-text-link" to={`/access?agent=${encodeURIComponent(agent.device_id)}#agent-jit-access`}>Manage temporary access</Link></> : <><p className="agent-detail-context">This capability is included in your plan but is not enabled for this organization.</p><Link className="agent-detail-text-link" to="/settings?section=features&feature=agent-jit">Review organization settings</Link></> : <><p className="agent-detail-context">This capability is not included in your current plan.</p><Link className="agent-detail-text-link" to="/settings?section=licence">Licence &amp; Plan</Link></>}</ReadState></Panel>
          <details className="agent-detail-disclosure"><summary><h3>Authority</h3></summary><dl className="agent-detail-facts tnx-resource-facts">{([["Manage", agent.permissions.manage], ["Assign ownership", agent.permissions.assign], ["Grant access", agent.permissions.grant_access], ["Rotate credentials", agent.permissions.rotate_credentials], ["Remove", agent.permissions.revoke]] as const).map(([label, allowed]) => <div key={label}><dt>{label}</dt><dd>{allowed ? "Allowed" : "Not allowed"}</dd></div>)}</dl></details>
        </>}
        {tab === "activity" && <div className="agent-detail-activity">{provenance.kind === "ready" && provenance.data.length === 0 ? <div className="agent-detail-empty" role="status"><h3>No workflow activity recorded</h3><p>Review related events for more context.</p></div> : <ReadState state={provenance} onRetry={refreshAgent} title="Workflow activity unavailable" retryLabel="Retry workflow activity">{items => <Panel title="Workflow history"><p className="sr-only">Signed workflow provenance received by the control plane.</p><AgentWorkflowProvenancePanel records={items} /></Panel>}</ReadState>}<div className="agent-detail-related-links"><Link className="agent-detail-text-link" to="/access-events">Access Events</Link><Link className="agent-detail-text-link" to="/audit">Audit Log</Link></div></div>}
        {mutationError && !profileEditorOpen && !assignmentOpen && !removeOpen && <p role="alert" className="agent-detail-error">{mutationError}</p>}
        </ResourceSummary>
      </section>
    </div>}</ReadState>
    {profileEditorOpen && data?.permissions.manage && <Modal title="Edit agent profile" placement="right" size="enrollment" showClose onDismiss={() => !busy && setProfileEditorOpen(false)} actions={<Button variant="ghost" disabled={busy} onClick={() => setProfileEditorOpen(false)}>Close</Button>}><div className="agent-detail-editor agent-detail-profile-editor">{mutationError && <p role="alert" className="agent-detail-error">{mutationError}</p>}<AgentProfileEditor key={`${data.device_id}:${data.status}:${data.environment}:${data.runtime}:${JSON.stringify(data.labels)}`} value={{ environment: data.environment, runtime: data.runtime, labels: data.labels, status: data.status as AgentProfileStatus }} canManageLifecycle={data.permissions.manage} disabled={busy} onSaveMetadata={(value: AgentProfileEditorValue) => void updateProfile(value, "Could not save agent metadata.").then(saved => saved && alive.current && setProfileEditorOpen(false))} onLifecycleChange={status => void updateProfile({ status }, "Could not change the agent lifecycle.").then(saved => saved && alive.current && setProfileEditorOpen(false))} /></div></Modal>}
    {assignmentOpen && data?.permissions.assign && <Modal title="Change agent ownership" placement="right" size="enrollment" showClose onDismiss={() => !busy && setAssignmentOpen(false)} actions={<Button variant="ghost" disabled={busy} onClick={() => setAssignmentOpen(false)}>Close</Button>}><div className="agent-detail-editor agent-detail-ownership-editor">{mutationError && <p role="alert" className="agent-detail-error">{mutationError}</p>}<AgentAssignment key={`${data.device_id}:${data.owner_id}:${data.managing_group_id ?? ""}`} profile={data} members={members} groups={groups} busy={busy} onSave={body => void updateProfile(body, "Could not save the agent assignment.").then(saved => saved && alive.current && setAssignmentOpen(false))} /></div></Modal>}
    {removeOpen && data?.permissions.revoke && <Modal title={`Remove ${data.name}?`} placement="right" size="enrollment" showClose danger onDismiss={() => !busy && setRemoveOpen(false)} actions={<><Button variant="ghost" disabled={busy} onClick={() => setRemoveOpen(false)}>Cancel</Button><Button variant="danger" disabled={busy} onClick={() => void removeAgent()}>{busy ? "Removing…" : "Revoke and remove"}</Button></>}><div className="agent-detail-editor agent-detail-remove-editor"><p>This first revokes the agent’s tunnel credential, then removes the roster record. Pending credential rotation is cancelled. Access-policy evidence is retained for review; recovery requires enrolling a new agent.</p>{mutationError && <p role="alert" className="agent-detail-error">{mutationError}</p>}</div></Modal>}
  </div>;
}
