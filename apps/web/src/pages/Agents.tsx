import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useOrg } from "../lib/useOrg";
import { api, loadOne, type Loaded, type Member, type Role, type UserGroup } from "../lib/api";
import { useAuth } from "../lib/auth";
import { can } from "../lib/rbac";
import {
  agentBootstrapCommand,
  AGENT_PREREQ,
  attributionNote,
  NO_AGENTS,
  sortAgents,
  livenessLabel,
  agentLiveness,
  formatTraffic,
  type AgentRow,
} from "../lib/agentview";
import {
  Badge,
  Button,
  Card,
  DataTable,
  Field,
  Input,
  PageHeader,
  Select,
  StatusDot,
} from "../components/ui";
import { AgentProfileEditor, type AgentProfileEditorValue, type AgentProfileStatus } from "../components/AgentProfileEditor";
import { OneTimeSecretModal } from "../components/OneTimeSecret";
import type { components } from "@tunnex/shared";

type AgentProfile = components["schemas"]["AgentProfile"];

type Node = {
  id: string;
  name: string;
  status: string;
  endpoint?: string | null;
  last_seen_at?: string;
};

type AgentRuntimeStatus = components["schemas"]["AgentRuntimeStatus"];
type AgentCredentialRotationStatus = components["schemas"]["AgentCredentialRotationStatus"];

function AgentRuntimePanel({ status }: { status: AgentRuntimeStatus }) {
  const healthLabel = status.health === "last_good"
    ? "Last-good configuration"
    : status.health === "ready"
      ? "Ready"
      : "Inconclusive";
  return (
    <div data-testid="agent-runtime-status" className="grid gap-2 text-xs text-slate-300 sm:grid-cols-3">
      <div>
        <span className="text-slate-500">Desired revision</span>
        <div className="font-mono">{status.desired_revision}</div>
      </div>
      <div>
        <span className="text-slate-500">Applied revision</span>
        <div className="font-mono">{status.applied_revision}</div>
      </div>
      <div>
        <span className="text-slate-500">Last attempted revision</span>
        <div className="font-mono">{status.last_attempted_revision}</div>
      </div>
      <div>
        <span className="text-slate-500">Connectivity</span>
        <div>{status.connectivity}</div>
      </div>
      <div>
        <span className="text-slate-500">Last seen</span>
        <div>{status.last_seen_at ?? "never reported"}</div>
      </div>
      <div>
        <span className="text-slate-500">Runtime health</span>
        <div>{healthLabel}</div>
      </div>
      <div>
        <span className="text-slate-500">Report freshness</span>
        <div>{status.stale ? "Stale report" : "Fresh report"}</div>
      </div>
      {status.last_error_code && (
        <div>
          <span className="text-slate-500">Last error</span>
          <div>{status.last_error_code}</div>
        </div>
      )}
    </div>
  );
}

function AgentQuotaCard({
  orgId,
  value,
  canEdit,
}: {
  orgId: string;
  value: number | null;
  canEdit: boolean;
}) {
  const [input, setInput] = useState(value == null ? "" : String(value));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    setInput(value == null ? "" : String(value));
  }, [orgId, value]);

  async function save() {
    setBusy(true);
    setError(null);
    setSaved(false);
    const parsed = input.trim() === "" ? null : Number(input);
    if (parsed !== null && (!Number.isInteger(parsed) || parsed < 0)) {
      setBusy(false);
      setError("Enter a non-negative whole number, or leave blank for unlimited.");
      return;
    }
    const result = await api.PUT("/api/v1/organizations/{orgId}/agent-quota", {
      params: { path: { orgId } },
      body: { max_agent_identities: parsed },
    });
    setBusy(false);
    if (result.error || !result.data) {
      setError("Could not save the agent quota.");
      return;
    }
    // The successful scoped mutation response is the server-owned truth. Do not refetch the
    // organization collection here: organization selection belongs exclusively to useOrg.
    const serverValue = result.data.max_agent_identities;
    setInput(serverValue == null ? "" : String(serverValue));
    setSaved(true);
  }

  if (!canEdit) return null;
  return (
    <Card data-testid="agent-quota-card">
      <h2 className="text-sm font-semibold text-ink-heading">Managed-agent quota</h2>
      <p className="mt-1 text-xs text-ink-secondary">
        Maximum organization-wide agent identities. Pending, active, and suspended agents count; revoked and deleted agents do not. Leave blank for unlimited.
      </p>
      <div className="mt-3 flex flex-wrap items-end gap-3">
        <Field label="Maximum identities">
          <Input
            inputMode="numeric"
            value={input}
            onChange={(e) => { setInput(e.target.value); setSaved(false); }}
            placeholder="Unlimited"
            disabled={busy}
            aria-label="Maximum agent identities"
          />
        </Field>
        <Button onClick={() => void save()} disabled={busy}>
          {busy ? "Saving…" : "Save quota"}
        </Button>
      </div>
      {saved && <p className="mt-2 text-xs text-accent-400">Quota saved from server response.</p>}
      {error && <p role="alert" className="mt-2 text-xs text-danger">{error}</p>}
    </Card>
  );
}

function AgentRuntimeSettingCard({
  orgId,
  value,
  canEdit,
  onSaved,
}: {
  orgId: string;
  value: boolean;
  canEdit: boolean;
  onSaved: (enabled: boolean) => void;
}) {
  const [enabled, setEnabled] = useState(value);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => setEnabled(value), [orgId, value]);

  async function toggle() {
    const next = !enabled;
    setBusy(true);
    setError(null);
    const result = await api.PUT(
      "/api/v1/organizations/{orgId}/agent-runtime-settings",
      { params: { path: { orgId } }, body: { enabled: next } },
    );
    setBusy(false);
    if (result.error || !result.data) {
      setError("Could not update managed runtime synchronization.");
      return;
    }
    setEnabled(result.data.enabled);
    onSaved(result.data.enabled);
  }

  // Permission-gated controls are absent from the DOM, not merely disabled.
  if (!canEdit) return null;
  return (
    <Card data-testid="agent-runtime-setting-card">
      <h2 className="text-sm font-semibold text-ink-heading">Runtime synchronization</h2>
      <p className="mt-1 text-xs text-ink-secondary">
        Off by default. Enable the managed runtime channel only when this organization is ready for server-owned configuration updates.
      </p>
      <div className="mt-3">
        <Button onClick={() => void toggle()} disabled={busy}>
          {busy ? "Saving…" : enabled ? "Disable runtime synchronization" : "Enable runtime synchronization"}
        </Button>
      </div>
      {error && <p role="alert" className="mt-2 text-xs text-danger">{error}</p>}
    </Card>
  );
}

function AgentProfilePanel({
  profile,
  runtime,
  credentialRotation,
  editorVersion,
  canManageLifecycle,
  canRotateCredential,
  assignmentMembers,
  assignmentGroups,
  onSaveMetadata,
  onSaveAssignment,
  onLifecycleChange,
  onRotateCredential,
  disabled,
}: {
  profile: AgentProfile;
  runtime: AgentRuntimeStatus | null;
  credentialRotation: AgentCredentialRotationStatus | null;
  editorVersion: number;
  canManageLifecycle: boolean;
  canRotateCredential: boolean;
  assignmentMembers: Member[];
  assignmentGroups: UserGroup[];
  onSaveMetadata: (value: AgentProfileEditorValue) => void;
  onSaveAssignment: (value: { owner_id?: string; managing_group_update?: { group_id: string | null } }) => void;
  onLifecycleChange: (status: "active" | "suspended") => void;
  onRotateCredential: () => void;
  disabled: boolean;
}) {
  return (
    <div data-testid="agent-profile" className="grid gap-3 text-xs text-slate-300">
      <div className="grid gap-2 sm:grid-cols-3">
        <div><span className="text-slate-500">Owner</span><div>{profile.owner_email}</div></div>
        <div><span className="text-slate-500">Managing team</span><div>{profile.managing_group_name ?? "None"}</div></div>
        <div><span className="text-slate-500">Telemetry</span><div>{profile.last_handshake_at ?? "never reported"}</div></div>
        {profile.rx_bytes != null && <div><span className="text-slate-500">Received</span><div className="font-mono">{profile.rx_bytes}</div></div>}
        {profile.tx_bytes != null && <div><span className="text-slate-500">Sent</span><div className="font-mono">{profile.tx_bytes}</div></div>}
      </div>
      <AgentProfileEditor
        key={`${profile.device_id}:${editorVersion}:${profile.status}:${profile.environment}:${profile.runtime}:${JSON.stringify(profile.labels)}`}
        value={{ environment: profile.environment, runtime: profile.runtime, labels: profile.labels, status: profile.status as AgentProfileStatus }}
        canManageLifecycle={canManageLifecycle}
        onSaveMetadata={onSaveMetadata}
        onLifecycleChange={onLifecycleChange}
        disabled={disabled}
      />
      {profile.permissions.assign && (
        <AgentAssignmentEditor
          key={`${profile.device_id}:${profile.owner_id}:${profile.managing_group_id ?? "none"}`}
          profile={profile}
          members={assignmentMembers}
          groups={assignmentGroups}
          onSave={onSaveAssignment}
          disabled={disabled}
        />
      )}
      {runtime && <AgentRuntimePanel status={runtime} />}
      {credentialRotation && (
        <div data-testid="agent-credential-rotation" className="flex flex-wrap items-center gap-3 rounded-md border border-slate-700 p-3">
          <div>
            <div className="text-slate-500">Runtime credential</div>
            <div>Revision {credentialRotation.current_revision} · {credentialRotation.state}</div>
            <div className="text-slate-500">WireGuard key</div>
            <div>Revision {credentialRotation.wireguard_current_revision} · {credentialRotation.wireguard_state}</div>
            {credentialRotation.deadline && <div className="text-slate-500">Deadline {credentialRotation.deadline}</div>}
          </div>
          {canRotateCredential && (
            <Button onClick={onRotateCredential} disabled={disabled || profile.status !== "active" || credentialRotation.state !== "current" || credentialRotation.wireguard_state !== "current"}>
              Rotate credential
            </Button>
          )}
        </div>
      )}
    </div>
  );
}

function AgentAssignmentEditor({
  profile,
  members,
  groups,
  onSave,
  disabled,
}: {
  profile: AgentProfile;
  members: Member[];
  groups: UserGroup[];
  onSave: (value: { owner_id?: string; managing_group_update?: { group_id: string | null } }) => void;
  disabled: boolean;
}) {
  const [ownerId, setOwnerId] = useState(profile.owner_id);
  const [groupId, setGroupId] = useState(profile.managing_group_id ?? "");
  const nextGroupId = groupId || null;
  const ownerChanged = ownerId !== profile.owner_id;
  const groupChanged = nextGroupId !== profile.managing_group_id;

  function save() {
    const value: { owner_id?: string; managing_group_update?: { group_id: string | null } } = {};
    if (ownerChanged) value.owner_id = ownerId;
    if (groupChanged) value.managing_group_update = { group_id: nextGroupId };
    onSave(value);
  }

  return (
    <div data-testid="agent-assignment-editor" className="grid gap-3 rounded-md border border-slate-700 p-3">
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Accountable owner">
          <Select value={ownerId} onChange={(event) => setOwnerId(event.target.value)} disabled={disabled}>
            {members.map((member) => <option key={member.user_id} value={member.user_id}>{member.email}</option>)}
          </Select>
        </Field>
        <Field label="Managing team">
          <Select value={groupId} onChange={(event) => setGroupId(event.target.value)} disabled={disabled}>
            <option value="">No managing team</option>
            {groups.map((group) => <option key={group.id} value={group.id}>{group.name}</option>)}
          </Select>
        </Field>
      </div>
      <p className="text-[11px] text-ink-secondary">
        Changing the owner changes accountability only; it does not change the tunnel or access grants.
        A managing team can view and manage this agent, but cannot grant access, rotate credentials, or revoke it.
      </p>
      <div><Button onClick={save} disabled={disabled || !ownerId || (!ownerChanged && !groupChanged)}>Save assignment</Button></div>
    </div>
  );
}

/**
 * AI agents — S15.3. A top-level destination in NETWORK, beside Kubernetes.
 *
 * ⛔ AN AGENT IS A PEER HOMED ON A GATEWAY. It is enrolled the way any device is: it holds its own /32, it
 * dials the gateway with a WireGuard config, and its traffic is FORWARDED through that gateway — which is
 * what puts it in front of the policy chain. A grant then names that one device.
 *
 * ⛔ THE RENDER FLOOR GOVERNS EVERY STRING HERE (see lib/agentview.ts, tests enforce it): no DETECTION
 * language, no PER-TOOL claim. The honest verb is REACH.
 *
 * ⛔ ENTERPRISE. The open edition gets 403 edition_required — a SUCCESSFUL refusal — and this screen renders
 * ABSENCE, never an error.
 */
export default function Agents() {
  // ⛔ THE ORG COMES FROM THE SEAM (S12.5).
  const { org: currentOrg } = useOrg();
  const { state: authState } = useAuth();
  const currentUserId = authState.status === "authed" ? authState.user.id : null;
  const [orgId, setOrgId] = useState<string | null>(null);
  const [rows, setRows] = useState<Loaded<AgentRow[]> | null>(null);
  const [runtimeStatus, setRuntimeStatus] = useState<Record<string, AgentRuntimeStatus | null>>({});
  const [credentialRotation, setCredentialRotation] = useState<Record<string, AgentCredentialRotationStatus | null>>({});
  const [profiles, setProfiles] = useState<Record<string, AgentProfile | null>>({});
  const [myRole, setMyRole] = useState<Role>();
  const [assignmentMembers, setAssignmentMembers] = useState<Member[]>([]);
  const [assignmentGroups, setAssignmentGroups] = useState<UserGroup[]>([]);
  const [gateways, setGateways] = useState<Node[]>([]);
  const [notEntitled, setNotEntitled] = useState(false);
  const [runtimeEnabled, setRuntimeEnabled] = useState(false);

  const [name, setName] = useState("");
  const [gw, setGw] = useState("");
  const [conf, setConf] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [reload, setReload] = useState(0);
  const [confirmRemove, setConfirmRemove] = useState<AgentRow | null>(null);
  const [removing, setRemoving] = useState(false);
  const [profileBusy, setProfileBusy] = useState<string | null>(null);
  const [profileEditorVersion, setProfileEditorVersion] = useState(0);
  const [profileError, setProfileError] = useState<string | null>(null);
  const [confirmLifecycle, setConfirmLifecycle] = useState<{ agent: AgentRow; status: "active" | "suspended" } | null>(null);

  useEffect(() => {
    setRuntimeEnabled(currentOrg?.managed_agent_runtime_enabled === true);
  }, [currentOrg?.id, currentOrg?.managed_agent_runtime_enabled]);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      // ⭐ The org-list fetch is gone (S12.5); the seam supplies it.
      if (cancelled || !currentOrg) return;
      const id = currentOrg.id;
      setOrgId(id);
      setRows(null);
      setGateways([]);
      setGw("");
      setNotEntitled(false);
      setRuntimeStatus({});
      setCredentialRotation({});
      setProfiles({});
      setMyRole(undefined);
      setAssignmentMembers([]);
      setAssignmentGroups([]);

      const n = await loadOne<Node[]>(() =>
        api.GET("/api/v1/organizations/{orgId}/nodes", {
          params: { path: { orgId: id } },
        }),
      );
      if (!cancelled && n.ok) {
        // ⛔ A GATEWAY WITH NO ENDPOINT CANNOT SERVE A PEER. Issuing a config for one emits
        // `Endpoint = ` and wg-quick refuses it — so the operator would be handed a command that can
        // never work. Excluded here rather than surfaced as a choice: a control that can only fail is
        // worse than a control that is absent.
        const live = n.data.filter(
          (x) => x.status === "active" && !!(x.endpoint && x.endpoint.trim()),
        );
        setGateways(live);
        setGw((g) => g || live[0]?.id || "");
      }

      const { data, error, response } = await api.GET(
        "/api/v1/organizations/{orgId}/agents",
        { params: { path: { orgId: id } } },
      );
      if (cancelled) return;
      // ⛔ 403 IS NOT A FAILURE — it is the server correctly stating an edition boundary. A 401 is likewise
      // an auth-router refusal: unauthenticated users must not receive an error-shaped Agents surface or facts.
      // Any OTHER error is real and must not render as "no agents": a failed load shown as emptiness is a zero
      // nobody measured.
      if (response?.status === 401 || response?.status === 403) {
        setNotEntitled(true);
        return;
      }
      if (error || !data) {
        setRows({ ok: false, error: "Could not load agents." });
        return;
      }
      setRows({ ok: true, data: data as AgentRow[] });

      let loadedRole: Role | undefined;
      if (currentUserId) {
        const members = await api.GET("/api/v1/organizations/{orgId}/members", { params: { path: { orgId: id } } });
        if (!cancelled && members.data) {
          const member = members.data.find((candidate) => candidate.user_id === currentUserId);
          loadedRole = member?.role as Role | undefined;
          setMyRole(loadedRole);
          if (can(loadedRole, "agent:manage")) {
            setAssignmentMembers((members.data as Member[]).filter((candidate) => candidate.status === "active"));
            const groups = await api.GET("/api/v1/organizations/{orgId}/groups", { params: { path: { orgId: id } } });
            if (!cancelled && groups.data) setAssignmentGroups(groups.data as UserGroup[]);
          }
        }
      }

      for (const agent of data as AgentRow[]) {
        void api.GET("/api/v1/organizations/{orgId}/agents/{deviceId}", {
          params: { path: { orgId: id, deviceId: agent.device_id } },
        }).then((profileResult) => {
          if (cancelled || profileResult.error || !profileResult.data) return;
          const profile = profileResult.data as AgentProfile;
          setProfiles((previous) => ({ ...previous, [agent.device_id]: profile }));
          void api.GET(
            "/api/v1/organizations/{orgId}/agents/{deviceId}/runtime-status",
            { params: { path: { orgId: id, deviceId: agent.device_id } } },
          ).then((runtimeResult) => {
            if (cancelled || runtimeResult.error || !runtimeResult.data) return;
            setRuntimeStatus((previous) => ({ ...previous, [agent.device_id]: runtimeResult.data as AgentRuntimeStatus }));
          });
          void api.GET(
            "/api/v1/organizations/{orgId}/agents/{deviceId}/credential-rotation",
            { params: { path: { orgId: id, deviceId: agent.device_id } } },
          ).then((rotationResult) => {
            if (cancelled || rotationResult.error || !rotationResult.data) return;
            setCredentialRotation((previous) => ({ ...previous, [agent.device_id]: rotationResult.data as AgentCredentialRotationStatus }));
          });
        });
      }
    })();
    return () => {
      cancelled = true;
    };
    // ⚠ currentOrg IS A DEPENDENCY — without it the switcher moves and the page keeps showing the org it
    // mounted with.
  }, [reload, currentOrg, currentUserId]);

  async function saveProfileMetadata(agent: AgentRow, value: AgentProfileEditorValue) {
    if (!orgId) return;
    setProfileBusy(agent.device_id);
    setProfileError(null);
    const result = await api.PATCH("/api/v1/organizations/{orgId}/agents/{deviceId}", {
      params: { path: { orgId, deviceId: agent.device_id } },
      body: value,
    });
    setProfileBusy(null);
    if (result.error || !result.data) {
      setProfileError("Could not save agent metadata.");
      setProfileEditorVersion((version) => version + 1);
      return;
    }
    setReload((n) => n + 1);
  }

  async function saveAgentAssignment(
    agent: AgentRow,
    value: { owner_id?: string; managing_group_update?: { group_id: string | null } },
  ) {
    if (!orgId || Object.keys(value).length === 0) return;
    setProfileBusy(agent.device_id);
    setProfileError(null);
    const result = await api.PATCH("/api/v1/organizations/{orgId}/agents/{deviceId}", {
      params: { path: { orgId, deviceId: agent.device_id } },
      body: value,
    });
    setProfileBusy(null);
    if (result.error || !result.data) {
      setProfileError("Could not save the agent assignment.");
      return;
    }
    setReload((revision) => revision + 1);
  }

  async function applyLifecycle(agent: AgentRow, status: "active" | "suspended") {
    if (!orgId) return;
    setConfirmLifecycle(null);
    setProfileBusy(agent.device_id);
    setProfileError(null);
    const result = await api.PATCH("/api/v1/organizations/{orgId}/agents/{deviceId}", {
      params: { path: { orgId, deviceId: agent.device_id } },
      body: { status },
    });
    setProfileBusy(null);
    if (result.error || !result.data) {
      setProfileError("Could not change the agent lifecycle.");
      setProfileEditorVersion((version) => version + 1);
      return;
    }
    setReload((n) => n + 1);
  }

  async function rotateCredential(agent: AgentRow) {
    if (!orgId) return;
    setProfileBusy(agent.device_id);
    setProfileError(null);
    const requested = await api.POST(
      "/api/v1/organizations/{orgId}/agents/{deviceId}/credential-rotation",
      { params: { path: { orgId, deviceId: agent.device_id } } },
    );
    if (requested.error) {
      setProfileBusy(null);
      setProfileError("Could not request credential rotation.");
      return;
    }
    // Refetch server state; do not render optimistic status from the mutation.
    const refreshed = await api.GET(
      "/api/v1/organizations/{orgId}/agents/{deviceId}/credential-rotation",
      { params: { path: { orgId, deviceId: agent.device_id } } },
    );
    setProfileBusy(null);
    if (refreshed.error || !refreshed.data) {
      setProfileError("Rotation was requested but its status could not be refreshed.");
      return;
    }
    setCredentialRotation((previous) => ({ ...previous, [agent.device_id]: refreshed.data as AgentCredentialRotationStatus }));
  }

  async function enrol() {
    if (!orgId || !gw) return;
    setBusy(true);
    setErr(null);
    // Managed bootstrap: the browser issues a one-time org+gateway token. The agent host generates its
    // private key locally and redeems the token with only its public key.
    const { data, error } = await api.POST(
      "/api/v1/organizations/{orgId}/agents/bootstrap-token",
      {
        params: { path: { orgId } },
        body: {
          name: name.trim(),
          gateway_id: gw,
        },
      },
    );
    setBusy(false);
    if (error || !data) {
      setErr("Could not enrol the agent.");
      return;
    }
    setConf(agentBootstrapCommand(data.bootstrap_token, data.release));
    setName("");
  }

  // Agent lifecycle uses the device safety contract: revoke first so its key is
  // dead, then remove the already-revoked roster row. Never expose a raw delete.
  async function removeAgent(agent: AgentRow) {
    if (!orgId) return;
    setRemoving(true);
    setErr(null);
    const revoke = await api.POST(
      "/api/v1/organizations/{orgId}/devices/{deviceId}/revoke",
      { params: { path: { orgId, deviceId: agent.device_id } } },
    );
    if (revoke.error) {
      setErr("Could not revoke the agent.");
      setRemoving(false);
      return;
    }
    const removed = await api.DELETE(
      "/api/v1/organizations/{orgId}/devices/{deviceId}",
      { params: { path: { orgId, deviceId: agent.device_id } } },
    );
    if (removed.error) {
      setErr("The agent was revoked but could not be removed from the roster.");
      setRemoving(false);
      setReload((n) => n + 1);
      return;
    }
    setConfirmRemove(null);
    setRemoving(false);
    setReload((n) => n + 1);
  }

  // A route render may run once with the prior org's state before the loading effect clears it.
  // Refuse that frame completely: privileged owner/team/runtime facts never enter the new org's DOM.
  if (currentOrg && orgId !== currentOrg.id) {
    return <Card>Loading agents…</Card>;
  }
  if (notEntitled) return null;

  return (
    <div className="flex flex-col gap-3.5">
      <div>
        <PageHeader
          title="AI agents"
          subtitle="An agent connects to a gateway over the tunnel and reaches only what it is granted."
        />
      </div>

      {orgId && (
        <>
          <AgentRuntimeSettingCard
            orgId={orgId}
            value={runtimeEnabled}
            canEdit={can(myRole, "agent_runtime:manage")}
            onSaved={(enabled) => { setRuntimeEnabled(enabled); setReload((n) => n + 1); }}
          />
          <AgentQuotaCard
            orgId={orgId}
            value={currentOrg?.max_agent_identities ?? null}
            canEdit={can(myRole, "org:update")}
          />
        </>
      )}

      {/* ⛔ THE CREATION PATH. Pick the gateway the agent connects through, name it, and get the command to
          run on the agent's own host. */}
      {can(myRole, "agent:enroll") && <Card>
        <div className="flex flex-wrap items-end gap-3">
          <div className="min-w-[12rem] flex-1">
            <Field label="Agent name">
              <Input
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="mcp-agent-prod"
              />
            </Field>
          </div>
          <div className="min-w-[12rem] flex-1">
            <Field label="Connects through gateway">
              <Select value={gw} onChange={(e) => setGw(e.target.value)}>
                {/* ⚠ THE ENDPOINT IS SHOWN, NOT JUST THE NAME. The agent will dial this address from its
                    own host — an operator choosing between gateways by name alone cannot tell a reachable
                    one from a demo fixture, and the command only fails later, on someone else's machine. */}
                {gateways.map((n) => (
                  <option key={n.id} value={n.id}>
                    {n.name} — {n.endpoint}
                  </option>
                ))}
              </Select>
            </Field>
          </div>
          <Button
            onClick={() => void enrol()}
            disabled={busy || !name.trim() || !gw}
          >
            {busy ? "Enrolling…" : "Enrol agent"}
          </Button>
        </div>
        {/* ⚠ SAID PLAINLY RATHER THAN DISCOVERED ON THE AGENT HOST. If no gateway can serve a peer, the
            reason is a missing endpoint — not a missing gateway — and the operator needs to know which. */}
        {gateways.length === 0 && (
          <p className="mt-2 text-xs text-warn">
            No gateway can accept a peer yet: a gateway needs a reachable public
            endpoint before an agent can connect to it. Set one on the gateway,
            then enrol.
          </p>
        )}
        {err && <p className="mt-2 text-xs text-danger">{err}</p>}
        <p className="mt-2 text-[11px] text-ink-secondary">
          Enrolling records <strong>you</strong> as the person who authorised
          this agent, and gives you one command to run on the agent's host.{" "}
          {AGENT_PREREQ}
        </p>
      </Card>}

      <Card>
        <p className="text-xs text-slate-500">
          What each agent may reach is set by the grants on{" "}
          <Link to="/access" className="text-slate-300 underline">
            Access Policies
          </Link>{" "}
          — choose <span className="font-mono text-[11px]">AI agent</span> as
          the source. <strong>An agent with no grant reaches nothing.</strong>
        </p>
        {rows === null ? (
          <p className="mt-3 text-xs text-ink-secondary">Loading…</p>
        ) : !rows.ok ? (
          <p
            data-state="load-failed"
            className="mt-3 rounded-md border border-danger/40 bg-danger/5 px-3 py-2 text-xs text-danger"
          >
            {rows.error} <strong>This is not the same as having none.</strong>
          </p>
        ) : rows.data.length === 0 ? (
          <p data-state="no-agents" className="mt-3 text-xs text-ink-secondary">
            {NO_AGENTS}
          </p>
        ) : (
          <div className="mt-3">
            <DataTable<AgentRow>
              caption="AI agents"
              rows={sortAgents(rows.data)}
              rowKey={(a) => a.device_id}
              rowAttrs={(a) => ({
                "data-unattributable": a.unattributable ? "yes" : "no",
                "data-liveness": agentLiveness(a),
              })}
              failed={false}
              empty={NO_AGENTS}
              expandable={(agent) => {
                const profile = profiles[agent.device_id];
                if (!profile) return null;
                const status = runtimeStatus[agent.device_id];
                return (
                  <>
                    <AgentProfilePanel
                      profile={profile}
                      runtime={status ?? null}
                      credentialRotation={credentialRotation[agent.device_id] ?? null}
                      editorVersion={profileEditorVersion}
                      canManageLifecycle={profile.permissions.manage}
                      canRotateCredential={profile.permissions.rotate_credentials}
                      assignmentMembers={assignmentMembers}
                      assignmentGroups={assignmentGroups}
                      onSaveMetadata={(value) => void saveProfileMetadata(agent, value)}
                      onSaveAssignment={(value) => void saveAgentAssignment(agent, value)}
                      onLifecycleChange={(next) => setConfirmLifecycle({ agent, status: next })}
                      onRotateCredential={() => void rotateCredential(agent)}
                      disabled={profileBusy === agent.device_id}
                    />
                    {profileError && profileBusy === null && <p role="alert" className="text-xs text-danger">{profileError}</p>}
                  </>
                );
              }}
              columns={[
                {
                  key: "name",
                  header: "Agent",
                  sortValue: (a) => a.name,
                  cell: (a, ctx) => {
                    const live = livenessLabel(a);
                    return (
                      <button
                        type="button"
                        className="inline-flex items-center gap-2 text-left"
                        aria-label={`Open ${a.name}`}
                        aria-expanded={ctx.expanded}
                        onClick={ctx.toggle}
                      >
                        {/* ⛔ THE DOT IS NEVER GREEN ON AN INFERENCE WE DO NOT HAVE. `unknown` and `never`
                            are muted/amber, not a red that claims a fault we cannot attribute. */}
                        <StatusDot
                          tone={
                            live.tone === "ok"
                              ? "on"
                              : live.tone === "warn"
                                ? "warn"
                                : "off"
                          }
                        />
                        <span className="text-white">{a.name}</span>
                      </button>
                    );
                  },
                },
                {
                  key: "address",
                  header: "Address",
                  sortValue: (a) => a.address ?? "",
                  cell: (a) => (
                    <span
                      className={`font-mono text-xs ${a.address ? "text-slate-500" : "italic text-slate-600"}`}
                    >
                      {a.address ?? "no address"}
                    </span>
                  ),
                },
                {
                  key: "gateway",
                  header: "Gateway",
                  sortValue: (a) => a.gateway_name,
                  cell: (a) => (
                    <span className="text-xs text-slate-400">
                      {a.gateway_name}
                    </span>
                  ),
                },
                ...(Object.values(profiles).some((profile) => profile?.permissions.view_privileged) ? [{
                  key: "owner",
                  header: "Authorised by",
                  // ⚠ THE UNATTRIBUTABLE STATE IS SEARCHABLE BY THE WORD THE BADGE USES, not only by an
                  // email that does not exist — otherwise the one row an operator most needs to find is the
                  // one row no search term reaches.
                  sortValue: (a: AgentRow) =>
                    profiles[a.device_id]?.owner_email ?? a.owner_email ?? "unattributable no owner recorded",
                  cell: (a: AgentRow) => {
                    const ownerEmail = profiles[a.device_id]?.owner_email ?? a.owner_email;
                    const note = attributionNote(a);
                    return ownerEmail ? (
                      <span className="text-xs text-slate-400">
                        {ownerEmail}
                      </span>
                    ) : note ? (
                      <span title={note.detail}>
                        <Badge tone="warn">{note.label}</Badge>
                      </span>
                    ) : null;
                  },
                }] : []),
                {
                  key: "status",
                  header: "Status",
                  // ⛔ THE STATE AS TEXT, because the cell renders it as a Badge. Without this a search for
                  // "unknown" or "never" would miss every row whose badge says exactly that.
                  sortValue: (a) => livenessLabel(a).label,
                  cell: (a) => {
                    const live = livenessLabel(a);
                    // The liveness word carries its own explanation on hover — an operator seeing
                    // "liveness unknown" must be able to learn WHY without leaving the row.
                    return (
                      <span title={live.detail}>
                        <Badge tone={live.tone}>{live.label}</Badge>
                      </span>
                    );
                  },
                },
                {
                  key: "traffic",
                  header: "Traffic",
                  numeric: true,
                  // ⚠ NULL SORTS AS NULL, NOT AS ZERO. An unreported counter is not a measurement of no
                  // traffic, and sorting it alongside real zeros would assert that it is.
                  sortValue: (a) => (a.rx_bytes ?? -1) + (a.tx_bytes ?? 0),
                  cell: (a) => (
                    <span className="font-mono text-[11px] text-slate-500">
                      {formatTraffic(a.rx_bytes, a.tx_bytes) ?? "n/a"}
                    </span>
                  ),
                },
                ...(Object.values(profiles).some((profile) => profile?.permissions.revoke) ? [{
                  key: "actions",
                  header: "Actions",
                  cell: (a: AgentRow) => profiles[a.device_id]?.permissions.revoke ? (
                    <Button variant="ghost" onClick={() => setConfirmRemove(a)}>Remove</Button>
                  ) : null,
                }] : []),
              ]}
            />
          </div>
        )}
      </Card>

      {confirmRemove && (
        <div className="fixed inset-0 z-50 grid place-items-center bg-black/60 p-4" role="dialog" aria-modal="true" aria-label="Remove agent">
          <Card>
            <h2 className="text-sm font-semibold text-ink-heading">Remove {confirmRemove.name}?</h2>
            <p className="mt-2 max-w-md text-xs text-ink-secondary">
              The agent will be revoked first, then removed from this roster. Its runtime service will offboard, any pending credential or WireGuard rotation will be cancelled, and its existing tunnel credential will stop working. Access-policy grants that no longer match an active agent remain saved for review; they are not silently deleted.
            </p>
            <div className="mt-4 flex justify-end gap-2">
              <Button variant="ghost" onClick={() => setConfirmRemove(null)} disabled={removing}>Cancel</Button>
              <Button onClick={() => void removeAgent(confirmRemove)} disabled={removing}>
                {removing ? "Removing…" : "Revoke and remove"}
              </Button>
            </div>
          </Card>
        </div>
      )}

      {confirmLifecycle && (
        <div className="fixed inset-0 z-50 grid place-items-center bg-black/60 p-4" role="alertdialog" aria-modal="true" aria-labelledby="agent-lifecycle-title">
          <Card>
            <h2 id="agent-lifecycle-title" className="text-sm font-semibold text-ink-heading">
              {confirmLifecycle.status === "suspended" ? "Suspend" : "Resume"} {confirmLifecycle.agent.name}?
            </h2>
            <p className="mt-2 max-w-md text-xs text-ink-secondary">
              This sends the lifecycle request to the control plane. The roster will refresh only after the server confirms it.
            </p>
            <div className="mt-4 flex justify-end gap-2">
              <Button variant="ghost" onClick={() => setConfirmLifecycle(null)}>Cancel</Button>
              <Button onClick={() => void applyLifecycle(confirmLifecycle.agent, confirmLifecycle.status)}>
                Confirm {confirmLifecycle.status === "suspended" ? "suspension" : "resume"}
              </Button>
            </div>
          </Card>
        </div>
      )}

      {conf && (
        <OneTimeSecretModal
          title="Connect your agent: run this on the agent's host"
          caption={
            <>
              Run this on the machine that runs your AI agent. It generates the
              private key locally, bootstraps the managed tunnel, and brings the
              interface up. Shown{" "}
              <span className="font-semibold">exactly once</span> — it contains
              a single-use bootstrap token; the private key never leaves the
              agent host. {AGENT_PREREQ} Also requires curl and jq.
            </>
          }
          secret={conf}
          copyLabel="Copy command"
          downloadFilename="tunnex-agent.sh"
          onDismiss={() => setConf(null)}
        />
      )}
    </div>
  );
}
