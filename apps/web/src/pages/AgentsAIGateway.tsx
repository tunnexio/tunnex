import "../network-workspaces.css";
import "../agents-workspace.css";
import "../components/ai-gateway-configuration.css";
import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import type { components } from "@tunnex/shared";
import { AgentsTabRail } from "../components/AgentsTabRail";
import { AIGatewaySettings } from "../components/AIGatewaySettings";
import { AIUsageWorkspace } from "../components/AIUsageWorkspace";
import {
  Button,
  Card,
  Field,
  Input,
  Loading,
  PageHeader,
  Select,
} from "../components/ui";
import { api } from "../lib/api";
import { useOrg } from "../lib/useOrg";
import { AgentsManagementGate } from "./AgentsManagementGate";
type S = components["schemas"];
type Inventory = {
  groups: S["AgentGroup"][];
  devices: { id: string; name: string; status: string }[];
  nextAgentCursor: string | null;
  teams: S["AITeamPolicy"][];
  assignments: S["AIAssignment"][];
};
const lines = (v: string) => [
  ...new Set(
    v
      .split("\n")
      .map((v) => v.trim())
      .filter(Boolean),
  ),
];
const area =
  "w-full rounded-lg border border-white/10 bg-ink-900 px-3 py-2 text-sm text-ink-heading";
export default function AgentsAIGateway() {
  const { org } = useOrg();
  const [view, setView] = useState<"usage" | "configuration">("usage");
  return (
    <div className="network-management agents-workspace space-y-5">
      <PageHeader
        title="AI gateway"
        subtitle="Understand AI spend, monitor usage, and manage agent access."
      />
      <AgentsTabRail />
      <nav aria-label="AI gateway views" className="flex gap-1 rounded-lg border border-white/10 bg-white/[0.02] p-1 w-fit">
        {(["usage", "configuration"] as const).map((v) => <button key={v} type="button" aria-current={view === v ? "page" : undefined} onClick={() => setView(v)} className={`rounded-md px-4 py-2 text-sm font-medium transition-colors ${view === v ? "bg-white/10 text-white" : "text-ink-tertiary hover:text-white"}`}>{v === "usage" ? "Usage & cost" : "Configuration"}</button>)}
      </nav>
      <AgentsManagementGate key={org?.id}>
        {(orgId) => (
          view === "usage" ? <AIUsageWorkspace key={orgId} orgId={orgId} inventory={{ groups: [], devices: [], teams: [], assignments: [] }} /> : <div className="ai-gateway-configuration">
            <div className="ai-config-heading"><div><p className="ai-config-eyebrow">AI GATEWAY / CONFIGURATION</p><h2>Gateway configuration</h2><p>Define team policies, then choose which agents can use them.</p></div><span className="ai-config-pill">Community available</span></div>
            <div className="ai-config-organization"><AIGatewaySettings orgId={orgId} canEdit /></div>
            {org?.agent_policy_templates_enabled ? (
              <AIGatewayWorkspace key={orgId} orgId={orgId} />
            ) : (
              <Card>
                <h2>Agent groups are turned off</h2>
                <p>Enable the Agent Groups organization setting before configuring AI teams. Paid managed runtime is not required.</p>
                <Link to="/settings?section=ai-agents">Configure Agent Group settings</Link>
              </Card>
            )}
          </div>
        )}
      </AgentsManagementGate>
    </div>
  );
}
export function AIGatewayWorkspace({ orgId }: { orgId: string }) {
  const [data, setData] = useState<Inventory | null>(null),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false),
    [loading, setLoading] = useState(true),
    [loadingAgents, setLoadingAgents] = useState(false);
  const [teamID, setTeamID] = useState(""),
    [deviceID, setDeviceID] = useState("");
  const alive = useRef(true),
    generation = useRef(0);
  async function reload() {
    const n = ++generation.current;
    setLoading(true);
    setLoadingAgents(false);
    setError("");
    try {
      const params = { params: { path: { orgId } } };
      const [g, d, t, a] = await Promise.all([
        api.GET("/api/v1/organizations/{orgId}/agent-groups", params),
        api.GET("/api/v1/organizations/{orgId}/agents", { params: { path: { orgId }, query: { limit: 100 } } }),
        api.GET("/api/v1/organizations/{orgId}/ai-gateway/teams", params),
        api.GET("/api/v1/organizations/{orgId}/ai-gateway/agents", params),
      ]);
      if (!alive.current || n !== generation.current) return;
      if (
        g.error ||
        d.error ||
        t.error ||
        a.error ||
        !g.data ||
        !d.data ||
        !t.data ||
        !a.data
      )
        throw Error();
      setDeviceID((selected) => d.data.items.some((agent) => agent.device_id === selected) ? selected : "");
      setTeamID((selected) => g.data.some((group) => group.id === selected) ? selected : "");
      setData({
        groups: g.data,
        devices: d.data.items.map((d) => ({ id: d.device_id, name: d.name, status: d.status })),
        nextAgentCursor: d.data.next_cursor ?? null,
        teams: t.data,
        assignments: a.data,
      });
    } catch {
      if (alive.current && n === generation.current)
        setError(
          "Could not load AI policies. Retry to refresh authoritative state.",
        );
    } finally {
      if (alive.current && n === generation.current) setLoading(false);
    }
  }
  async function loadMoreAgents() {
    if (!data?.nextAgentCursor || loadingAgents || busy) return;
    const n = generation.current;
    const cursor = data.nextAgentCursor;
    setLoadingAgents(true);
    setError("");
    try {
      const result = await api.GET("/api/v1/organizations/{orgId}/agents", {
        params: { path: { orgId }, query: { limit: 100, cursor } },
      });
      if (!alive.current || n !== generation.current) return;
      if (result.error || !result.data || result.data.next_cursor === cursor) throw Error();
      const page = result.data;
      setData((current) => current ? {
        ...current,
        devices: [...new Map([...current.devices, ...page.items.map((d) => ({ id: d.device_id, name: d.name, status: d.status }))].map((d) => [d.id, d])).values()],
        nextAgentCursor: page.next_cursor ?? null,
      } : current);
    } catch {
      if (alive.current && n === generation.current)
        setError("Could not load more agents. Your selection is preserved; retry loading more agents.");
    } finally {
      if (alive.current && n === generation.current) setLoadingAgents(false);
    }
  }
  useEffect(() => {
    alive.current = true;
    void reload();
    return () => {
      alive.current = false;
      generation.current++;
    };
  }, [orgId]);
  async function mutate(
    call: () => Promise<{
      data?: unknown;
      error?: unknown;
    }>,
  ) {
    if (busy) return;
    setBusy(true);
    setError("");
    try {
      const r = await call();
      if (!alive.current) return;
      if (r.error || !r.data) {
        setError(
          "Update failed. Refresh before retrying if another administrator changed this policy.",
        );
        return;
      }
      await reload();
    } catch {
      if (alive.current)
        setError(
          "Could not reach the API. Saved state has not been changed locally.",
        );
    } finally {
      if (alive.current) setBusy(false);
    }
  }
  if (loading) return <Loading label="Loading AI policies…" />;
  if (!data)
    return (
      <Card>
        <p role="alert">{error}</p>
        <Button onClick={() => void reload()}>Retry AI policies</Button>
      </Card>
    );
  const team = data.teams.find((t) => t.team_id === teamID),
    assignment = data.assignments.find((a) => a.device_id === deviceID);
  const teamName = (id: string) =>
    data.groups.find((g) => g.id === id)?.name ??
    `Archived/unavailable group (${id})`;
  return (
    <div className="ai-config-workspace">
      <div className="ai-config-workspace-summary"><span><strong>{data.teams.length}</strong> team policies</span><span><strong>{data.assignments.length}</strong> agent assignments</span><span><strong>{data.devices.length}</strong> loaded agents{data.nextAgentCursor ? " · more available" : ""}</span></div>
      {error && (
        <p role="alert" className="ai-config-error">
          {error}
        </p>
      )}
      <div className="ai-config-grid">
      <Card className="ai-config-card">
        <div className="ai-config-section-heading"><span className="ai-config-section-number" aria-hidden="true">01</span><div><p className="ai-config-eyebrow">MODEL ACCESS</p><h2 className="text-sm font-semibold">Team model policy</h2></div><span className="ai-config-pill">Team scope</span></div>
        <p className="my-2 text-sm">
          Use exact models and provider key IDs, never provider secrets.
        </p>
        {data.groups.length === 0 ? (
          <p>
            No Agent Groups yet.{" "}
            <Link to="/access/groups?type=agents">Create a group</Link> first.
          </p>
        ) : (
          <>
            <Field label="Policy team">
              <Select
                value={teamID}
                disabled={busy}
                onChange={(e) => setTeamID(e.target.value)}
              >
                <option value="">Choose a group</option>
                {data.groups.map((g) => (
                  <option key={g.id} value={g.id}>
                    {g.name}
                  </option>
                ))}
              </Select>
            </Field>
            {!teamID && <div className="ai-config-selection-note"><span className="ai-config-note-symbol" aria-hidden="true">↗</span><h3>Select a team to configure its models</h3><p>Set exact models, provider key IDs and an optional daily soft threshold.</p></div>}
            {teamID && (
              <TeamEditor
                key={`${teamID}:${team?.revision ?? 0}`}
                team={team}
                busy={busy}
                save={(body) =>
                  mutate(() =>
                    api.PUT(
                      "/api/v1/organizations/{orgId}/ai-gateway/teams/{teamId}",
                      { params: { path: { orgId, teamId: teamID } }, body },
                    ),
                  )
                }
              />
            )}
          </>
        )}
        {data.teams
          .filter((t) => !data.groups.some((g) => g.id === t.team_id))
          .map((t) => (
            <p key={t.team_id}>
              {teamName(t.team_id)} — retained policy revision {t.revision}.
            </p>
          ))}
      </Card>
      <Card className="ai-config-card">
        <div className="ai-config-section-heading"><span className="ai-config-section-number" aria-hidden="true">02</span><div><p className="ai-config-eyebrow">WORKLOAD ACCESS</p><h2 className="text-sm font-semibold">Agent access</h2></div><span className="ai-config-pill">One team per agent</span></div>
        <p className="my-2 text-sm">
          Disabling blocks new requests. Accepted streams may finish within 30
          seconds.
        </p>
        {data.devices.length === 0 ? (
          <p>No enrolled agents are available.</p>
        ) : (
          <Field label="Agent">
            <Select
              value={deviceID}
              disabled={busy}
              onChange={(e) => setDeviceID(e.target.value)}
            >
              <option value="">Choose an agent</option>
              {data.devices.map((d) => (
                <option key={d.id} value={d.id}>
                  {d.name} ({d.status})
                </option>
              ))}
            </Select>
          </Field>
        )}
        {data.nextAgentCursor && <Button disabled={busy || loadingAgents} onClick={() => void loadMoreAgents()}>{loadingAgents ? "Loading more agents…" : "Load more agents"}</Button>}
        {!deviceID && data.devices.length > 0 && <div className="ai-config-selection-note"><span className="ai-config-note-symbol" aria-hidden="true">↗</span><h3>Select an agent to manage access</h3><p>Choose its team, narrow model access and review synchronization.</p></div>}
        {deviceID && (
          <AssignmentEditor
            key={`${deviceID}:${assignment?.revision ?? 0}`}
            orgId={orgId}
            deviceID={deviceID}
            assignment={assignment}
            inventory={data}
            busy={busy}
            save={(body) =>
              mutate(() =>
                api.PUT(
                  "/api/v1/organizations/{orgId}/ai-gateway/agents/{deviceId}",
                  { params: { path: { orgId, deviceId: deviceID } }, body },
                ),
              )
            }
            reconcile={() =>
              mutate(() =>
                api.POST(
                  "/api/v1/organizations/{orgId}/ai-gateway/agents/{deviceId}/reconcile",
                  { params: { path: { orgId, deviceId: deviceID } } },
                ),
              )
            }
          />
        )}
        {data.assignments
          .filter((a) => !data.devices.some((d) => d.id === a.device_id))
          .map((a) => (
            <p key={a.device_id}>
              Agent not in loaded inventory ({a.device_id}): {a.status}; retained
              usage history.
            </p>
          ))}
      </Card>
      </div>
      <div className="ai-config-footer"><p>Changes apply to new requests. Existing accepted streams may finish within 30 seconds.</p><Button disabled={busy} onClick={() => void reload()}>
        Refresh AI policies
      </Button></div>
    </div>
  );
}
function TeamEditor({
  team,
  busy,
  save,
}: {
  team?: S["AITeamPolicy"];
  busy: boolean;
  save: (body: S["AITeamPolicyWrite"]) => Promise<void>;
}) {
  const [models, setModels] = useState(team?.models.join("\n") ?? ""),
    [keys, setKeys] = useState(team?.key_ids.join("\n") ?? ""),
    [limit, setLimit] = useState(team?.daily_cost_limit?.toString() ?? "");
  const valid =
    lines(models).length > 0 &&
    lines(keys).length > 0 &&
    (limit === "" ||
      (Number.isFinite(Number(limit)) &&
        Number(limit) > 0 &&
        Number(limit) <= 100000));
  return (
    <div className="ai-config-editor">
      <div className="ai-config-policy-summary"><span className="ai-config-pill">{team ? `Revision ${team.revision}` : "New policy"}</span>{team && <span>{team.models.length} model{team.models.length === 1 ? "" : "s"} · {team.key_ids.length} provider key ID{team.key_ids.length === 1 ? "" : "s"}</span>}</div>
      <Field label="Exact models (one per line)">
        <textarea
          className={area}
          rows={3}
          value={models}
          onChange={(e) => setModels(e.target.value)}
          placeholder="openrouter/openai/gpt-4o-mini"
        />
      </Field>
      <Field label="Provider key IDs (one per line)">
        <textarea
          className={area}
          rows={2}
          value={keys}
          onChange={(e) => setKeys(e.target.value)}
          placeholder="openrouter-primary"
        />
      </Field>
      <Field label="Daily USD soft threshold (optional)">
        <Input
          type="number"
          min="0.01"
          max="100000"
          step="any"
          value={limit}
          onChange={(e) => setLimit(e.target.value)}
        />
      </Field>
      <p className="text-xs text-ink-secondary">
        Observed usage since midnight UTC. Concurrent requests may exceed this
        threshold. Unknown prices fail closed with monetary thresholds; this is
        not a strict spending cap.
      </p>
      <Button
        disabled={busy || !valid}
        onClick={() =>
          void save({
            models: lines(models),
            key_ids: lines(keys),
            daily_cost_limit: limit === "" ? null : Number(limit),
            expected_revision: team?.revision ?? 0,
          })
        }
      >
        Save team policy
      </Button>
    </div>
  );
}
function AssignmentEditor({
  orgId,
  deviceID,
  assignment,
  inventory,
  busy,
  save,
  reconcile,
}: {
  orgId: string;
  deviceID: string;
  assignment?: S["AIAssignment"];
  inventory: Inventory;
  busy: boolean;
  save: (body: S["AIAssignmentWrite"]) => Promise<void>;
  reconcile: () => Promise<void>;
}) {
  const [teamID, setTeamID] = useState(assignment?.team_id ?? ""),
    [models, setModels] = useState(
      assignment?.models_override.join("\n") ?? "",
    ),
    [membership, setMembership] = useState("absent"),
    [attempt, setAttempt] = useState(0);
  const team = inventory.teams.find((t) => t.team_id === teamID);
  useEffect(() => {
    let live = true;
    setMembership(teamID ? "loading" : "absent");
    if (teamID)
      void api
        .GET("/api/v1/organizations/{orgId}/agent-groups/{groupId}/members", {
          params: { path: { orgId, groupId: teamID } },
        })
        .then(({ data, error }) => {
          if (live)
            setMembership(
              error || !data
                ? "error"
                : data.some(
                      (m) => m.device_id === deviceID && m.status === "active",
                    )
                  ? "member"
                  : "absent",
            );
        })
        .catch(() => {
          if (live) setMembership("error");
        });
    return () => {
      live = false;
    };
  }, [orgId, deviceID, teamID, attempt]);
  const valid =
    team &&
    membership === "member" &&
    lines(models).every((m) => team.models.includes(m));
  return (
    <div className="ai-config-editor">
      {assignment && (
        <div role="status" className={`ai-config-sync ai-config-sync-${assignment.status}`}><div className="ai-config-sync-heading"><span className="ai-config-pill">Synchronization: {assignment.status}</span><span>{assignment.enabled ? "Access requested." : "Access disabled."}</span></div><p>Desired revision {assignment.revision}; applied revision {assignment.applied_revision}; applied team revision {assignment.applied_team_revision}.</p></div>
      )}
      <Field label="Agent AI team">
        <Select
          disabled={busy}
          value={teamID}
          onChange={(e) => {
            setTeamID(e.target.value);
            setModels("");
          }}
        >
          <option value="">Choose one policy team</option>
          {inventory.teams.map((t) => (
            <option key={t.team_id} value={t.team_id}>
              {inventory.groups.find((g) => g.id === t.team_id)?.name ??
                `Archived/unavailable group (${t.team_id})`}
            </option>
          ))}
        </Select>
      </Field>
      <p className={`ai-config-membership ai-config-membership-${membership}`}>
        {membership === "member"
          ? "Current group membership verified; the server rechecks it on every request."
          : membership === "loading"
            ? "Checking current group membership…"
            : membership === "error"
              ? "Could not verify current group membership."
              : "The agent must be an active member of the selected group before access can be enabled."}
      </p>
      {membership === "error" && (
        <Button onClick={() => setAttempt((v) => v + 1)}>
          Retry membership
        </Button>
      )}
      <Field label="Agent models (must narrow the team policy)">
        <textarea
          className={area}
          rows={3}
          value={models}
          onChange={(e) => setModels(e.target.value)}
        />
      </Field>
      <p className="text-xs text-ink-secondary">Leave agent models blank to inherit all models from the selected team.</p>
      {team && (
        <p className="ai-config-model-summary">
          Team models: {team.models.join(", ")}
        </p>
      )}
      <div className="ai-config-actions">
        <Button
          disabled={busy || !valid}
          onClick={() =>
            void save({
              team_id: teamID,
              enabled: true,
              models_override: lines(models),
              expected_revision: assignment?.revision ?? 0,
            })
          }
        >
          Save agent access
        </Button>
        {assignment && (
          <>
            <Button
              disabled={busy || !assignment.enabled}
              onClick={() =>
                void save({
                  team_id: assignment.team_id,
                  enabled: false,
                  models_override: assignment.models_override,
                  expected_revision: assignment.revision,
                })
              }
            >
              Disable agent access
            </Button>
            <Button disabled={busy} onClick={() => void reconcile()}>
              Retry synchronization
            </Button>
          </>
        )}
      </div>
    </div>
  );
}
