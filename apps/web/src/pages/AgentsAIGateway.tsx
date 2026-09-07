import "../network-workspaces.css";
import "../agents-workspace.css";
import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import type { components } from "@tunnex/shared";
import { AgentsTabRail } from "../components/AgentsTabRail";
import { AIGatewaySettings } from "../components/AIGatewaySettings";
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
  devices: S["Device"][];
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
  return (
    <div className="network-management agents-workspace space-y-5">
      <PageHeader
        title="AI gateway"
        subtitle="Choose exact models for enrolled agents. Provider secrets stay on your gateway."
      />
      <AgentsTabRail />
      <AgentsManagementGate key={org?.id}>
        {(orgId) => (
          <>
            <AIGatewaySettings orgId={orgId} canEdit />
            {org?.agent_policy_templates_enabled ? (
              <AIGatewayWorkspace key={orgId} orgId={orgId} />
            ) : (
              <Card>
                <h2>Agent groups are turned off</h2>
                <p>
                  Enable the Agent Groups organization setting before
                  configuring AI teams. Paid managed runtime is not required.
                </p>
                <Link to="/settings?section=ai-agents">
                  Configure Agent Group settings
                </Link>
              </Card>
            )}
          </>
        )}
      </AgentsManagementGate>
    </div>
  );
}
export function AIGatewayWorkspace({ orgId }: { orgId: string }) {
  const [data, setData] = useState<Inventory | null>(null),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false),
    [loading, setLoading] = useState(true);
  const [teamID, setTeamID] = useState(""),
    [deviceID, setDeviceID] = useState("");
  const alive = useRef(true),
    generation = useRef(0);
  async function reload() {
    const n = ++generation.current;
    setLoading(true);
    setError("");
    try {
      const params = { params: { path: { orgId } } };
      const [g, d, t, a] = await Promise.all([
        api.GET("/api/v1/organizations/{orgId}/agent-groups", params),
        api.GET("/api/v1/organizations/{orgId}/devices", params),
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
      setData({
        groups: g.data,
        devices: d.data.filter((d) => d.kind === "agent"),
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
    <div className="space-y-5">
      {error && (
        <p role="alert" className="text-danger">
          {error}
        </p>
      )}
      <Card>
        <h2 className="text-sm font-semibold">Team model policy</h2>
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
      <Card>
        <h2 className="text-sm font-semibold">Agent access</h2>
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
              Archived/unavailable agent ({a.device_id}): {a.status}; retained
              usage history.
            </p>
          ))}
      </Card>
      <UsagePanel orgId={orgId} inventory={data} />
      <Button disabled={busy} onClick={() => void reload()}>
        Refresh AI policies
      </Button>
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
    <div className="mt-3 space-y-3">
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
    <div className="mt-3 space-y-3">
      {assignment && (
        <p role="status">
          Synchronization: {assignment.status}. Desired revision{" "}
          {assignment.revision}; applied revision {assignment.applied_revision};
          applied team revision {assignment.applied_team_revision}.{" "}
          {assignment.enabled ? "Access requested." : "Access disabled."}
        </p>
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
      <p className="text-xs text-ink-secondary">
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
        <p className="text-xs text-ink-secondary">
          Team models: {team.models.join(", ")}
        </p>
      )}
      <div className="flex flex-wrap gap-2">
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
function UsagePanel({
  orgId,
  inventory,
}: {
  orgId: string;
  inventory: Inventory;
}) {
  const [team, setTeam] = useState(""),
    [device, setDevice] = useState(""),
    [from, setFrom] = useState(
      new Date().toISOString().slice(0, 10) + "T00:00",
    ),
    [to, setTo] = useState(new Date().toISOString().slice(0, 16));
  const [report, setReport] = useState<S["AIUsageReport"] | null>(null),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false);
  const serial = useRef(0);
  useEffect(
    () => () => {
      serial.current++;
    },
    [],
  );
  const change = (set: (v: string) => void, v: string) => {
    serial.current++;
    set(v);
    setReport(null);
    setError("");
    setBusy(false);
  };
  async function load() {
    const start = new Date(from + "Z"),
      end = new Date(to + "Z"),
      span = end.getTime() - start.getTime();
    if (!Number.isFinite(span) || span <= 0 || span > 31 * 86400000) {
      setError("Choose a positive UTC range of at most 31 days.");
      return;
    }
    const n = ++serial.current;
    setBusy(true);
    setError("");
    setReport(null);
    try {
      const { data, error } = await api.GET(
        "/api/v1/organizations/{orgId}/ai-gateway/usage",
        {
          params: {
            path: { orgId },
            query: {
              from: start.toISOString(),
              to: end.toISOString(),
              ...(team ? { team_id: team } : {}),
              ...(device ? { device_id: device } : {}),
            },
          },
        },
      );
      if (n !== serial.current) return;
      if (error || !data)
        setError("Usage is unavailable. No zero-spend claim can be made.");
      else setReport(data);
    } catch {
      if (n === serial.current)
        setError("Usage is unavailable. No zero-spend claim can be made.");
    } finally {
      if (n === serial.current) setBusy(false);
    }
  }
  return (
    <Card>
      <h2 className="text-sm font-semibold">Observed usage</h2>
      <div className="mt-3 grid gap-3 md:grid-cols-2">
        <Field label="Usage team">
          <Select
            value={team}
            onChange={(e) => change(setTeam, e.target.value)}
          >
            <option value="">All teams</option>
            {inventory.teams.map((t) => (
              <option key={t.team_id} value={t.team_id}>
                {inventory.groups.find((g) => g.id === t.team_id)?.name ??
                  `Archived group (${t.team_id})`}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Usage agent">
          <Select
            value={device}
            onChange={(e) => change(setDevice, e.target.value)}
          >
            <option value="">All agents</option>
            {inventory.assignments.map((a) => (
              <option key={a.device_id} value={a.device_id}>
                {inventory.devices.find((d) => d.id === a.device_id)?.name ??
                  `Archived agent (${a.device_id})`}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="From (UTC)">
          <Input
            type="datetime-local"
            value={from}
            onChange={(e) => change(setFrom, e.target.value)}
          />
        </Field>
        <Field label="To (UTC)">
          <Input
            type="datetime-local"
            value={to}
            onChange={(e) => change(setTo, e.target.value)}
          />
        </Field>
      </div>
      <Button className="mt-3" disabled={busy} onClick={() => void load()}>
        {busy ? "Loading usage…" : "Load usage"}
      </Button>
      {error && (
        <p role="alert" className="mt-2 text-danger">
          {error}
        </p>
      )}
      {report && (
        <div className="mt-3 space-y-1 text-sm">
          <p>
            Requests: {report.total_requests}. Tokens: {report.total_tokens}{" "}
            (input {report.prompt_tokens}, output {report.completion_tokens}).
          </p>
          <p>
            Observed estimated cost: ${report.total_cost.toFixed(6)}. Requests
            without cost: {report.uncosted_requests}.
          </p>
          <p>
            {report.semantics}. Soft thresholds are not strict caps. Historical
            totals reflect retained native metadata, including archived bindings
            where available.
          </p>
        </div>
      )}
    </Card>
  );
}
