import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useOrg } from "../lib/useOrg";
import { api, loadOne, type Loaded } from "../lib/api";
import {
  agentConnectCommand,
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
  Select,
  StatusDot,
} from "../components/ui";
import { OneTimeSecretModal } from "../components/OneTimeSecret";

type Node = {
  id: string;
  name: string;
  status: string;
  endpoint?: string | null;
  last_seen_at?: string;
};

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
  const [orgId, setOrgId] = useState<string | null>(null);
  const [rows, setRows] = useState<Loaded<AgentRow[]> | null>(null);
  const [gateways, setGateways] = useState<Node[]>([]);
  const [notEntitled, setNotEntitled] = useState(false);

  const [name, setName] = useState("");
  const [gw, setGw] = useState("");
  const [conf, setConf] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [reload, setReload] = useState(0);
  const [confirmRemove, setConfirmRemove] = useState<AgentRow | null>(null);
  const [removing, setRemoving] = useState(false);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      // ⭐ The org-list fetch is gone (S12.5); the seam supplies it.
      if (cancelled || !currentOrg) return;
      const id = currentOrg.id;
      setOrgId(id);

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
      // ⛔ 403 IS NOT A FAILURE — it is the server correctly stating an edition boundary. Any OTHER error is
      // a real failure and must not render as "no agents": a failed load shown as emptiness is a zero
      // nobody measured.
      if (response?.status === 403) {
        setNotEntitled(true);
        return;
      }
      if (error || !data) {
        setRows({ ok: false, error: "Could not load agents." });
        return;
      }
      setRows({ ok: true, data: data as AgentRow[] });
    })();
    return () => {
      cancelled = true;
    };
    // ⚠ currentOrg IS A DEPENDENCY — without it the switcher moves and the page keeps showing the org it
    // mounted with.
  }, [reload, currentOrg]);

  async function enrol() {
    if (!orgId || !gw) return;
    setBusy(true);
    setErr(null);
    // ⛔ THE DEVICE PATH, WITH kind: "agent". Same enrolment a laptop uses — the server generates the
    // keypair and returns the config ONCE. What makes it an agent is the kind, which carries the cap
    // exemption and makes it nameable as a policy source.
    const { data, error } = await api.POST(
      "/api/v1/organizations/{orgId}/devices",
      {
        params: { path: { orgId } },
        body: {
          name: name.trim(),
          node_id: gw,
          kind: "agent",
          platform: "agent",
        },
      },
    );
    setBusy(false);
    if (error || !data) {
      setErr("Could not enrol the agent.");
      return;
    }
    const cfg = (data as { config?: string }).config;
    if (!cfg) {
      // ⚠ LOUD, NOT SILENT. Without the config the operator has an agent that can never connect, and a
      // quiet success would leave them looking for a command that was never shown.
      setErr(
        "The agent was created but no configuration was returned — it cannot connect. Remove it and retry.",
      );
      setReload((n) => n + 1);
      return;
    }
    setConf(cfg);
    setName("");
    setReload((n) => n + 1);
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

  if (notEntitled) return null;

  return (
    <div className="flex flex-col gap-3.5">
      <div>
        <h1 className="text-[22px] font-semibold text-ink-heading">
          AI agents
        </h1>
        <p className="text-cell text-ink-tertiary">
          An agent connects to a gateway over the tunnel and reaches only what
          it is granted.
        </p>
      </div>

      {/* ⛔ THE CREATION PATH. Pick the gateway the agent connects through, name it, and get the command to
          run on the agent's own host. */}
      <Card>
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
      </Card>

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
              columns={[
                {
                  key: "name",
                  header: "Agent",
                  sortValue: (a) => a.name,
                  cell: (a) => {
                    const live = livenessLabel(a);
                    return (
                      <span className="inline-flex items-center gap-2">
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
                      </span>
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
                {
                  key: "owner",
                  header: "Authorised by",
                  // ⚠ THE UNATTRIBUTABLE STATE IS SEARCHABLE BY THE WORD THE BADGE USES, not only by an
                  // email that does not exist — otherwise the one row an operator most needs to find is the
                  // one row no search term reaches.
                  sortValue: (a) =>
                    a.owner_email ?? "unattributable no owner recorded",
                  cell: (a) => {
                    const note = attributionNote(a);
                    return a.owner_email ? (
                      <span className="text-xs text-slate-400">
                        {a.owner_email}
                      </span>
                    ) : note ? (
                      <span title={note.detail}>
                        <Badge tone="warn">{note.label}</Badge>
                      </span>
                    ) : null;
                  },
                },
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
                {
                  key: "actions",
                  header: "Actions",
                  cell: (a) => (
                    <Button variant="ghost" onClick={() => setConfirmRemove(a)}>
                      Remove
                    </Button>
                  ),
                },
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
              The agent will be revoked first, then removed from this roster. Its existing tunnel credential will stop working.
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

      {conf && (
        <OneTimeSecretModal
          title="Connect your agent: run this on the agent's host"
          caption={
            <>
              Run this on the machine that runs your AI agent. It writes the
              tunnel config and brings the interface up. Shown{" "}
              <span className="font-semibold">exactly once</span> — it contains
              the agent's private key. {AGENT_PREREQ}
            </>
          }
          secret={agentConnectCommand(conf)}
          copyLabel="Copy command"
          downloadFilename="tunnex-agent.sh"
          onDismiss={() => setConf(null)}
        />
      )}
    </div>
  );
}
