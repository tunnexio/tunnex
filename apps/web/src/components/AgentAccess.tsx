import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import type { components } from "@tunnex/shared";
import { api, apiErrorCode, apiErrorMessage, loadOne } from "../lib/api";
import { compactDateTime } from "../lib/format";
import { planName } from "./FeatureEnableInline";
import { Badge, Button, DataTable, Modal } from "./ui";

type Summary = components["schemas"]["AgentAccessSummary"];
type Rule = components["schemas"]["AgentAccessRule"];
type Destination = components["schemas"]["AgentAccessDestinationSummary"];
type Refusal = components["schemas"]["AgentAccessRefusal"];
type Preview = components["schemas"]["AgentOwnerAccessPreview"];
type Candidate = components["schemas"]["AgentOwnerAccessCandidate"];

const KIND: Record<string, string> = { resource: "Resource", group: "Resource group", site: "Site", k8s_service: "Kubernetes service", k8s_cluster_scope: "Kubernetes cluster", fqdn_resource: "Host name", k8s_api: "Kubernetes API" };
const kindLabel = (kind: string) => KIND[kind] ?? "Destination";

/** Protocol and ports in words: "TCP 5432", "TCP 8000 to 8100", "Any protocol, any port". */
export function portsText(destination: Pick<Destination, "protocol" | "port_low" | "port_high">): string {
  const protocol = (destination.protocol ?? "").toLowerCase();
  const name = !protocol || protocol === "any" ? "Any protocol" : protocol.toUpperCase();
  const low = destination.port_low ?? null, high = destination.port_high ?? null;
  if (low === null && high === null) return `${name}, any port`;
  if (low !== null && high !== null && low !== high) return `${name} ${low} to ${high}`;
  return `${name} ${low ?? high}`;
}

function DestinationCell({ destination }: { destination: Destination }) {
  return <div className="min-w-0"><span className="break-words text-ink-heading">{destination.name}</span><span className="block break-all text-xs text-ink-tertiary">{kindLabel(destination.kind)}{destination.address ? ` · ${destination.address}` : ""}</span></div>;
}

type State = { kind: "loading" } | { kind: "error"; message: string } | { kind: "ready"; summary: Summary };

/**
 * What one agent can reach now, rule by rule, and what it was refused recently. An agent reaches only
 * what a rule gives to it or to one of its agent groups; it never uses its owner's access.
 */
export function AgentAccessPanel({ orgId, deviceId, agentName, ownerEmail, canGrant }: { orgId: string; deviceId: string; agentName: string; /** Empty when nobody is accountable for the agent. */ ownerEmail?: string | null; canGrant: boolean }) {
  const [state, setState] = useState<State>({ kind: "loading" });
  const [version, setVersion] = useState(0);
  const [copying, setCopying] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  useEffect(() => {
    let cancelled = false;
    setState({ kind: "loading" });
    void loadOne(() => api.GET("/api/v1/organizations/{orgId}/agents/{deviceId}/access-summary", { params: { path: { orgId, deviceId } } })).then((result) => {
      if (cancelled) return;
      setState(result.ok && Array.isArray(result.data.rules) && result.data.refusals ? { kind: "ready", summary: result.data } : { kind: "error", message: result.ok ? "The list was not returned." : result.error });
    });
    return () => { cancelled = true; };
  }, [orgId, deviceId, version]);

  const rulesHref = `/access?agent=${encodeURIComponent(deviceId)}`;
  const fromOwner = canGrant && ownerEmail ? <Button variant="ghost" onClick={() => { setNotice(null); setCopying(true); }}>Create rules from the owner&apos;s access</Button> : null;
  return <div data-testid="agent-access" className="grid min-w-0 gap-5">
    <p className="agent-detail-context" data-testid="agent-access-principal">An agent reaches only what a rule gives to it by name, or to one of its agent groups. It does not use the access of its owner or of its owner&apos;s groups.</p>
    {notice && <p role="status" className="text-sm text-ink-body">{notice}</p>}
    {state.kind === "loading" ? <p role="status" className="text-sm text-ink-secondary">Loading what this agent can reach…</p>
      : state.kind === "error" ? <div><p role="alert" className="text-sm text-danger">What this agent can reach could not be loaded: {state.message}</p><Button size="sm" variant="ghost" className="mt-2" aria-label="Retry access" onClick={() => setVersion((value) => value + 1)}>Retry</Button></div>
        : <>
          <section aria-label="What this agent can reach" className="min-w-0">
            {state.summary.rules.length === 0 ? <div className="rounded-lg border border-line p-4"><h4 className="text-sm font-semibold text-ink-heading">This agent cannot reach anything yet</h4><p className="mt-1 text-sm text-ink-tertiary">No rule names {agentName} or one of its agent groups.{ownerEmail ? ` You can start from what its owner, ${ownerEmail}, can reach and choose which of those to give the agent.` : " It has no owner to start from, so add rules for it directly."}</p><div className="mt-3 flex flex-wrap items-center gap-3">{fromOwner}{canGrant && <Link className="agent-detail-text-link" to={rulesHref}>Add a rule for this agent</Link>}</div></div>
              : <>
                <DataTable caption="What this agent can reach" rows={state.summary.rules} rowKey={(rule: Rule) => rule.rule_id} failed={false} filterable={false} pageSize={0} empty={<>No rules.</>} columns={[
                  { key: "destination", header: "Destination", cell: (rule: Rule) => <DestinationCell destination={rule.destination} /> },
                  { key: "ports", header: "Protocol and port", cell: (rule: Rule) => <span className="whitespace-nowrap">{portsText(rule.destination)}</span> },
                  { key: "via", header: "Given to", cell: (rule: Rule) => rule.via === "agent_group" ? <span className="break-words">Agent group {rule.group_name ?? ""}</span> : <span>This agent</span> },
                  { key: "state", header: "Status", cell: (rule: Rule) => !rule.enabled ? <Badge tone="neutral">Turned off</Badge> : rule.expires_at ? <span title={new Date(rule.expires_at).toLocaleString()}>Until {compactDateTime(rule.expires_at)}</span> : <Badge tone="ok">Active</Badge> },
                ]} />
                <div className="mt-3 flex flex-wrap items-center gap-3"><Link className="agent-detail-text-link" to={rulesHref}>{canGrant ? "Add or change rules for this agent" : "See these rules in Access Policies"}</Link>{fromOwner}</div>
              </>}
          </section>
          <section aria-label="Recently refused" className="min-w-0">
            <h4 className="text-sm font-semibold text-ink-heading">Recently refused</h4>
            {!state.summary.refusals.available ? <p role="note" className="mt-1 text-sm text-ink-secondary">{planName(state.summary.refusals.required_plan) ? `Seeing what an agent was refused is included in the ${planName(state.summary.refusals.required_plan)} plan.` : "Seeing what an agent was refused is not included in your plan."} <Link className="underline" to="/settings?section=licence">See your plan</Link></p>
              : state.summary.refusals.items.length === 0 ? <p className="mt-1 text-sm text-ink-tertiary">Nothing this agent tried to reach was refused recently.</p>
                : <><p className="mt-1 text-sm text-ink-tertiary">Connections this agent tried and no rule allowed. If one should work, add a rule for it.</p><div className="mt-2"><DataTable caption="Recently refused" rows={state.summary.refusals.items} rowKey={(item: Refusal) => `${item.dst}:${item.port ?? ""}:${item.protocol}`} failed={false} filterable={false} pageSize={0} empty={<>None.</>} columns={[
                  { key: "dst", header: "Destination", cell: (item: Refusal) => <span className="break-all font-mono">{item.dst}</span> },
                  { key: "port", header: "Protocol and port", cell: (item: Refusal) => <span className="whitespace-nowrap">{item.protocol.toUpperCase()}{item.port != null ? ` ${item.port}` : ""}</span> },
                  { key: "count", header: "Times", cell: (item: Refusal) => item.count },
                  { key: "last", header: "Last time", cell: (item: Refusal) => <span className="whitespace-nowrap" title={new Date(item.last_seen).toLocaleString()}>{compactDateTime(item.last_seen)}</span> },
                ]} /></div></>}
          </section>
        </>}
    {copying && <OwnerAccessDialog orgId={orgId} deviceId={deviceId} agentName={agentName} onDismiss={() => setCopying(false)} onCreated={(count) => { setCopying(false); setNotice(count === 1 ? "1 rule was created for this agent." : `${count} rules were created for this agent.`); setVersion((value) => value + 1); }} />}
  </div>;
}

type PreviewState = { kind: "loading" } | { kind: "error"; message: string } | { kind: "ready"; preview: Preview };

/**
 * A preview of the owner's current destinations as rules for the agent. Nothing is ticked to begin with
 * and nothing is created until the administrator confirms the ones they ticked.
 */
function OwnerAccessDialog({ orgId, deviceId, agentName, onDismiss, onCreated }: { orgId: string; deviceId: string; agentName: string; onDismiss: () => void; onCreated: (count: number) => void }) {
  const [state, setState] = useState<PreviewState>({ kind: "loading" });
  const [ticked, setTicked] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);
  const alive = useRef(true);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  const path = { orgId, deviceId };
  useEffect(() => {
    let cancelled = false;
    setState({ kind: "loading" }); setTicked(new Set());
    void (async () => {
      try {
        // A preview only: this request creates nothing.
        const result = await api.POST("/api/v1/organizations/{orgId}/agents/{deviceId}/owner-access-preview", { params: { path } });
        if (cancelled) return;
        if (result.error || !result.data || !Array.isArray(result.data.candidates)) setState({ kind: "error", message: apiErrorCode(result.error) === "agent_owner_unattributable" ? "This agent has no owner whose access can be looked up. Give it an owner on the Overview tab, or add rules for it directly." : apiErrorMessage(result.error, "The owner's access could not be read. Try again.") });
        else setState({ kind: "ready", preview: result.data });
      } catch { if (!cancelled) setState({ kind: "error", message: "Could not reach the API." }); }
    })();
    return () => { cancelled = true; };
  }, [orgId, deviceId, attempt]);

  const candidates = state.kind === "ready" ? state.preview.candidates : [];
  const pickable = (candidate: Candidate) => candidate.copyable && !candidate.already_covered;
  const choices = candidates.filter(pickable);
  async function create() {
    if (busy || ticked.size === 0) return;
    setBusy(true); setError(null);
    try {
      const result = await api.POST("/api/v1/organizations/{orgId}/agents/{deviceId}/owner-access-rules", { params: { path }, body: { keys: candidates.filter((candidate) => ticked.has(candidate.key)).map((candidate) => candidate.key) } });
      if (!alive.current) return;
      if (result.error || !result.data) {
        if (apiErrorCode(result.error) === "owner_access_preview_stale") { setError("The owner's access changed while you were choosing. The list was read again and nothing was created: check it and choose again."); setAttempt((value) => value + 1); return; }
        setError(apiErrorMessage(result.error, "The rules could not be created. Nothing was changed."));
        return;
      }
      onCreated(result.data.rule_ids.length);
    } catch { if (alive.current) setError("Could not reach the API. Check the agent's rules before trying again."); }
    finally { if (alive.current) setBusy(false); }
  }
  const owner = state.kind === "ready" ? state.preview.owner_email : null;
  return <Modal title="Create rules from the owner's access" size="wide" showClose onDismiss={() => !busy && onDismiss()} actions={<><Button variant="ghost" disabled={busy} onClick={onDismiss}>Cancel</Button><Button disabled={busy || ticked.size === 0} onClick={() => void create()}>{busy ? "Creating…" : ticked.size === 0 ? "Create rules" : ticked.size === 1 ? "Create 1 rule" : `Create ${ticked.size} rules`}</Button></>}>
    <div className="grid gap-3">
      <p className="text-ink-tertiary">{owner ? `These are the destinations ${owner} can reach now.` : "These are the destinations the agent's owner can reach now."} Tick the ones {agentName} should reach too. Each tick becomes a rule that names the agent. Nothing is created until you confirm.</p>
      {state.kind === "loading" ? <p role="status" className="text-ink-secondary">Reading the owner&apos;s access…</p>
        : state.kind === "error" ? <div><p role="alert" className="text-danger">{state.message}</p><Button size="sm" variant="ghost" className="mt-2" onClick={() => setAttempt((value) => value + 1)}>Retry</Button></div>
          : candidates.length === 0 ? <p className="text-ink-secondary">The owner cannot reach anything right now, so there is nothing to copy.</p>
            : <>
              {choices.length > 1 && <div className="flex flex-wrap gap-2"><Button size="sm" variant="ghost" disabled={busy} onClick={() => setTicked(new Set(choices.map((candidate) => candidate.key)))}>Tick all</Button><Button size="sm" variant="ghost" disabled={busy || ticked.size === 0} onClick={() => setTicked(new Set())}>Untick all</Button></div>}
              <ul aria-label="The owner's destinations" className="grid gap-0">{candidates.map((candidate) => {
                const why = candidate.already_covered ? "The agent already has a rule for this." : !candidate.copyable ? "A rule for an agent cannot name this kind of destination." : null;
                return <li key={candidate.key} className="border-t border-line py-2"><label className="flex min-w-0 items-start gap-3"><input type="checkbox" className="mt-1" aria-label={candidate.destination.name} checked={ticked.has(candidate.key)} disabled={busy || !pickable(candidate)} onChange={(event) => setTicked((current) => { const next = new Set(current); if (event.target.checked) next.add(candidate.key); else next.delete(candidate.key); return next; })} />
                  <span className="min-w-0 flex-1"><DestinationCell destination={candidate.destination} /><span className="mt-0.5 block text-xs text-ink-secondary">{portsText(candidate.destination)} · {candidate.via === "group" ? `the owner has it through the group ${candidate.via_group_name ?? ""}`.trim() : "the owner has it by name"}</span>{why && <span className="mt-0.5 block text-xs text-ink-secondary">{why}</span>}</span></label></li>;
              })}</ul>
            </>}
      {error && <p role="alert" className="text-danger">{error}</p>}
    </div>
  </Modal>;
}
