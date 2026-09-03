import { useCallback, useEffect, useRef, useState } from "react";
import { useOrg } from "../lib/useOrg";
import {
  api,
  loadOne,
  type Device,
  type Loaded,
  type Member,
  type Org,
} from "../lib/api";
import { relativeAge } from "../lib/format";
import {
  Button,
  DataTable,
  EmptyState,
  Loading,
  Modal,
  PageHeader,
} from "../components/ui";
import { LoadRetry } from "../components/LoadRetry";
import {
  ATTRIBUTION_NOTE,
  accessIdentityOptions,
  accessIdentityQuery,
  accessIdentityValue,
  causeFor,
  collectorStateLabel,
  collectorStateTone,
  decisionLabel,
  decisionTone,
  destinationFor,
  emptyAccessEventsNote,
  eventTimeline,
  isLastPage,
  nextCursor,
  retentionNote,
  sourceFor,
  type AccessIdentityLabels,
  type AccessIdentityKind,
  type AccessEvent,
  type AccessLogHealth,
} from "../lib/flowlogview";
import type { AgentRow } from "../lib/agentview";

const PAGE = 100;
const IDENTITY_PAGE = 100;
const UUID_PATTERN = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i;

type AgentPage = { items?: AgentRow[]; next_cursor?: string | null };

function currentMemberLabel(member: Member): string {
  const name = member.name.trim();
  return name && name !== member.email ? `${name} · ${member.email}` : member.email;
}

async function loadAllAgents(
  orgId: string,
  stale: () => boolean,
): Promise<Loaded<AgentRow[]>> {
  const agents: AgentRow[] = [];
  const cursors = new Set<string>();
  let cursor: string | undefined;
  do {
    const result = await loadOne(() =>
      api.GET("/api/v1/organizations/{orgId}/agents", {
        params: {
          path: { orgId },
          query: { limit: IDENTITY_PAGE, cursor },
        },
      }),
    );
    if (!result.ok) return { ok: false, error: result.error };
    if (stale()) return { ok: false, error: "Identity request superseded." };
    const page = result.data as AgentRow[] | AgentPage;
    if (Array.isArray(page)) {
      agents.push(...page);
      return { ok: true, data: agents };
    }
    agents.push(...(page.items ?? []));
    const next = page.next_cursor ?? undefined;
    if (!next) return { ok: true, data: agents };
    if (cursors.has(next)) {
      return { ok: false, error: "Could not load current AI-agent labels." };
    }
    cursors.add(next);
    cursor = next;
  } while (!stale());
  return { ok: false, error: "Identity request superseded." };
}

/**
 * Access events — the Zero Trust flow log.
 *
 * ⛔ FOURTH UNREACHABLE-SURFACE INSTANCE. `/access-events` and `/access-log/health` shipped in
 * S7.5.1 and nothing in `apps/web` read either. Found only by censusing the DESIGN rather than the
 * codebase — a census of what exists cannot find what was never built.
 */
export default function AccessEvents() {
  // ⛔ THE ORG COMES FROM THE SEAM (S12.5).
  const { org: currentOrg, loading: orgLoading, failed: orgFailed } = useOrg();
  const [org, setOrg] = useState<Org | null>(null);
  const [rows, setRows] = useState<AccessEvent[] | null>(null);
  const [health, setHealth] = useState<AccessLogHealth | null>(null);
  const [healthBusy, setHealthBusy] = useState(false);
  const [healthError, setHealthError] = useState<string | null>(null);
  const [deniesOnly, setDeniesOnly] = useState(false);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [members, setMembers] = useState<Member[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [agents, setAgents] = useState<AgentRow[]>([]);
  const [identitiesBusy, setIdentitiesBusy] = useState(false);
  const [identitiesError, setIdentitiesError] = useState<string | null>(null);
  const [identityValue, setIdentityValue] = useState("");
  const [historicalIdentityKind, setHistoricalIdentityKind] =
    useState<AccessIdentityKind>("person");
  const [historicalIdentityID, setHistoricalIdentityID] = useState("");
  const [selected, setSelected] = useState<AccessEvent | null>(null);
  const queryEpoch = useRef(0);
  const healthEpoch = useRef(0);
  const identityEpoch = useRef(0);

  const prepareFilterReload = useCallback(() => {
    // Invalidate an in-flight query before React runs the filter effect. Clearing only the results
    // keeps the controls mounted (and focused) without presenting rows from the previous filter as
    // matches for the new one.
    queryEpoch.current++;
    setBusy(true);
    setSelected(null);
    setRows([]);
    setError(null);
    setDone(false);
  }, []);

  const loadIdentities = useCallback(async (target: Org) => {
    const epoch = ++identityEpoch.current;
    setIdentitiesBusy(true);
    setIdentitiesError(null);
    const stale = () => epoch !== identityEpoch.current;
    const [memberResult, deviceResult, agentResult] = await Promise.all([
      loadOne(() =>
        api.GET("/api/v1/organizations/{orgId}/members", {
          params: { path: { orgId: target.id } },
        }),
      ),
      loadOne(() =>
        api.GET("/api/v1/organizations/{orgId}/devices", {
          params: { path: { orgId: target.id } },
        }),
      ),
      loadAllAgents(target.id, stale),
    ]);
    if (stale()) return;
    setIdentitiesBusy(false);
    if (memberResult.ok) setMembers(memberResult.data);
    if (deviceResult.ok) setDevices(deviceResult.data);
    if (agentResult.ok) setAgents(agentResult.data);
    const failed = [
      !memberResult.ok && "people",
      !deviceResult.ok && "device",
      !agentResult.ok && "AI-agent",
    ].filter(Boolean);
    if (failed.length > 0) {
      setIdentitiesError(
        `Could not load current ${failed.join(", ")} labels. Recorded event identities remain available.`,
      );
    }
  }, []);

  const loadHealth = useCallback(async (target: Org) => {
    const epoch = ++healthEpoch.current;
    setHealthBusy(true);
    setHealthError(null);
    const result = await loadOne(() =>
      api.GET("/api/v1/organizations/{orgId}/access-log/health", {
        params: { path: { orgId: target.id } },
      }),
    );
    if (epoch !== healthEpoch.current) return;
    setHealthBusy(false);
    if (!result.ok) {
      setHealthError(
        result.error === "Could not load."
          ? "Could not load access-event collection and retention status."
          : result.error,
      );
      return;
    }
    setHealth(result.data as AccessLogHealth);
  }, []);

  useEffect(() => {
    queryEpoch.current++;
    healthEpoch.current++;
    identityEpoch.current++;
    setOrg(null);
    setRows(null);
    setHealth(null);
    setHealthBusy(false);
    setHealthError(null);
    setMembers([]);
    setDevices([]);
    setAgents([]);
    setIdentitiesBusy(false);
    setIdentitiesError(null);
    setIdentityValue("");
    setHistoricalIdentityKind("person");
    setHistoricalIdentityID("");
    setSelected(null);
    setError(null);
    setBusy(false);
    setDone(false);
    if (!orgLoading && currentOrg) setOrg(currentOrg);
    return () => {
      queryEpoch.current++;
      healthEpoch.current++;
      identityEpoch.current++;
    };
  }, [currentOrg, orgFailed, orgLoading]);

  useEffect(() => {
    if (!org) return;
    // Current inventory supplies display labels only. Event UUIDs remain the source of historical
    // identity, including after a person, device, or AI agent is no longer in these live rosters.
    void loadIdentities(org);
    void loadHealth(org);
    return () => {
      healthEpoch.current++;
      identityEpoch.current++;
    };
  }, [loadHealth, loadIdentities, org]);

  const load = useCallback(
    async (reset: boolean) => {
      if (!org) return;
      const epoch = reset ? ++queryEpoch.current : queryEpoch.current;
      setBusy(true);
      setError(null);
      if (reset) {
        if (rows !== null) setRows([]);
        setDone(false);
      }
      const cursor = reset ? null : nextCursor(rows ?? []);
      const identityQuery = accessIdentityQuery(identityValue);
      const result = await loadOne(() =>
        api.GET(
          "/api/v1/organizations/{orgId}/access-events",
          {
            params: {
              path: { orgId: org.id },
              query: {
                limit: PAGE,
                denies_only: deniesOnly || undefined,
                ...identityQuery,
                ...(cursor ?? {}),
              },
            },
          },
        ),
      );
      if (epoch !== queryEpoch.current) return;
      setBusy(false);
      if (!result.ok) {
        setError(
          result.error === "Could not load."
            ? "Could not load access events."
            : result.error,
        );
        return;
      }
      const page = (result.data as AccessEvent[] | undefined) ?? [];
      setRows(reset ? page : [...(rows ?? []), ...page]);
      // The API documents that a short page IS the last page — so stop asking.
      setDone(isLastPage(page, PAGE));
    },
    [org, rows, deniesOnly, identityValue],
  );

  useEffect(() => {
    if (!org) return;
    void load(true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [org, deniesOnly, identityValue]);

  if (orgLoading) {
    return <Loading size="page" label="Loading access events…" />;
  }

  if (orgFailed && !currentOrg) {
    return (
      <div>
        <PageHeader title="Access events" subtitle="Policy decisions and audit evidence" />
        <LoadRetry
          error="Could not load your organizations."
          onRetry={() => window.location.reload()}
        />
      </div>
    );
  }

  if (!currentOrg) {
    return (
      <div>
        <PageHeader title="Access events" subtitle="Policy decisions and audit evidence" />
        <section className="tnx-card-surface mt-5 px-5">
          <EmptyState>You are not a member of any organization yet.</EmptyState>
        </section>
      </div>
    );
  }

  if (!org || currentOrg.id !== org.id) {
    return <Loading size="page" label="Loading access events…" />;
  }

  if (rows === null && !error) {
    return (
      <div>
        <PageHeader title="Access events" subtitle={`${org.name} · policy decisions and audit evidence`} />
        <Loading label="Loading access events…" />
      </div>
    );
  }

  if (rows === null && error) {
    return (
      <div>
        <PageHeader title="Access events" subtitle={`${org.name} · policy decisions and audit evidence`} />
        <LoadRetry error={error} onRetry={() => void load(true)} />
      </div>
    );
  }

  const events = rows ?? [];
  const humanDevices = devices.filter((device) => device.kind !== "agent");
  const memberLabels = new Map(
    members.map((member) => [member.user_id, currentMemberLabel(member)]),
  );
  const deviceLabels = new Map(
    humanDevices.map((device) => [device.id, device.name]),
  );
  const agentLabels = new Map(
    agents.map((agent) => [agent.device_id, agent.name]),
  );
  const identities = accessIdentityOptions(
    events,
    {
      people: members.map((member) => ({
        id: member.user_id,
        label: currentMemberLabel(member),
      })),
      devices: humanDevices.map((device) => ({
        id: device.id,
        label: device.name,
      })),
      agents: agents.map((agent) => ({
        id: agent.device_id,
        label: agent.name,
      })),
    },
    identityValue,
  );
  const historicalUUID = historicalIdentityID.trim().toLowerCase();
  const historicalUUIDValid = UUID_PATTERN.test(historicalUUID);
  const historicalUUIDInvalid = historicalIdentityID.length > 0 && !historicalUUIDValid;
  const hasActiveFilters = deniesOnly || identityValue !== "";
  const identityLabelsFor = (event: AccessEvent): AccessIdentityLabels => {
    const agentID = event.src_agent_id ??
      (event.src_kind === "agent" ? event.src_device_id ?? undefined : undefined);
    return {
      person: event.src_user_id
        ? memberLabels.get(event.src_user_id)
        : undefined,
      device: event.src_device_id
        ? deviceLabels.get(event.src_device_id)
        : undefined,
      agent: agentID ? agentLabels.get(agentID) : undefined,
    };
  };
  const rn = health ? retentionNote(health) : null;
  const allowedCount = events.filter((event) => event.decision === "allow").length;
  const deniedCount = events.filter((event) =>
    event.decision === "deny" || event.decision === "deny_aggregate",
  ).length;
  const gapCount = events.filter((event) => event.decision === "gap").length;

  const decisionClass = (event: AccessEvent) => {
    const tone = decisionTone(event.decision);
    return tone === "ok"
      ? "bg-accent-500/10 text-accent-400"
      : tone === "bad"
        ? "bg-danger/10 text-danger"
        : tone === "gap"
          ? "bg-warn/20 text-warn"
          : "bg-warn/10 text-warn";
  };

  return (
    <div>
      <PageHeader
        title="Access events"
        subtitle={org ? `${org.name} · policy decisions and audit evidence` : "…"}
      />

      <section className="tnx-card-surface mt-5 overflow-hidden">
        <div className="grid grid-cols-2 border-b border-line-row sm:grid-cols-4">
          {[
            { label: "Loaded records", value: events.length, tone: "text-white" },
            { label: "Allowed", value: allowedCount, tone: "text-accent-400" },
            { label: "Denied records", value: deniedCount, tone: "text-danger" },
            { label: "Integrity gaps", value: gapCount, tone: gapCount > 0 ? "text-warn" : "text-ink-body" },
          ].map((metric) => (
            <div key={metric.label} className="min-w-0 border-b border-line-row px-5 py-4 last:border-b-0 odd:border-r sm:border-b-0 sm:border-r sm:last:border-r-0">
              <div className={`font-mono text-2xl font-semibold tabular-nums ${metric.tone}`}>{metric.value}</div>
              <div className="mt-1 text-micro font-medium uppercase tracking-[0.12em] text-ink-faint">{metric.label}</div>
            </div>
          ))}
        </div>

        <div className="flex flex-col gap-3 border-b border-line-row px-4 py-3 lg:flex-row lg:flex-wrap lg:items-center">
          {/* ⛔ ONE VERDICT FILTER, BECAUSE THE API HAS ONE. Per-verdict chips would have to filter a
              keyset PAGE, hiding events on other pages while looking like a complete filter. */}
          <div className="inline-flex w-fit rounded-md border border-line bg-ink-950 p-1" aria-label="Event scope">
            <button
              type="button"
              aria-pressed={!deniesOnly}
              onClick={() => {
                if (!deniesOnly) return;
                prepareFilterReload();
                setDeniesOnly(false);
              }}
              className={`rounded px-3 py-1.5 text-sm font-medium transition-colors ${!deniesOnly ? "bg-white/[.10] text-white" : "text-ink-tertiary hover:text-white"}`}
            >
              All activity
            </button>
            <button
              type="button"
              aria-pressed={deniesOnly}
              onClick={() => {
                if (deniesOnly) return;
                prepareFilterReload();
                setDeniesOnly(true);
              }}
              className={`rounded px-3 py-1.5 text-sm font-medium transition-colors ${deniesOnly ? "bg-white/[.10] text-white" : "text-ink-tertiary hover:text-white"}`}
            >
              Denies only
            </button>
          </div>

          <label className="flex min-w-0 items-center gap-3 text-sm text-ink-tertiary lg:ml-auto">
            <span className="shrink-0">Source identity</span>
            <select
              aria-label="Source identity"
              value={identityValue}
              onChange={(e) => {
                if (e.target.value === identityValue) return;
                prepareFilterReload();
                setIdentityValue(e.target.value);
              }}
              className="min-h-9 min-w-0 rounded-md border border-line bg-ink-950 px-3 text-sm text-white focus-visible:border-white/25 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-inset focus-visible:ring-white/35 sm:min-w-56"
            >
              <option value="">All sources</option>
              {identities.people.length > 0 && (
                <optgroup label="People">
                  {identities.people.map((identity) => (
                    <option key={identity.value} value={identity.value}>{identity.label}</option>
                  ))}
                </optgroup>
              )}
              {identities.devices.length > 0 && (
                <optgroup label="Devices">
                  {identities.devices.map((identity) => (
                    <option key={identity.value} value={identity.value}>{identity.label}</option>
                  ))}
                </optgroup>
              )}
              {identities.agents.length > 0 && (
                <optgroup label="AI agents">
                  {identities.agents.map((identity) => (
                    <option key={identity.value} value={identity.value}>{identity.label}</option>
                  ))}
                </optgroup>
              )}
            </select>
            {identitiesBusy && (
              <span className="shrink-0 text-micro text-ink-faint" role="status">
                Loading current labels…
              </span>
            )}
          </label>

          <form
            className="flex min-w-0 flex-wrap items-center gap-2 text-sm text-ink-tertiary"
            aria-label="Filter by historical identity UUID"
            onSubmit={(event) => {
              event.preventDefault();
              if (!historicalUUIDValid) return;
              const next = accessIdentityValue(historicalIdentityKind, historicalUUID);
              if (next === identityValue) return;
              prepareFilterReload();
              setIdentityValue(next);
            }}
          >
            <span className="shrink-0">Historical UUID</span>
            <select
              aria-label="Historical identity type"
              value={historicalIdentityKind}
              onChange={(event) => setHistoricalIdentityKind(event.target.value as AccessIdentityKind)}
              className="min-h-9 rounded-md border border-line bg-ink-950 px-2 text-sm text-white focus-visible:border-white/25 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-inset focus-visible:ring-white/35"
            >
              <option value="person">Person</option>
              <option value="device">Device</option>
              <option value="agent">AI agent</option>
            </select>
            <input
              aria-label="Historical identity UUID"
              aria-invalid={historicalUUIDInvalid || undefined}
              aria-describedby={historicalUUIDInvalid ? "historical-identity-uuid-error" : undefined}
              value={historicalIdentityID}
              onChange={(event) => setHistoricalIdentityID(event.target.value)}
              placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
              spellCheck={false}
              autoComplete="off"
              className="min-h-9 min-w-64 flex-1 rounded-md border border-line bg-ink-950 px-3 font-mono text-xs text-white placeholder:text-ink-faint focus-visible:border-white/25 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-inset focus-visible:ring-white/35"
            />
            <Button size="sm" variant="ghost" type="submit" disabled={!historicalUUIDValid}>
              Apply UUID
            </Button>
            {historicalUUIDInvalid && (
              <span
                id="historical-identity-uuid-error"
                className="basis-full text-micro text-danger"
                role="alert"
              >
                Enter a complete UUID in xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx format.
              </span>
            )}
          </form>

          {rn && (
            <span className={`text-micro ${rn.tone === "danger" ? "text-danger" : rn.tone === "warn" ? "text-warn" : "text-ink-faint"}`}>
              {rn.text}{health?.retention_last_sweep ? ` · ${relativeAge(health.retention_last_sweep)}` : ""}
            </span>
          )}
        </div>

        {identitiesError && (
          <div className="border-b border-line-row px-4 pb-3">
            <LoadRetry error={identitiesError} onRetry={() => void loadIdentities(org)} />
          </div>
        )}

        <div className="border-b border-line-row px-4 py-3" aria-label="Gateway collector status">
          <div className="text-micro font-medium uppercase tracking-[0.12em] text-ink-faint">
            Gateway collectors
          </div>
          {healthBusy && !health ? (
            <Loading size="inline" label="Loading collector status…" />
          ) : healthError ? (
            <LoadRetry error={healthError} onRetry={() => void loadHealth(org)} />
          ) : health?.gateway_collectors?.length ? (
            <ul className="mt-2 grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
              {health.gateway_collectors.map((collector) => {
                const tone = collectorStateTone(collector.state);
                return (
                  <li key={collector.node_id} className="rounded-md border border-line bg-ink-950 px-3 py-2">
                    <div className="flex items-center justify-between gap-3">
                      <span className="truncate text-xs font-medium text-ink-body">{collector.name}</span>
                      <span className={`shrink-0 font-mono text-micro ${tone === "ok" ? "text-accent-400" : tone === "danger" ? "text-danger" : tone === "warn" ? "text-warn" : "text-ink-faint"}`}>
                        {collectorStateLabel(collector.state)}
                      </span>
                    </div>
                    <dl className="mt-2 grid grid-cols-2 gap-x-3 gap-y-1 text-micro text-ink-faint">
                      {[
                        ["Heartbeat", collector.last_reported_at],
                        ["Observed", collector.last_observed_at],
                        ["Delivered", collector.last_delivered_at],
                        ["Retained", collector.last_event_at],
                      ].map(([label, timestamp]) => (
                        <div key={label}>
                          <dt className="inline">{label}: </dt>
                          <dd className="inline text-ink-tertiary">
                            {timestamp ? relativeAge(timestamp) : "not reported"}
                          </dd>
                        </div>
                      ))}
                    </dl>
                  </li>
                );
              })}
            </ul>
          ) : health ? (
            <p className="mt-2 text-xs text-warn">No gateway has reported collector status yet.</p>
          ) : null}
        </div>

        <div className="px-4 py-3" aria-busy={busy && events.length === 0}>
        {/* ⛔ TWO PAGERS, AND THEY ARE NOT RIVALS ONCE THEY ARE NAMED. This page pages SERVER-SIDE with a
                keyset cursor; the table pages the rows already FETCHED. I first disabled the client pager to
                avoid the collision, which meant this screen dumped everything loaded at once — the one thing
                the pager exists to stop, and the founder saw it immediately.

                They compose as long as each says which set it is talking about: the table's count reads
                "of N" where N is what has been LOADED, and the server control says so on its face. Silence
                about which set a number describes is what makes two pagers contradict each other. */}
        {error && (
          <div className="mb-3">
            <LoadRetry
              error={error}
              onRetry={() => void load(events.length === 0)}
            />
          </div>
        )}
        {busy && events.length === 0 ? (
          <Loading
            label={hasActiveFilters
              ? "Loading access events matching the current filters…"
              : "Loading access events…"}
          />
        ) : error && events.length === 0 ? null : (
          <DataTable<AccessEvent>
            caption="Access events"
            rows={events}
            rowKey={(e) => e.id}
            empty={hasActiveFilters
              ? "No retained access events match the current filters."
              : emptyAccessEventsNote(health, healthError !== null)}
            failed={false}
            columns={[
            {
              key: "event",
              header: "Outcome",
              cell: (e) => (
                <button
                  type="button"
                  onClick={() => setSelected(e)}
                  aria-label={`View ${decisionLabel(e.decision)} event details`}
                  data-decision={e.decision}
                  className={`rounded px-2 py-1 font-mono text-badge font-semibold tracking-wide hover:brightness-125 focus-visible:outline focus-visible:outline-1 focus-visible:outline-offset-2 focus-visible:outline-white ${decisionClass(e)}`}
                >
                  {decisionLabel(e.decision)}
                </button>
              ),
            },
            {
              key: "time",
              header: "Observed",
              sortValue: (e) => Date.parse(e.occurred_at),
              cell: (e) => (
                <span className="whitespace-nowrap font-mono text-xs text-ink-tertiary">
                  {relativeAge(e.occurred_at)}
                </span>
              ),
            },
            {
              key: "flow",
              header: "Flow",
              sortValue: (e) => sourceFor(e, identityLabelsFor(e)),
              cell: (e) => (
                <button type="button" onClick={() => setSelected(e)} className="group block min-w-0 text-left focus-visible:outline focus-visible:outline-1 focus-visible:outline-offset-2 focus-visible:outline-white">
                  <span className="block truncate font-mono text-xs text-ink-body group-hover:text-white">
                    {sourceFor(e, identityLabelsFor(e))}
                  </span>
                  <span className="mt-1 block truncate font-mono text-micro text-ink-faint">
                    → {destinationFor(e)}
                  </span>
                </button>
              ),
            },
            {
              key: "protocol",
              header: "Protocol",
              cell: (e) => (
                <span className="font-mono text-xs uppercase text-ink-tertiary">
                  {e.protocol}{e.dst_port ? ` · ${e.dst_port}` : ""}
                </span>
              ),
            },
            {
              key: "cause",
              header: "Decision evidence",
              cell: (e) => (
                <span className="text-xs text-ink-tertiary">
                  {causeFor(e, () => null)}
                </span>
              ),
            },
            ]}
          />
        )}
        </div>

        {/* ⛔ KEYSET, NOT PAGE NUMBERS — the cursor is (created_at, id), the INGEST clock. */}
        <div className="flex flex-col gap-2 border-t border-line-row px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
          <p className="text-micro text-ink-faint">{ATTRIBUTION_NOTE}</p>
          <div className="flex shrink-0 items-center gap-3">
            <span className="font-mono text-micro text-ink-faint">{events.length} loaded · newest first</span>
            <Button size="sm" onClick={() => void load(false)} disabled={busy || done}>
              {busy ? "Loading…" : done ? "No older events" : "Load older"}
            </Button>
          </div>
        </div>
      </section>

      {selected && (
        <Modal title="Access event" size="wide" showClose onDismiss={() => setSelected(null)}>
          <div className="flex flex-col gap-5">
            <div className="flex flex-wrap items-start justify-between gap-4 border-b border-line-row pb-4">
              <div>
                <span className={`inline-flex rounded px-2 py-1 font-mono text-badge font-semibold tracking-wide ${decisionClass(selected)}`}>
                  {decisionLabel(selected.decision)}
                </span>
                <p className="mt-2 text-sm text-ink-tertiary">Observed {relativeAge(selected.occurred_at)}</p>
              </div>
              <div className="text-right font-mono text-micro text-ink-faint">
                <div>sequence {selected.seq}</div>
                <div className="mt-1">ingested {selected.created_at}</div>
              </div>
            </div>

            <div className="grid gap-3 sm:grid-cols-[1fr_auto_1fr] sm:items-center">
              <div className="rounded-md border border-line bg-ink-950 px-4 py-3">
                <div className="text-micro font-medium uppercase tracking-[0.12em] text-ink-faint">Source</div>
                <div className="mt-2 break-all font-mono text-sm text-white">
                  {sourceFor(selected, identityLabelsFor(selected))}
                </div>
              </div>
              <span className="text-center text-ink-faint" aria-hidden="true">→</span>
              <div className="rounded-md border border-line bg-ink-950 px-4 py-3">
                <div className="text-micro font-medium uppercase tracking-[0.12em] text-ink-faint">Destination</div>
                <div className="mt-2 break-all font-mono text-sm text-white">{destinationFor(selected)}</div>
              </div>
            </div>

            <dl className="grid grid-cols-2 gap-x-5 gap-y-4 border-y border-line-row py-4 text-sm sm:grid-cols-3">
              <div><dt className="text-micro uppercase tracking-wide text-ink-faint">Protocol</dt><dd className="mt-1 font-mono uppercase text-ink-body">{selected.protocol}</dd></div>
              <div><dt className="text-micro uppercase tracking-wide text-ink-faint">Rule / cause</dt><dd className="mt-1 text-ink-body">{causeFor(selected, () => null)}</dd></div>
              <div><dt className="text-micro uppercase tracking-wide text-ink-faint">Policy</dt><dd className="mt-1 font-mono text-ink-body">{selected.policy_version ? `v${selected.policy_version}` : "not recorded"}</dd></div>
              <div><dt className="text-micro uppercase tracking-wide text-ink-faint">Policy hash</dt><dd className="mt-1 break-all font-mono text-ink-body">{selected.policy_hash ?? "not recorded"}</dd></div>
              <div><dt className="text-micro uppercase tracking-wide text-ink-faint">Source config</dt><dd className="mt-1 font-mono text-ink-body">{selected.src_config_revision ?? "not recorded"}</dd></div>
              <div><dt className="text-micro uppercase tracking-wide text-ink-faint">Gateway</dt><dd className="mt-1 font-mono text-ink-body">{selected.node_id ?? "not recorded"}</dd></div>
            </dl>

            <div>
              <h3 className="text-xs font-semibold uppercase tracking-[0.12em] text-ink-faint">Evidence trace</h3>
              <ol className="mt-3 space-y-2 border-l border-line pl-4">
                {eventTimeline(selected).map((item) => (
                  <li key={item} className="relative text-xs text-ink-tertiary before:absolute before:-left-[1.19rem] before:top-1.5 before:h-1.5 before:w-1.5 before:rounded-full before:bg-ink-faint">{item}</li>
                ))}
              </ol>
            </div>
            <p className="text-micro text-ink-faint">
              Any displayed person, device, or AI-agent names are current labels; the evidence trace preserves event-time IDs because historical labels are not recorded. A recorded person is device-owner accountability at ingest, not proof that they initiated the traffic.
            </p>
          </div>
        </Modal>
      )}
    </div>
  );
}
