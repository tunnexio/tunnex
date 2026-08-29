import { useCallback, useEffect, useRef, useState } from "react";
import { useOrg } from "../lib/useOrg";
import { api, apiErrorMessage, type Org } from "../lib/api";

function agentListItems<T>(value: T[] | { items?: T[] } | undefined): T[] {
  return Array.isArray(value) ? value : value?.items ?? [];
}
import { relativeAge } from "../lib/format";
import {
  Button,
  DataTable,
  ErrorText,
  Loading,
  Modal,
  PageHeader,
} from "../components/ui";
import {
  ATTRIBUTION_NOTE,
  causeFor,
  decisionLabel,
  decisionTone,
  destinationFor,
  eventTimeline,
  isLastPage,
  nextCursor,
  retentionNote,
  sourceFor,
  type AccessEvent,
  type AccessLogHealth,
} from "../lib/flowlogview";
import type { AgentRow } from "../lib/agentview";

const PAGE = 100;

/**
 * Access events — the Zero Trust flow log.
 *
 * ⛔ FOURTH UNREACHABLE-SURFACE INSTANCE. `/access-events` and `/access-log/health` shipped in
 * S7.5.1 and nothing in `apps/web` read either. Found only by censusing the DESIGN rather than the
 * codebase — a census of what exists cannot find what was never built.
 */
export default function AccessEvents() {
  // ⛔ THE ORG COMES FROM THE SEAM (S12.5).
  const { org: currentOrg } = useOrg();
  const [org, setOrg] = useState<Org | null>(null);
  const [rows, setRows] = useState<AccessEvent[] | null>(null);
  const [health, setHealth] = useState<AccessLogHealth | null>(null);
  const [deniesOnly, setDeniesOnly] = useState(false);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [agents, setAgents] = useState<AgentRow[]>([]);
  const [agentId, setAgentId] = useState("");
  const [selected, setSelected] = useState<AccessEvent | null>(null);
  const loadEpoch = useRef(0);
  const queryEpoch = useRef(0);

  useEffect(() => {
    const epoch = ++loadEpoch.current;
    queryEpoch.current++;
    setOrg(null);
    setRows(null);
    setHealth(null);
    setAgents([]);
    setAgentId("");
    setSelected(null);
    setError(null);
    (async () => {
      setOrg(currentOrg);
      if (!currentOrg) return;
      // Base agent inventory is available on Community and higher plans. The
      // access-event filter is populated from the same source without using
      // legacy edition metadata as an entitlement oracle.
      const { data } = await api.GET("/api/v1/organizations/{orgId}/agents", {
        params: { path: { orgId: currentOrg.id } },
      });
      if (epoch === loadEpoch.current) {
        setAgents(agentListItems(data) as AgentRow[]);
      }
    })();
    return () => {
      loadEpoch.current++;
    };
  }, [currentOrg]);

  const load = useCallback(
    async (reset: boolean) => {
      if (!org) return;
      const epoch = reset ? ++queryEpoch.current : queryEpoch.current;
      setBusy(true);
      setError(null);
      const cursor = reset ? null : nextCursor(rows ?? []);
      const { data, error: err } = await api.GET(
        "/api/v1/organizations/{orgId}/access-events",
        {
          params: {
            path: { orgId: org.id },
            query: {
              limit: PAGE,
              denies_only: deniesOnly || undefined,
              src_agent_id: agentId || undefined,
              ...(cursor ?? {}),
            },
          },
        },
      );
      if (epoch !== queryEpoch.current) return;
      setBusy(false);
      if (err)
        return setError(apiErrorMessage(err, "Could not load access events."));
      const page = (data as AccessEvent[] | undefined) ?? [];
      setRows(reset ? page : [...(rows ?? []), ...page]);
      // The API documents that a short page IS the last page — so stop asking.
      setDone(isLastPage(page, PAGE));
    },
    [org, rows, deniesOnly, agentId],
  );

  useEffect(() => {
    if (!org) return;
    void load(true);
    void (async () => {
      const epoch = loadEpoch.current;
      const { data } = await api.GET(
        "/api/v1/organizations/{orgId}/access-log/health",
        { params: { path: { orgId: org.id } } },
      );
      if (epoch === loadEpoch.current && data) setHealth(data as AccessLogHealth);
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [org, deniesOnly, agentId]);

  if (currentOrg && (!org || currentOrg.id !== org.id)) {
    return <Loading label="Loading access events…" />;
  }

  const events = rows ?? [];
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
      <ErrorText>{error}</ErrorText>

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

        <div className="flex flex-col gap-3 border-b border-line-row px-4 py-3 lg:flex-row lg:items-center">
          {/* ⛔ ONE VERDICT FILTER, BECAUSE THE API HAS ONE. Per-verdict chips would have to filter a
              keyset PAGE, hiding events on other pages while looking like a complete filter. */}
          <div className="inline-flex w-fit rounded-md border border-line bg-ink-950 p-1" aria-label="Event scope">
            <button
              type="button"
              aria-pressed={!deniesOnly}
              onClick={() => {
                setDeniesOnly(false);
                setSelected(null);
              }}
              className={`rounded px-3 py-1.5 text-sm font-medium transition-colors ${!deniesOnly ? "bg-white/[.10] text-white" : "text-ink-tertiary hover:text-white"}`}
            >
              All activity
            </button>
            <button
              type="button"
              aria-pressed={deniesOnly}
              onClick={() => {
                setDeniesOnly(true);
                setSelected(null);
              }}
              className={`rounded px-3 py-1.5 text-sm font-medium transition-colors ${deniesOnly ? "bg-white/[.10] text-white" : "text-ink-tertiary hover:text-white"}`}
            >
              Denies only
            </button>
          </div>

          <label className="flex min-w-0 items-center gap-3 text-sm text-ink-tertiary lg:ml-auto">
            <span className="shrink-0">Source agent</span>
            <select
              aria-label="Agent"
              value={agentId}
              onChange={(e) => {
                setAgentId(e.target.value);
                setSelected(null);
              }}
              className="min-h-9 min-w-0 rounded-md border border-line bg-ink-950 px-3 text-sm text-white focus-visible:border-white/25 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-inset focus-visible:ring-white/35 sm:min-w-56"
            >
              <option value="">All sources</option>
              {agents.map((a) => <option key={a.device_id} value={a.device_id}>{a.name}</option>)}
            </select>
          </label>

          {rn && (
            <span className={`text-micro ${rn.loud ? "text-danger" : "text-ink-faint"}`}>
              {rn.text}
            </span>
          )}
        </div>

        <div className="px-4 py-3">
        {/* ⛔ TWO PAGERS, AND THEY ARE NOT RIVALS ONCE THEY ARE NAMED. This page pages SERVER-SIDE with a
                keyset cursor; the table pages the rows already FETCHED. I first disabled the client pager to
                avoid the collision, which meant this screen dumped everything loaded at once — the one thing
                the pager exists to stop, and the founder saw it immediately.

                They compose as long as each says which set it is talking about: the table's count reads
                "of N" where N is what has been LOADED, and the server control says so on its face. Silence
                about which set a number describes is what makes two pagers contradict each other. */}
        <DataTable<AccessEvent>
          caption="Access events"
          rows={events}
          rowKey={(e) => e.id}
          empty="No access events recorded yet."
          failed={error !== null}
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
              sortValue: (e) => sourceFor(e, agents.find((a) => a.device_id === e.src_agent_id)?.name),
              cell: (e) => (
                <button type="button" onClick={() => setSelected(e)} className="group block min-w-0 text-left focus-visible:outline focus-visible:outline-1 focus-visible:outline-offset-2 focus-visible:outline-white">
                  <span className="block truncate font-mono text-xs text-ink-body group-hover:text-white">
                    {sourceFor(e, agents.find((a) => a.device_id === e.src_agent_id)?.name)}
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
                  {sourceFor(selected, agents.find((agent) => agent.device_id === selected.src_agent_id)?.name)}
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
            <p className="text-micro text-ink-faint">Gateway and rule names are current labels only; historical labels are not recorded in this event.</p>
          </div>
        </Modal>
      )}
    </div>
  );
}
