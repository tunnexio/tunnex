import { useCallback, useEffect, useRef, useState } from "react";
import { useOrg } from "../lib/useOrg";
import { api, apiErrorMessage, type Org } from "../lib/api";
import { relativeAge } from "../lib/format";
import {
  Button,
  Card,
  DataTable,
  ErrorText,
  PageHeader,
} from "../components/ui";
import { isEnterprise, type Edition } from "../lib/edition";
import {
  ATTRIBUTION_NOTE,
  FLOW_LOG_CUTS,
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
  const [edition, setEdition] = useState<Edition>("unknown");
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
      const { data: meta } = await api.GET("/api/v1/meta");
      if (epoch !== loadEpoch.current) return;
      setEdition(meta?.edition === "enterprise" ? "enterprise" : "open");
      setOrg(currentOrg);
      if (currentOrg && meta?.edition === "enterprise") {
        const { data } = await api.GET("/api/v1/organizations/{orgId}/agents", {
          params: { path: { orgId: currentOrg.id } },
        });
        if (epoch === loadEpoch.current) setAgents((data as AgentRow[] | undefined) ?? []);
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
    if (!org || !isEnterprise(edition)) return;
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
  }, [org, edition, deniesOnly, agentId]);

  if (currentOrg && (!org || currentOrg.id !== org.id)) {
    return <p className="text-sm text-slate-500">Loading access events…</p>;
  }

  if (!isEnterprise(edition)) {
    return (
      <div>
        <PageHeader title="Access events" />
        <Card className="mt-4">
          <p className="text-sm text-slate-400">
            The Zero Trust flow log is a Tunnex Enterprise feature.
          </p>
        </Card>
      </div>
    );
  }

  const events = rows ?? [];
  const rn = health ? retentionNote(health) : null;

  return (
    <div>
      <PageHeader title="Access events" subtitle={org ? org.name : "…"} />
      <ErrorText>{error}</ErrorText>

      <Card className="mt-4">
        <div className="flex flex-wrap items-center gap-3">
          {/* ⛔ ONE FILTER, BECAUSE THE API HAS ONE. Per-verdict chips would have to filter a keyset
              PAGE, hiding events on other pages while looking like a complete filter. */}
          <label className="flex items-center gap-2 text-sm text-slate-300">
            <input
              type="checkbox"
              checked={deniesOnly}
              onChange={(e) => {
                setDeniesOnly(e.target.checked);
                setSelected(null);
              }}
            />
            Denies only
          </label>
          <label className="flex items-center gap-2 text-sm text-slate-300">
            Agent
            <select
              value={agentId}
              onChange={(e) => {
                setAgentId(e.target.value);
                setSelected(null);
              }}
              className="rounded border border-slate-700 bg-slate-950 px-2 py-1 text-xs"
            >
              <option value="">All sources</option>
              {agents.map((a) => <option key={a.device_id} value={a.device_id}>{a.name}</option>)}
            </select>
          </label>
          {rn && (
            <span
              className={
                "text-xs " + (rn.loud ? "text-danger" : "text-slate-500")
              }
            >
              {rn.text}
            </span>
          )}
        </div>
        <p className="mt-2 text-xs text-slate-600">{ATTRIBUTION_NOTE}</p>
      </Card>

      <div className="mt-4">
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
              key: "time",
              header: "Time",
              sortValue: (e) => Date.parse(e.occurred_at),
              cell: (e) => (
                <span className="font-mono text-xs text-slate-500">
                  {relativeAge(e.occurred_at)}
                </span>
              ),
            },
            {
              key: "event",
              header: "Event",
              cell: (e) => {
                const tone = decisionTone(e.decision);
                return (
                  <span
                    data-decision={e.decision}
                    className={
                      "rounded px-1.5 py-0.5 font-mono text-[10px] font-semibold " +
                      (tone === "ok"
                        ? "bg-accent-500/10 text-accent-400"
                        : tone === "bad"
                          ? "bg-danger/10 text-danger"
                          : tone === "gap"
                            ? "bg-warn/20 text-warn"
                            : "bg-warn/10 text-warn")
                    }
                  >
                    {decisionLabel(e.decision)}
                  </span>
                );
              },
            },
            {
              key: "source",
              header: "Source",
              sortValue: (e) => sourceFor(e, agents.find((a) => a.device_id === e.src_agent_id)?.name),
              cell: (e) => (
                <span className="font-mono text-xs text-slate-300">
                  {sourceFor(e, agents.find((a) => a.device_id === e.src_agent_id)?.name)}
                </span>
              ),
            },
            {
              key: "destination",
              header: "Destination",
              sortValue: (e) => destinationFor(e),
              cell: (e) => (
                <span className="font-mono text-xs text-slate-300">
                  {destinationFor(e)}
                </span>
              ),
            },
            {
              key: "cause",
              header: "Rule / cause",
              cell: (e) => (
                <span className="text-xs text-slate-500">
                  {causeFor(e, () => null)}
                </span>
              ),
            },
            {
              key: "details",
              header: "Details",
              cell: (e) => <Button onClick={() => setSelected(e)}>View</Button>,
            },
          ]}
        />
      </div>

      {selected && (
        <Card className="mt-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-slate-300">Event timeline</h2>
            <Button onClick={() => setSelected(null)}>Close</Button>
          </div>
          <ol className="mt-3 space-y-2">
            {eventTimeline(selected).map((item) => (
              <li key={item} className="text-xs text-slate-400">{item}</li>
            ))}
          </ol>
          <p className="mt-3 text-xs text-slate-600">Gateway and rule names are current labels only and are not recorded in this historical event.</p>
        </Card>
      )}

      {/* ⛔ KEYSET, NOT PAGE NUMBERS — the cursor is (created_at, id), the INGEST clock. Paginating
          on occurred_at would skew: an agent with a slow clock inserts rows that sort before ones
          already shown, and a page boundary could skip them forever. */}
      <div className="mt-3 flex items-center gap-3">
        <Button onClick={() => void load(false)} disabled={busy || done}>
          {busy ? "Loading…" : done ? "No older events" : "Load older"}
        </Button>
        <span className="text-xs text-slate-600">
          {events.length} loaded · newest first
        </span>
      </div>

      {/* ⛔ WHAT THIS SCREEN DOES NOT SHOW, AND WHY. A screen that silently omits four of the
          design's controls looks unfinished; one that names them looks decided. */}
      <Card className="mt-4">
        <h2 className="text-sm font-semibold text-slate-300">Not shown here</h2>
        <ul className="mt-2 space-y-1.5">
          {FLOW_LOG_CUTS.map((c) => (
            <li key={c.what} className="text-xs text-slate-500">
              <span className="text-slate-400">{c.what}</span> — {c.why}
            </li>
          ))}
        </ul>
      </Card>
    </div>
  );
}
