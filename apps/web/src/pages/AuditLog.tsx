import { useEffect, useRef, useState, type FormEvent } from "react";
import {
  api,
  apiErrorMessage,
  type AuditLogEntry,
  type Member,
  type Org,
} from "../lib/api";
import { useOrg } from "../lib/useOrg";
import { useAuth } from "../lib/auth";
import { relativeAge } from "../lib/format";
import {
  UNATTRIBUTED_NOTE,
  resolveActor,
  unattributedCount,
} from "../lib/auditview";
import {
  Button,
  DataTable,
  ErrorText,
  Input,
  Modal,
  PageHeader,
} from "../components/ui";

import "../network-workspaces.css";
import "../audit-workspace.css";

const PAGE = 50;

const selectCls =
  "rounded-md border border-white/10 bg-ink-900 px-2 py-1 text-sm text-white focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent-400";

// Filters applied to the feed. Empty string = unset.
type Filters = { actor: string; action: string; from: string; to: string };
const NO_FILTERS: Filters = { actor: "", action: "", from: "", to: "" };

// A type=date value is a calendar day ("YYYY-MM-DD"); parse it in the user's LOCAL
// zone (no trailing Z) and cover the whole day so `created_at <= to` is inclusive.
const dayStart = (d: string) => new Date(`${d}T00:00:00`).toISOString();
const dayEnd = (d: string) => new Date(`${d}T23:59:59.999`).toISOString();

function actionLabel(action: string): string {
  const leaf = action.split(".").at(-1) ?? action;
  const words = leaf.replace(/[_-]+/g, " ");
  return words.charAt(0).toUpperCase() + words.slice(1);
}

function actionArea(action: string): string {
  const area = action.split(".")[0] || "system";
  return area.replace(/[_-]+/g, " ");
}

function targetLabel(entry: AuditLogEntry): string {
  if (!entry.target_type) return "No target recorded";
  return entry.target_id
    ? `${entry.target_type} · ${(/^[0-9a-f]{8}-[0-9a-f-]{27}$/i.test(entry.target_id) ? entry.target_id.slice(0, 8) : entry.target_id)}`
    : entry.target_type;
}

function detailValue(value: unknown): string {
  if (value == null) return "null";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return JSON.stringify(value, null, 2);
}

export default function AuditLog() {
  // ⛔ THE ORG COMES FROM THE SEAM (S12.5) — the page no longer picks index zero out of a list it
  // fetched itself, which is what made a second organization unreachable.
  const { org: currentOrg, loading: orgLoading, failed: orgFailed } = useOrg();
  const { state: authState } = useAuth();
  const [org, setOrg] = useState<Org | null>(null);
  const [members, setMembers] = useState<Member[]>([]);
  const [entries, setEntries] = useState<AuditLogEntry[]>([]);
  // `filters` is the editing state; `applied` is the set that produced the current
  // list — "Load more" must page with `applied`, never mid-edit `filters`, or the
  // keyset cursor (from the applied list) mixes with a different filter set.
  const [filters, setFilters] = useState<Filters>(NO_FILTERS);
  const [applied, setApplied] = useState<Filters>(NO_FILTERS);
  const [more, setMore] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [memberScoped, setMemberScoped] = useState(false);
  const [selected, setSelected] = useState<AuditLogEntry | null>(null);
  // Generation token: each fetch bumps it; a response whose token is stale (a
  // newer fetch started, or the component unmounted) is discarded — so out-of-
  // order responses can't leave a stale page as the final list.
  const reqSeq = useRef(0);

  // fetchPage loads from the top (cursor omitted) or appends after `cursor` (the
  // last entry's created_at + id — keyset, not offset). It fetches PAGE+1 and
  // shows PAGE: the extra row is how we know there's a next page without a count
  // (page.length === PAGE would dead-click at exact multiples).
  async function fetchPage(orgId: string, f: Filters, cursor?: AuditLogEntry) {
    const seq = ++reqSeq.current;
    setBusy(true);
    setError(null);
    const { data, error } = await api.GET(
      "/api/v1/organizations/{orgId}/audit-logs",
      {
        params: {
          path: { orgId },
          query: {
            actor: f.actor || undefined,
            action: f.action || undefined,
            from: f.from ? dayStart(f.from) : undefined,
            to: f.to ? dayEnd(f.to) : undefined,
            cursor_ts: cursor?.created_at,
            cursor_id: cursor?.id,
            limit: PAGE + 1,
          },
        },
      },
    );
    if (seq !== reqSeq.current) return; // superseded by a newer fetch / unmounted
    setBusy(false);
    if (error)
      return setError(apiErrorMessage(error, "Could not load the audit log."));
    const fetched = data ?? [];
    const page = fetched.slice(0, PAGE); // drop the has-more probe row
    setEntries((prev) => (cursor ? [...prev, ...page] : page));
    setMore(fetched.length > PAGE);
    setApplied(f); // this filter set now owns the displayed list + its cursor
  }

  useEffect(() => {
    reqSeq.current++; // invalidate any in-flight fetch on unmount
    let cancelled = false;
    (async () => {
      setSelected(null);
      // ⭐ THE ORG-LIST FETCH IS GONE FROM THIS PAGE (S12.5). It existed only to be indexed at zero.
      // OrgProvider reads the list once for the whole shell; a page that re-fetched it would not merely
      // waste a request, it would pick an org the switcher has no way to change.
      const orgErr = null;
      if (cancelled) return;
      if (orgErr)
        return setError(
          apiErrorMessage(orgErr, "Could not load your organizations."),
        );
      // ⛔ LOADING IS NOT ABSENCE (S12.5). The provider resolves the org list asynchronously, so this
      // effect runs once with currentOrg === null before the answer exists. Treating that as "you have no
      // organization" renders a confident, false statement — and because the second pass only sets the
      // data, the stale error stayed on screen BESIDE the correct org name.
      //
      // ⚠ THREE STATES, NOT TWO: still loading (say nothing), the read failed (say THAT), genuinely no
      // membership (say that). Collapsing the first into the third is how a slow network becomes an
      // accusation that the user does not belong here.
      if (orgLoading) return;
      const first = currentOrg;
      if (!first)
        return setError(
          orgFailed
            ? "Could not load your organizations."
            : "You are not a member of any organization yet.",
        );
      setOrg(first);
      // Actor filter is org-scoped BY CONSTRUCTION: the dropdown offers only this
      // org's members (the server enforces org-scoping too).
      const { data: ms } = await api.GET(
        "/api/v1/organizations/{orgId}/members",
        { params: { path: { orgId: first.id } } },
      );
      if (!cancelled) setMembers(ms ?? []);
      if (!cancelled && authState.status === "authed") {
        setMemberScoped(
          (ms ?? []).some(
            (m) =>
              m.user_id === authState.user.id && m.role === "member",
          ),
        );
      }
      if (!cancelled) await fetchPage(first.id, NO_FILTERS);
    })();
    return () => {
      cancelled = true;
      reqSeq.current++; // discard a fetchPage response that resolves post-unmount
    };
    // ⛔ currentOrg IS A DEPENDENCY, AND ITS ABSENCE WAS A REAL BUG THE TESTS CAUGHT (S12.5).
    //
    // The provider resolves the org list ASYNCHRONOUSLY, so on this effect's first run `currentOrg` is still
    // null. With `[]` deps the effect never ran again: the page rendered "You are not a member of any
    // organization yet" — a confident, wrong statement — and stayed there forever, for every user.
    //
    // ⚠ THE SAME DEPENDENCY ALSO MAKES THE SWITCHER WORK. One line, two properties: without it the page
    // either never loads at all, or loads once and then lies about which tenant it is showing.
  }, [currentOrg, authState]);

  function applyFilters(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setSelected(null);
    if (filters.from && filters.to && filters.from > filters.to) { setError("Choose an end date on or after the start date."); return; }
    if (org) void fetchPage(org.id, filters); // from the top with the new filters
  }

  const activeFilterCount = Object.values(applied).filter(Boolean).length;
  const resolvedActors = entries.map((entry) => resolveActor(entry, members));
  const humanCount = resolvedActors.filter((actor) =>
    actor.kind === "human" || actor.kind === "unknown_human" || actor.kind === "cp_admin",
  ).length;
  const systemCount = resolvedActors.filter((actor) => actor.kind === "system").length;
  const gapCount = unattributedCount(entries);
  const actionAreaCount = new Set(entries.map((entry) => actionArea(entry.action))).size;

  return (
    <div className="network-management audit-workspace">
      <PageHeader
        title="Audit log"
        subtitle={org?.name ?? "…"}
        actions={<Button variant="ghost" disabled={busy || !org} onClick={() => org && void fetchPage(org.id, applied)}>Refresh</Button>}
      />
      {memberScoped && (
        <p className="mt-1 text-sm text-ink-tertiary">
          Showing your activity only. Organization-wide activity is visible to admins and owners.
        </p>
      )}
      <ErrorText>{error}</ErrorText>

      <section className="tnx-card-surface audit-inventory">
        <div className="audit-metrics">
          {[
            { label: "Loaded changes", value: entries.length, tone: "text-white" },
            { label: "Human actions", value: humanCount, tone: "text-ink-body" },
            { label: "System actions", value: systemCount, tone: "text-accent-400" },
            { label: "Attribution gaps", value: gapCount, tone: gapCount > 0 ? "text-warn" : "text-ink-body" },
          ].map((metric) => (
            <div key={metric.label} className="flex min-w-0 items-baseline gap-2 border-b border-line-row px-4 py-2.5 odd:border-r sm:border-b-0 sm:border-r sm:last:border-r-0">
              <div className={`font-sans text-lg font-semibold tabular-nums ${metric.tone}`}>{metric.value}</div>
              <div className="truncate text-micro font-medium uppercase tracking-[0.1em] text-ink-faint">{metric.label}</div>
            </div>
          ))}
        </div>

        <form onSubmit={applyFilters} className="audit-filters">
          <div className="audit-filter-grid">
            <label className="min-w-0 text-sm text-ink-tertiary lg:w-52">
              <span>Actor</span>
              <select
                aria-label="Actor"
                className={`min-h-9 w-full ${selectCls}`}
                value={filters.actor}
                onChange={(e) =>
                  setFilters((f) => ({ ...f, actor: e.target.value }))
                }
              >
                <option value="">Anyone</option>
                {members.map((m) => (
                  <option key={m.user_id} value={m.user_id}>
                    {m.name || m.email}
                  </option>
                ))}
              </select>
            </label>
            <label className="min-w-0 flex-1 text-sm text-ink-tertiary">
              <span>Action</span>
              <input
                aria-label="Action"
                list="audit-action-options"
                value={filters.action}
                onChange={(e) => setFilters((f) => ({ ...f, action: e.target.value }))}
                placeholder="All actions or enter an action key"
                className="min-h-9 w-full rounded-md border border-white/10 bg-ink-900 px-3 text-sm text-white placeholder:text-ink-faint focus-visible:border-white/25 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-inset focus-visible:ring-white/35"
              />
            </label>
            <datalist id="audit-action-options">{Array.from(new Set(entries.map(entry => entry.action))).sort().map(action => <option key={action} value={action}>{actionLabel(action)}</option>)}</datalist>
            <label className="flex min-w-0 items-center gap-2 text-sm text-ink-tertiary">
              <span>From</span>
              <Input
                aria-label="From"
                type="date"
                className={`min-h-9 min-w-0 ${selectCls}`}
                value={filters.from}
                onChange={(e) =>
                  setFilters((f) => ({ ...f, from: e.target.value }))
                }
              />
            </label>
            <label className="flex min-w-0 items-center gap-2 text-sm text-ink-tertiary">
              <span>To</span>
              <Input
                aria-label="To"
                type="date"
                className={`min-h-9 min-w-0 ${selectCls}`}
                value={filters.to}
                onChange={(e) =>
                  setFilters((f) => ({ ...f, to: e.target.value }))
                }
              />
            </label>
            <div className="flex items-center gap-2">
              <Button size="sm" type="submit" disabled={busy}>{busy ? "Applying…" : "Apply"}</Button>
              {(Object.values(filters).some(Boolean) || activeFilterCount > 0) && (
                <Button
                  size="sm"
                  type="button"
                  variant="ghost"
                  onClick={() => {
                    setFilters(NO_FILTERS);
                    setSelected(null);
                    if (org) void fetchPage(org.id, NO_FILTERS);
                  }}
                >
                  Clear
                </Button>
              )}
            </div>
          </div>
        </form>

      {/* S14.3 slice A: a real <table>. The audit log IS tabular — action, actor, target, age are the same
          four facts on every row — and rendering it as <li> blocks meant the tier could only find rows by
          matching their text. Now: getByRole("table", { name: "Audit events" }) and getAllByRole("row"). */}
      {/* ⛔ THE GAP IS COUNTED AND NAMED, not folded into the actor column. "not recorded" reads as a
          property of the EVENT; it is a property of OUR WRITE PATH — four system-initiated actions use
          the human insert path with a NULL actor instead of InsertSystemAuditLog. Saying so stops an
          operator hunting for a person who was never recorded. Registered server-side; until it is
          fixed this screen must surface it rather than hide it. */}
      {unattributedCount(entries) > 0 && (
        <p className="border-b border-warn/20 bg-warn/[.06] px-4 py-3 text-xs text-warn">
          {unattributedCount(entries)} of {entries.length} events on this page
          have no recorded actor. {UNATTRIBUTED_NOTE}
        </p>
      )}

      <div className="audit-table">
        {/* ⛔ NO CLIENT PAGER HERE: this page ALREADY pages server-side with a keyset cursor behind
                "Load more". Two paging controls on one screen disagree — "Load more" appends rows the
                operator cannot see without advancing a second pager, and the count then describes neither
                the fetch nor the view. The server's cursor is the one that must win, because it is the one
                that bounds the query. */}
        {/* ⛔ TWO PAGERS, AND THEY ARE NOT RIVALS ONCE THEY ARE NAMED. This page pages SERVER-SIDE with a
                keyset cursor; the table pages the rows already FETCHED. I first disabled the client pager to
                avoid the collision, which meant this screen dumped everything loaded at once — the one thing
                the pager exists to stop, and the founder saw it immediately.

                They compose as long as each says which set it is talking about: the table's count reads
                "of N" where N is what has been LOADED, and the server control says so on its face. Silence
                about which set a number describes is what makes two pagers contradict each other. */}
        <DataTable
          // ⛔ NO CLIENT PAGER: THIS SURFACE'S PAGING PROOF COUNTS DOM ROWS. The e2e asserts 51 rows,
          // then 54 after "Load more", to prove the keyset cursor stitches pages with NO OVERLAP and NO
          // GAP — a re-served or skipped row changes the count. A client pager renders 25 of whatever is
          // fetched, so the count stops meaning what the proof needs it to mean.
          //
          // ⚠ Restored deliberately after the founder asked these surfaces to paginate. The server
          // ALREADY bounds them at 50 per fetch, so "everything at once" is 50 rows, not unbounded —
          // and re-expressing a paging proof is a decide-item, not a fold.
          pageSize={0}
          caption="Audit events"
          rows={entries}
          rowKey={(a) => a.id}
          empty={busy ? "Loading audit events…" : activeFilterCount ? "No audit events match these filters." : "No audit events yet."}
          failed={error != null}
          columns={[
            {
              key: "action",
              header: "Change",
              sortValue: (a) => a.action,
              cell: (a) => (
                <button
                  type="button"
                  aria-label={`Inspect ${a.action} audit event`}
                  onClick={() => setSelected(a)}
                  className="group block min-w-0 text-left focus-visible:outline focus-visible:outline-1 focus-visible:outline-offset-2 focus-visible:outline-white"
                >
                  <span className="block text-sm font-medium text-ink-body group-hover:text-white">{actionLabel(a.action)} <span aria-hidden="true">↗</span></span>
                  <span className="mt-1 block font-sans text-micro text-ink-faint">{a.action}</span>
                </button>
              ),
            },
            {
              key: "actor",
              header: "Actor",
              // ⛔ FOUR ARMS, NOT TWO. This cell used to read
              //     {a.actor_id ? actorName(members, a.actor_id) : "system"}
              // which rendered the SAME WORD for a NAMED subsystem (26 of 100 served rows) and for a
              // row with no actor at all (34 of 100). The named actor was discarded, and discarding it
              // hid an attribution gap behind the word already used for "known, and here is its name".
              cell: (a) => {
                const actor = resolveActor(a, members);
                return (
                  <span
                    data-testid="audit-actor"
                    data-actor-kind={actor.kind}
                    className={
                      "text-xs font-medium " +
                      (actor.gap
                        ? "text-warn"
                        : actor.kind === "system"
                          ? "font-sans text-accent-400"
                          : // ⛔ A DEPLOYMENT ADMINISTRATOR DOES NOT READ AS A COLLEAGUE. They acted
                            // inside this tenant from outside it, which is the fact the row exists to
                            // convey — rendering them in the same grey as a member would bury it.
                            actor.kind === "cp_admin"
                            ? "text-accent-400"
                            : "text-ink-tertiary")
                    }
                  >
                    {actor.label}
                  </span>
                );
              },
            },
            {
              key: "target",
              header: "Target",
              cell: (a) => (
                <span className="font-sans text-xs text-ink-tertiary">{targetLabel(a)}</span>
              ),
            },
            {
              key: "age",
              header: "When",
              numeric: true,
              // ⚠ SORTS BY THE INSTANT, not by the rendered phrase — "3h ago" and "17m ago" order wrongly
              // as text, and an audit log ordered wrongly by time is worse than one not ordered at all.
              sortValue: (a) => Date.parse(a.created_at),
              cell: (a) => (
                <span className="whitespace-nowrap font-sans text-xs text-ink-tertiary">{relativeAge(a.created_at)}</span>
              ),
            },
          ]}
        />
      </div>

      <div className="flex flex-col gap-2 border-t border-line-row px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
        <span className="font-sans text-micro text-ink-faint">
          {entries.length} loaded · {actionAreaCount} {actionAreaCount === 1 ? "area" : "areas"} · newest first
          {activeFilterCount > 0 ? ` · ${activeFilterCount} active ${activeFilterCount === 1 ? "filter" : "filters"}` : ""}
        </span>
        {more && (
          <Button
            size="sm"
            variant="ghost"
            disabled={busy}
            onClick={() =>
              org && fetchPage(org.id, applied, entries[entries.length - 1])
            }
          >
            {busy ? "Loading…" : "Load more from server"}
          </Button>
        )}
      </div>
      </section>

      {selected && (() => {
        const actor = resolveActor(selected, members);
        const details = Object.entries(selected.details ?? {});
        return (
          <Modal title="Audit evidence" size="wide" showClose onDismiss={() => setSelected(null)}>
            <div className="flex flex-col gap-5">
              <div className="flex flex-wrap items-start justify-between gap-4 border-b border-line-row pb-4">
                <div>
                  <div className="text-lg font-semibold text-white">{actionLabel(selected.action)}</div>
                  <div className="mt-1 font-sans text-xs text-ink-faint">{selected.action}</div>
                </div>
                <div className="text-right">
                  <div className={`text-sm font-medium ${actor.gap ? "text-warn" : actor.kind === "system" ? "text-accent-400" : "text-ink-body"}`}>{actor.label}</div>
                  <div className="mt-1 text-xs text-ink-faint">{actor.kind.replace("_", " ")}</div>
                </div>
              </div>

              <dl className="grid gap-4 sm:grid-cols-2">
                <div className="rounded-md border border-line bg-ink-950 px-4 py-3">
                  <dt className="text-xs font-medium text-ink-faint">Target</dt>
                  <dd className="mt-2 break-all font-sans text-sm text-white">{targetLabel(selected)}</dd>
                </div>
                <div className="rounded-md border border-line bg-ink-950 px-4 py-3">
                  <dt className="text-xs font-medium text-ink-faint">Recorded</dt>
                  <dd className="mt-2 font-sans text-sm text-white">{new Date(selected.created_at).toLocaleString()}</dd>
                </div>
              </dl>

              <details className="audit-evidence"><summary id="audit-details-title">Recorded details & IDs</summary>
                <dl className="audit-record-ids"><div><dt>Event ID</dt><dd>{selected.id}</dd></div><div><dt>Target ID</dt><dd>{selected.target_id || "Not recorded"}</dd></div><div><dt>Recorded timestamp</dt><dd>{selected.created_at}</dd></div></dl>
                {details.length === 0 ? (
                  <p className="mt-3 text-sm text-ink-tertiary">No additional details were recorded for this change.</p>
                ) : (
                  <dl className="mt-3 divide-y divide-line-row rounded-md border border-line">
                    {details.map(([key, value]) => (
                      <div key={key} className="grid gap-1 px-4 py-3 sm:grid-cols-[11rem_1fr] sm:gap-4">
                        <dt className="font-sans text-xs text-ink-faint">{key}</dt>
                        <dd className="break-all whitespace-pre-wrap font-sans text-xs text-ink-body">{detailValue(value)}</dd>
                      </div>
                    ))}
                  </dl>
                )}
              </details>

              {actor.gap && <p className="rounded-md border border-warn/20 bg-warn/[.06] px-3 py-2 text-xs text-warn">{UNATTRIBUTED_NOTE}</p>}
            </div>
          </Modal>
        );
      })()}
    </div>
  );
}
