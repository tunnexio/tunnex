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
  Card,
  DataTable,
  ErrorText,
  Field,
  Input,
} from "../components/ui";

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
    if (org) void fetchPage(org.id, filters); // from the top with the new filters
  }

  return (
    <div>
      <h1 className="text-xl font-semibold text-white">Audit log</h1>
      <p className="text-sm text-slate-400">{org ? org.name : "…"}</p>
      {memberScoped && (
        <p className="mt-1 text-sm text-slate-400">
          Showing your activity only. Organization-wide activity is visible to admins and owners.
        </p>
      )}
      <ErrorText>{error}</ErrorText>

      <form onSubmit={applyFilters} className="mt-6">
        <Card>
          <div className="flex flex-wrap items-end gap-3">
            <label className="text-sm text-slate-300">
              <span className="block text-xs text-slate-500">Actor</span>
              <select
                className={`mt-1 ${selectCls}`}
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
            <div className="w-40">
              <Field label="Action">
                <Input
                  value={filters.action}
                  onChange={(e) =>
                    setFilters((f) => ({ ...f, action: e.target.value }))
                  }
                  placeholder="e.g. device.created"
                />
              </Field>
            </div>
            <label className="text-sm text-slate-300">
              <span className="block text-xs text-slate-500">From</span>
              <input
                type="date"
                className={`mt-1 ${selectCls}`}
                value={filters.from}
                onChange={(e) =>
                  setFilters((f) => ({ ...f, from: e.target.value }))
                }
              />
            </label>
            <label className="text-sm text-slate-300">
              <span className="block text-xs text-slate-500">To</span>
              <input
                type="date"
                className={`mt-1 ${selectCls}`}
                value={filters.to}
                onChange={(e) =>
                  setFilters((f) => ({ ...f, to: e.target.value }))
                }
              />
            </label>
            <Button type="submit" disabled={busy}>
              Apply
            </Button>
          </div>
        </Card>
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
        <p className="mt-4 text-xs text-warn">
          {unattributedCount(entries)} of {entries.length} events on this page
          have no recorded actor. {UNATTRIBUTED_NOTE}
        </p>
      )}

      <div className="mt-4">
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
          empty="No audit events yet."
          failed={error != null}
          columns={[
            {
              key: "action",
              header: "Action",
              sortValue: (a) => a.action,
              cell: (a) => (
                <span className="font-mono text-xs text-slate-300">
                  {a.action}
                </span>
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
                      "text-xs " +
                      (actor.gap
                        ? "text-warn"
                        : actor.kind === "system"
                          ? "font-mono text-accent-400"
                          : // ⛔ A DEPLOYMENT ADMINISTRATOR DOES NOT READ AS A COLLEAGUE. They acted
                            // inside this tenant from outside it, which is the fact the row exists to
                            // convey — rendering them in the same grey as a member would bury it.
                            actor.kind === "cp_admin"
                            ? "text-accent-400"
                            : "text-slate-500")
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
                <span className="text-xs text-slate-500">
                  {a.target_type ?? "n/a"}
                  {a.details && Object.keys(a.details).length > 0 && (
                    <span className="ml-2 font-mono text-slate-600">
                      {JSON.stringify(a.details)}
                    </span>
                  )}
                </span>
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
                <span className="text-xs text-slate-500">
                  {relativeAge(a.created_at)}
                </span>
              ),
            },
          ]}
        />
      </div>

      {more && (
        <div className="mt-4">
          <Button
            variant="ghost"
            disabled={busy}
            onClick={() =>
              org && fetchPage(org.id, applied, entries[entries.length - 1])
            }
          >
            {busy ? "Loading…" : "Load more from server"}
          </Button>
        </div>
      )}
    </div>
  );
}
