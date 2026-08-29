import { useCallback, useEffect, useMemo, useState } from "react";
import { useOrg } from "../lib/useOrg";
import {
  api,
  loadOne,
  type DNSForward,
  type Loaded,
  type Org,
  type Site,
  type SiteSubnet,
} from "../lib/api";
import { LoadRetry } from "../components/LoadRetry";
import {
  DataTable,
  EmptyState,
  Loading,
  PageHeader,
  Panel,
} from "../components/ui";
import { AddressSpaceMap, MAP_LIST_MAX } from "../components/viz";
import { useMotionPreference } from "../components/MotionProvider";
import { motionAllowed } from "../lib/motion";
import {
  attributeRanges,
  attributionClass,
  attributionLabel,
  forwardsEmptyCopy,
  mapAddressSpace,
  nextFreeRange,
  sortForwards,
  type Allocation,
  type RangeRow,
  type SubnetFetch,
} from "../lib/routedrangesview";

// ── S14.7 — ROUTED RANGES ───────────────────────────────────────────────────────────────────────────────
//
// The answer to "what LAN traffic goes down the tunnel", read from the SAME endpoint a device reads. That is
// the screen's whole value: not a reconstruction of what should be pushed, but the served projection itself.
//
// ⛔ TWO PANELS FROM THE HANDOFF ARE CUT, both recorded in docs/CUT-REGISTER.md before this file existed.
//
//   ADDRESS-SPACE HEATMAP — two independent reasons. A /24 lights a whole /16 cell, so the picture is
//   coarser than every range it draws; and the grid's domain is 10.0.0.0/8 while real customers use
//   172.16/12 and 192.168/16, which get NO CELLS AT ALL. A map that cannot draw two of the three private
//   blocks is not a map.
//
//   PENDING QUEUE — lives on Sites, because that is where the MUTATION ENDPOINT is: /site-subnets/pending
//   and /approve are `site:manage`, while /routed-ranges is `org:view` with no approve verb. (Its first
//   recorded reason was "the grid was cut, so this is read-only", which was DEPENDENT on the other cut and
//   would evaporate if the grid ever came back. THE GRID HAS SINCE COME BACK, and the reason held — which is
//   the whole argument for recording an INDEPENDENT reason at the time of the cut.)
//
// ⛔ THE HEATMAP WAS CUT AND IS NOW FOUNDER-RULED BACK IN — built with BOTH cut reasons closed rather than
// reproduced. See `mapAddressSpace`. The pending CELLS are legitimate here even though the pending QUEUE is
// not: the per-site fan-out this screen already issues for attribution returns pending subnets too, so they
// are real served data, and showing a withheld range as a dashed cell is the opposite of offering an
// approve control we have no permission for.
//
// SCALE: one row per range, constant height. N=many here is a /8 fully allocated — 256 /16s, or thousands of
// /24s — so there is nothing per-row that grows, and the teaching text renders once.

// ⛔ THE `STATUS` COLUMN IS CUT AS A CONSTANT COLUMN, and that is a statement about the endpoint.
// `/routed-ranges` is APPROVED-ONLY. A status column here would have exactly one value in every row of every
// org forever, which is not information — it is a column that teaches the reader the wrong thing, namely
// that some other value is possible on this screen.

// Legend rows, in the same order the eye meets them on the grid.
const LEGEND = [
  {
    text: "routed, pushed to devices",
    tone: "var(--tnx-ok)",
    small: false,
    dashed: false,
  },
  {
    text: "part of a cell (finer than the grid)",
    tone: "var(--tnx-ok)",
    small: true,
    dashed: false,
  },
  {
    text: "pending, withheld until approved on Sites",
    tone: "var(--tnx-warn)",
    small: false,
    dashed: true,
  },
  {
    text: "device pool",
    tone: "var(--tnx-accent)",
    small: false,
    dashed: false,
  },
  {
    text: "cluster VIP range",
    tone: "var(--tnx-neutral)",
    small: false,
    dashed: false,
  },
];

export default function RoutedRangesPage() {
  const { org: currentOrg, loading: orgLoading, failed: orgFailed } = useOrg();
  const [org, setOrg] = useState<Org | null>(null);
  const [ranges, setRanges] = useState<string[] | null>(null);
  const [forwards, setForwards] = useState<DNSForward[] | null>(null);
  const [sites, setSites] = useState<Site[]>([]);
  // `null` = the fan-out has not resolved. NOT `[]` — see the four-armed union in the view model. This is the
  // state that keeps an in-flight SITE cell from reading as "no site owns this".
  const [fanOut, setFanOut] = useState<SubnetFetch[] | null>(null);
  // ⛔ THE OTHER ALLOCATION CLASSES. `subnetguard` refuses a collision with site subnets, the DEVICE POOL and
  // K8s VIP RANGES (its fourth class, `reserved`, is measured DEAD — `WithReserved` has no callers). A map
  // that draws only site subnets renders the pool's cell DARK, i.e. "yours to take", and the server refuses
  // it. `null` = not yet known, which is why "free" is qualified until every class has answered.
  const [vipRanges, setVipRanges] = useState<Array<{
    cidr: string;
    label: string;
  }> | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [mapExpanded, setMapExpanded] = useState(true);

  const reload = useCallback(async () => {
    setLoadError(null);
    setFanOut(null);

    // ⛔ THE ORG COMES FROM THE SEAM, NOT FROM INDEX ZERO (S12.5). This used to fetch the org list here and
    // take `[0]`, which meant a user in two organizations could reach only one of them and the switcher in
    // the header would have had nothing to switch.
    // ⛔ LOADING IS NOT ABSENCE (S12.5). See the note in Dashboard.tsx — three states, not two: still
    // loading (say nothing), the read failed (say THAT), genuinely no membership (say that).
    if (orgLoading) return;
    const first = currentOrg;
    if (!first)
      return setLoadError(
        orgFailed
          ? "Could not load your organizations."
          : "You are not a member of any organization yet.",
      );
    setOrg(first);

    // ⛔ A FAILED READ IS NOT AN EMPTY ROUTING TABLE. On the screen that answers "does my LAN traffic go down
    // the tunnel", `[]` rendered for a fetch failure says NO with total confidence. Blank the page to a retry.
    const rRes = (await loadOne(() =>
      api.GET("/api/v1/organizations/{orgId}/routed-ranges", {
        params: { path: { orgId: first.id } },
      }),
    )) as Loaded<{ ranges: string[]; forwards: DNSForward[] }>;
    if (!rRes.ok) return setLoadError(rRes.error);
    setRanges(rRes.data.ranges);
    setForwards(rRes.data.forwards);

    // Attribution is a SECOND-CLASS read: it enriches rows that are already correct and already rendered. A
    // failure here degrades the SITE column to "Could not load" and never blanks the table.
    const sRes = (await loadOne(() =>
      api.GET("/api/v1/organizations/{orgId}/sites", {
        params: { path: { orgId: first.id } },
      }),
    )) as Loaded<Site[]>;
    if (!sRes.ok) {
      // We do not know the site list, so we cannot even enumerate who to ask. One synthetic failure marks the
      // census incomplete, which is exactly what it is — every unmatched row becomes `unknown`, not "no site".
      setSites([]);
      setFanOut([{ ok: false, siteId: "" }]);
      return;
    }
    setSites(sRes.data);

    // ⛔ THE FAN-OUT. N sites = N+1 requests, in PARALLEL, ONCE per visit. `/routed-ranges` does not serve
    // `site_id` (it is a device-facing projection), so attribution has to be joined here.
    //
    // `Promise.all` over `loadOne` results, never over raw promises: one 500 must not reject the batch and
    // lose the sites that DID answer. Partial knowledge is representable; a thrown batch is not.
    const results = await Promise.all(
      sRes.data.map(async (s): Promise<SubnetFetch> => {
        const res = (await loadOne(() =>
          api.GET("/api/v1/organizations/{orgId}/sites/{siteId}/subnets", {
            params: { path: { orgId: first.id, siteId: s.id } },
          }),
        )) as Loaded<SiteSubnet[]>;
        return res.ok
          ? { ok: true, siteId: s.id, subnets: res.data }
          : { ok: false, siteId: s.id };
      }),
    );
    setFanOut(results);

    // Cluster VIP ranges. `listK8sClusters` is org:view (verified at the handler, not inferred from the nav's
    // ENT badge). NON-FATAL: a failure leaves `vipRanges` null, which downgrades the free-space claim rather
    // than silently drawing space as available.
    const kRes = (await loadOne(() =>
      api.GET("/api/v1/organizations/{orgId}/k8s/clusters", {
        params: { path: { orgId: first.id } },
      }),
    )) as Loaded<Array<{ name: string; vip_range: string }>>;
    setVipRanges(
      kRes.ok
        ? kRes.data.map((c) => ({
            cidr: c.vip_range,
            label: `${c.name} cluster VIPs`,
          }))
        : null,
    );
    // ⚠ currentOrg IS A DEPENDENCY, AND THAT IS THE HALF THAT MAKES THE SWITCHER WORK. Without it the
    // page keeps rendering the org it mounted with — the control moves, the data does not, and the user is
    // looking at one tenant's screen labelled with another's name.
  }, [currentOrg, orgLoading, orgFailed]);

  useEffect(() => {
    void reload();
  }, [reload]);

  const rows = useMemo(
    () => attributeRanges(ranges ?? [], sites, fanOut),
    [ranges, sites, fanOut],
  );
  // EVERY CLASS THE VALIDATOR ENFORCES, in one list. Pending subnets ride the fan-out attribution already
  // needs, so they cost no extra request.
  const siteName = useMemo(
    () => new Map(sites.map((s) => [s.id, s.name])),
    [sites],
  );
  const allocations = useMemo<Allocation[]>(() => {
    const out: Allocation[] = [];
    for (const row of rows)
      out.push({
        cidr: row.range,
        kind: "approved",
        label:
          row.attribution.kind === "site"
            ? row.attribution.siteName
            : attributionLabel(row.attribution),
      });
    for (const f of fanOut ?? [])
      if (f.ok)
        for (const sub of f.subnets)
          if (sub.status === "pending")
            out.push({
              cidr: sub.cidr,
              kind: "pending",
              label: `${siteName.get(sub.site_id) ?? "a site"}, awaiting approval`,
            });
    if (org?.pool_cidr)
      out.push({ cidr: org.pool_cidr, kind: "pool", label: "device pool" });
    for (const v of vipRanges ?? [])
      out.push({ cidr: v.cidr, kind: "vip", label: v.label });
    return out;
  }, [rows, fanOut, siteName, org, vipRanges]);

  const spaceMap = useMemo(() => mapAddressSpace(allocations), [allocations]);

  // ⛔ "FREE" IS ONLY KNOWABLE WHEN EVERY CLASS HAS ANSWERED. A failed fan-out or an unread cluster list means
  // some space we would draw dark might be taken — so the suggestion is WITHHELD rather than guessed. The
  // same census discipline as the SITE column, applied to a number an admin would act on.
  const spaceComplete =
    fanOut !== null && fanOut.every((f) => f.ok) && vipRanges !== null;
  const suggestion = useMemo(() => {
    if (!spaceComplete || spaceMap.blocks.length === 0) return null;
    const primary = spaceMap.blocks[0];
    const at24 = nextFreeRange(allocations, primary.block, 24);
    const at16 = nextFreeRange(allocations, primary.block, 16);
    if (at24 === null && at16 === null) return null;
    // ⛔ THE /16 IS SHOWN ONLY WHEN IT IS A DIFFERENT ANSWER. When the first free /24 and the first free /16
    // start at the same address — the common case on a fresh block — printing both rendered
    // "10.0.0.0/24 · 10.0.0.0/16", which reads as a duplicate or a bug rather than as two options.
    const base = (c: string | null) => (c === null ? null : c.split("/")[0]);
    return {
      at24,
      at16: base(at16) === base(at24) ? null : at16,
      block: primary.block,
    };
  }, [spaceComplete, spaceMap, allocations]);
  const failedSites = useMemo(
    () => (fanOut ?? []).filter((f) => !f.ok).length,
    [fanOut],
  );
  const attributedSites = useMemo(
    () =>
      new Set(
        rows.flatMap((row) =>
          row.attribution.kind === "site" ? [row.attribution.siteId] : [],
        ),
      ).size,
    [rows],
  );
  const pendingRanges = useMemo(
    () => allocations.filter((allocation) => allocation.kind === "pending").length,
    [allocations],
  );

  const columns = [
    {
      key: "range",
      header: "Range",
      sortValue: (r: RangeRow) => r.range,
      cell: (r: RangeRow) => (
        // Monospace and unabbreviated. This is the string a device actually receives in its AllowedIPs; an
        // admin comparing it against a router config needs it character-for-character.
        <span className="font-mono text-ink-primary">{r.range}</span>
      ),
    },
    {
      key: "site",
      header: "Site",
      sortValue: (r: RangeRow) => attributionLabel(r.attribution),
      cell: (r: RangeRow) => (
        <span className={`text-cell ${attributionClass(r.attribution)}`}>
          {attributionLabel(r.attribution)}
        </span>
      ),
    },
    {
      key: "pushed",
      header: "Pushed to",
      cell: () => (
        // ⛔ CONSTANT BY CONSTRUCTION, AND SAID ONCE PER ROW ANYWAY, because it is the answer to the question
        // that brings people here. The handoff shows "split-tunnel AllowedIPs · 126 devices"; THE DEVICE
        // COUNT IS NOT SERVED — same class as the gateway peer count — and is absent with its reason below
        // rather than invented from the device list, which would count devices that never fetched this.
        <span className="text-micro text-ink-tertiary">
          split-tunnel AllowedIPs
        </span>
      ),
    },
  ];

  const reduced = useMotionPreference();
  const animate = motionAllowed(reduced);
  const loading = !loadError && (org === null || ranges === null);

  return (
    <div className="flex flex-col gap-3.5">
      <PageHeader title="Routed ranges" subtitle={org ? org.name : "…"} />

      {loadError && <LoadRetry error={loadError} onRetry={reload} />}
      {loading && <Loading size="inline" label="Loading routed ranges…" />}

      {!loadError && org && ranges && forwards && (
        <>
          <section
            aria-label="Routing summary"
            className="grid overflow-hidden rounded-xl border border-line bg-ink-800 sm:grid-cols-2 xl:grid-cols-4"
          >
            {[
              { label: "Approved ranges", value: ranges.length, detail: "published" },
              { label: "Sites", value: attributedSites, detail: "carrying traffic" },
              { label: "Pending", value: pendingRanges, detail: pendingRanges ? "needs approval" : "none waiting", attention: pendingRanges > 0 },
              { label: "DNS forwards", value: forwards.length, detail: "reachable" },
            ].map((stat) => (
              <div key={stat.label} className="min-w-0 border-b border-line px-4 py-3 last:border-b-0 sm:border-r sm:[&:nth-child(2)]:border-r-0 sm:[&:nth-child(3)]:border-b-0 xl:border-b-0 xl:[&:nth-child(2)]:border-r xl:[&:nth-child(4)]:border-r-0">
                <p className="text-micro font-medium uppercase tracking-wide text-ink-tertiary">{stat.label}</p>
                <div className="mt-1 flex items-baseline gap-2">
                  <span className="text-title font-semibold tabular-nums text-ink-heading">{stat.value}</span>
                  <span className={`truncate text-micro ${stat.attention ? "text-warn" : "text-ink-faint"}`}>{stat.detail}</span>
                </div>
              </div>
            ))}
          </section>

          <Panel title="Routing inventory">
            <DataTable
              caption="Approved routed ranges"
              columns={columns}
              rows={rows}
              rowKey={(r: RangeRow) => r.range}
              empty="No LAN ranges are routed. Approve an advertised subnet in Sites to publish it here."
              failed={false}
            />
            {failedSites > 0 && (
              <p className="mt-2 text-micro text-warn">
                {failedSites} site{failedSites === 1 ? "" : "s"} could not be read; unmatched ownership may be incomplete.
              </p>
            )}
          </Panel>

          <div className="grid grid-cols-1 items-start gap-3 lg:grid-cols-[7fr_5fr]">
            {spaceMap.blocks.length > 0 && (
              <Panel
                title="Address space"
                actions={
                  <button
                    type="button"
                    aria-expanded={mapExpanded}
                    aria-controls="address-space-details"
                    onClick={() => setMapExpanded((current) => !current)}
                    className="min-h-8 rounded-md px-2.5 text-micro font-medium text-ink-tertiary hover:bg-white/5 hover:text-ink-heading focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-inset focus-visible:ring-white/35"
                  >
                    {mapExpanded ? "Hide map" : "View map"}
                  </button>
                }
              >
                <div className="grid grid-cols-2 gap-3 border-t border-line pt-3 sm:grid-cols-3">
                  <div>
                    <p className="text-micro uppercase tracking-wide text-ink-faint">Allocations</p>
                    <p className="mt-1 text-cell font-semibold tabular-nums text-ink-heading">{allocations.length}</p>
                  </div>
                  <div>
                    <p className="text-micro uppercase tracking-wide text-ink-faint">Private blocks</p>
                    <p className="mt-1 text-cell font-semibold tabular-nums text-ink-heading">{spaceMap.blocks.length}</p>
                  </div>
                  <div className="col-span-2 sm:col-span-1">
                    <p className="text-micro uppercase tracking-wide text-ink-faint">Next free</p>
                    {suggestion?.at24 ? (
                      <p className="mt-1 font-mono text-cell text-ink-heading">{suggestion.at24}</p>
                    ) : (
                      <p className={`mt-1 text-micro ${spaceComplete ? "text-ink-tertiary" : "text-warn"}`}>
                        {spaceComplete ? "No suggestion" : "Census incomplete"}
                      </p>
                    )}
                  </div>
                </div>

                <div id="address-space-details" className={mapExpanded ? "mt-3 space-y-3 border-t border-line pt-3" : "hidden"}>
                  {spaceMap.blocks.map((m) => (
                    <AddressSpaceMap key={m.block.key} map={m} animate={animate} />
                  ))}
                  <ul className="flex flex-wrap items-center gap-x-4 gap-y-1.5 text-micro text-ink-tertiary">
                    {LEGEND.map((l) => (
                      <li key={l.text} className="flex items-center gap-1.5">
                        <span
                          aria-hidden
                          className={`rounded-[2px] ${l.small ? "h-[5px] w-[5px]" : "h-[9px] w-[9px]"} ${l.dashed ? "border border-dashed" : ""}`}
                          style={l.dashed ? { borderColor: l.tone } : { background: l.tone, opacity: 0.55 }}
                        />
                        {l.text}
                      </li>
                    ))}
                    <li className="flex items-center gap-1.5">
                      <span aria-hidden className="h-[9px] w-[9px] rounded-[2px] border" style={{ background: "var(--tnx-surface-inset)", borderColor: "var(--tnx-divider)" }} />
                      free
                    </li>
                  </ul>
                  {suggestion?.at16 && (
                    <p className="text-micro text-ink-tertiary">
                      Whole-block option: <span className="font-mono text-ink-heading">{suggestion.at16}</span>
                    </p>
                  )}
                  {!spaceComplete && (
                    <p className="text-micro text-warn">Empty cells are not verified while the allocation census is incomplete.</p>
                  )}
                  {spaceMap.blocks.some((m) => m.lit.length > MAP_LIST_MAX) && (
                    <p className="text-micro text-ink-faint">Dense call-outs are capped; the routing inventory remains complete.</p>
                  )}
                  {spaceMap.offMap.length > 0 && (
                    <p className="text-micro text-warn">
                      Outside the private blocks and therefore not drawn: <span className="font-mono">{spaceMap.offMap.map((x) => x.cidr).join(", ")}</span>. They are routed exactly the same; only the map cannot place them.
                    </p>
                  )}
                  {spaceMap.unparseable.length > 0 && (
                    <p className="text-micro text-danger">
                      Not a parseable IPv4 CIDR, so not drawn: <span className="font-mono">{spaceMap.unparseable.map((x) => x.cidr).join(", ")}</span>.
                    </p>
                  )}
                </div>
              </Panel>
            )}

            <Panel title={`Reachable DNS (${forwards.length})`}>
              {forwards.length === 0 ? (
                <EmptyState>{forwardsEmptyCopy(ranges.length)}</EmptyState>
              ) : (
                <ul className="max-h-44 space-y-0.5 overflow-y-auto [scrollbar-gutter:stable]">
                  {sortForwards(forwards).map((f) => (
                    <li key={`${f.domain}@${f.resolver_ip}`} className="flex min-h-10 items-center justify-between gap-3 rounded-md px-1.5 text-cell transition-colors hover:bg-white/[.03]">
                      <span className="truncate font-mono text-ink-body" title={f.domain}>{f.domain}</span>
                      <span className="shrink-0 font-mono text-micro text-ink-tertiary">{f.resolver_ip}</span>
                    </li>
                  ))}
                </ul>
              )}
              <p className="mt-2 border-t border-white/[.06] pt-2 text-micro text-ink-faint">
                A forward is handed to devices only when its resolver falls inside a routed range.
              </p>
            </Panel>
          </div>
        </>
      )}
    </div>
  );
}
