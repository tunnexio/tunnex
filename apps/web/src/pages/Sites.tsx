import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useOrg } from "../lib/useOrg";
import {
  api,
  apiErrorMessage,
  loadOne,
  type Loaded,
  type Meta,
  type Member,
  type Org,
  type Role,
  type Site,
  type SiteSubnet,
  type SiteReferences,
  type AgentPolicyTemplateDestinationImpact,
  type Node,
  type HubSet,
  type DNSForward,
} from "../lib/api";
import { hubSetView } from "../lib/hubsetview";
import { mergeOrgForwards, type OrgForwardsView } from "../lib/dnsview";
import { useAuth } from "../lib/auth";
import { toast } from "../components/Toasts";
import {
  Badge,
  Button,
  Card,
  DataTable,
  EmptyState,
  ErrorText,
  Field,
  Input,
  Modal,
  PageHeader,
  Panel,
  Select,
} from "../components/ui";
import { NodeLink } from "../components/viz";
import { LoadRetry } from "../components/LoadRetry";
import { badgeClass } from "../lib/healthview";
import { roleFromMembers } from "../lib/policyview";
import {
  assembleTopology,
  gatewayLiveness,
  gatewayOnline,
  crossesMultiSiteThreshold,
  disjointRefusal,
  forwardsInSubnet,
  nameMatchesExactly,
  meshFrom,
  siteGate,
  sitesView,
  subCeilingGateways,
  type GatewayView,
  type SiteCard,
} from "../lib/sitesview";

// Sites (S8.3): the topology + its mutation surfaces. Reads render wire-truth only (render-floor law);
// mutations all go through the AUDITED service endpoints (Slice-3 condition 4 — nothing routed around the
// audit trail). The pending queue + every mutation affordance are canManage-gated (D5: a member sees the
// read-only topology, never the queue).

interface Raw {
  sites: Site[];
  nodes: Node[];
  subnetsBySite: Record<string, SiteSubnet[]>;
  hubSet: HubSet | null; // S8.6 — the persisted HA hub set (null when unpinned / load failed: no HA surface)
  // S14.5 D1 — the ORG-WIDE zone list, fanned out one request per site. Carries its own per-site failure
  // record, because a short list on a conflict view reads as "no conflict".
  forwards: OrgForwardsView;
}

export default function Sites() {
  const [params, setParams] = useSearchParams();
  const { org: currentOrg, loading: orgLoading, failed: orgFailed } = useOrg();
  const { state } = useAuth();
  const myId = state.status === "authed" ? state.user.id : "";
  const emailVerified = state.status === "authed" && state.user.email_verified;
  const [meta, setMeta] = useState<Meta | null>(null);
  const [org, setOrg] = useState<Org | null>(null);
  const [myRole, setMyRole] = useState<Role | undefined>(undefined);
  const [raw, setRaw] = useState<Raw | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [registering, setRegistering] = useState(false);
  const [routingLan, setRoutingLan] = useState(false); // S8.5 D1 one-screen "route a LAN" affordance
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchIndex, setSearchIndex] = useState(0);
  const priorOrgId = useRef<string | null>(null);
  const selectedSiteId = params.get("site");
  const selectedGatewayId = params.get("gateway");
  const dnsFocus = params.get("dns") === "1";
  const query = params.get("q") ?? "";
  const requestedSection = params.get("section") ?? "overview";
  const section = ["overview", "approvals", "ha", "dns"].includes(requestedSection)
    ? requestedSection
    : "overview";

  const updateQuery = useCallback((next: { site?: string | null; gateway?: string | null; q?: string | null; section?: string | null; dns?: string | null }) => {
    setParams((current) => {
      const updated = new URLSearchParams(current);
      for (const [key, value] of Object.entries(next)) {
        if (value) updated.set(key, value);
        else updated.delete(key);
      }
      return updated;
    });
  }, [setParams]);

  // A selected Site, Gateway focus, search term, and DNS disclosure all belong to
  // Overview. Canonicalize a pasted/reloaded task URL before rendering a different
  // workspace so browser history never preserves an impossible mixed state.
  useEffect(() => {
    if (section === "overview") return;
    if (!params.has("site") && !params.has("gateway") && !params.has("q") && !params.has("dns")) return;
    setParams((current) => {
      const normalized = new URLSearchParams(current);
      normalized.delete("site");
      normalized.delete("gateway");
      normalized.delete("q");
      normalized.delete("dns");
      return normalized;
    }, { replace: true });
  }, [params, section, setParams]);

  useEffect(() => {
    const nextOrgId = currentOrg?.id ?? null;
    if (priorOrgId.current && priorOrgId.current !== nextOrgId) {
      setMeta(null);
      setOrg(null);
      setMyRole(undefined);
      setRaw(null);
      setLoadError(null);
      setRegistering(false);
      setRoutingLan(false);
      updateQuery({ site: null });
    }
    priorOrgId.current = nextOrgId;
  }, [currentOrg?.id, updateQuery]);

  const reload = useCallback(async () => {
    setMeta(null);
    setOrg(null);
    setMyRole(undefined);
    setLoadError(null);
    setRaw(null);
    const mRes = await loadOne(() => api.GET("/api/v1/meta"));
    if (!mRes.ok) return setLoadError(mRes.error);
    setMeta(mRes.data as Meta);
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
    const memRes = (await loadOne(() =>
      api.GET("/api/v1/organizations/{orgId}/members", {
        params: { path: { orgId: first.id } },
      }),
    )) as Loaded<Member[]>;
    setMyRole(roleFromMembers(memRes, myId).role);

    const sRes = (await loadOne(() =>
      api.GET("/api/v1/organizations/{orgId}/sites", {
        params: { path: { orgId: first.id } },
      }),
    )) as Loaded<Site[]>;
    if (!sRes.ok) return setLoadError(sRes.error);
    const nRes = (await loadOne(() =>
      api.GET("/api/v1/organizations/{orgId}/nodes", {
        params: { path: { orgId: first.id } },
      }),
    )) as Loaded<Node[]>;
    if (!nRes.ok) return setLoadError(nRes.error);
    // Per-site subnet fetches are independent → run them in PARALLEL (review #6: was a serial for-await
    // that stalled N round-trips deep on an N-site org).
    const subResults = (await Promise.all(
      sRes.data.map((site) =>
        loadOne(() =>
          api.GET("/api/v1/organizations/{orgId}/sites/{siteId}/subnets", {
            params: { path: { orgId: first.id, siteId: site.id } },
          }),
        ),
      ),
    )) as Loaded<SiteSubnet[]>[];
    const subnetsBySite: Record<string, SiteSubnet[]> = {};
    for (let i = 0; i < sRes.data.length; i++) {
      const subRes = subResults[i];
      if (!subRes.ok) return setLoadError(subRes.error); // any failed subnet load → legible retry, not a partial topology
      subnetsBySite[sRes.data[i].id] = subRes.data;
    }
    // S8.6 hub set (member-readable). NON-fatal: a load failure just hides the HA surface (render-floor —
    // show nothing rather than a broken card or block the whole topology).
    const hRes = (await loadOne(() =>
      api.GET("/api/v1/organizations/{orgId}/hub-set", {
        params: { path: { orgId: first.id } },
      }),
    )) as Loaded<HubSet>;
    // D1 — the org-wide DNS fan-out. ONE request per site, issued HERE with the rest of the page load, not
    // per render: a per-site effect would re-fire on every selection change the mesh causes.
    //
    // NON-FATAL per site, unlike the subnet loads above. A failed subnet load blocks the page because a
    // partial topology is a wrong topology; a failed forwards load is recorded and NAMED instead, because
    // one unreachable site must not hide the zones of the others. `mergeOrgForwards` carries which sites
    // failed so the panel can refuse to claim a clean bill of health.
    const fwdResults = (await Promise.all(
      sRes.data.map((site) =>
        loadOne(() =>
          api.GET("/api/v1/organizations/{orgId}/sites/{siteId}/dns-forwards", {
            params: { path: { orgId: first.id, siteId: site.id } },
          }),
        ),
      ),
    )) as Loaded<DNSForward[]>[];
    setRaw({
      sites: sRes.data,
      nodes: nRes.data,
      subnetsBySite,
      hubSet: hRes.ok ? hRes.data : null,
      forwards: mergeOrgForwards(
        sRes.data.map((site, i) => ({ site, res: fwdResults[i] })),
      ),
    });
    // ⚠ currentOrg IS A DEPENDENCY, AND THAT IS THE HALF THAT MAKES THE SWITCHER WORK. Without it the
    // page keeps rendering the org it mounted with — the control moves, the data does not, and the user is
    // looking at one tenant's screen labelled with another's name.
  }, [currentOrg, myId]);
  useEffect(() => {
    reload();
  }, [reload]);

  const gate = siteGate({ role: myRole, emailVerified });
  const view = sitesView({
    ready: meta != null && org != null,
    loadError: loadError != null,
  });

  const cards: SiteCard[] = useMemo(
    () =>
      raw ? assembleTopology(raw.sites, raw.subnetsBySite, raw.nodes) : [],
    [raw],
  );
  // Approved-subnet count per site — the CW threshold input. Unbound nodes — the bind picker. All gateways
  // (nodes bound to any site) — the CW sub-ceiling naming input. All derived from wire data.
  const approvedCountBySite = useMemo(() => {
    const m: Record<string, number> = {};
    if (raw)
      for (const [sid, subs] of Object.entries(raw.subnetsBySite))
        m[sid] = subs.filter((s) => s.status === "approved").length;
    return m;
  }, [raw]);
  const unboundGatewayNodes = useMemo(
    () =>
      raw
        ? raw.nodes.filter(
            (n) => !n.site_id && n.status === "active" && n.enrolled_kind === "gateway",
          )
        : [],
    [raw],
  );
  const allGateways = useMemo(() => cards.flatMap((c) => c.gateways), [cards]);

  const selectedCard = cards.find((c) => c.id === selectedSiteId) ?? null;
  const visibleCards = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return cards;
    return cards.filter((card) =>
      card.name.toLowerCase().includes(needle) ||
      card.gateways.some((gateway) => gateway.name.toLowerCase().includes(needle)),
    );
  }, [cards, query]);

  const searchResults = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle || !raw) return [];
    const results: Array<{ id: string; label: string; detail: string; siteId: string | null; gatewayId: string | null; unbound: boolean }> = [];
    for (const card of cards) {
      if (card.name.toLowerCase().includes(needle))
        results.push({ id: `site:${card.id}`, label: card.name, detail: "Site", siteId: card.id, gatewayId: null, unbound: false });
      for (const gateway of card.gateways)
        if (gateway.name.toLowerCase().includes(needle))
          results.push({ id: `gateway:${gateway.id}`, label: gateway.name, detail: `Gateway bound to ${card.name}`, siteId: card.id, gatewayId: gateway.id, unbound: false });
    }
    for (const node of unboundGatewayNodes)
      if (node.name.toLowerCase().includes(needle))
        results.push({ id: `unbound:${node.id}`, label: node.name, detail: "Eligible unbound Gateway", siteId: null, gatewayId: node.id, unbound: true });
    return results;
  }, [cards, query, raw, unboundGatewayNodes]);

  function selectSearchResult(result: typeof searchResults[number]) {
    setSearchOpen(false);
    setSearchIndex(0);
    if (result.unbound) {
      updateQuery({ site: null, gateway: result.gatewayId });
      return;
    }
    updateQuery({ site: result.siteId, gateway: result.gatewayId });
  }

  useEffect(() => {
    if (selectedSiteId && cards.length > 0 && !cards.some((card) => card.id === selectedSiteId)) {
      updateQuery({ site: null });
    }
  }, [cards, selectedSiteId, updateQuery]);

  const selectSite = useCallback((siteId: string | null) => updateQuery({ site: siteId, gateway: null }), [updateQuery]);

  const mesh = useMemo(
    () => meshFrom(cards, raw?.nodes ?? [], raw?.hubSet),
    [cards, raw],
  );

  return (
    <div className="flex flex-col gap-3.5">
      <PageHeader
        title="Sites"
        subtitle={org ? org.name : "…"}
        actions={
          view === "body" && gate.canManage ? (
          <div className="flex items-center gap-2.5">
            {unboundGatewayNodes.length > 0 && (
              <Button variant="ghost" onClick={() => setRoutingLan(true)}>
                Route a LAN
              </Button>
            )}
            <Button onClick={() => setRegistering(true)}>Add site</Button>
          </div>
          ) : null
        }
      />

      {view === "load_retry" && (
        <LoadRetry error={loadError ?? "Couldn't load."} onRetry={reload} />
      )}
      {view === "loading" && (
        <p className="text-cell text-ink-faint">Loading…</p>
      )}

      {view === "body" && raw != null && org != null && (
        <>
          <nav aria-label="Sites workspace" className="flex flex-wrap gap-1 rounded-lg border border-line bg-ink-900 p-1">
            {[
              ["overview", "Overview"],
              ["approvals", "Pending approvals"],
              ["ha", "Hub availability"],
              ["dns", "DNS overview"],
            ].map(([id, label]) => (
              <button
                key={id}
                type="button"
                aria-current={section === id ? "page" : undefined}
                onClick={() => updateQuery(id === "overview" ? { section: id } : { section: id, site: null, gateway: null, q: null, dns: null })}
                className={`rounded-md px-3 py-1.5 text-cell ${section === id ? "bg-ink-700 text-ink-heading" : "text-ink-tertiary hover:text-ink-heading"}`}
              >
                {label}
              </button>
            ))}
          </nav>
          {section === "overview" && (
            <div className="flex min-w-0 flex-col gap-3">
              <Panel
                title="Network map"
                className="min-w-0"
                actions={
                  /* D2 (ruled): scoped to the MAP, not the page. The mesh's edges are handshake-derived, so
                     the claim is true here. Over the subnet queue it would not be — those are control-plane
                     rows. */
                  <span className="rounded-full border border-line bg-ink-800 px-2 py-0.5 font-mono text-micro text-ink-tertiary">
                    ● WIRE-TRUTH
                  </span>
                }
              >
                {/* The handoff puts the hint INLINE beside the title (dc.html L454). Ours drops "hover to
                    trace a link" because we do not implement hover tracing — describing an interaction the
                    component does not have is the same class of lie as a chart with no source. */}
                <p className="-mt-1.5 text-micro text-ink-faint">
                  Select a Site to focus it · Hub membership is derived by the backend
                </p>
                <div className="mb-2 flex flex-wrap items-center gap-2">
                  <Input
                    aria-label="Search Sites or Gateways"
                    role="combobox"
                    aria-expanded={searchOpen && query.trim().length > 0}
                    aria-controls="site-search-results"
                    value={query}
                    onChange={(event) => {
                      const next = event.target.value;
                      updateQuery({ q: next, site: null, gateway: null });
                      setSearchOpen(true);
                      setSearchIndex(0);
                    }}
                    onFocus={() => setSearchOpen(true)}
                    onKeyDown={(event) => {
                      if (event.key === "Escape") return setSearchOpen(false);
                      if (event.key === "ArrowDown") { event.preventDefault(); setSearchIndex((i) => Math.min(i + 1, Math.max(0, searchResults.length - 1))); }
                      if (event.key === "ArrowUp") { event.preventDefault(); setSearchIndex((i) => Math.max(0, i - 1)); }
                      if (event.key === "Enter") {
                        const exact = searchResults.find((r) => r.label.toLowerCase() === query.trim().toLowerCase());
                        const result = exact ?? (searchResults.length === 1 ? searchResults[0] : searchResults[searchIndex]);
                        if (result) { event.preventDefault(); selectSearchResult(result); }
                      }
                    }}
                    placeholder="Find a Site or Gateway"
                    className="max-w-sm"
                  />
                  <Button variant="ghost" onClick={() => { updateQuery({ q: null, site: null, gateway: null }); setSearchOpen(false); }}>
                    Fit overview
                  </Button>
                  <span className="text-micro text-ink-faint">{cards.length} Sites · overview only</span>
                </div>
                {searchOpen && query.trim() && (
                  <div id="site-search-results" role="listbox" aria-label="Site and Gateway search results" className="mb-3 max-w-xl overflow-hidden rounded-lg border border-line bg-ink-800">
                    {searchResults.length ? searchResults.map((result, index) => (
                      <button key={result.id} type="button" role="option" aria-selected={index === searchIndex} onMouseDown={(event) => event.preventDefault()} onClick={() => selectSearchResult(result)} className={`flex w-full items-center justify-between gap-3 border-b border-line px-3 py-2 text-left text-cell last:border-0 ${index === searchIndex ? "bg-ink-700 text-ink-heading" : "text-ink-body hover:bg-ink-700"}`}>
                        <span className="font-medium">{result.label}</span><span className="text-micro text-ink-tertiary">{result.detail}</span>
                      </button>
                    )) : <p className="px-3 py-2 text-cell text-ink-tertiary">No Sites or loaded Gateways match. Clear the search to restore the overview.</p>}
                  </div>
                )}
                <NodeLink
                  label="Site topology"
                  source={{ endpoint: "/api/v1/organizations/{orgId}/sites" }}
                  failed={false}
                  nodes={mesh.nodes}
                  links={mesh.links}
                  selectedId={selectedSiteId}
                  onSelect={selectSite}
                  maxHeight={300}
                  empty="Route a LAN to draw your first site here."
                />
                <p className="text-micro text-ink-faint">
                  Link state is derived from the WireGuard handshake. A down
                  site bridge is never shown as healthy. The moving line means
                  the handshake is current, not that traffic is flowing.
                </p>
              </Panel>
              <SelectedSiteStrip card={selectedCard} selectedGatewayId={selectedGatewayId} unboundGateway={unboundGatewayNodes.find((node) => node.id === selectedGatewayId) ?? null} onRouteLan={() => setRoutingLan(true)} />

              {/* D3 (ruled): the mesh sits ABOVE the list and scopes it; it does not replace it. The wireframe
              drew only a diagram because a drawing never had to manage anything.

              ⛔ THE LIST IS A TABLE AND THE DETAIL IS ONE CARD. Rendering a full card per site made the page
              grow with the network — 10 sites was 3,200px of scroll, and the two teaching accordions were
              identical on every one of them. Now: every site is one row, and the SELECTED site alone expands
              into the card that carries the forms. */}
              <SiteList
                cards={visibleCards}
                canManage={gate.canManage}
                query={query}
                selectedId={selectedSiteId}
                onSelect={selectSite}
              />

              {selectedCard && (
                <div id="site-details">
                  <SiteCardView
                    card={selectedCard}
                    canManage={gate.canManage}
                    orgId={org.id}
                    unboundNodes={unboundGatewayNodes}
                    dnsFocus={dnsFocus}
                    onDone={reload}
                  />
                </div>
              )}
            </div>
          )}

          {section === "approvals" && (
            gate.canManage ? (
              <PendingQueue
                orgId={org.id}
                approvedCountBySite={approvedCountBySite}
                allGateways={allGateways}
                ceiling={meta?.protocol_version ?? 0}
                siteNames={Object.fromEntries(raw.sites.map((site) => [site.id, site.name]))}
                onDone={reload}
              />
            ) : (
              <Panel title="Pending subnet approvals">
                <p className="text-cell text-ink-tertiary">You can view Sites, but approving routed ranges requires site:manage and a verified email.</p>
              </Panel>
            )
          )}

          {section === "ha" && (
            <HubSetSection
              orgId={org.id}
              canManage={gate.canManage}
              hubSet={raw.hubSet}
              gateways={allGateways}
              onDone={reload}
            />
          )}

          {section === "dns" && (
            <DNSForwardsPanel
              view={raw.forwards}
              siteCount={raw.sites.length}
              canManage={gate.canManage}
              onManageSite={(siteId) => updateQuery({ section: "overview", site: siteId, gateway: null, q: null, dns: "1" })}
            />
          )}
        </>
      )}
      {view === "body" && raw == null && (
        <p className="text-cell text-ink-faint">Loading…</p>
      )}

      {registering && org && (
        <RegisterSiteModal
          orgId={org.id}
          onDone={reload}
          onClose={() => setRegistering(false)}
        />
      )}
      {routingLan && org && (
        <RouteLANModal
          orgId={org.id}
          nodes={unboundGatewayNodes}
          onDone={reload}
          onClose={() => setRoutingLan(false)}
        />
      )}
    </div>
  );
}

// ── S14.5 — CROSS-SITE DNS FORWARDING, ORG-WIDE (D1) ────────────────────────────────────────────────────
//
// The wireframe lists zones across the org with a `via <site>` column. Our endpoint is per-site, so this is
// an N+1 — founder-ruled and accepted, because the invariant it exists to show (one zone maps to one
// resolver ORG-WIDE) cannot be seen from inside any single site.
function DNSForwardsPanel({
  view,
  siteCount,
  canManage,
  onManageSite,
}: {
  view: OrgForwardsView;
  siteCount: number;
  canManage: boolean;
  onManageSite: (siteId: string) => void;
}) {
  return (
    <Panel title="DNS overview" className="min-w-0">
      <p className="-mt-1 text-cell text-ink-tertiary">Organization-wide forwarding inventory and conflicts. Manage each resolver from its Site.</p>
      {/* ⛔ THE PARTIAL-LOAD BANNER COMES FIRST, above the rows it qualifies. Below them it would be read
          after the list had already been believed. */}
      {view.failedSites.length > 0 && (
        <p role="status" className="text-cell text-danger">
          Could not read zones from {view.failedSites.join(", ")}. This list is
          incomplete, so conflicts cannot be ruled out.
        </p>
      )}

      {siteCount === 0 ? (
        <EmptyState>Nothing to forward between yet.</EmptyState>
      ) : view.rows.length === 0 ? (
        <EmptyState>
          {view.conflictsAreComplete
            ? "No forwarded zones. Add one on a site below."
            : "No zones read from the sites that answered."}
        </EmptyState>
      ) : (
        <div className="overflow-x-auto">
          <div className="min-w-[680px]">
            <div className="grid grid-cols-[minmax(12rem,1.3fr)_minmax(10rem,1fr)_minmax(8rem,.8fr)_7rem_8.5rem] gap-3 border-b border-line px-2.5 py-1.5 text-micro uppercase tracking-wide text-ink-faint">
              <span>Zone</span>
              <span>Resolver</span>
              <span>Site</span>
              <span className="text-right">Status</span>
              <span className="text-right">Action</span>
            </div>
            <ul className="flex flex-col gap-1.5 pt-1.5">
          {view.rows.map((r) => {
            const clashes = view.conflicts.includes(r.domain);
            return (
              <li
                key={`${r.siteId}-${r.domain}`}
                className={`grid grid-cols-1 gap-2 rounded-md border px-2.5 py-2 sm:grid-cols-[minmax(12rem,1.3fr)_minmax(10rem,1fr)_minmax(8rem,.8fr)_7rem_8.5rem] sm:items-center sm:gap-3 ${clashes ? "border-danger/40 bg-danger/5" : "border-line bg-ink-800"}`}
              >
                <span className="font-mono text-cell text-ink-body"><span className="mr-2 text-micro text-ink-faint sm:hidden">Zone</span>{r.domain}</span>
                <span className="font-mono text-cell text-ink-tertiary"><span className="mr-2 text-micro text-ink-faint sm:hidden">Resolver</span>{r.resolverIp}</span>
                <span className="text-cell text-ink-tertiary"><span className="mr-2 text-micro text-ink-faint sm:hidden">Site</span>{r.siteName}</span>
                <span className="sm:justify-self-end">{clashes ? <Badge tone="danger">conflict</Badge> : <Badge tone="neutral">configured</Badge>}</span>
                {canManage ? <Button className="w-[8.5rem] sm:justify-self-end" variant="ghost" size="sm" onClick={() => onManageSite(r.siteId)}>Manage in Site</Button> : <span className="text-right text-micro text-ink-faint">Read-only</span>}
              </li>
            );
          })}
            </ul>
          </div>
        </div>
      )}

      {/* ⛔ ONLY CLAIM A CLEAN BILL OF HEALTH WHEN THE READ WAS COMPLETE. "No conflicts found" and "no
          conflicts exist" are different claims and only the second is reassuring. */}
      {view.conflicts.length > 0 && (
        <p className="rounded-md border border-danger/40 bg-danger/5 px-3 py-2 text-cell text-danger">
          {view.conflicts.join(", ")} has conflicting resolvers across Sites.
          Resolution order is not deterministic; correct the conflicting zone
          before relying on it.
        </p>
      )}

      <p className="text-micro text-ink-faint">
        A resolver must sit inside one of the site&rsquo;s approved subnets (409
        dns_resolver_not_in_site_subnet). One zone maps to one resolver org-wide
        (409 dns_domain_conflict). Removing a zone withdraws it from every
        gateway on the next reconcile.
      </p>
    </Panel>
  );
}

// RouteLANModal (S8.5 D1) — the one-screen affordance for the solo-admin / Pritunl migrator: pick a
// gateway, type a LAN CIDR, go. One POST does register-site + bind + advertise + approve (byte-identical
// to the long ceremony). Name is optional (the server derives one). A range collision renders the typed
// refusal VERBATIM (the one validator + its teaching text — no JS re-check).
function RouteLANModal({
  orgId,
  nodes,
  onDone,
  onClose,
}: {
  orgId: string;
  nodes: Node[];
  onDone: () => void;
  onClose: () => void;
}) {
  const [nodeId, setNodeId] = useState(nodes[0]?.id ?? "");
  const [cidr, setCidr] = useState("");
  const [name, setName] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  async function submit() {
    setBusy(true);
    setErr(null);
    const { error } = await api.POST(
      "/api/v1/organizations/{orgId}/routed-lans",
      {
        params: { path: { orgId } },
        body: {
          node_id: nodeId,
          cidr: cidr.trim(),
          ...(name.trim() ? { name: name.trim() } : {}),
        },
      },
    );
    setBusy(false);
    if (error)
      return setErr(apiErrorMessage(error, "Could not route the LAN.")); // verbatim typed refusal — no JS re-check
    onClose();
    onDone();
  }
  return (
    <Modal
      title="Route a LAN through this gateway"
      onDismiss={onClose}
      actions={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={busy || !nodeId || !cidr.trim()}>
            Route it
          </Button>
        </>
      }
    >
      <p className="text-sm text-slate-400">
        Route a behind-gateway LAN to your devices. This registers a site on the
        gateway, advertises the range, and approves it. The range then pushes to
        split-tunnel devices.
      </p>
      <Field label="Gateway">
        <Select value={nodeId} onChange={(e) => setNodeId(e.target.value)}>
          {nodes.map((n) => (
            <option key={n.id} value={n.id}>
              {n.name}
            </option>
          ))}
        </Select>
      </Field>
      <Field label="LAN CIDR">
        <Input
          value={cidr}
          onChange={(e) => setCidr(e.target.value)}
          placeholder="192.168.10.0/24"
          autoFocus
        />
      </Field>
      <Field label="Site name (optional)">
        <Input
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="derived from the CIDR"
        />
      </Field>
      <ErrorText>{err}</ErrorText>
    </Modal>
  );
}

// ── S8.6 hub set (HA): the operator surface + the L1 metrics ─────────────────────────
// The persisted HA hub set — ordered candidates (PRIMARY on members[0], evolving the HUB badge vocabulary),
// warm/handshake state + L1 byte counters per member (from node_peer_status — render-floor: a not-reporting
// link shows "—", NEVER 0; an idle link shows its real 0 bytes), and the generation as the set's version
// tag. When the active order diverges from the configured pins a failover is IN EFFECT — stated, with the
// demoted member marked and an audit pointer. Member-readable; the pin control is manage-gated.
function HubSetSection({
  orgId,
  canManage,
  hubSet,
  gateways,
  onDone,
}: {
  orgId: string;
  canManage: boolean;
  hubSet: HubSet | null;
  gateways: GatewayView[];
  onDone: () => void;
}) {
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const view = hubSetView(hubSet, Date.now());
  const nameOf = (id: string) =>
    gateways.find((g) => g.id === id)?.name ?? id.slice(0, 8);
  const priorityByNode = new Map<string, number | null>();
  for (const m of hubSet?.members ?? [])
    priorityByNode.set(m.node_id, m.hub_priority ?? null);

  async function setPin(nodeId: string, priority: number | null) {
    setBusy(true);
    setErr(null);
    const { error } = await api.PUT(
      "/api/v1/organizations/{orgId}/nodes/{nodeId}/hub-priority",
      {
        params: { path: { orgId, nodeId } },
        body: { priority },
      },
    );
    setBusy(false);
    if (error)
      return setErr(apiErrorMessage(error, "Could not set the hub priority."));
    onDone();
  }

  // Nothing to show a MEMBER when no HA set is configured (zero-config — no HA surface).
  if (!view && !canManage) return null;

  // ⛔ BELOW THE THRESHOLD THE PANEL EXPLAINS ITSELF AND OFFERS NO CONTROL (S14.5, founder-ruled).
  //
  // It used to render "pin as primary" beside a lone gateway, under copy about failing transit over to a
  // standby if the primary goes stale. THERE IS NOTHING TO FAIL OVER TO. A control for multi-gateway transit,
  // offered on a one-gateway stack, describes machinery that cannot engage — the same family as a
  // `site link down` badge on a link that was never attempted.
  //
  // THE RULE, FOR EVERY SCREEN: WHEN A CONTROL IS MEANINGLESS AT CURRENT SCALE, RENDER THE PANEL WITH AN
  // EMPTY STATE THAT NAMES THE PRECONDITION AND THE ACTION THAT CROSSES IT. NEVER THE CONTROL, NEVER
  // DISABLED-WITHOUT-REASON, NEVER ABSENT.
  //
  //   · not ABSENT   — scale is a state the operator MOVES THROUGH, unlike an edition boundary, which is a
  //                    purchase. Hiding HA means they never learn it exists nor what unlocks it.
  //   · not DISABLED — a greyed control says something is unavailable without saying why or what to do.
  //   · not OFFERED  — which is what shipped, and it produced the question "when does connectivity start?"
  //
  // An EXISTING hub set still renders in full: crossing back below the threshold (a gateway revoked) must
  // show the set that is still configured, not hide it behind a precondition notice.
  const HA_MIN_GATEWAYS = 2;
  if (!view && gateways.length < HA_MIN_GATEWAYS) {
    return (
      <Panel title="Hub high-availability">
        <p className="mt-1 text-xs text-slate-500">
          High availability needs {HA_MIN_GATEWAYS} or more gateways. You have{" "}
          {gateways.length}. Enrol another gateway and bind it to a site, then
          pin the candidates here to create the hub set.
        </p>
      </Panel>
    );
  }

  return (
    <Panel
      title="Hub high-availability"
      className="min-w-0"
      actions={view ? <span className="text-micro text-ink-tertiary">hub set v{view.generation}</span> : undefined}
    >
      <div className="space-y-4">
        <div className="rounded-lg border border-line bg-ink-800 p-3">
          {view ? (
        <>
          {view.promotionInEffect && (
            <p className="mt-2 rounded border border-amber-500/30 bg-amber-500/5 px-2 py-1 text-xs text-amber-300">
              Failover in effect: the configured primary is unreachable, and a
              standby is carrying transit. The hub restores when it recovers.
              See the{" "}
              <Link className="text-accent-400 underline underline-offset-2 hover:text-ink-primary" to="/audit">
                audit log
              </Link>{" "}
              (<span className="font-mono">hub_set.promotion</span>) for the timeline.
            </p>
          )}
          <ul className="mt-2 space-y-1">
            {view.members.map((m) => (
              <li key={m.nodeId} className="flex items-center gap-2 text-sm">
                <span className="text-slate-200">{nameOf(m.nodeId)}</span>
                {m.role === "primary" ? (
                  <span className="rounded bg-sky-500/10 px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-sky-300">
                    primary
                  </span>
                ) : (
                  <span className="rounded bg-white/5 px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-slate-400">
                    standby
                  </span>
                )}
                {m.demoted && (
                  <span className="text-[11px] text-amber-400">
                    demoted (stale)
                  </span>
                )}
                {m.warm === true && (
                  <span className="text-[11px] text-emerald-400">warm</span>
                )}
                {m.warm === false && (
                  <span className="text-[11px] text-rose-400">stale</span>
                )}
                <span className="ml-auto text-[11px] text-slate-500">
                  ↓{m.rx} ↑{m.tx} ·{" "}
                  {m.handshakeAge === "n/a"
                    ? "no data"
                    : `handshake ${m.handshakeAge}`}
                </span>
              </li>
            ))}
          </ul>
          <p className="mt-2 text-[11px] text-slate-600">
            Byte counters are cumulative since the last handshake (raw gauges).
            Refreshed on load.
          </p>
        </>
          ) : (
            canManage && (
          <p className="mt-2 text-xs text-slate-500">
            No HA hub set. Pin two or more gateways below to create one. The
            pinned gateways become the ordered hub candidates (primary +
            standbys) and the CP fails transit over if the primary goes stale.
          </p>
            )
          )}
        </div>

        {canManage && (
        <div className="border-t border-line pt-4">
          <p className="text-[11px] text-slate-500">
            Pin a gateway as a hub candidate (lower number = more preferred).
            Pinning creates/edits the HA hub set.
          </p>
          <ul className="mt-2 space-y-1">
            {gateways.map((g) => {
              const pri = priorityByNode.get(g.id);
              const pinned = pri != null;
              const pins = [...priorityByNode.values()].filter(
                (v): v is number => v != null,
              );
              const nextPin = pins.length ? Math.max(...pins) + 1 : 1; // append after the current candidates
              return (
                <li key={g.id} className="flex flex-wrap items-center gap-2 border-b border-line/70 py-2 text-sm last:border-0">
                  <span className="text-slate-300">{g.name}</span>
                  {pinned && (
                    <span className="text-[11px] text-slate-500">
                      pin #{pri}
                    </span>
                  )}
                  <span className="ml-auto flex gap-1">
                    {pinned ? (
                      <Button
                        variant="ghost"
                        size="sm"
                        disabled={busy}
                        onClick={() => setPin(g.id, null)}
                      >
                        unpin
                      </Button>
                    ) : (
                      <Button
                        variant="ghost"
                        size="sm"
                        disabled={busy}
                        onClick={() => setPin(g.id, nextPin)}
                      >
                        {nextPin === 1 ? "pin as primary" : `pin #${nextPin}`}
                      </Button>
                    )}
                  </span>
                </li>
              );
            })}
          </ul>
        </div>
        )}
      </div>
      <ErrorText>{err}</ErrorText>
    </Panel>
  );
}

function SelectedSiteStrip({ card, selectedGatewayId, unboundGateway, onRouteLan }: { card: SiteCard | null; selectedGatewayId: string | null; unboundGateway: Node | null; onRouteLan: () => void }) {
  if (unboundGateway) {
    return <section aria-label="Selected Site" className="flex flex-wrap items-center gap-x-4 gap-y-2 rounded-lg border border-line bg-ink-800 px-3 py-2 text-cell"><span className="font-semibold text-ink-heading">{unboundGateway.name}</span><Badge tone="neutral">Unbound Gateway</Badge><span className="text-ink-tertiary">No Site is bound. Its location is not shown on this topology.</span><Button className="ml-auto" variant="ghost" onClick={onRouteLan}>Route a LAN</Button></section>;
  }
  if (!card) {
    return (
      <section
        aria-label="Selected Site"
        className="flex flex-wrap items-center gap-x-4 gap-y-1 rounded-lg border border-line bg-ink-800 px-3 py-2 text-cell text-ink-tertiary"
      >
        <span className="font-medium text-ink-heading">Select a Site</span>
        <span>Choose one from the map or inventory to inspect its configuration and actions.</span>
      </section>
    );
  }
  const activeGateway = card.gateways.find((gateway) => gateway.id === selectedGatewayId) ?? card.gateways.find((gateway) => gateway.status === "active");
  const state = activeGateway?.health?.label ?? (activeGateway ? "Gateway active" : "No active Gateway");
  const tone = activeGateway?.health?.tone as "ok" | "warn" | "danger" | "neutral" | undefined;
  return (
    <section
      aria-label={`Selected Site: ${card.name}`}
      className="flex flex-wrap items-center gap-x-4 gap-y-2 rounded-lg border border-line bg-ink-800 px-3 py-2 text-cell"
    >
      <span className="font-semibold text-ink-heading">{card.name}</span>
      <Badge tone={tone ?? "neutral"}>{state}</Badge>
      <span className="text-ink-tertiary">{activeGateway ? `Gateway: ${activeGateway.name}` : `${card.gateways.length} gateway${card.gateways.length === 1 ? "" : "s"}`}</span>
      <span className="text-ink-tertiary">{card.subnets.length} range{card.subnets.length === 1 ? "" : "s"}</span>
      <a className="ml-auto text-accent-400 underline underline-offset-2 hover:text-ink-primary" href="#site-details">
        View details
      </a>
    </section>
  );
}

// ── the read-only topology + per-site mutation affordances ───────────────────────────
// ── S14.5 — THE SITE LIST SCALES, THE DETAIL DOES NOT REPEAT ────────────────────────────────────────────
//
// ⛔ WHAT WAS WRONG. Every site rendered as a full CARD: name, gateway, health, subnet chips, TWO collapsed
// teaching accordions and four buttons. ~320px each.
//
//     5 sites  = 1,600px of scroll
//    10 sites  = 3,200px
//    50 sites  = unusable
//
// And the two accordions — "Cloud fabric setup" and "Cross-site DNS forwarding" — are STATIC TEACHING TEXT,
// IDENTICAL ON EVERY CARD. N sites meant N copies of the same paragraph. The page's height grew with the
// network while the information in it did not.
//
// ⛔ THE SHAPE THAT SCALES: A LIST IS A TABLE. A DETAIL IS ONE PANEL. SELECTION IS THE LINK BETWEEN THEM.
//
// One row per site — scannable, sortable-shaped, constant height, works at 500 sites. The row carries the
// facts you compare ACROSS sites (health, gateway, ranges). The panel carries what you only need for ONE
// (actions, teaching text, forms). Nothing that is the same on every site is rendered more than once.
//
// Selecting a row selects the same site the MESH selects — one selection, two ways in.
function SiteList({
  cards,
  canManage,
  query,
  selectedId,
  onSelect,
}: {
  cards: SiteCard[];
  canManage: boolean;
  query: string;
  selectedId: string | null;
  onSelect: (id: string | null) => void;
}) {
  const columns = [
    {
      key: "name",
      header: "Site",
      cell: (c: SiteCard) => (
        <button
          type="button"
          aria-pressed={c.id === selectedId}
          onClick={() => onSelect(c.id === selectedId ? null : c.id)}
          className={`text-left font-mono ${c.id === selectedId ? "text-ink-heading underline" : "text-ink-primary"}`}
        >
          {c.name}
        </button>
      ),
    },
    {
      key: "gw",
      header: "Gateway",
      cell: (c: SiteCard) => {
        const gw = c.gateways.find((g) => g.status === "active");
        return gw ? (
          <span className="flex items-center gap-1.5">
            <span className="font-mono text-ink-body">{gw.name}</span>
            {gw.isHub && <Badge tone="neutral">HUB</Badge>}
          </span>
        ) : (
          // NOT an empty cell: "no gateway bound" is a fact, and a blank would read as missing data.
          <span className="text-ink-faint">none bound</span>
        );
      },
    },
    {
      key: "health",
      header: "State",
      cell: (c: SiteCard) => {
        const gw = c.gateways.find((g) => g.status === "active");
        if (!gw) return <span className="text-ink-faint">no link</span>;
        return gw.health ? (
          <Badge tone={gw.health.tone as "ok" | "warn" | "danger" | "neutral"}>
            {gw.health.label}
          </Badge>
        ) : (
          <Badge tone="ok">linked</Badge>
        );
      },
    },
    {
      key: "ranges",
      header: "Ranges",
      cell: (c: SiteCard) =>
        c.subnets.length === 0 ? (
          <span className="text-ink-faint">none</span>
        ) : (
          // ⛔ role + accessible name, NOT `title`. A `title` on a role-less <span> is not an accessible
          // name a screen reader reliably announces, and querying it violated query rule 1 — role and
          // accessible name only. The chip is a LIST ITEM stating a range's routing state, so it says so.
          <span role="list" className="flex flex-wrap gap-1">
            {c.subnets.map((sn) => (
              <span
                key={sn.id}
                role="listitem"
                aria-label={`${sn.cidr}: ${
                  sn.status === "approved"
                    ? "Approved, routed"
                    : "Pending approval, not yet routed"
                }`}
                className={`rounded border px-1.5 py-px font-mono text-micro ${
                  sn.status === "approved"
                    ? "border-line text-ink-body"
                    : "border-warn/50 text-warn"
                }`}
              >
                {sn.cidr}
                {sn.status === "pending" && " · pending"}
              </span>
            ))}
          </span>
        ),
    },
  ];

  return (
    <Panel title={`Sites · ${cards.length}`}>
      <DataTable
        caption="Sites"
        columns={columns}
        rows={cards}
        rowKey={(c: SiteCard) => c.id}
        empty={
          query.trim()
            ? "No Sites or Gateways match this search. Clear the search to restore the inventory."
            : canManage
            ? "No sites yet. Use Route a LAN above, or Add site for an empty one."
            : "No sites yet. An owner or admin can add one."
        }
        // The page blanks to a retry on any failed load, so reaching this render means the read succeeded.
        failed={false}
      />
    </Panel>
  );
}

function SiteCardView({
  card,
  canManage,
  orgId,
  unboundNodes,
  dnsFocus,
  onDone,
}: {
  card: SiteCard;
  canManage: boolean;
  orgId: string;
  unboundNodes: Node[];
  dnsFocus: boolean;
  onDone: () => void;
}) {
  const approvedSubnet = card.subnets.find((subnet) => subnet.status === "approved")?.cidr;
  const resolverHint = approvedSubnet
    ? `Resolver IP inside ${approvedSubnet}`
    : "Resolver IP inside an approved subnet";
  const [modal, setModal] = useState<
    "subnet" | "bind" | "unbind" | "delete" | null
  >(null);
  const [removing, setRemoving] = useState<{
    id: string;
    cidr: string;
    status: string;
  } | null>(null); // WF-5
  const hasGateway = card.gateways.length > 0;
  return (
    <Card className="space-y-5">
      <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1 border-b border-line pb-3">
        <div>
          <p className="text-micro uppercase tracking-wide text-ink-faint">Selected Site</p>
          <h2 className="text-title font-semibold text-ink-heading">{card.name}</h2>
        </div>
        <span className="text-xs text-slate-500">
          {card.gateways.length === 1
            ? "1 gateway"
            : `${card.gateways.length} gateways`}
        </span>
      </div>

      <section>
        <h3 className="text-cell font-semibold text-ink-heading">Gateways</h3>
        {card.gateways.length === 0 ? (
          <p className="mt-1 text-xs text-slate-500">No gateway bound.</p>
        ) : (
          <ul className="mt-2 space-y-1">
          {card.gateways.map((g) => (
            <GatewayRow key={g.id} g={g} />
          ))}
          </ul>
        )}
      </section>

      <section>
        <h3 className="text-cell font-semibold text-ink-heading">Routed ranges</h3>
        {card.subnets.length === 0 ? (
          <p className="mt-1 text-xs text-slate-500">No ranges advertised.</p>
        ) : (
        <div role="list" className="mt-2 flex flex-wrap gap-2">
          {card.subnets.map((s) => (
            <span
              key={s.id}
              role="listitem"
              aria-label={`${s.cidr}: ${
                s.status === "approved"
                  ? "Approved, routed"
                  : "Pending approval, not yet routed"
              }`}
              className={`rounded px-2 py-0.5 text-xs ${
                s.status === "approved"
                  ? "bg-white/5 text-slate-300"
                  : "border border-amber-500/30 text-amber-300"
              }`}
            >
              {s.cidr}
              {s.status === "pending" && " · pending"}
              {canManage && (
                <button
                  type="button"
                  className="ml-1.5 text-slate-500 hover:text-rose-400"
                  aria-label={`Remove ${s.cidr}`}
                  title="Remove this subnet (un-advertise)"
                  onClick={() =>
                    setRemoving({ id: s.id, cidr: s.cidr, status: s.status })
                  }
                >
                  ✕
                </button>
              )}
            </span>
          ))}
        </div>
        )}
      </section>

      {/* WF-3: guided cloud-fabric setup, SURFACED IN-UI (not docs-only). STATIC per cloud — the SDN
          steps that get a behind-host's packet to this gateway are un-codeable, so we show the copy-paste
          the operator applies in ONE cloud-console visit (the Zero-Touch Law boundary clause). No
          cloud-detection this pass (that rides S8.5); doc link for the full reference. */}
      {hasGateway && card.subnets.some((s) => s.status === "approved") && (
        <details className="mt-3 rounded-lg border border-white/5 bg-ink-900/60 px-3 py-2 text-xs text-slate-400">
          <summary className="cursor-pointer text-slate-300">
            Cloud fabric setup, one console visit per side (why a behind-host
            may not reach yet)
          </summary>
          <div className="mt-2 space-y-2">
            <p>
              A gateway VM forwards for hosts on its LAN, but the cloud SDN must
              (1) let the VM forward and (2) route the REMOTE site's CIDR to
              this gateway. Apply once, in the cloud console, never on the
              gateway.
            </p>
            <p>
              <span className="font-semibold text-slate-300">Both clouds:</span>{" "}
              enable <span className="font-mono">IP forwarding</span> on this
              gateway VM's NIC.
            </p>
            <p>
              <span className="font-semibold text-slate-300">Azure:</span> route
              table on the behind-hosts' subnet → add
              <span className="font-mono"> &lt;REMOTE_CIDR&gt;</span> → next hop{" "}
              <span className="font-mono">Virtual appliance</span> → this
              gateway's private IP.
            </p>
            <p>
              <span className="font-semibold text-slate-300">AWS:</span> disable{" "}
              <span className="font-mono">source/dest check</span> on the
              gateway ENI; route table → add
              <span className="font-mono"> &lt;REMOTE_CIDR&gt;</span> → target =
              the gateway instance/ENI.
            </p>
            {/* A3b PD-4: the DEVICE POOL needs the same return route as the site ranges — behind-host
                replies to a connected device (its 10.99.x pool address) die at the cloud router without
                it. Wording sourced from the Deck-D Leg-10 console fixes (the walk that found the gap). */}
            <p>
              <span className="font-semibold text-slate-300">Devices too:</span>{" "}
              add the SAME route for the org's
              <span className="font-mono"> device pool CIDR</span> (Settings
              shows it, e.g. <span className="font-mono">10.99.0.0/24</span>) →
              this gateway. Behind-host replies to a connected device need a way
              back, exactly like a remote site's CIDR.
            </p>
            {/* WF-B (EPIC-8 smooth walk): behind-host HA needs a CLOUD-side route failover. The overlay
                fails over (a standby is promoted) but the VPC route to the gateway ENI is STATIC — the
                zero-touch boundary Tunnex won't cross. By design; documented here so it's not a surprise. */}
            <p>
              <span className="font-semibold text-slate-300">
                High availability:
              </span>{" "}
              a promoted standby carries overlay transit automatically, but a
              behind-host's VPC route points at ONE gateway ENI, so on failover
              repoint it to the new hub (AWS: route-table health check / a small
              Lambda; or a Gateway Load Balancer. Azure: a UDR update). Overlay
              HA is automatic; cloud-fabric HA is yours to wire (the zero-touch
              boundary).
            </p>
            <p className="text-slate-500">
              Full reference:{" "}
              <span className="font-mono">docs/deploy-cloud-gateway.md</span>.
            </p>
          </div>
        </details>
      )}

      {/* S8.4 D7: cross-site DNS forwarding — rides the same card as the fabric steps (one site, one story). */}
      {canManage && card.subnets.some((s) => s.status === "approved") && (
        <DNSForwardSection
          orgId={orgId}
          siteId={card.id}
          open={dnsFocus}
          resolverHint={resolverHint}
        />
      )}

      {canManage && (
        <>
        <div className="flex flex-wrap gap-2 border-t border-line pt-4">
          <Button variant="ghost" onClick={() => setModal("subnet")}>
            Advertise subnet
          </Button>
          {/* S8.6 D4: Bind and Unbind are NOT mutually exclusive — a site can carry MORE THAN ONE gateway (an
              HA hub pair is exactly that). The old `hasGateway ? Unbind : Bind` was the list-of-one assumption
              in the action path: once the first gateway bound, the second was unreachable through the product's
              own UI (the box-walk had to POST /bind from the console). Unbind shows when a gateway is bound;
              Bind shows whenever an unbound gateway exists — both can show together. */}
          {hasGateway && (
            <Button variant="ghost" onClick={() => setModal("unbind")}>
              Unbind gateway
            </Button>
          )}
          {unboundNodes.length > 0 && (
            <Button variant="ghost" onClick={() => setModal("bind")}>
              Bind gateway
            </Button>
          )}
        </div>
        <section className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-danger/40 bg-danger/5 px-3 py-2.5">
          <div><h3 className="text-cell font-semibold text-danger">Danger zone</h3><p className="mt-0.5 text-micro text-ink-tertiary">Deleting this Site removes its record and server-reported dependent ranges and rules. It cannot be undone; create, bind, and advertise again to recover.</p></div>
          <Button variant="danger" onClick={() => setModal("delete")}>Delete site</Button>
        </section>
        </>
      )}

      {modal === "subnet" && (
        <AddSubnetModal
          orgId={orgId}
          siteId={card.id}
          onDone={onDone}
          onClose={() => setModal(null)}
        />
      )}
      {modal === "bind" && (
        <BindGatewayModal
          orgId={orgId}
          siteId={card.id}
          nodes={unboundNodes}
          onDone={onDone}
          onClose={() => setModal(null)}
        />
      )}
      {modal === "unbind" && (
        <UnbindConfirm
          orgId={orgId}
          siteId={card.id}
          gateways={card.gateways}
          onDone={onDone}
          onClose={() => setModal(null)}
        />
      )}
      {modal === "delete" && (
        <DeleteSiteModal
          orgId={orgId}
          site={card}
          onDone={onDone}
          onClose={() => setModal(null)}
        />
      )}
      {removing && (
        <RemoveSubnetConfirm
          orgId={orgId}
          siteId={card.id}
          subnet={removing}
          onDone={() => {
            setRemoving(null);
            onDone();
          }}
          onClose={() => setRemoving(null)}
        />
      )}
    </Card>
  );
}

// EXPORTED FOR THE SIBLING-CONSISTENCY TEST (D4), not for reuse. The revoked-suppression rule is rendered by
// THREE surfaces — this row, Gateways.tsx and Devices.tsx — and a per-screen test passes on all three while
// they disagree, which is exactly how WF-S11-10 survived on this one. The assertion has to reach the row.
export function GatewayRow({ g }: { g: GatewayView }) {
  // S8.4 rider (VERIFY-0): render the last-seen FACT + an OFFLINE badge when stale, so a stopped gateway no
  // longer reads healthy on the site surface. Extends the S8.3 badge system — no third health vocabulary.
  const live = gatewayLiveness(g.lastSeenAt, Date.now());
  // S8.5 WF-1: the POSITIVE liveness signal — a fresh, healthy, active gateway reads "online" instead of
  // silent absence. Same clock + health bool as the offline/degraded badges (no third vocabulary).
  const online = gatewayOnline(g.status, live.offline, g.health);
  return (
    <li className="flex items-center gap-2 text-sm">
      <a
        className="text-slate-200 hover:text-accent-400 hover:underline"
        href={`/gateways/${g.id}`}
      >
        {g.name}
      </a>
      {g.isHub && (
        <span className="rounded bg-sky-500/10 px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-sky-300">
          hub
        </span>
      )}
      {g.status === "revoked" && (
        <span className="text-xs text-rose-400">revoked</span>
      )}
      {live.offline && (
        <span className={`text-xs ${badgeClass("danger")}`}>offline</span>
      )}
      {/* WF-S11-10, THIRD SURFACE. The fix landed on Gateways.tsx and Devices.tsx already suppressed health on
          revoked rows — this list rendered the same concept with the same defect, so a revoked gateway could
          read "revoked" beside "certificate expired — re-enroll this gateway": two labels contradicting each
          other, the instructional one telling an operator to UNDO a deliberate security action. `offline` stays
          unguarded on purpose — it is a liveness FACT, not an instruction, and a revoked gateway genuinely is
          offline. It is the health/instruction vocabulary that must not describe a gateway no longer meant to
          work. Found by asking who ELSE renders this concept, not by walking the UI. */}
      {g.status !== "revoked" && g.health && (
        <span className={`text-xs ${badgeClass(g.health.tone)}`}>
          {g.health.label}
        </span>
      )}
      {online && <span className="text-xs text-emerald-400">online</span>}
      {/* WF-B: the SUBORDINATE site-link note — a demoted-dead peer while transit is healthy. A distinct
          muted line item naming the peer + "(demoted)", NEVER the headline (a healthy failover reads
          transit-healthy above; this is the "why is there a dead link" detail). Independent of g.health. */}
      {g.siteLinkNote && (
        <span className="text-xs text-slate-500">
          site link down: {g.siteLinkNote.peer}
          {g.siteLinkNote.demoted && " (demoted)"}
        </span>
      )}
      <span className="ml-auto text-[11px] text-slate-500">
        {live.lastSeen}
        {" · "}
        {g.agentVersion}
        {g.maxPolicyVersion != null && ` · policy v${g.maxPolicyVersion}`}
      </span>
    </li>
  );
}

// ── mutation modals (all hit the audited service endpoints) ──────────────────────────
function RegisterSiteModal({
  orgId,
  onDone,
  onClose,
}: {
  orgId: string;
  onDone: () => void;
  onClose: () => void;
}) {
  const [name, setName] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  async function submit() {
    setBusy(true);
    setErr(null);
    const { error } = await api.POST("/api/v1/organizations/{orgId}/sites", {
      params: { path: { orgId } },
      body: { name },
    });
    setBusy(false);
    if (error) {
      const msg = apiErrorMessage(error, "Could not register the site.");
      setErr(msg);
      toast.error(msg);
      return;
    }
    toast.success(`Site "${name}" registered successfully`);
    onClose();
    onDone();
  }
  return (
    <Modal
      title="Register a site"
      onDismiss={onClose}
      actions={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={busy || name.trim() === ""}>
            Register
          </Button>
        </>
      }
    >
      <Field label="Site name">
        <Input
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="e.g. Mumbai office"
          autoFocus
        />
      </Field>
      <ErrorText>{err}</ErrorText>
    </Modal>
  );
}

function AddSubnetModal({
  orgId,
  siteId,
  onDone,
  onClose,
}: {
  orgId: string;
  siteId: string;
  onDone: () => void;
  onClose: () => void;
}) {
  const [cidr, setCidr] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  async function submit() {
    setBusy(true);
    setErr(null);
    const { error } = await api.POST(
      "/api/v1/organizations/{orgId}/sites/{siteId}/subnets",
      {
        params: { path: { orgId, siteId } },
        body: { cidr },
      },
    );
    setBusy(false);
    if (error) {
      const msg = apiErrorMessage(error, "Could not advertise the subnet.");
      setErr(msg);
      toast.error(msg);
      return;
    }
    toast.success(`Subnet ${cidr} advertised`);
    onClose();
    onDone();
  }
  return (
    <Modal
      title="Advertise a subnet"
      onDismiss={onClose}
      actions={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={busy || cidr.trim() === ""}>
            Advertise
          </Button>
        </>
      }
    >
      <p className="text-xs text-slate-500">
        The subnet is advertised as PENDING. An owner or admin must approve it
        before it routes.
      </p>
      <div className="mt-2">
        <Field label="LAN CIDR">
          <Input
            value={cidr}
            onChange={(e) => setCidr(e.target.value)}
            placeholder="10.20.0.0/24"
            autoFocus
          />
        </Field>
      </div>
      <ErrorText>{err}</ErrorText>
    </Modal>
  );
}

function BindGatewayModal({
  orgId,
  siteId,
  nodes,
  onDone,
  onClose,
}: {
  orgId: string;
  siteId: string;
  nodes: Node[];
  onDone: () => void;
  onClose: () => void;
}) {
  const [nodeId, setNodeId] = useState(nodes[0]?.id ?? "");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  async function submit() {
    setBusy(true);
    setErr(null);
    const { error } = await api.POST(
      "/api/v1/organizations/{orgId}/sites/{siteId}/bind",
      {
        params: { path: { orgId, siteId } },
        body: { node_id: nodeId },
      },
    );
    setBusy(false);
    if (error) {
      const msg = apiErrorMessage(error, "Could not bind the gateway.");
      setErr(msg);
      toast.error(msg);
      return;
    }
    toast.success("Gateway bound to site");
    onClose();
    onDone();
  }
  return (
    <Modal
      title="Bind a gateway"
      onDismiss={onClose}
      actions={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={busy || nodeId === ""}>
            Bind
          </Button>
        </>
      }
    >
      <Field label="Gateway node">
        <Select value={nodeId} onChange={(e) => setNodeId(e.target.value)}>
          {nodes.map((n) => (
            <option key={n.id} value={n.id}>
              {n.name}
            </option>
          ))}
        </Select>
      </Field>
      <ErrorText>{err}</ErrorText>
    </Modal>
  );
}

function UnbindConfirm({
  orgId,
  siteId,
  gateways,
  onDone,
  onClose,
}: {
  orgId: string;
  siteId: string;
  gateways: GatewayView[];
  onDone: () => void;
  onClose: () => void;
}) {
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // S8.6 #3: a site may hold several gateways — name WHICH to unbind (no arbitrary server-side pick). Default
  // to the first; a picker appears when there is more than one.
  const [nodeId, setNodeId] = useState(gateways[0]?.id ?? "");
  async function submit() {
    setBusy(true);
    setErr(null);
    const { error } = await api.DELETE(
      "/api/v1/organizations/{orgId}/sites/{siteId}/bind",
      {
        params: { path: { orgId, siteId } },
        body: { node_id: nodeId },
      },
    );
    setBusy(false);
    if (error) {
      const msg = apiErrorMessage(error, "Could not unbind the gateway.");
      setErr(msg);
      toast.error(msg);
      return;
    }
    toast.success("Gateway unbound from site");
    onClose();
    onDone();
  }
  return (
    <Modal
      title="Unbind the gateway?"
      onDismiss={onClose}
      actions={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={busy || !nodeId}>
            Unbind
          </Button>
        </>
      }
    >
      <p className="text-sm text-slate-400">
        The gateway's site-link peers and routes are swept. The site and its
        subnets are kept. Bind a replacement to restore routing.
      </p>
      {gateways.length > 1 && (
        <Field label="Gateway to unbind">
          <Select value={nodeId} onChange={(e) => setNodeId(e.target.value)}>
            {gateways.map((g) => (
              <option key={g.id} value={g.id}>
                {g.name}
              </option>
            ))}
          </Select>
        </Field>
      )}
      <ErrorText>{err}</ErrorText>
    </Modal>
  );
}

// WF-5: un-advertise / remove a single subnet — no longer needs a whole-site delete. The confirm STATES
// the full-sweep consequence for an approved subnet (route withdrawn from every gateway).
function RemoveSubnetConfirm({
  orgId,
  siteId,
  subnet,
  onDone,
  onClose,
}: {
  orgId: string;
  siteId: string;
  subnet: { id: string; cidr: string; status: string };
  onDone: () => void;
  onClose: () => void;
}) {
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // F4 preview: name the DNS forwards this removal will ALSO sweep (server does the authoritative sweep in
  // the same tx; this is the present-tense advisory, matching the WF-5 confirm pattern). No enforcement here.
  const [dependents, setDependents] = useState<string[]>([]);
  useEffect(() => {
    api
      .GET("/api/v1/organizations/{orgId}/sites/{siteId}/dns-forwards", {
        params: { path: { orgId, siteId } },
      })
      .then(({ data }) => {
        if (data)
          setDependents(
            forwardsInSubnet(
              data as { domain: string; resolver_ip: string }[],
              subnet.cidr,
            ),
          );
      })
      .catch(() => {});
  }, [orgId, siteId, subnet.cidr]);
  async function submit() {
    setBusy(true);
    setErr(null);
    const { error } = await api.DELETE(
      "/api/v1/organizations/{orgId}/site-subnets/{subnetId}",
      {
        params: { path: { orgId, subnetId: subnet.id } },
      },
    );
    setBusy(false);
    if (error) {
      const msg = apiErrorMessage(error, "Could not remove the subnet.");
      setErr(msg);
      toast.error(msg);
      return;
    }
    toast.success(`Subnet ${subnet.cidr} removed`);
    onClose();
    onDone();
  }
  return (
    <Modal
      title={`Remove ${subnet.cidr}?`}
      onDismiss={onClose}
      actions={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button
            variant="danger"
            className="bg-danger hover:bg-danger"
            onClick={submit}
            disabled={busy}
          >
            Remove
          </Button>
        </>
      }
    >
      <p className="text-sm text-slate-400">
        {subnet.status === "approved" ? (
          <>
            This subnet is approved and routed. Removing it{" "}
            <span className="font-semibold">
              withdraws its route from every gateway
            </span>{" "}
            on the next reconcile. Behind-hosts on other sites will no longer
            reach <span className="font-mono">{subnet.cidr}</span>.
          </>
        ) : (
          <>
            This pending subnet is not yet routed, so removing it just
            un-advertises it.
          </>
        )}
      </p>
      {dependents.length > 0 && (
        <p className="mt-2 text-sm text-amber-400">
          {dependents.length === 1
            ? "1 DNS forward resolves"
            : `${dependents.length} DNS forwards resolve`}{" "}
          via this subnet and will also be removed:{" "}
          <span className="font-mono">{dependents.join(", ")}</span>
        </p>
      )}
      <ErrorText>{err}</ErrorText>
    </Modal>
  );
}

// S8.4 D7: per-site cross-site DNS forwarding config. The typed server refusals (dns_domain_conflict,
// dns_resolver_not_in_site_subnet) are rendered VERBATIM — no JS re-check, ONE validator (the D3/S8.3
// convention). Rides the fabric-card layout.
function DNSForwardSection({
  orgId,
  siteId,
  open,
  resolverHint,
}: {
  orgId: string;
  siteId: string;
  open: boolean;
  resolverHint: string;
}) {
  const [forwards, setForwards] = useState<
    { domain: string; resolver_ip: string }[]
  >([]);
  const [domain, setDomain] = useState("");
  const [resolverIp, setResolverIp] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const load = useCallback(async () => {
    const { data } = await api.GET(
      "/api/v1/organizations/{orgId}/sites/{siteId}/dns-forwards",
      { params: { path: { orgId, siteId } } },
    );
    if (data) setForwards(data as { domain: string; resolver_ip: string }[]);
  }, [orgId, siteId]);
  useEffect(() => {
    load().catch(() => {});
  }, [load]);
  async function add() {
    setBusy(true);
    setErr(null);
    const { error } = await api.POST(
      "/api/v1/organizations/{orgId}/sites/{siteId}/dns-forwards",
      {
        params: { path: { orgId, siteId } },
        body: { domain: domain.trim(), resolver_ip: resolverIp.trim() },
      },
    );
    setBusy(false);
    if (error) {
      const msg = apiErrorMessage(error, "Could not add the forward.");
      setErr(msg);
      toast.error(msg);
      return;
    }
    toast.success(`DNS forward added for ${domain.trim()}`);
    setDomain("");
    setResolverIp("");
    load().catch(() => {});
  }
  async function remove(d: string) {
    setErr(null);
    const { error } = await api.DELETE(
      "/api/v1/organizations/{orgId}/sites/{siteId}/dns-forwards/{domain}",
      {
        params: { path: { orgId, siteId, domain: d } },
      },
    );
    if (error) {
      const msg = apiErrorMessage(error, "Could not remove the forward.");
      setErr(msg);
      toast.error(msg);
      return;
    }
    toast.success(`DNS forward removed for ${d}`);
    load().catch(() => {});
  }
  return (
    <details open={open} className="mt-3 rounded-lg border border-white/5 bg-ink-900/60 px-3 py-2 text-xs text-slate-400">
      <summary className="cursor-pointer text-slate-300">
        Cross-site DNS forwarding: resolve this site's names from other sites
      </summary>
      <div className="mt-2 space-y-2">
        <p>
          Forward a domain to this site's internal resolver (an IP inside an
          approved subnet). Other sites resolve those names over the tunnel.
        </p>
        <ul className="space-y-1">
          {forwards.map((f) => (
            <li key={f.domain} className="flex items-center gap-2">
              <span className="font-mono text-slate-300">{f.domain}</span>
              <span className="text-slate-500">→ {f.resolver_ip}</span>
              <button
                type="button"
                className="ml-auto text-slate-500 hover:text-rose-400"
                aria-label={`Remove ${f.domain} resolver`}
                onClick={() => remove(f.domain)}
              >
                ✕
              </button>
            </li>
          ))}
          {forwards.length === 0 && (
            <li className="text-slate-500">No forwarded zones.</li>
          )}
        </ul>
        <div className="flex flex-wrap items-end gap-2">
          <Field label="DNS zone">
          <Input
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="corp.local"
            className="w-40"
            maxLength={253}
          />
          </Field>
          <Field label="Resolver IP">
          <Input
            value={resolverIp}
            onChange={(e) => setResolverIp(e.target.value)}
            placeholder={resolverHint}
            className="w-36"
            maxLength={45}
          />
          </Field>
          <Button
            variant="ghost"
            onClick={add}
            disabled={busy || !domain.trim() || !resolverIp.trim()}
          >
            Add
          </Button>
        </div>
        <ErrorText>{err}</ErrorText>
      </div>
    </details>
  );
}

function DeleteSiteModal({
  orgId,
  site,
  onDone,
  onClose,
}: {
  orgId: string;
  site: SiteCard;
  onDone: () => void;
  onClose: () => void;
}) {
  const [refs, setRefs] = useState<SiteReferences | null>(null);
  const [refErr, setRefErr] = useState<string | null>(null);
  const [templateImpact, setTemplateImpact] =
    useState<AgentPolicyTemplateDestinationImpact | null>(null);
  const [templateImpactErr, setTemplateImpactErr] = useState<string | null>(
    null,
  );
  const [typed, setTyped] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    (async () => {
      const [r, template] = await Promise.all([
        loadOne(() =>
          api.GET("/api/v1/organizations/{orgId}/sites/{siteId}", {
            params: { path: { orgId, siteId: site.id } },
          }),
        ) as Promise<Loaded<SiteReferences>>,
        loadOne(() =>
          api.GET(
            "/api/v1/organizations/{orgId}/agent-policy-template-destination-impact",
            {
              params: {
                path: { orgId },
                query: {
                  destination_kind: "site",
                  destination_id: site.id,
                },
              },
            },
          ),
        ) as Promise<Loaded<AgentPolicyTemplateDestinationImpact>>,
      ]);
      if (r.ok) setRefs(r.data);
      else setRefErr(r.error);
      if (template.ok) setTemplateImpact(template.data);
      else setTemplateImpactErr(template.error);
    })();
  }, [orgId, site.id]);

  async function submit() {
    setBusy(true);
    setErr(null);
    const { error } = await api.DELETE(
      "/api/v1/organizations/{orgId}/sites/{siteId}",
      { params: { path: { orgId, siteId: site.id } } },
    );
    setBusy(false);
    if (error) {
      const msg = apiErrorMessage(error, "Could not delete the site.");
      setErr(msg);
      toast.error(msg);
      return;
    }
    toast.success(`Site "${site.name}" deleted`);
    onClose();
    onDone();
  }

  return (
    <Modal
      title={`Delete “${site.name}”?`}
      danger
      onDismiss={onClose}
      actions={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button
            variant="primary"
            className="bg-danger hover:bg-danger"
            onClick={submit}
            disabled={
              busy ||
              !nameMatchesExactly(typed, site.name) ||
              templateImpact === null ||
              templateImpact.version_count > 0
            }
          >
            Delete site
          </Button>
        </>
      }
    >
      {/* PRESENT-TENSE cascade preview (the ratified copy — advisory, not a promise; the audit records the
          actual counts). */}
      {refErr && (
        <p className="text-xs text-amber-300">
          Couldn’t read what this affects ({refErr}). Deleting still cascades.
        </p>
      )}
      {templateImpactErr && (
        <p className="text-xs text-amber-300">
          Couldn’t read immutable template impact ({templateImpactErr}), so
          deletion is blocked.
        </p>
      )}
      {refs && (
        <p className="text-sm text-slate-400">
          This deletes the site and cascades what currently references it:{" "}
          <strong>{refs.rule_count}</strong>{" "}
          {refs.rule_count === 1 ? "rule" : "rules"} and{" "}
          <strong>{refs.subnet_count}</strong>{" "}
          {refs.subnet_count === 1 ? "subnet" : "subnets"}; the gateway is
          unbound.
        </p>
      )}
      {templateImpact && (
        <p className="mt-2 text-xs text-slate-400">
          {templateImpact.version_count === 0
            ? "No immutable agent policy template version references this site."
            : `${templateImpact.version_count} immutable agent policy template ${templateImpact.version_count === 1 ? "version references" : "versions reference"} this site, so deletion is blocked.`}
        </p>
      )}
      <p className="mt-3 text-xs text-slate-500">
        Type the site name to confirm.
      </p>
      <div className="mt-1">
        <Input
          value={typed}
          onChange={(e) => setTyped(e.target.value)}
          placeholder={site.name}
          autoFocus
        />
      </div>
      <ErrorText>{err}</ErrorText>
    </Modal>
  );
}

// ── the pending-approval queue (admin-only, D5) + the CW upgrade confirm ──────────────
function PendingQueue({
  orgId,
  approvedCountBySite,
  allGateways,
  ceiling,
  siteNames,
  onDone,
}: {
  orgId: string;
  approvedCountBySite: Record<string, number>;
  allGateways: GatewayView[];
  ceiling: number;
  siteNames: Record<string, string>;
  onDone: () => void;
}) {
  const [pending, setPending] = useState<SiteSubnet[] | null>(null);
  const [loadErr, setLoadErr] = useState<string | null>(null);
  const [confirm, setConfirm] = useState<{
    subnet: SiteSubnet;
    gateways: { id: string; name: string }[];
  } | null>(null);
  const [rowErr, setRowErr] = useState<string | null>(null);

  const loadQueue = useCallback(async () => {
    setLoadErr(null);
    const r = (await loadOne(() =>
      api.GET("/api/v1/organizations/{orgId}/site-subnets/pending", {
        params: { path: { orgId } },
      }),
    )) as Loaded<SiteSubnet[]>;
    if (r.ok) setPending(r.data);
    else setLoadErr(r.error);
  }, [orgId]);
  useEffect(() => {
    loadQueue();
  }, [loadQueue]);

  // approve does the actual POST + shared error handling (verbatim refusal). Called directly for a
  // non-crossing approval, or from the CW confirm's onConfirm.
  async function approve(subnet: SiteSubnet) {
    setRowErr(null);
    const { error } = await api.POST(
      "/api/v1/organizations/{orgId}/site-subnets/{subnetId}/approve",
      {
        params: { path: { orgId, subnetId: subnet.id } },
      },
    );
    if (error) {
      // D3: a disjointness refusal renders VERBATIM (the API names the class + colliding range). No
      // client-side re-check.
      const refusal = disjointRefusal(error);
      return setRowErr(
        refusal ?? apiErrorMessage(error, "Could not approve the subnet."),
      );
    }
    setConfirm(null);
    await loadQueue();
    onDone(); // refresh the topology (a newly-approved subnet now routes)
  }

  // onApproveClick decides whether this approval crosses the multi-site threshold with sub-ceiling
  // gateways present — if so it opens the CW confirm naming them; otherwise it approves directly.
  function onApproveClick(subnet: SiteSubnet) {
    const gateways = subCeilingGateways(allGateways, ceiling);
    if (
      crossesMultiSiteThreshold(subnet.site_id, approvedCountBySite) &&
      gateways.length > 0
    ) {
      setConfirm({ subnet, gateways });
    } else {
      approve(subnet);
    }
  }

  if (loadErr)
    return (
      <Panel title="Pending subnet approvals">
        <LoadRetry error={loadErr} onRetry={loadQueue} />
      </Panel>
    );
  if (pending == null)
    return (
      <Panel title="Pending subnet approvals">
        <p role="status" className="text-cell text-ink-faint">Loading pending subnet approvals…</p>
      </Panel>
    );
  if (pending.length === 0)
    return (
      <Panel title="Pending subnet approvals">
        <EmptyState>No advertised subnets are awaiting approval.</EmptyState>
      </Panel>
    );

  return (
    <Panel title="Pending subnet approvals">
      <p className="mt-1 text-xs text-slate-500">
        Advertised subnets route only once approved (disjointness is checked on
        approval).
      </p>
      <div className="mt-3 overflow-x-auto">
        <div className="min-w-[520px]">
          <div className="grid grid-cols-[minmax(12rem,1.2fr)_minmax(10rem,1fr)_minmax(10rem,1fr)_auto] gap-3 border-b border-line px-2.5 py-1.5 text-micro uppercase tracking-wide text-ink-faint">
            <span>CIDR</span>
            <span>Site</span>
            <span>State</span>
            <span>Action</span>
          </div>
          <ul className="space-y-1.5 pt-1.5">
        {pending.map((s) => (
          <li key={s.id} className="grid grid-cols-[minmax(12rem,1.2fr)_minmax(10rem,1fr)_minmax(10rem,1fr)_auto] items-center gap-3 rounded-md border border-line bg-ink-800 px-2.5 py-2 text-sm">
            <span className="font-mono text-slate-200">{s.cidr}</span>
            <span className="text-ink-tertiary">{siteNames[s.site_id] ?? "Site unavailable"}</span>
            <span className="text-ink-tertiary">Pending · not routed</span>
            <Button
              variant="ghost"
              onClick={() => onApproveClick(s)}
            >
              Approve
            </Button>
          </li>
        ))}
      </ul>
        </div>
      </div>
      <ErrorText>{rowErr}</ErrorText>

      {confirm && (
        <Modal
          title="Enable cross-site routing?"
          danger
          onDismiss={() => setConfirm(null)}
          actions={
            <>
              <Button variant="ghost" onClick={() => setConfirm(null)}>
                Cancel
              </Button>
              <Button onClick={() => approve(confirm.subnet)}>
                Approve anyway
              </Button>
            </>
          }
        >
          <p className="text-sm text-slate-400">
            Approving this subnet enables site-to-site routing, which requires
            policy version {ceiling}. These gateways cannot apply it and will{" "}
            <strong>deny all traffic</strong> until upgraded:
          </p>
          <ul className="mt-2 list-disc pl-5 text-sm text-rose-300">
            {confirm.gateways.map((g) => (
              <li key={g.id}>{g.name}</li>
            ))}
          </ul>
        </Modal>
      )}
    </Panel>
  );
}
