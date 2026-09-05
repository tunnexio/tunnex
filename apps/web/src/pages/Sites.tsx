import "../network-workspaces.css";
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
  Loading,
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
  const [mapCollapsed, setMapCollapsed] = useState(false);
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

  const selectSite = useCallback(
    (siteId: string | null) => updateQuery({ site: siteId, gateway: null, dns: null }),
    [updateQuery],
  );

  const mesh = useMemo(
    () => meshFrom(cards, raw?.nodes ?? [], raw?.hubSet),
    [cards, raw],
  );

  return (
    <div className="network-management flex flex-col gap-6">
      <PageHeader
        title="Sites"
        subtitle={org ? `${org.name}${raw ? ` · ${cards.length} sites` : ""}` : "…"}
        actions={
          view === "body" && gate.canManage ? (
          <div className="network-header-actions"><Link className="network-setup-link" to="/network/setup">Set up a network →</Link>
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
        <Card>
          <Loading label="Loading Sites…" />
        </Card>
      )}

      {view === "body" && raw != null && org != null && (
        <>
          <nav aria-label="Sites workspace" className="flex flex-wrap border-b border-white/10">
            {[
              ["overview", "Overview"],
              ["approvals", "Pending approvals"],
              ["ha", "Hub availability"],
            ].map(([id, label]) => (
              <button
                key={id}
                type="button"
                aria-current={section === id ? "page" : undefined}
                onClick={() => updateQuery(id === "overview" ? { section: id } : { section: id, site: null, gateway: null, q: null, dns: null })}
                className={`min-h-10 border-b-2 px-3 text-cell transition-colors ${section === id ? "border-ink-heading text-ink-heading" : "border-transparent text-ink-tertiary hover:border-white/20 hover:text-ink-heading"}`}
              >
                {label}
              </button>
            ))}
          </nav>
          {section === "overview" && (
            <div className="flex min-w-0 flex-col gap-3">
              <SiteOverviewSummary cards={cards} unboundCount={unboundGatewayNodes.length} />
              <Panel
                title="Network map"
                className="min-w-0"
                actions={
                  /* D2 (ruled): scoped to the MAP, not the page. The mesh's edges are handshake-derived, so
                     the claim is true here. Over the subnet queue it would not be — those are control-plane
                     rows. */
                  <div className="flex items-center gap-2">
                    <span className="text-micro text-ink-tertiary">Live topology</span>
                    <button type="button" className="rounded px-2 py-1 text-micro text-ink-tertiary hover:bg-white/5 hover:text-ink-heading focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-inset focus-visible:ring-white/35" aria-expanded={!mapCollapsed} onClick={() => setMapCollapsed((collapsed) => !collapsed)}>
                      {mapCollapsed ? "Expand" : "Collapse"}
                    </button>
                  </div>
                }
              >
                {/* The handoff puts the hint INLINE beside the title (dc.html L454). Ours drops "hover to
                    trace a link" because we do not implement hover tracing — describing an interaction the
                    component does not have is the same class of lie as a chart with no source. */}
                {mapCollapsed ? (
                  <div className="flex flex-wrap items-center gap-x-5 gap-y-1 py-1 text-cell text-ink-tertiary">
                    <span><strong className="font-semibold text-ink-heading">{cards.length}</strong> Sites</span>
                    <span><strong className="font-semibold text-ink-heading">{allGateways.length}</strong> bound gateways</span>
                    <span><strong className="font-semibold text-ink-heading">{mesh.links.length}</strong> topology links</span>
                  </div>
                ) : <>
                <div className="mb-1.5 flex flex-wrap items-center gap-2">
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
                  maxHeight={225}
                  empty="Route a LAN to draw your first site here."
                />
                <p className="text-micro text-ink-faint">Live links reflect current WireGuard handshakes; animation does not imply traffic volume.</p>
                </>}
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

              <div className="flex flex-wrap items-center justify-between gap-3 border-t border-line px-1 pt-3">
                <p className="text-cell text-ink-tertiary"><strong className="font-medium text-ink-heading">Advanced Site Networking:</strong> cross-site zone forwarding is optional and is not required for FQDN access.</p>
                <Button variant="ghost" size="sm" onClick={() => updateQuery({ section: "dns", site: null, gateway: null, q: null, dns: null })}>Review DNS forwarding</Button>
              </div>

              {selectedCard && (
                <Modal title={selectedCard.name} size="workspace" showClose onDismiss={() => selectSite(null)}>
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
                </Modal>
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
            <div className="space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-3"><div><p className="text-xs font-semibold uppercase tracking-wide text-ink-faint">Advanced Site Networking</p><p className="mt-1 text-cell text-ink-tertiary">Optional site-to-site zone forwarding. Private DNS Resolver remains the only primary configuration for FQDN access.</p></div><Button variant="ghost" onClick={() => updateQuery({ section: "overview", site: null, gateway: null, q: null, dns: null })}>Back to Sites overview</Button></div>
              <DNSForwardsPanel
                view={raw.forwards}
                siteCount={raw.sites.length}
                canManage={gate.canManage}
                onManageSite={(siteId) => updateQuery({ section: "overview", site: siteId, gateway: null, q: null, dns: "1" })}
              />
            </div>
          )}
        </>
      )}
      {view === "body" && raw == null && (
        <Card><Loading label="Loading Sites…" /></Card>
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
  const columns = [
    { key: "zone", header: "Zone", cell: (row: OrgForwardsView["rows"][number]) => <span className="font-sans text-ink-body">{row.domain}</span> },
    { key: "resolver", header: "Resolver", cell: (row: OrgForwardsView["rows"][number]) => <span className="font-sans text-ink-tertiary">{row.resolverIp}</span> },
    { key: "site", header: "Site", cell: (row: OrgForwardsView["rows"][number]) => <span className="text-ink-tertiary">{row.siteName}</span> },
    { key: "status", header: "Status", cell: (row: OrgForwardsView["rows"][number]) => view.conflicts.includes(row.domain) ? <Badge tone="danger">conflict</Badge> : <Badge tone="neutral">configured</Badge> },
    { key: "action", header: "", cell: (row: OrgForwardsView["rows"][number]) => canManage ? <Button variant="ghost" size="sm" onClick={() => onManageSite(row.siteId)}>Manage</Button> : <span className="text-micro text-ink-faint">Read-only</span> },
  ];
  return (
    <Panel title="Cross-site DNS forwarding" className="min-w-0" actions={<span className="text-micro text-ink-tertiary">{view.rows.length} configured</span>}>
      <p className="-mt-1 text-cell text-ink-tertiary">Optional Site-to-Site zone routes. FQDN access uses <Link className="text-accent-400 hover:underline" to="/access/resources?type=fqdn#private-dns-heading">Private DNS Resolvers</Link>.</p>
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
      ) : <DataTable caption="DNS forwarding" columns={columns} rows={view.rows} rowKey={(row: OrgForwardsView["rows"][number]) => `${row.siteId}-${row.domain}`} empty="No forwarded zones." failed={false} />}

      {/* ⛔ ONLY CLAIM A CLEAN BILL OF HEALTH WHEN THE READ WAS COMPLETE. "No conflicts found" and "no
          conflicts exist" are different claims and only the second is reassuring. */}
      {view.conflicts.length > 0 && (
        <p className="rounded-md border border-danger/40 bg-danger/5 px-3 py-2 text-cell text-danger"><strong>{view.conflicts.length} conflict{view.conflicts.length === 1 ? "" : "s"}:</strong> {view.conflicts.join(", ")}. Keep one resolver per zone.</p>
      )}
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
      title="Route a LAN"
      onDismiss={onClose}
      actions={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={busy || !nodeId || !cidr.trim()}>
            Route LAN
          </Button>
        </>
      }
    >
      <p className="text-cell text-ink-tertiary">Choose an available gateway and the private range behind it. Tunnex creates the Site and approves the route in one step.</p>
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
          placeholder="e.g. Mumbai office"
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
      title="Hub availability"
      className="min-w-0"
      actions={view ? <Badge tone={view.promotionInEffect ? "warn" : "neutral"}>generation {view.generation}</Badge> : undefined}
    >
      {view ? (
        <>
          <div className="grid overflow-hidden rounded-lg border border-line sm:grid-cols-3">
            <div className="border-b border-line px-3 py-2.5 sm:border-b-0 sm:border-r"><p className="text-micro uppercase tracking-wide text-ink-faint">Primary</p><p className="mt-1 font-medium text-ink-heading">{nameOf(view.members.find((member) => member.role === "primary")?.nodeId ?? "")}</p></div>
            <div className="border-b border-line px-3 py-2.5 sm:border-b-0 sm:border-r"><p className="text-micro uppercase tracking-wide text-ink-faint">Standbys</p><p className="mt-1 font-medium tabular-nums text-ink-heading">{view.members.filter((member) => member.role !== "primary").length}</p></div>
            <div className="px-3 py-2.5"><p className="text-micro uppercase tracking-wide text-ink-faint">State</p><p className={`mt-1 font-medium ${view.promotionInEffect ? "text-warn" : "text-ink-heading"}`}>{view.promotionInEffect ? "Failover active" : "Configured"}</p></div>
          </div>
          {view.promotionInEffect && <p className="mt-3 flex flex-wrap items-center justify-between gap-2 rounded-md border border-warn/40 bg-warn/5 px-3 py-2 text-cell text-warn"><span>Standby is carrying transit while the primary is unavailable.</span><Link className="text-ink-heading underline underline-offset-2" to="/audit">View timeline</Link></p>}
          <div className="mt-3 overflow-x-auto">
            <div className="min-w-[560px]">
              <div className="grid grid-cols-[minmax(12rem,1fr)_7rem_7rem_minmax(14rem,1fr)] gap-3 border-b border-line px-2 py-1.5 text-micro uppercase tracking-wide text-ink-faint"><span>Gateway</span><span>Role</span><span>Health</span><span className="text-right">Traffic · handshake</span></div>
              <ul>
                {view.members.map((member) => (
                  <li key={member.nodeId} className="grid min-h-11 grid-cols-[minmax(12rem,1fr)_7rem_7rem_minmax(14rem,1fr)] items-center gap-3 border-b border-line/70 px-2 text-cell last:border-0">
                    <span className="font-medium text-ink-body">{nameOf(member.nodeId)}</span>
                    <span><Badge tone="neutral">{member.role}</Badge></span>
                    <span className={member.warm === false ? "text-danger" : member.warm === true ? "text-ok" : "text-ink-tertiary"}>{member.demoted ? "demoted" : member.warm === false ? "stale" : member.warm === true ? "warm" : "unknown"}</span>
                    <span className="text-right font-sans text-micro text-ink-tertiary">↓{member.rx} ↑{member.tx} · {member.handshakeAge === "n/a" ? "no handshake" : member.handshakeAge}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </>
      ) : <EmptyState>No hub set is configured. Choose at least two candidates to enable gateway failover.</EmptyState>}

      {canManage && (
        <details className="mt-3 border-t border-line pt-3">
          <summary className="cursor-pointer text-cell font-medium text-ink-body">Manage hub candidates · {gateways.length} gateways</summary>
          <p className="mt-1 text-micro text-ink-tertiary">Lower pin numbers are preferred during failover.</p>
          <ul className="mt-2">
            {gateways.map((g) => {
              const pri = priorityByNode.get(g.id);
              const pinned = pri != null;
              const pins = [...priorityByNode.values()].filter(
                (v): v is number => v != null,
              );
              const nextPin = pins.length ? Math.max(...pins) + 1 : 1; // append after the current candidates
              return (
                <li key={g.id} className="flex min-h-10 flex-wrap items-center gap-2 border-b border-line/70 text-cell last:border-0">
                  <span className="font-medium text-ink-body">{g.name}</span>
                  {pinned && (
                    <Badge tone="neutral">priority {pri}</Badge>
                  )}
                  <span className="ml-auto flex gap-1">
                    {pinned ? (
                      <Button
                        variant="ghost"
                        size="sm"
                        disabled={busy}
                        onClick={() => setPin(g.id, null)}
                      >
                        Unpin
                      </Button>
                    ) : (
                      <Button
                        variant="ghost"
                        size="sm"
                        disabled={busy}
                        onClick={() => setPin(g.id, nextPin)}
                      >
                        {nextPin === 1 ? "Set primary" : `Pin #${nextPin}`}
                      </Button>
                    )}
                  </span>
                </li>
              );
            })}
          </ul>
        </details>
      )}
      <ErrorText>{err}</ErrorText>
    </Panel>
  );
}

function SiteOverviewSummary({
  cards,
  unboundCount,
}: {
  cards: SiteCard[];
  unboundCount: number;
}) {
  const gateways = cards.flatMap((card) => card.gateways);
  const approved = cards.reduce(
    (total, card) => total + card.subnets.filter((subnet) => subnet.status === "approved").length,
    0,
  );
  const pending = cards.reduce(
    (total, card) => total + card.subnets.filter((subnet) => subnet.status === "pending").length,
    0,
  );
  const stats = [
    { label: "Sites", value: cards.length, detail: `${cards.filter((card) => card.gateways.length > 0).length} connected` },
    { label: "Gateways", value: gateways.length + unboundCount, detail: unboundCount > 0 ? `${unboundCount} available to bind` : "all assigned" },
    { label: "Routed ranges", value: approved, detail: "approved" },
    { label: "Pending", value: pending, detail: pending > 0 ? "needs review" : "nothing waiting", attention: pending > 0 },
  ];

  return (
    <section aria-label="Sites summary" className="tnx-card-surface network-site-summary grid overflow-hidden sm:grid-cols-2 xl:grid-cols-4">
      {stats.map((stat) => (
        <div key={stat.label} className="min-w-0 border-b border-line px-4 py-3 last:border-b-0 sm:border-r sm:[&:nth-child(2)]:border-r-0 sm:[&:nth-child(3)]:border-b-0 xl:border-b-0 xl:[&:nth-child(2)]:border-r xl:[&:nth-child(4)]:border-r-0">
          <p className="text-micro font-medium uppercase tracking-wide text-ink-tertiary">{stat.label}</p>
          <div className="mt-1 flex items-baseline gap-2">
            <span className="text-title font-semibold tabular-nums text-ink-heading">{stat.value}</span>
            <span className={`truncate text-micro ${stat.attention ? "text-warn" : "text-ink-faint"}`}>{stat.detail}</span>
          </div>
        </div>
      ))}
    </section>
  );
}

function SelectedSiteStrip({ card, selectedGatewayId, unboundGateway, onRouteLan }: { card: SiteCard | null; selectedGatewayId: string | null; unboundGateway: Node | null; onRouteLan: () => void }) {
  if (unboundGateway) {
    return <section aria-label="Selected Site" className="flex flex-wrap items-center gap-x-4 gap-y-2 rounded-lg border border-line bg-ink-800 px-3 py-2 text-cell"><span className="font-semibold text-ink-heading">{unboundGateway.name}</span><Badge tone="neutral">Unbound Gateway</Badge><span className="text-ink-tertiary">No Site is bound. Its location is not shown on this topology.</span><Button className="ml-auto" variant="ghost" onClick={onRouteLan}>Route a LAN</Button></section>;
  }
  if (!card) return null;
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
          className={`text-left font-sans ${c.id === selectedId ? "text-ink-heading underline" : "text-ink-primary"}`}
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
            <span className="font-sans text-ink-body">{gw.name}</span>
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
                className={`rounded border px-1.5 py-px font-sans text-micro ${
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
    <Panel
      title="Site inventory"
      actions={<span className="text-micro tabular-nums text-ink-tertiary">{cards.length} total</span>}
    >
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
    <Card variant="plain" className="space-y-0 overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-line pb-3">
        <p className="text-cell text-ink-tertiary">Gateways carry this Site&rsquo;s routed ranges.</p>
        <div className="flex items-center gap-2 text-micro text-ink-tertiary">
          <span>{card.gateways.length} gateway{card.gateways.length === 1 ? "" : "s"}</span>
          <span aria-hidden="true">·</span>
          <span>{card.subnets.length} range{card.subnets.length === 1 ? "" : "s"}</span>
        </div>
      </div>

      <div className="mt-3 grid overflow-hidden rounded-lg border border-line lg:grid-cols-2">
        <section className="border-b border-line px-3 py-3 lg:border-b-0 lg:border-r">
          <div className="flex items-center justify-between gap-3">
            <h3 className="text-cell font-semibold text-ink-heading">Gateways</h3>
            {canManage && unboundNodes.length > 0 && <Button variant="ghost" size="sm" onClick={() => setModal("bind")}>Bind gateway</Button>}
          </div>
          {card.gateways.length === 0 ? (
            <p className="py-4 text-cell text-ink-tertiary">No gateway is bound to this Site.</p>
          ) : (
            <ul className="mt-1 max-h-[8.25rem] overflow-y-auto pr-1 [scrollbar-gutter:stable]">
              {card.gateways.map((g) => <GatewayRow key={g.id} g={g} />)}
            </ul>
          )}
        </section>

        <section className="px-3 py-3">
          <div className="flex items-center justify-between gap-3">
            <h3 className="text-cell font-semibold text-ink-heading">Routed ranges</h3>
            {canManage && <Button variant="ghost" size="sm" onClick={() => setModal("subnet")}>Advertise subnet</Button>}
          </div>
          {card.subnets.length === 0 ? (
            <p className="py-4 text-cell text-ink-tertiary">No ranges advertised.</p>
          ) : (
            <ul role="list" className="mt-1 max-h-[8.25rem] overflow-y-auto pr-1 [scrollbar-gutter:stable]">
              {card.subnets.map((s) => (
                <li key={s.id} role="listitem" aria-label={`${s.cidr}: ${s.status === "approved" ? "Approved, routed" : "Pending approval, not yet routed"}`} className="flex min-h-10 items-center gap-2 border-b border-line/70 text-cell last:border-0">
                  <span className="font-sans text-ink-body">{s.cidr}</span>
                  <Badge tone={s.status === "approved" ? "ok" : "warn"}>{s.status === "approved" ? "routed" : "pending"}</Badge>
                  {canManage && <button type="button" className="ml-auto rounded px-2 py-1 text-micro text-ink-tertiary hover:bg-danger/10 hover:text-danger focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-inset focus-visible:ring-white/35" aria-label={`Remove ${s.cidr}`} onClick={() => setRemoving({ id: s.id, cidr: s.cidr, status: s.status })}>Remove</button>}
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>

      {hasGateway && card.subnets.some((s) => s.status === "approved") && (
        <details className="border-t border-line py-3 text-cell text-ink-tertiary">
          <summary className="cursor-pointer font-medium text-ink-body">Advanced cloud routing</summary>
          <div className="mt-2 grid gap-2 text-micro sm:grid-cols-2">
            <p><span className="font-medium text-ink-body">Gateway VM:</span> enable IP forwarding. On AWS, disable source/destination checks.</p>
            <p><span className="font-medium text-ink-body">Cloud routes:</span> send remote Site and device-pool CIDRs to this gateway. Update that target when cloud-side HA fails over.</p>
            <p className="sm:col-span-2 text-ink-faint">Full operator reference: <span className="font-sans">docs/deploy-cloud-gateway.md</span></p>
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
        <div className="border-t border-line py-3">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h3 className="text-cell font-semibold text-ink-heading">Lifecycle</h3>
              <p className="text-micro text-ink-tertiary">Move gateways before permanently deleting this Site.</p>
            </div>
            <div className="flex flex-wrap gap-2">
              {hasGateway && <Button variant="ghost" size="sm" onClick={() => setModal("unbind")}>Unbind gateway</Button>}
              <Button variant="danger" size="sm" onClick={() => setModal("delete")}>Delete site</Button>
            </div>
          </div>
          <span className="sr-only">Danger zone</span>
        </div>
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
    <li className="flex min-h-10 min-w-0 items-center gap-2 border-b border-line/70 text-cell last:border-0">
      <a
        className="min-w-0 flex-1 truncate font-medium text-ink-body hover:text-ink-heading hover:underline"
        title={g.name}
        href={`/gateways/${g.id}`}
      >
        {g.name}
      </a>
      {g.isHub && (
        <span className="shrink-0 rounded bg-sky-500/10 px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-sky-300">
          hub
        </span>
      )}
      {g.status === "revoked" && (
        <span className="text-xs text-rose-400">revoked</span>
      )}
      {live.offline && (
        <span className={`shrink-0 whitespace-nowrap text-xs ${badgeClass("danger")}`}>offline</span>
      )}
      {/* WF-S11-10, THIRD SURFACE. The fix landed on Gateways.tsx and Devices.tsx already suppressed health on
          revoked rows — this list rendered the same concept with the same defect, so a revoked gateway could
          read "revoked" beside "certificate expired — re-enroll this gateway": two labels contradicting each
          other, the instructional one telling an operator to UNDO a deliberate security action. `offline` stays
          unguarded on purpose — it is a liveness FACT, not an instruction, and a revoked gateway genuinely is
          offline. It is the health/instruction vocabulary that must not describe a gateway no longer meant to
          work. Found by asking who ELSE renders this concept, not by walking the UI. */}
      {g.status !== "revoked" && g.health && (
        <span className={`shrink-0 whitespace-nowrap text-xs ${badgeClass(g.health.tone)}`}>
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
      <span className="ml-auto shrink-0 whitespace-nowrap text-[11px] text-slate-500">
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
      title="Add Site"
      onDismiss={onClose}
      actions={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={busy || name.trim() === ""}>
            Add Site
          </Button>
        </>
      }
    >
      <p className="text-cell text-ink-tertiary">Create the location first, then bind gateways and advertise its private ranges.</p>
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
      <p className="text-cell text-ink-tertiary">The range stays inactive until an owner or admin approves it.</p>
      <div>
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
      <p className="text-cell text-ink-tertiary">Assign an enrolled, unbound gateway to this Site.</p>
      <Field label="Gateway">
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
      <p className="text-cell text-ink-tertiary">This withdraws the gateway’s Site links and routes. The Site and its ranges remain available for a replacement gateway.</p>
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
            reach <span className="font-sans">{subnet.cidr}</span>.
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
          <span className="font-sans">{dependents.join(", ")}</span>
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
    <details open={open} className="border-t border-line py-3 text-cell text-ink-tertiary">
      <summary className="cursor-pointer font-medium text-ink-body">
        Advanced Site DNS forwarding
      </summary>
      <div className="mt-2 space-y-2">
        <p className="text-micro">Forward a Site-local zone through an approved range. FQDN access uses Private DNS Resolvers instead.</p>
        <ul className="max-h-[7.25rem] space-y-1 overflow-y-auto pr-1 [scrollbar-gutter:stable]">
          {forwards.map((f) => (
            <li key={f.domain} className="flex min-h-9 items-center gap-2 border-b border-line/70 last:border-0">
              <span className="font-sans text-slate-300">{f.domain}</span>
              <span className="text-slate-500">→ {f.resolver_ip}</span>
              <button
                type="button"
                className="ml-auto rounded px-2 py-1 text-micro text-ink-tertiary hover:bg-danger/10 hover:text-danger focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-inset focus-visible:ring-white/35"
                aria-label={`Remove ${f.domain} resolver`}
                onClick={() => remove(f.domain)}
              >
                Remove
              </button>
            </li>
          ))}
          {forwards.length === 0 && (
            <li className="text-slate-500">No forwarded zones.</li>
          )}
        </ul>
        <div className="grid items-end gap-2 sm:grid-cols-[minmax(10rem,1fr)_minmax(10rem,1fr)_auto]">
          <Field label="DNS zone">
          <Input
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="corp.local"
            maxLength={253}
          />
          </Field>
          <Field label="Forwarding target IP">
          <Input
            value={resolverIp}
            onChange={(e) => setResolverIp(e.target.value)}
            placeholder={resolverHint}
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
        <Loading size="inline" label="Loading pending subnet approvals…" />
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
            <span className="font-sans text-slate-200">{s.cidr}</span>
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
