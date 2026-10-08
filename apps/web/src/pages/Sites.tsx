import { NetworkDetailList } from "../components/NetworkDetailList";
import { ResourceSummary } from "../components/ResourceSummary";
import { SiteToSiteNavigation } from "../components/SiteToSiteNavigation";
import "../network-workspaces.css";
import "../site-to-site-workspace.css";
import AppAccessPagination, { appAccessPageSize } from "../components/AppAccessPagination";
import AppAccessRowMenu from "../components/AppAccessRowMenu";
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
import { hubSetView, type HubMemberRow } from "../lib/hubsetview";
import { mergeOrgForwards, type OrgForwardsView } from "../lib/dnsview";
import { useAuth } from "../lib/auth";
import { toast } from "../components/Toasts";
import { Badge, Button, DataTable, EmptyState, ErrorText, Field, Input, Loading, Modal, Select, RefreshButton } from "../components/ui";
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
  hubSet: HubSet | null; // The persisted HA hub set; failed reads are distinguished below from an unconfigured set.
  hubSetUnavailable: boolean;
  // S14.5 D1 — the ORG-WIDE zone list, fanned out one request per site. Carries its own per-site failure
  // record, because a short list on a conflict view reads as "no conflict".
  forwards: OrgForwardsView;
}

type NetworkStep = "overview" | "gateways" | "ranges" | "advanced";
const networkSteps: Array<{ id: NetworkStep; label: string }> = [
  { id: "overview", label: "Overview" }, { id: "gateways", label: "Gateways" },
  { id: "ranges", label: "Ranges" }, { id: "advanced", label: "Advanced" },
];
function networkStep(value: string | null): NetworkStep {
  return value === "gateways" || value === "ranges" || value === "advanced" ? value : "overview";
}
function OperationalSection({ title, actions, className = "", children }: { title: string; actions?: import("react").ReactNode; className?: string; children: import("react").ReactNode }) {
  return <section className={`s2s-operation-panel ${className}`} aria-label={title}><header className="s2s-operation-header"><h2>{title}</h2>{actions}</header>{children}</section>;
}

function useNetworkListPage(count: number) {
  const [requestedPage, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const page = Math.min(requestedPage, Math.max(1, Math.ceil(count / pageSize)));
  useEffect(() => { if (page !== requestedPage) setPage(page); }, [page, requestedPage]);
  return { page, pageSize, start: (page - 1) * pageSize, end: page * pageSize, hasNext: page * pageSize < count, onPageChange: setPage, onPageSizeChange: (size: number) => { setPageSize(size); setPage(1); } };
}

export default function Sites() {
  const [params, setParams] = useSearchParams();
  const { org: currentOrg, loading: orgLoading, failed: orgFailed } = useOrg();
  const { state } = useAuth();
  const myId = state.status === "authed" ? state.user.id : "";
  const emailVerified = state.status === "authed" && state.user.email_verified;
  const loadScope = `${currentOrg?.id ?? ""}:${myId}:${emailVerified ? "verified" : "unverified"}`;
  const loadScopeRef = useRef(loadScope);
  loadScopeRef.current = loadScope;
  const requestSequence = useRef(0);
  const [loadedScope, setLoadedScope] = useState("");
  const scopeCurrent = loadedScope === loadScope;
  const [meta, setMeta] = useState<Meta | null>(null);
  const [org, setOrg] = useState<Org | null>(null);
  const [myRole, setMyRole] = useState<Role | undefined>(undefined);
  const [raw, setRaw] = useState<Raw | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [registering, setRegistering] = useState(false);
  const [routingLan, setRoutingLan] = useState(false); // S8.5 D1 one-screen "route a LAN" affordance
  const mapCollapsed = params.get("section") !== "topology";
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchIndex, setSearchIndex] = useState(0);
  const priorOrgId = useRef<string | null>(null);
  const selectedSiteId = params.get("site");
  const selectedGatewayId = params.get("gateway");
  const dnsFocus = params.get("dns") === "1";
  const query = params.get("q") ?? "";
  const inventoryPageSize = appAccessPageSize(params.get("page_size"));
  const requestedInventoryPage = Math.max(1, Number(params.get("page")) || 1);
  const detail = dnsFocus ? "advanced" : selectedGatewayId ? "gateways" : networkStep(params.get("detail"));
  const requestedSection = params.get("section") ?? "overview";
  const section = ["overview", "approvals", "ha", "dns"].includes(requestedSection)
    ? requestedSection
    : "overview";

  const updateQuery = useCallback((next: { site?: string | null; gateway?: string | null; q?: string | null; section?: string | null; dns?: string | null; detail?: string | null; page?: string | null; page_size?: string | null }) => {
    setParams((current) => {
      const updated = new URLSearchParams(current);
      if ("q" in next || "page_size" in next) updated.delete("page");
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
    if (!params.has("site") && !params.has("gateway") && !params.has("q") && !params.has("dns") && !params.has("detail") && !params.has("page")) return;
    setParams((current) => {
      const normalized = new URLSearchParams(current);
      normalized.delete("site");
      normalized.delete("gateway");
      normalized.delete("q");
      normalized.delete("dns");
      normalized.delete("detail");
      normalized.delete("page");
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
      updateQuery({ site: null, gateway: null, dns: null, detail: null, page: null });
    }
    priorOrgId.current = nextOrgId;
  }, [currentOrg?.id, updateQuery]);

  const reload = useCallback(async () => {
    const request = ++requestSequence.current;
    const requestedScope = loadScope;
    const isCurrent = () => request === requestSequence.current && requestedScope === loadScopeRef.current;
    setLoadedScope(requestedScope);
    setMeta(null);
    setOrg(null);
    setMyRole(undefined);
    setLoadError(null);
    setRaw(null);
    const mRes = await loadOne(() => api.GET("/api/v1/meta"));
    if (!isCurrent()) return;
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
    if (!isCurrent()) return;
    setMyRole(roleFromMembers(memRes, myId).role);

    const sRes = (await loadOne(() =>
      api.GET("/api/v1/organizations/{orgId}/sites", {
        params: { path: { orgId: first.id } },
      }),
    )) as Loaded<Site[]>;
    if (!isCurrent()) return;
    if (!sRes.ok) return setLoadError(sRes.error);
    const nRes = (await loadOne(() =>
      api.GET("/api/v1/organizations/{orgId}/nodes", {
        params: { path: { orgId: first.id } },
      }),
    )) as Loaded<Node[]>;
    if (!isCurrent()) return;
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
    if (!isCurrent()) return;
    const subnetsBySite: Record<string, SiteSubnet[]> = {};
    for (let i = 0; i < sRes.data.length; i++) {
      const subRes = subResults[i];
      if (!subRes.ok) return setLoadError(subRes.error); // any failed subnet load → legible retry, not a partial topology
      subnetsBySite[sRes.data[i].id] = subRes.data;
    }
    // A failed hub read does not block the topology. Failover shows an unavailable state
    // and withholds pin controls until the current configuration can be read.
    const hRes = (await loadOne(() =>
      api.GET("/api/v1/organizations/{orgId}/hub-set", {
        params: { path: { orgId: first.id } },
      }),
    )) as Loaded<HubSet>;
    if (!isCurrent()) return;
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
    if (!isCurrent()) return;
    setRaw({
      sites: sRes.data,
      nodes: nRes.data,
      subnetsBySite,
      hubSet: hRes.ok ? hRes.data : null,
      hubSetUnavailable: !hRes.ok,
      forwards: mergeOrgForwards(
        sRes.data.map((site, i) => ({ site, res: fwdResults[i] })),
      ),
    });
    // ⚠ currentOrg IS A DEPENDENCY, AND THAT IS THE HALF THAT MAKES THE SWITCHER WORK. Without it the
    // page keeps rendering the org it mounted with — the control moves, the data does not, and the user is
    // looking at one tenant's screen labelled with another's name.
  }, [currentOrg, myId, loadScope, orgLoading, orgFailed]);
  useEffect(() => {
    reload();
  }, [reload]);

  const gate = siteGate({ role: scopeCurrent ? myRole : undefined, emailVerified });
  const view = sitesView({
    ready: scopeCurrent && meta != null && org != null,
    loadError: scopeCurrent && loadError != null,
  });

  const cards: SiteCard[] = useMemo(
    () =>
      scopeCurrent && raw ? assembleTopology(raw.sites, raw.subnetsBySite, raw.nodes) : [],
    [raw, scopeCurrent],
  );
  // Approved-subnet count per site — the CW threshold input. Unbound nodes — the bind picker. All gateways
  // (nodes bound to any site) — the CW sub-ceiling naming input. All derived from wire data.
  const approvedCountBySite = useMemo(() => {
    const m: Record<string, number> = {};
    if (scopeCurrent && raw)
      for (const [sid, subs] of Object.entries(raw.subnetsBySite))
        m[sid] = subs.filter((s) => s.status === "approved").length;
    return m;
  }, [raw, scopeCurrent]);
  const unboundGatewayNodes = useMemo(
    () =>
      scopeCurrent && raw
        ? raw.nodes.filter(
            (n) => !n.site_id && n.status === "active" && n.enrolled_kind === "gateway",
          )
        : [],
    [raw, scopeCurrent],
  );
  const allGateways = useMemo(() => cards.flatMap((c) => c.gateways), [cards]);

  const selectedCard = cards.find(c => selectedSiteId ? c.id === selectedSiteId : selectedGatewayId ? c.gateways.some(gateway => gateway.id === selectedGatewayId) : false) ?? null;
  const visibleCards = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return cards;
    return cards.filter((card) =>
      card.name.toLowerCase().includes(needle) ||
      card.gateways.some((gateway) => gateway.name.toLowerCase().includes(needle)),
    );
  }, [cards, query]);

  const inventoryPage = Math.min(Math.floor(requestedInventoryPage), Math.max(1, Math.ceil(visibleCards.length / inventoryPageSize)));
  const inventoryRows = visibleCards.slice((inventoryPage - 1) * inventoryPageSize, inventoryPage * inventoryPageSize);

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
    updateQuery({ site: result.siteId, gateway: result.gatewayId, detail: null, dns: null });
  }

  useEffect(() => {
    if (selectedSiteId && cards.length > 0 && !cards.some((card) => card.id === selectedSiteId)) {
      updateQuery({ site: null });
    }
  }, [cards, selectedSiteId, updateQuery]);

  const selectSite = useCallback(
    (siteId: string | null) => updateQuery({ site: siteId, gateway: null, dns: null, detail: null }),
    [updateQuery],
  );

  const mesh = useMemo(
    () => meshFrom(cards, raw?.nodes ?? [], raw?.hubSet),
    [cards, raw],
  );

  return (
    <div className="site-to-site-workspace network-management sites-workspace s2s-networks-workspace">
      {!selectedCard && <h1 className="sr-only">Site-to-site</h1>}
      <div className="s2s-networks-topbar">
        <SiteToSiteNavigation active="networks" />
        {view === "body" && <div className="s2s-networks-actions"><RefreshButton label="Refresh networks" onClick={() => void reload()} />{gate.canManage && <Link className="sites-primary-action" to="/network/setup">Set up a network</Link>}</div>}
      </div>

      {view === "load_retry" && (
        <LoadRetry error={loadError ?? "Couldn't load."} onRetry={reload} />
      )}
      {view === "loading" && (
        <div className="s2s-network-state"><Loading label="Loading Sites…" /></div>
      )}

      {view === "body" && raw != null && org != null && (
        <div className="sites-layout">
          <nav className="sites-section-nav s2s-networks-sections" aria-label="Network management">
            {[
              ["overview", "Inventory", "Your networks and gateways"],
              ["topology", "Topology", "See how networks connect"],
              ["approvals", "Range approvals", "Review advertised IP ranges"],
              ["ha", "Failover", "WireGuard primary and standby"],
              ["dns", "DNS forwarding", "Resolve names across sites"],
            ].map(([key, label, description]) => (
              <Link key={key} title={description} to={`?section=${key}`} aria-current={(section === "overview" && !mapCollapsed ? "topology" : section) === key ? "page" : undefined}>
                <span>{label}</span>
              </Link>
            ))}
          </nav>
          <div className="sites-section-content">
          {section === "overview" && (
            <div className="flex min-w-0 flex-col gap-3">
              {!selectedCard && mapCollapsed && <SiteList
                toolbar={<Input aria-label="Search networks" placeholder="Search networks…" value={query} onChange={event => updateQuery({ q: event.target.value, site: null, gateway: null, dns: null, detail: null })} className="sites-search" />}
                cards={inventoryRows}
                total={visibleCards.length}
                page={inventoryPage}
                pageSize={inventoryPageSize}
                onPageChange={page => updateQuery({ page: page === 1 ? null : String(page) })}
                onPageSizeChange={size => updateQuery({ page_size: size === 20 ? null : String(size) })}
                onClearSearch={() => updateQuery({ q: null, page: null })}
                canManage={gate.canManage}
                query={query}
                selectedId={selectedSiteId}
                onSelect={selectSite}
                onRanges={site => updateQuery({ site, gateway: null, dns: null, detail: "ranges" })}
              />}
              {!selectedCard && !mapCollapsed && <OperationalSection
                title="WireGuard topology"
                className="min-w-0"
                actions={
                  /* D2 (ruled): scoped to the MAP, not the page. The mesh's edges are handshake-derived, so
                     the claim is true here. Over the subnet queue it would not be — those are control-plane
                     rows. */
                  <div className="flex items-center gap-2">
                    <span className="text-micro text-ink-tertiary">Live topology</span>

                  </div>
                }
              >
                {/* The handoff puts the hint INLINE beside the title (dc.html L454). Ours drops "hover to
                    trace a link" because we do not implement hover tracing — describing an interaction the
                    component does not have is the same class of lie as a chart with no source. */}
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
                  maxHeight={360}
                  empty="Route a LAN to draw your first site here."
                />
                <p className="text-micro text-ink-faint">WireGuard links only. View Connections for IPsec tunnel status.</p>
              </OperationalSection>}
              {!selectedCard && <SelectedSiteStrip canManage={gate.canManage} unboundGateway={unboundGatewayNodes.find((node) => node.id === selectedGatewayId) ?? null} onRouteLan={() => setRoutingLan(true)} />}

              {!selectedCard && gate.canManage && <details className="sites-advanced s2s-disclosure"><summary>Advanced setup</summary><div className="s2s-disclosure-body">{unboundGatewayNodes.length > 0 && <Button variant="ghost" size="sm" onClick={() => setRoutingLan(true)}>Route a LAN</Button>}<Button variant="ghost" size="sm" onClick={() => setRegistering(true)}>Create empty location</Button><Button variant="ghost" size="sm" onClick={() => updateQuery({ section: "dns", site: null, gateway: null, q: null, dns: null })}>Review DNS forwarding</Button></div></details>}

              {selectedCard && <SiteCardView key={`${org.id}:${selectedCard.id}`}
                card={selectedCard} canManage={gate.canManage} orgId={org.id}
                unboundNodes={unboundGatewayNodes} dnsFocus={dnsFocus} selectedGatewayId={selectedGatewayId}
                step={detail} params={params} onStepChange={next => updateQuery({ detail: next === "overview" ? null : next, gateway: next === "gateways" ? selectedGatewayId : null, dns: next === "advanced" && dnsFocus ? "1" : null })}
                onDone={reload}
              />}

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
              <OperationalSection title="Range approvals">
                <p className="text-cell text-ink-tertiary">You can view Sites, but approving routed ranges requires site:manage and a verified email.</p>
              </OperationalSection>
            )
          )}

          {section === "ha" && (
            <HubSetSection
              orgId={org.id}
              canManage={gate.canManage}
              hubSet={raw.hubSet}
              unavailable={raw.hubSetUnavailable}
              gateways={allGateways}
              onDone={reload}
            />
          )}

          {section === "dns" && (
            <div className="s2s-dns-workspace">
              <DNSForwardsPanel
                view={raw.forwards}
                siteCount={raw.sites.length}
                canManage={gate.canManage}
                onManageSite={(siteId) => updateQuery({ section: "overview", site: siteId, gateway: null, q: null, dns: "1" })}
                onRetry={reload}
              />
            </div>
          )}
          </div>
        </div>
      )}
      {view === "body" && raw == null && (
        <div className="s2s-network-state"><Loading label="Loading Sites…" /></div>
      )}

      {registering && org && gate.canManage && (
        <RegisterSiteModal
          orgId={org.id}
          onDone={reload}
          onClose={() => setRegistering(false)}
        />
      )}
      {routingLan && org && gate.canManage && (
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
function DNSForwardsPanel({ view, siteCount, canManage, onManageSite, onRetry }: {
  view: OrgForwardsView; siteCount: number; canManage: boolean;
  onManageSite: (siteId: string) => void; onRetry: () => void;
}) {
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState("all");
  const [zone, setZone] = useState<string | null>(null);
  const conflictRows = view.rows.filter(row => view.conflicts.includes(row.domain));
  const filtered = view.rows.filter(row => (filter !== "conflicts" || view.conflicts.includes(row.domain)) && `${row.domain} ${row.resolverIp} ${row.siteName}`.toLowerCase().includes(query.trim().toLowerCase()));
  const pagination = useNetworkListPage(filtered.length);
  const pageRows = filtered.slice(pagination.start, pagination.end);
  const selectedRows = zone === null ? [] : view.rows.filter(row => row.domain === zone);
  const selectedPagination = useNetworkListPage(selectedRows.length);
  const selectedPageRows = selectedRows.slice(selectedPagination.start, selectedPagination.end);
  const clearFilters = () => { setQuery(""); setFilter("all"); pagination.onPageChange(1); };
  const openZone = (domain: string) => { setZone(domain); selectedPagination.onPageChange(1); };
  const partialNotice = view.failedSites.length > 0 && <div role="status" className="s2s-operational-notice s2s-partial-notice"><p>Could not read zones from {view.failedSites.join(", ")}. This list is incomplete, so conflicts cannot be ruled out.</p><Button size="sm" variant="ghost" onClick={onRetry}>Retry DNS reads</Button></div>;
  const rowMenu = (row: OrgForwardsView["rows"][number], includeDetails = true) => <AppAccessRowMenu label={`DNS actions for ${row.domain} in ${row.siteName}`} actions={[
    ...(includeDetails ? [{ key: "details", label: "Zone details", onSelect: () => openZone(row.domain) }] : []),
    ...(canManage ? [{ key: "edit", label: `Edit forwarding in ${row.siteName}`, onSelect: () => onManageSite(row.siteId) }] : []),
  ]} />;
  if (zone !== null) return <section className="s2s-dns-detail" aria-label={`${zone} forwarding`}>
    <nav className="s2s-network-breadcrumb" aria-label="DNS forwarding breadcrumb"><button type="button" onClick={() => setZone(null)}>Back to DNS forwarding</button><span aria-hidden="true">/</span><span aria-current="page">{zone}</span></nav>
    <header className="s2s-network-header"><h2>{zone}</h2><span className="s2s-muted">{selectedRows.length} network{selectedRows.length === 1 ? "" : "s"}</span></header>
    {partialNotice}
    {view.conflicts.includes(zone) && <div className="s2s-operational-notice" role="status"><p>Multiple resolvers for this zone. Keep one target IP across networks.</p></div>}
    {!selectedRows.length ? <div className="s2s-empty-state" role="status"><h3>No forwarding records</h3><p>{view.conflictsAreComplete ? "This zone is no longer configured." : "This zone was not returned by the networks that answered."}</p></div> : <div className="s2s-flat-table s2s-dns-target-table"><DataTable caption="Zone resolver targets" rows={selectedPageRows} rowKey={row => `${row.siteId}-${row.domain}`} failed={false} empty={null} pageSize={0} filterable={false} variant="flat" columns={[
      { key: "site", header: "Network", cell: row => row.siteName },
      { key: "resolver", header: "Resolver target", cell: row => row.resolverIp },
      { key: "actions", header: "Actions", cell: row => rowMenu(row, false) },
    ]} /></div>}
    <AppAccessPagination maxOffset={null} page={selectedPagination.page} pageSize={selectedPagination.pageSize} count={selectedPageRows.length} hasNext={selectedPagination.hasNext} onPageChange={selectedPagination.onPageChange} onPageSizeChange={selectedPagination.onPageSizeChange} previousLabel="Previous resolver targets" nextLabel="Next resolver targets" />
    <p className="s2s-operation-context s2s-dns-detail-note">{canManage ? "Use a network’s row menu to edit its forwarding settings." : "An owner or admin can edit forwarding settings."}</p>
  </section>;
  return <section className="s2s-dns-workspace" aria-label="Cross-site DNS forwarding">
    <h2 className="sr-only">Cross-site DNS forwarding</h2>
    {partialNotice}
    <div className="s2s-operations-toolbar">
      <div className="s2s-operations-filters"><Input aria-label="Search DNS forwards" placeholder="Search zones, resolvers or networks…" value={query} onChange={event => { setQuery(event.target.value); pagination.onPageChange(1); }} /><Select aria-label="DNS forwarding status" width="auto" value={filter} onChange={event => { setFilter(event.target.value); pagination.onPageChange(1); }}><option value="all">All forwards</option><option value="conflicts">Conflicts ({conflictRows.length})</option></Select></div>
      <div className="s2s-operations-summary"><span>{filtered.length}{view.conflictsAreComplete ? " forwards" : " loaded forwards"}</span>{view.conflicts.length > 0 && <button className="s2s-conflict-filter" type="button" aria-label="Show conflicting forwards" onClick={() => { setFilter("conflicts"); setQuery(""); pagination.onPageChange(1); }}>{view.conflicts.length} zone conflict{view.conflicts.length === 1 ? "" : "s"}</button>}</div>
    </div>
    {!pageRows.length ? <div className="s2s-empty-state" role="status"><h3>{query || filter !== "all" ? "No matching forwards" : siteCount === 0 ? "No networks yet" : view.conflictsAreComplete ? "No forwarded zones" : "No records loaded"}</h3><p>{query || filter !== "all" ? "Try another zone, resolver or network." : siteCount === 0 ? "Add a network before configuring zone forwarding." : view.conflictsAreComplete ? "Add a zone in a network’s Advanced settings." : "Retry the unavailable networks to read their zones."}</p>{(query || filter !== "all") && <Button size="sm" variant="ghost" onClick={clearFilters}>Clear filters</Button>}</div> : <div className="s2s-flat-table s2s-dns-table"><DataTable caption="DNS forwarding" rows={pageRows} rowKey={row => `${row.siteId}-${row.domain}`} failed={false} empty={null} filterable={false} pageSize={0} variant="flat" columns={[
      { key: "zone", header: "Zone", cell: row => <button type="button" className="s2s-name-link" onClick={() => openZone(row.domain)}>{row.domain}</button> },
      { key: "network", header: "Network", cell: row => row.siteName },
      { key: "resolver", header: "Resolver", cell: row => row.resolverIp },
      { key: "status", header: "Status", cell: row => view.conflicts.includes(row.domain) ? <Badge tone="danger">Conflict</Badge> : <Badge tone="neutral">Configured</Badge> },
      { key: "actions", header: "Actions", cell: row => rowMenu(row) },
    ]} /></div>}
    <AppAccessPagination maxOffset={null} page={pagination.page} pageSize={pagination.pageSize} count={pageRows.length} hasNext={pagination.hasNext} onPageChange={pagination.onPageChange} onPageSizeChange={pagination.onPageSizeChange} previousLabel="Previous DNS forwards" nextLabel="Next DNS forwards" />
    <details className="s2s-disclosure s2s-operations-help"><summary>About DNS forwarding</summary><div className="s2s-disclosure-body"><p>Use the same resolver target for a zone across networks.</p><p>Private DNS Resolver remains the only primary configuration for FQDN access. Manage it in <Link className="s2s-text-link" to="/access/resources?type=fqdn#private-dns-heading">Private DNS Resolvers</Link>.</p></div></details>
  </section>;
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
      placement="right" showClose
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
      <div className="s2s-setup-form">
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
      </div>
    </Modal>
  );
}

// ── S8.6 hub set (HA): the operator surface + the L1 metrics ─────────────────────────
// The persisted HA hub set — ordered candidates (PRIMARY on members[0], evolving the HUB badge vocabulary),
// warm/handshake state + L1 byte counters per member (from node_peer_status — render-floor: a not-reporting
// link shows "—", NEVER 0; an idle link shows its real 0 bytes), and the generation as the set's version
// tag. When the active order diverges from the configured pins a failover is IN EFFECT — stated, with the
// demoted member marked and an audit pointer. Member-readable; the pin control is manage-gated.
function HubSetSection({ orgId, canManage, hubSet, unavailable, gateways, onDone }: {
  orgId: string; canManage: boolean; hubSet: HubSet | null; unavailable: boolean;
  gateways: GatewayView[]; onDone: () => void;
}) {
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [managing, setManaging] = useState(false);
  const [report, setReport] = useState<HubMemberRow | null>(null);
  const view = hubSetView(hubSet, Date.now());
  const nameOf = (id: string) => gateways.find(gateway => gateway.id === id)?.name ?? id.slice(0, 8);
  const priorities = new Map((hubSet?.members ?? []).map(member => [member.node_id, member.hub_priority ?? null]));
  const pins = [...priorities.values()].filter((value): value is number => value != null);
  const nextPin = pins.length ? Math.max(...pins) + 1 : 1;

  async function setPin(nodeId: string, priority: number | null) {
    if (busy || !canManage || unavailable) return;
    setBusy(true);
    setErr(null);
    try {
      const { error } = await api.PUT("/api/v1/organizations/{orgId}/nodes/{nodeId}/hub-priority", {
        params: { path: { orgId, nodeId } }, body: { priority },
      });
      if (error) setErr(apiErrorMessage(error, "Could not set the hub priority."));
      else { setManaging(false); onDone(); }
    } catch { setErr("Could not set the hub priority. Refresh before trying again."); }
    finally { setBusy(false); }
  }

  if (unavailable) return <section className="s2s-failover-workspace" aria-label="WireGuard redundancy">
    <div className="s2s-empty-state" role="status"><h2>Hub configuration unavailable</h2><p>Refresh to read the current primary and standby configuration.</p><Button variant="ghost" size="sm" onClick={onDone}>Retry hub configuration</Button></div>
  </section>;
  if (!view && !canManage) return null;
  const tooFewGateways = !view && gateways.length < 2;
  const stale = view?.members.filter(member => member.warm === false).length ?? 0;
  const missing = view?.members.filter(member => member.warm === null).length ?? 0;
  return <section className="s2s-failover-workspace" aria-label="WireGuard redundancy">
    <h2 className="sr-only">WireGuard redundancy</h2>
    <div className="s2s-operations-toolbar">
      <div className="s2s-operations-summary"><span>{view ? `${view.members.length} transit hubs` : "No transit hubs"}</span>{view && <span className="s2s-muted">Generation {view.generation}</span>}{stale > 0 && <span className="s2s-report-warning">{stale} stale handshake report{stale === 1 ? "" : "s"}</span>}{missing > 0 && <span className="s2s-muted">{missing} report{missing === 1 ? "" : "s"} unavailable</span>}</div>
      {canManage && !tooFewGateways && <Button size="sm" onClick={() => setManaging(true)}>Manage candidates</Button>}
    </div>
    {view?.promotionInEffect && <div className="s2s-operational-notice" role="status"><span>Standby promoted to acting primary.</span><Link to="/audit">View timeline</Link></div>}
    {view ? <div className="s2s-flat-table s2s-hub-table"><DataTable<HubMemberRow> caption="Transit hubs" rows={view.members} rowKey={member => member.nodeId} failed={false} filterable={false} pageSize={0} empty={null} variant="flat" columns={[
      { key: "gateway", header: "Gateway", cell: member => <Link className="s2s-name-link" to={`/gateways/${member.nodeId}`}>{nameOf(member.nodeId)}</Link> },
      { key: "role", header: "Acting role", cell: member => <div className="s2s-role-cell"><span>{member.role === "primary" ? "Primary" : "Standby"}</span>{member.demoted && <span className="s2s-muted">Configured primary · demoted</span>}</div> },
      { key: "health", header: "Handshake", cell: member => <Badge tone={member.warm === false ? "danger" : member.warm === true ? "ok" : "neutral"}>{member.warm === false ? "Stale" : member.warm === true ? "Recent" : "Not reported"}</Badge> },
      { key: "last", header: "Last handshake", cell: member => member.handshakeAge === "n/a" ? "Not reported" : member.handshakeAge },
      { key: "actions", header: "Actions", cell: member => <AppAccessRowMenu label={`Hub actions for ${nameOf(member.nodeId)}`} actions={[{ key: "report", label: "Report details", onSelect: () => setReport(member) }]} /> },
    ]} /></div> : <div className="s2s-empty-state" role="status"><h2>{tooFewGateways ? "Add another gateway" : "Choose your transit hubs"}</h2><p>{tooFewGateways ? "Failover needs a primary and standby gateway. Assign another gateway to a network to begin." : "Pin a preferred primary and at least one standby."}</p>{tooFewGateways && <Link className="s2s-text-link" to="/gateways">View gateways</Link>}</div>}
    <ErrorText>{err}</ErrorText>
    <details className="s2s-disclosure s2s-operations-help"><summary>How failover works</summary><div className="s2s-disclosure-body"><p>Lower pin numbers are preferred. The acting primary can change when a candidate becomes unavailable.</p><p>A recent handshake is a gateway report, not an application reachability check.</p><Link className="s2s-text-link" to="/site-to-site?method=ipsec">IPsec tunnel redundancy in Connections</Link></div></details>
    {canManage && managing && <Modal placement="right" size="wide" showClose title="Hub candidates" onDismiss={busy ? () => {} : () => setManaging(false)} actions={<Button variant="ghost" disabled={busy} onClick={() => setManaging(false)}>Done</Button>}>
      <div className="s2s-candidate-editor"><p>Pin gateways in order of preference. The lowest number is the preferred primary.</p>
        <NetworkDetailList label="Hub candidates" items={gateways} searchText={gateway => `${gateway.name} ${priorities.get(gateway.id) ?? ""}`} renderItem={gateway => {
          const priority = priorities.get(gateway.id);
          const pinned = priority != null;
          return <li key={gateway.id} className="s2s-candidate-row"><div><strong>{gateway.name}</strong><span>{pinned ? `Priority ${priority}` : "Not pinned"}</span></div><Button variant="ghost" size="sm" disabled={busy} onClick={() => void setPin(gateway.id, pinned ? null : nextPin)}>{pinned ? "Unpin" : nextPin === 1 ? "Set primary" : `Pin #${nextPin}`}</Button></li>;
        }} />
        <ErrorText>{err}</ErrorText>
      </div>
    </Modal>}
    {report && <Modal placement="right" showClose title={nameOf(report.nodeId)} onDismiss={() => setReport(null)} actions={<Button variant="ghost" onClick={() => setReport(null)}>Done</Button>}>
      <ResourceSummary className="s2s-hub-report" title="Last reported hub metrics"><dl className="s2s-network-facts tnx-resource-facts"><div><dt>Acting role</dt><dd>{report.role === "primary" ? "Primary" : "Standby"}{report.demoted && " · configured primary demoted"}</dd></div><div><dt>Last handshake</dt><dd>{report.handshakeAge === "n/a" ? "Not reported" : report.handshakeAge}</dd></div><div><dt>Received</dt><dd>{report.reporting ? report.rx : "Not reported"}</dd></div><div><dt>Sent</dt><dd>{report.reporting ? report.tx : "Not reported"}</dd></div></dl><p className="s2s-operation-context mt-5">These counters do not verify application traffic.</p></ResourceSummary>
    </Modal>}
  </section>;
}

function SelectedSiteStrip({ unboundGateway, canManage, onRouteLan }: { unboundGateway: Node | null; canManage: boolean; onRouteLan: () => void }) {
  if (!unboundGateway) return null;
  return <section aria-label="Selected Site" className="s2s-unbound-gateway"><strong>{unboundGateway.name}</strong><Badge tone="neutral">Unbound Gateway</Badge><p>No Site is bound. Its location is not shown on this topology.</p>{canManage && <Button variant="ghost" size="sm" onClick={onRouteLan}>Route a LAN</Button>}</section>;
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
  toolbar,
  cards,
  canManage,
  query,
  selectedId,
  onSelect, onRanges, total, page, pageSize, onPageChange, onPageSizeChange, onClearSearch,
}: {
  toolbar: import("react").ReactNode;
  cards: SiteCard[];
  canManage: boolean;
  query: string;
  selectedId: string | null;
  onSelect: (id: string | null) => void;
  onRanges: (id: string) => void;
  total: number; page: number; pageSize: number;
  onPageChange: (page: number) => void; onPageSizeChange: (size: number) => void; onClearSearch: () => void;
}) {
  const columns = [
    {
      key: "name",
      header: "Network",
      cell: (c: SiteCard) => (
        <button
          type="button"
          aria-pressed={c.id === selectedId}
          onClick={() => onSelect(c.id === selectedId ? null : c.id)}
          className="s2s-network-name"
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
          <span className="text-ink-faint">Not assigned</span>
        );
      },
    },
    {
      key: "health",
      header: "Gateway status",
      cell: (c: SiteCard) => {
        const gw = c.gateways.find((g) => g.status === "active");
        if (!gw) return <span className="text-ink-faint">Needs a gateway</span>;
        return gw.health ? (
          <Badge tone={gw.health.tone as "ok" | "warn" | "danger" | "neutral"}>
            {gw.health.label}
          </Badge>
        ) : (
          <Badge tone="neutral">Assigned</Badge>
        );
      },
    },
    {
      key: "ranges",
      header: "Local IP ranges",
      cell: (c: SiteCard) =>
        c.subnets.length === 0 ? (
          <span className="text-ink-faint">none</span>
        ) : (
          // ⛔ role + accessible name, NOT `title`. A `title` on a role-less <span> is not an accessible
          // name a screen reader reliably announces, and querying it violated query rule 1 — role and
          // accessible name only. The chip is a LIST ITEM stating a range's routing state, so it says so.
          <span className="s2s-network-range-cell"><span role="list" className="s2s-network-range-preview">
            {c.subnets.slice(0, 3).map((sn) => (
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
          </span>{c.subnets.length > 3 && <button type="button" className="s2s-text-link" aria-label={`View ${c.subnets.length - 3} more ranges for ${c.name}`} onClick={() => onRanges(c.id)}>+{c.subnets.length - 3} more</button>}</span>
        ),
    },
  ];

  return <section className="s2s-networks-inventory" aria-label="Network inventory">
    <div className="s2s-network-toolbar">{toolbar}<span>{total} network{total === 1 ? "" : "s"}</span></div>
    {cards.length ? <div className="s2s-network-table"><DataTable caption="Sites" columns={columns} rows={cards} rowKey={(card: SiteCard) => card.id} empty={null} failed={false} filterable={false} pageSize={0} variant="flat" /></div> : <div className="s2s-empty-state" role="status"><h3>{query.trim() ? "No matching networks" : "No networks yet"}</h3><p>{query.trim() ? "No Sites or Gateways match this search." : canManage ? "Set up a network to assign gateways and route its private ranges." : "An owner or admin can add a network."}</p>{query.trim() && <Button size="sm" variant="ghost" onClick={onClearSearch}>Clear search</Button>}</div>}
    <AppAccessPagination maxOffset={null} page={page} pageSize={pageSize} count={cards.length} hasNext={page * pageSize < total} previousLabel="Previous networks" nextLabel="Next networks" onPageChange={onPageChange} onPageSizeChange={onPageSizeChange} />
  </section>;
}


function SiteCardView({ card, canManage, orgId, unboundNodes, dnsFocus, selectedGatewayId, step, params, onStepChange, onDone }: {
  card: SiteCard; canManage: boolean; orgId: string; unboundNodes: Node[]; dnsFocus: boolean;
  selectedGatewayId: string | null; step: NetworkStep; params: URLSearchParams; onStepChange: (step: NetworkStep) => void; onDone: () => void;
}) {
  const approved = card.subnets.filter(subnet => subnet.status === "approved");
  const pending = card.subnets.filter(subnet => subnet.status === "pending");
  const activeGateways = card.gateways.filter(gateway => gateway.status === "active");
  const focusedGateway = card.gateways.find(gateway => gateway.id === selectedGatewayId) ?? activeGateways[0];
  const resolverHint = approved[0] ? `Resolver IP inside ${approved[0].cidr}` : "Resolver IP inside an approved subnet";
  const [modal, setModal] = useState<"subnet" | "bind" | "unbind" | "delete" | null>(null);
  const [removing, setRemoving] = useState<{ id: string; cidr: string; status: string } | null>(null);
  const hasGateway = card.gateways.length > 0;
  const listParams = new URLSearchParams(params);
  for (const key of ["site", "gateway", "dns", "detail"]) listParams.delete(key);
  const listHref = `/sites${listParams.size ? `?${listParams}` : ""}`;
  const stepIndex = networkSteps.findIndex(item => item.id === step);
  return <section id="site-details" aria-label={`Selected Site: ${card.name}`} className="s2s-network-detail">
    <nav className="s2s-network-breadcrumb" aria-label="Network breadcrumb"><Link to={listHref}>Networks</Link><span aria-hidden="true">/</span><span aria-current="page">{card.name}</span></nav>
    <header className="s2s-network-header"><h1>{card.name}</h1><Badge tone={focusedGateway?.status === "revoked" ? "neutral" : focusedGateway?.health?.tone ?? "neutral"}>{focusedGateway?.status === "revoked" ? "Gateway revoked" : focusedGateway?.health?.label ?? (activeGateways.length ? "Assigned" : "Needs a gateway")}</Badge></header>
    <div className="s2s-network-detail-layout">
      <aside className="s2s-network-rail"><nav className="s2s-network-detail-nav" aria-label="Network detail sections">{networkSteps.map(item => <button type="button" key={item.id} aria-current={item.id === step ? "page" : undefined} onClick={() => onStepChange(item.id)}>{item.label}</button>)}</nav><p>Routing approval and access policies are separate.</p></aside>
      <ResourceSummary className="s2s-network-stage" headingLevel={2} headingId="network-stage-heading" title={step === "overview" ? "Network settings" : networkSteps[stepIndex].label} actions={<div className="s2s-network-stage-actions">
          {step === "gateways" && canManage && unboundNodes.length > 0 && <Button size="sm" onClick={() => setModal("bind")}>Bind gateway</Button>}
          {step === "gateways" && canManage && hasGateway && <Button size="sm" variant="ghost" onClick={() => setModal("unbind")}>Unbind gateway</Button>}
          {step === "ranges" && canManage && <Button size="sm" onClick={() => setModal("subnet")}>Advertise subnet</Button>}
        </div>} footer={<>{stepIndex > 0 ? <Button size="sm" variant="ghost" onClick={() => onStepChange(networkSteps[stepIndex - 1].id)}>Back to {networkSteps[stepIndex - 1].label.toLowerCase()}</Button> : <span />}{stepIndex < networkSteps.length - 1 && <Button size="sm" onClick={() => onStepChange(networkSteps[stepIndex + 1].id)}>Continue to {networkSteps[stepIndex + 1].label.toLowerCase()}</Button>}</>}>
        {step === "overview" && <dl className="s2s-network-overview-facts tnx-resource-facts">
          <div className="s2s-network-assignment"><dt>Gateway assignment</dt><dd>{activeGateways.length ? activeGateways.map(gateway => <Link key={gateway.id} to={`/gateways/${gateway.id}`}><span>{gateway.name}</span>{gateway.isHub && <small> · hub</small>}</Link>) : "No active gateway assigned"}</dd></div>
          <div><dt>Approved ranges</dt><dd><span className="s2s-network-fact-value">{approved.length}</span>{" "}<span className="s2s-network-fact-note">routed</span></dd></div>
          <div><dt>Pending ranges</dt><dd><span className="s2s-network-fact-value">{pending.length || "None"}</span>{pending.length > 0 && <>{" "}<span className="s2s-network-fact-note">awaiting approval · not routed</span></>}</dd></div>
        </dl>}
        {step === "gateways" && (hasGateway ? <NetworkDetailList label="Gateways" items={card.gateways} searchText={gateway => `${gateway.name} ${gateway.status}`} renderItem={gateway => <GatewayRow key={gateway.id} g={gateway} />} /> : <div className="s2s-empty-state" role="status"><h3>No gateway assigned</h3><p>{canManage ? unboundNodes.length ? "Bind an available gateway to connect this network." : "Enroll a gateway before binding it to this network." : "An owner or admin can bind a gateway."}</p></div>)}
        {step === "ranges" && <><p className="s2s-operation-context">Approved ranges are routed. Access Policies control who can use them.</p>{card.subnets.length ? <NetworkDetailList label="Routed ranges" items={card.subnets} searchText={subnet => `${subnet.cidr} ${subnet.status}`} renderItem={subnet => <li key={subnet.id} role="listitem" aria-label={`${subnet.cidr}: ${subnet.status === "approved" ? "Approved, routed" : "Pending approval, not yet routed"}`} className="network-range-row"><span>{subnet.cidr}</span><Badge tone={subnet.status === "approved" ? "ok" : "warn"}>{subnet.status === "approved" ? "routed" : "pending"}</Badge>{canManage && <button type="button" className="s2s-text-link s2s-range-remove" aria-label={`Remove ${subnet.cidr}`} onClick={() => setRemoving({ id: subnet.id, cidr: subnet.cidr, status: subnet.status })}>Remove</button>}</li>} /> : <div className="s2s-empty-state" role="status"><h3>No ranges advertised</h3><p>{canManage ? "Advertise the private range behind this network’s gateway." : "An owner or admin can advertise a private range."}</p></div>}</>}
        {step === "advanced" && <div className="s2s-network-advanced">
          {hasGateway && approved.length > 0 && <details className="s2s-disclosure"><summary>Advanced cloud routing</summary><div className="s2s-disclosure-body"><p>Enable IP forwarding on the gateway VM. On AWS, disable source/destination checks.</p><p>Point remote Site and device-pool CIDRs at this gateway. Update cloud route targets after cloud-side HA failover.</p><p>Operator reference: <span>docs/deploy-cloud-gateway.md</span></p></div></details>}
          {canManage && approved.length > 0 && <DNSForwardSection orgId={orgId} siteId={card.id} open={dnsFocus} resolverHint={resolverHint} />}
          {canManage && approved.length === 0 && <p className="s2s-operation-context">DNS forwarding requires an approved range in this network.</p>}
          {canManage && <details className="s2s-disclosure"><summary>Lifecycle actions</summary><div className="s2s-network-lifecycle s2s-disclosure-body"><div><h3>Delete this network</h3><p>Deletion removes the Site, its rules and ranges, and unbinds gateways. Immutable policy-template references can block deletion.</p></div><Button variant="danger" size="sm" onClick={() => setModal("delete")}>Delete site</Button><span className="sr-only">Danger zone</span></div></details>}
          {!canManage && <p className="s2s-operation-context">Changes to forwarding and network lifecycle require site management access.</p>}
        </div>}
      </ResourceSummary>
    </div>
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
  </section>;
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
    <li className="network-gateway-row">
      <a
        className="network-gateway-name font-medium text-ink-body hover:text-ink-heading hover:underline"
        title={g.name}
        href={`/gateways/${g.id}`}
      >
        {g.name}
      </a>
      <div className="network-gateway-status">
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
      </div>
      <span className="network-gateway-meta">
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
      placement="right" showClose
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
      <div className="s2s-setup-form">
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
      </div>
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
      placement="right" showClose
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
      <div className="s2s-setup-form">
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
      </div>
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
      placement="right" showClose
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
      <div className="s2s-setup-form">
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
      </div>
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
    { domain: string; resolver_ip: string }[] | null
  >(null);
  const [loadErr, setLoadErr] = useState<string | null>(null);
  const [domain, setDomain] = useState("");
  const [resolverIp, setResolverIp] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const load = useCallback(async () => {
    setForwards(null);
    setLoadErr(null);
    const result = await loadOne(() => api.GET(
      "/api/v1/organizations/{orgId}/sites/{siteId}/dns-forwards",
      { params: { path: { orgId, siteId } } },
    ));
    if (result.ok) setForwards(result.data as { domain: string; resolver_ip: string }[]);
    else setLoadErr(result.error);
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
    <details open={open} className="s2s-disclosure s2s-site-dns">
      <summary className="cursor-pointer font-medium text-ink-body">
        Advanced Site DNS forwarding
      </summary>
      <div className="s2s-disclosure-body">
        <p className="text-micro">Forward a Site-local zone through an approved range. FQDN access uses Private DNS Resolvers instead.</p>
        {loadErr ? <LoadRetry error={loadErr} onRetry={load} /> : forwards === null ? <Loading size="inline" label="Loading DNS forwards…" /> : <ul className="s2s-dns-forward-list">
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
        </ul>}
        <div className="s2s-dns-form">
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
  const pagination = useNetworkListPage(pending?.length ?? 0);
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
      <OperationalSection title="Range approvals">
        <LoadRetry error={loadErr} onRetry={loadQueue} />
      </OperationalSection>
    );
  if (pending == null)
    return (
      <OperationalSection title="Range approvals">
        <Loading size="inline" label="Loading pending subnet approvals…" />
      </OperationalSection>
    );
  if (pending.length === 0)
    return (
      <OperationalSection title="Range approvals">
        <EmptyState>No local IP ranges are waiting for approval. Access is controlled separately in Access Policies.</EmptyState>
      </OperationalSection>
    );

  return (
    <OperationalSection title="Range approvals">
      <p className="mt-1 text-xs text-slate-500">
        Approve local IP ranges advertised by gateways so they can be routed. Access Policies control who can use them.
      </p>
      <div className="s2s-flat-table">
        <div className="min-w-[520px]">
          <div className="s2s-approval-columns">
            <span>CIDR</span>
            <span>Site</span>
            <span>State</span>
            <span>Action</span>
          </div>
          <ul className="space-y-1.5 pt-1.5">
        {pending.slice(pagination.start, pagination.end).map((s) => (
          <li key={s.id} className="s2s-approval-row">
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
      <AppAccessPagination maxOffset={null} page={pagination.page} pageSize={pagination.pageSize} count={pending.slice(pagination.start, pagination.end).length} hasNext={pagination.hasNext} onPageChange={pagination.onPageChange} onPageSizeChange={pagination.onPageSizeChange} previousLabel="Previous range approvals" nextLabel="Next range approvals" />
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
    </OperationalSection>
  );
}
