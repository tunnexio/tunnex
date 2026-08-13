import type { Node, Site, SiteSubnet } from "./api";
import { can } from "./rbac";
import type { Role } from "./api";
import {
  policyHealthBadge,
  siteLinkNote,
  type HealthBadge,
  type SiteLinkNote,
} from "./healthview";
import { relativeAge } from "./format";
import type { Node as VizNode, Link as VizLink } from "../components/viz";

// sitesview — PURE, electron-free view-models for the Sites page (S8.3 Slice 2). The page is a thin
// render over these; the render-floor law binds here — every field a card shows traces to a WIRE value
// (a real Node/Site/SiteSubnet property), nothing derived that the backend didn't produce, nothing
// animated. The hub designation is READ from node.is_site_hub (backend-derived, the D2 overrule — the UI
// never re-elects), health is READ from policyHealthBadge (the S7.4b/S8.2 kinds), and a site's gateways
// are a LIST (CH: many nodes → one site; the UI never assumes one-gateway-per-site).

// ── RBAC gate ────────────────────────────────────────────────────────────────────────
// ⛔ NO EDITION TERM (S14.5, founder-ruled). This comment used to open "The Sites PAGE is enterprise-gated
// (D1/D5)" and that was never true of the server — see siteGate below. It is corrected rather than deleted
// because a stale comment asserting a boundary is the same false-record class as the test that asserted it.
// ANY member sees the read-only topology (canView); mutating needs site:manage + a verified
// email (mirrors the server). A member (no site:manage) sees topology but NOT the pending queue (D5:
// the queue is an action surface — visible-but-inert is the B6 cousin).
export interface SiteGate {
  canView: boolean; // every member → read-only topology, every edition
  canManage: boolean; // owner/admin + verified → mutations + queue
}

/**
 * ⛔ NO EDITION TERM. FOUNDER-RULED 2026-08-02 — THE GATE WAS THE BUG.
 *
 * This read `edition === "enterprise"` and the page rendered an UPSELL to everyone else. The server
 * disagrees, in writing, three times:
 *
 *   apps/api/internal/http/site_handlers.go:19   "(all editions, D11)"
 *   :95                                          "site:manage (all-editions core, D11)"
 *   :280                                         "All-editions core ... (authorize FIRST, no edition gate)"
 *
 * `ListSites` authorizes on `org:view` alone, NO site endpoint returns `edition_required`, and `/sites` is
 * absent from `ENTERPRISE_PATHS`. So an open-edition org could drive the whole site model through the CLI
 * and the API while this screen asked it to buy enterprise.
 *
 * ⛔ THE ONE-TRUTH RULE, STATED SO THE NEXT SCREEN INHERITS IT:
 *
 *     THE SERVER OWNS THE EDITION DECISION. THE CLIENT CONSUMES IT.
 *     A CLIENT-SIDE EDITION BRANCH THAT IS NOT DERIVED FROM THE SEAM IS A SECOND SOURCE OF TRUTH.
 *
 * The seam is `ENTERPRISE_PATHS` + `gate()` in `src/lib/edition.ts`, which is held to the spec by a census.
 * An edition branch written by hand, as this one was, is exactly the drift the census cannot see — because
 * it never passes through the seam at all.
 */
export function siteGate(input: {
  role: Role | undefined;
  emailVerified: boolean;
}): SiteGate {
  return {
    canView: true, // every member reads the topology their traffic traverses (D5), in every edition
    canManage: input.emailVerified && can(input.role, "site:manage"),
  };
}

// sitesView decides the page's top-level render. No "member_gate" — unlike Access, a member SEES the
// topology (D5 read-only). No "upsell" either, as of S14.5: there is nothing to sell.
export type SitesViewState = "loading" | "load_retry" | "body";

export function sitesView(i: {
  ready: boolean;
  loadError: boolean;
}): SitesViewState {
  if (i.loadError) return "load_retry";
  if (!i.ready) return "loading";
  return "body";
}

// ── topology assembly (the wire-truth join) ──────────────────────────────────────────
export interface SubnetView {
  id: string;
  cidr: string;
  status: SiteSubnet["status"]; // pending | approved — rendered as the real state, never assumed approved
}

export interface GatewayView {
  id: string;
  name: string;
  status: Node["status"]; // active | revoked
  isHub: boolean; // READ from node.is_site_hub (backend election), never recomputed here
  health: HealthBadge | null; // null = healthy (no badge); otherwise the S7.4b/S8.2 kind badge
  siteLinkNote: SiteLinkNote | null; // WF-B: the SUBORDINATE demoted-dead-peer line, INDEPENDENT of `health`
  maxPolicyVersion: number | null; // reported max; null = never reported (below-ceiling — CW, Slice 3 uses it)
  agentVersion: string;
  lastSeenAt: string | null; // S8.4 rider (VERIFY-0): the freshness fact the Devices page already renders
}

// GATEWAY_OFFLINE_MS: past this staleness a gateway reads OFFLINE. ~3 missed status reports (30s cadence).
export const GATEWAY_OFFLINE_MS = 90_000;

// gatewayLiveness (S8.4 rider) renders the FACT (last-seen age) and INFERS offline from a threshold — closing
// VERIFY-0's dead-gateway-renders-healthy hole on the site surface. It reads the SAME node.last_seen_at the
// Devices page already shows; no new signal, no third health vocabulary — the offline flag styles via the
// existing badge system. PURE.
export function gatewayLiveness(
  lastSeenAt: string | null | undefined,
  nowMs: number,
): { lastSeen: string; offline: boolean } {
  if (!lastSeenAt) {
    return { lastSeen: "never connected", offline: true };
  }
  const t = Date.parse(lastSeenAt);
  if (Number.isNaN(t)) {
    return { lastSeen: "unknown", offline: true };
  }
  return {
    lastSeen: relativeAge(lastSeenAt),
    offline: nowMs - t > GATEWAY_OFFLINE_MS,
  };
}

// gatewayOnline (S8.5 WF-1 — positive health) is the affirmative liveness signal on the site surface: a
// gateway reads ONLINE when it is active, reporting FRESH (not offline — the SAME gatewayLiveness clock),
// AND carries no degraded-health badge (no site_link_down / site_hub_down / desync). It is the fresh side
// of the SAME clock + health bool the offline/degraded badges already read — the deferred WF-1 item's
// discharge with NO third vocabulary and NO new data. (The numeric handshake age + link bytes — L1 — are
// re-deferred to S8.6's commit-one: "reported" ≢ "stored" for gateway peers, so a fresh/stale signal is
// what the surface honestly has; numeric age is richer, not required for liveness.) PURE.
export function gatewayOnline(
  status: GatewayView["status"],
  offline: boolean,
  health: HealthBadge | null,
): boolean {
  return status === "active" && !offline && health == null;
}

export interface SiteCard {
  id: string;
  name: string;
  // A LIST, never a scalar (CH probe target): a site's gateways are all nodes bound to it. v1 binds one,
  // so this is usually length 1 (or 0 when no gateway is bound yet), but the shape does not foreclose HA.
  gateways: GatewayView[];
  subnets: SubnetView[];
}

// ── mutation-surface decisions (Slice 3, all PURE) ───────────────────────────────────

// crossesMultiSiteThreshold — the CW confirm's ACTION-ORDERING gate. The cross-site upgrade warning fires
// at the ONE crossing: approving a subnet that takes the org from single-site-routable (≤1 site with an
// approved subnet, so NO routes compile) to multi-site-routable (≥2, so hub-and-spoke routes compile and
// the artifact bumps to v5). That happens iff THIS site has no approved subnet yet AND exactly ONE OTHER
// site already does (1 → 2). A first site's first approval (0 others) does not cross; a 3rd-site approval
// when already multi-site (≥2 others) does not newly cross (v5 already active). PURE.
export function crossesMultiSiteThreshold(
  approvingSiteId: string,
  approvedCountBySite: Record<string, number>,
): boolean {
  if ((approvedCountBySite[approvingSiteId] ?? 0) > 0) return false; // site already contributes routes
  const otherSitesWithApproved = Object.entries(approvedCountBySite).filter(
    ([id, c]) => id !== approvingSiteId && c > 0,
  ).length;
  return otherSitesWithApproved === 1; // was single-site-routable, becomes multi-site — the crossing
}

// subCeilingGateways — the gateways the CW confirm NAMES: those whose reported max policy version is below
// the server ceiling. Absence (null — a pre-CW/pre-upgrade agent that never reported) counts as BELOW (the
// S7.5.3 absence-is-not-compliance rule; those are the very gateways the warning exists for). PURE.
export function subCeilingGateways(
  gateways: { id: string; name: string; maxPolicyVersion: number | null }[],
  ceiling: number,
): { id: string; name: string }[] {
  return gateways
    .filter((g) => (g.maxPolicyVersion ?? 0) < ceiling)
    .map((g) => ({ id: g.id, name: g.name }));
}

// nameMatchesExactly — the delete-site name-typed ceremony (D4, the S4.5 one-time grain): the typed value
// must EQUAL the site's name exactly. The Delete button stays dead until this is true.
export function nameMatchesExactly(typed: string, siteName: string): boolean {
  return typed === siteName;
}

// disjointRefusal — the D3 VERBATIM refusal: on a `subnet_not_disjoint` 409, return the API's own message
// (it names the overlap_class + colliding range). Returns null for any other error so the caller shows its
// generic message. NO client-side disjointness re-computation (the comparison-set law's UI corollary — one
// validator, never a second copy in JS). PURE.
export function disjointRefusal(err: unknown): string | null {
  const e = err as { error?: { code?: string; message?: string } } | undefined;
  if (e?.error?.code === "subnet_not_disjoint")
    return (
      e.error.message ??
      "This subnet overlaps an existing range; approval refused."
    );
  return null;
}

// ── subnet-removal DNS preview (S8.4 F4, all PURE) ───────────────────────────────────────────────────
// ipv4ToInt parses a dotted-quad to a uint32, or null if it is not a valid IPv4 literal.
export function ipv4ToInt(ip: string): number | null {
  const parts = ip.trim().split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const b = Number(p);
    if (b > 255) return null;
    n = n * 256 + b;
  }
  return n >>> 0;
}

// forwardsInSubnet NAMES the DNS forwards whose resolver lives inside cidr — the ADVISORY preview for the
// subnet-removal confirm ("removing this also removes N forwards"). NOT an enforcement check: the server
// sweeps authoritatively in the same tx (RemoveSubnet); this only tells the admin what that sweep will do.
// Anything it can't parse as IPv4 is excluded (the server stays the truth). Site subnets are IPv4-only.
export function forwardsInSubnet(
  forwards: { domain: string; resolver_ip: string }[],
  cidr: string,
): string[] {
  const [base, bitsStr] = cidr.split("/");
  const bits = Number(bitsStr);
  const baseInt = ipv4ToInt(base ?? "");
  if (baseInt === null || !Number.isInteger(bits) || bits < 0 || bits > 32)
    return [];
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  const net = (baseInt & mask) >>> 0;
  return forwards
    .filter((f) => {
      const ipInt = ipv4ToInt(f.resolver_ip);
      return ipInt !== null && (ipInt & mask) >>> 0 === net;
    })
    .map((f) => f.domain);
}

// assembleTopology joins sites + their subnets + the nodes list into render-ready cards. PURE. A site's
// gateways = the nodes whose site_id is this site (the D2/CH join). Everything a card shows is a wire
// field; the only computation is the join + the health-badge projection (itself pure).
export function assembleTopology(
  sites: Site[],
  subnetsBySite: Record<string, SiteSubnet[]>,
  nodes: Node[],
): SiteCard[] {
  return sites.map((s) => ({
    id: s.id,
    name: s.name,
    gateways: nodes
      .filter((n) => n.site_id === s.id)
      .map((n) => ({
        id: n.id,
        name: n.name,
        status: n.status,
        isHub: n.is_site_hub === true,
        // WF-S11-10c: no health badge on a REVOKED gateway. `revoked` IS its state, and a degradation badge
        // beside it describes a gateway that is no longer meant to work — on the walk this rendered
        // "aws-gw-1 revoked ... certificate expired — re-enroll this gateway", two labels contradicting each
        // other with the instructional one urging an operator to undo a deliberate revocation. Suppressed here,
        // in the view-model, rather than in the component: the same fix in Gateways.tsx was component-local and
        // that is precisely why this second surface still had the defect.
        // S14.21: the revoked guard moved INTO policyHealthBadge. Restating it here was the copy-paste
        // that made the rule a caller responsibility in the first place.
        health: policyHealthBadge(n),
        siteLinkNote: siteLinkNote(n), // WF-B: independent of `health` — the demoted-dead-peer subordinate line
        maxPolicyVersion: n.max_policy_version ?? null,
        agentVersion: n.agent_version,
        lastSeenAt: n.last_seen_at ?? null,
      })),
    subnets: (subnetsBySite[s.id] ?? []).map((ss) => ({
      id: ss.id,
      cidr: ss.cidr,
      status: ss.status,
    })),
  }));
}

// ── the mesh (S14.5) ─────────────────────────────────────────────────────────────────
//
// ⛔ ONE NODE PER SITE, NOT PER REGION — the four-way test's case 2.
//
// The wireframe's mesh draws five REGIONS, each carrying a site count that drives its radius and its edge
// width. We serve no region field on `Node` or `Site`, so the drawing's encoding has no data behind it.
// Deriving a region client-side from gateway names would be a guess wearing a diagram's authority.
//
// So: one node per site, uniform size, no count glyph. The hub is READ from `is_site_hub` (the backend
// election, never recomputed here) and is rendered as its own node when a hub gateway exists.

export interface Mesh {
  nodes: VizNode[];
  links: VizLink[];
}

/**
 * Build the topology diagram from the same wire facts the cards render.
 *
 * ⛔ TONE COMES FROM THE HEALTH KIND, NOT FROM A GUESS. `site_hub_down` / `site_link_down` are DOWN;
 * anything else degraded is DEGRADED; no badge is LINKED. A site with no gateway bound has no link at all —
 * which is different from a link that is down, and is drawn as an absent edge rather than a red one.
 */
export function meshFrom(
  cards: SiteCard[],
  nodes: Node[],
  hubGeneration?: number,
  /**
   * ⛔ DID THE CALLER ACTUALLY LOAD SUBNETS? Overview renders this same mesh but does NOT fetch per-site
   * subnets, and with them absent the sub-line would read "no approved subnet" for every site — asserting a
   * fact nobody measured, on a screen whose whole job is to be trusted at a glance.
   *
   * Absent-because-unloaded and absent-because-none are different, so the caller says which it has.
   */
  subnetsKnown = true,
): Mesh {
  const hubNode = nodes.find((n) => n.is_site_hub && n.status === "active");
  const out: Mesh = { nodes: [], links: [] };
  if (hubNode) {
    out.nodes.push({
      id: "__hub",
      label: hubNode.name,
      kind: "hub",
      // The handoff's hub sub-line is `HA set gen 7 · pri +1` — the SET's identity, not the node's role.
      // We serve that generation, so it goes here rather than the constant "transit hub" I had invented.
      sub:
        hubGeneration != null ? `HA set gen ${hubGeneration}` : "· transit hub",
    });
  }
  for (const c of cards) {
    const approved = c.subnets.filter((s) => s.status === "approved");
    const sub = !subnetsKnown
      ? undefined
      : approved.length
        ? "· " + approved.map((s) => s.cidr).join(", ")
        : "· no approved subnet";
    // `value` = the site's bound gateway count. The wireframe puts a SITE COUNT inside the ring because its
    // nodes are regions; ours are sites, so the honest analogue is how many gateways front this one. Zero is
    // a real fact here (a site with no gateway bound), unlike an absent count.
    const gwCount = c.gateways.filter((g) => g.status === "active").length;

    // No gateway bound → no site link exists yet. An absent edge, never a red one: "not connected" and
    // "connection failed" are different facts and only one of them is a fault.
    const gw = c.gateways.find((g) => g.status === "active");
    const kind = gw?.health?.label ?? null;
    const down = kind != null && /hub down|link down/i.test(kind);

    // ⛔ WHETHER A LINK EXISTS AT ALL IS DECIDED *BEFORE* ITS STATE — and getting that order wrong is how the
    // law this file already states got broken one line later.
    //
    // The first version drew no EDGE when there was no link (correct) and then still stamped the NODE with
    // the failure tone from the gateway's health badge. So a lone gateway that is its own hub rendered with
    // NO line and a `down` pill: the map silently repeated the same claim — that a link failed — that the
    // health badge beside it was already making wrongly.
    //
    // ABSENCE OF A RELATIONSHIP IS ABSENCE, IN EVERY ENCODING THAT DESCRIBES IT. An edge, a colour, a pill,
    // a dot: if the thing was never attempted, none of them may say it failed.
    // A directly-attached one-site gateway still has a real local-VPC attachment. It is
    // not a site-to-site WireGuard handshake, so it gets a neutral connected marker and
    // never inherits a site-link health/down verdict.
    const localAttachment = hubNode != null && gw != null && gw.id === hubNode.id;
    const linked = hubNode != null && gw != null && (gw.id !== hubNode.id || localAttachment);
    const tone: VizLink["tone"] | undefined = !linked
      ? undefined // no link exists → no link STATE exists either
      : localAttachment
        ? "linked"
        : down
        ? "down"
        : kind
          ? "degraded"
          : "linked";

    out.nodes.push({
      id: c.id,
      label: c.name,
      kind: "spoke",
      sub,
      value: gwCount,
      tone: localAttachment ? undefined : tone,
      // The honest word for the no-link case, so the row still says something true rather than nothing.
      note: localAttachment
        ? "local VPC attachment"
        : linked
          ? undefined
          : gw
            ? "no site link"
            : "no gateway bound",
    });

    // `linked` is exactly the condition under which `tone` was assigned, so this narrowing is the same fact
    // stated for the compiler rather than a second decision.
    if (!linked || !tone) continue;
    out.links.push({
      from: "__hub",
      to: c.id,
      tone,
      note: localAttachment ? "local VPC attachment" : kind ?? undefined,
    });
  }
  return out;
}
