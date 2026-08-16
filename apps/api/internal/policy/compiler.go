// Package policy is the enterprise Zero Trust policy engine (S7.1): the CRUD
// service plus the pure Compile function that turns the stored model (groups,
// resources, allow-rules, org mode) into the per-node compiled artifact
// (policyspec.Compiled) the control plane pushes to agents.
//
// Compile is a PURE function of a Snapshot (a plain-data view of DB state) — no
// database, no clock, no I/O — so the security-critical policy decision is
// exhaustively unit-testable and DETERMINISTIC (equal input => byte-identical
// output, keeping reconcile a steady-state no-op). The service layer builds the
// Snapshot from sqlc rows; the model is enterprise-gated at the API, so this code
// only runs in the enterprise build (open build never imports it).
package policy

import (
	"net/netip"
	"sort"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
)

// containingSite returns the site whose approved subnet CONTAINS the given source CIDR (S8.7 src_kind='cidr'
// placement) — the site gateway that forwards that host's LAN traffic. Site subnets are disjoint (the S8.1
// validator), so at most one contains it; uuid.Nil when none does (an out-of-world / device-pool / routed-
// range CIDR → no site placement → the grant compiles to nothing, the warn-not-refuse case). Pure.
func containingSite(cidr string, siteCIDRs map[uuid.UUID][]string) uuid.UUID {
	c, err := netip.ParsePrefix(cidr)
	if err != nil {
		return uuid.Nil
	}
	for siteID, cidrs := range siteCIDRs {
		for _, sc := range cidrs {
			s, err := netip.ParsePrefix(sc)
			if err != nil {
				continue
			}
			if s.Bits() <= c.Bits() && s.Contains(c.Masked().Addr()) { // the src CIDR is within this site subnet
				return siteID
			}
		}
	}
	return uuid.Nil
}

// cidrPlacementSite is THE placement predicate for a src_kind='cidr' rule (S8.7 [0]+[9] reduce): the site the
// grant PLACES on — its containing approved site subnet that ALSO has a bound gateway — with ok=false when it
// places NOWHERE (out-of-world, OR a containing site with no gateway node). ONE FUNCTION, used by BOTH the
// compiler (bails where ok=false) AND the read-time warning (fires where ok=false) — so warn ⟺ won't-place by
// construction, in BOTH directions: [0] (a warned rule must never still emit ACCEPT on the dst/hub) and [9]
// (a clean rule must never silently compile to nothing). Pure.
func cidrPlacementSite(cidr string, siteCIDRs map[uuid.UUID][]string, siteNode map[uuid.UUID]uuid.UUID) (uuid.UUID, bool) {
	s := containingSite(cidr, siteCIDRs)
	if s == uuid.Nil || siteNode[s] == uuid.Nil {
		return uuid.Nil, false
	}
	return s, true
}

// Modes (mirror the organizations.zero_trust_mode CHECK).
const (
	ModeOff       = "off"
	ModeEnforcing = "enforcing"
)

// Rule is an allow grant: the SOURCE subject may reach the destination. SrcKind
// selects the subject ("group" => members of SrcGroupID; "user" => the single
// SrcUserID, S7.5.4). DstKind selects which Dst*ID is meaningful ("resource" =>
// static cidr:ports; "group" => that group's members' device /32s). A per-user
// rule resolves to that user's device /32s CP-side, IDENTICALLY to a group — the
// artifact stays IP-only, no wire-version bump. Expired temporary rules are
// filtered OUT of the Snapshot before Compile (the pure compiler is clockless).
type Rule struct {
	ID              uuid.UUID // the CP policy_rules.uuid — stamped onto each produced AllowEntry as rule_id (S7.5.1)
	SrcKind         string    // "group" | "user" | "site" (S8.2) | "cidr" (S8.7) ("" treated as group for legacy rows)
	SrcGroupID      uuid.UUID
	SrcUserID       uuid.UUID
	SrcSiteID       uuid.UUID // S8.2: src_kind='site' — resolved to the SOURCE site's subnet CIDRs
	SrcCIDR         string    // S8.7: src_kind='cidr' — a LITERAL source CIDR, placed on its containing site's gateway
	SrcDeviceID     uuid.UUID // S15.3: src_kind='agent' — the agent DEVICE whose /32 is the source
	DstKind         string
	DstResourceID   uuid.UUID
	DstGroupID      uuid.UUID
	DstSiteID       uuid.UUID // S8.1: dst_kind='site' — resolved to the site's subnet CIDRs
	DstK8sServiceID uuid.UUID // S10.3: dst_kind='k8s_service' — resolved to the Service's CURRENT VIP/32
	Disabled        bool      // F3: a disabled rule compiles to ZERO AllowEntries (the skip below) — its allow is
	//                        withdrawn, so under default-deny it's "as if the rule weren't there". Not a deny.
}

// SiteSubnet is one routed LAN of a site (S8.1). The compiler expands a dst_kind='site' rule to one
// AllowEntry per the target site's subnets — a site with zero subnets compiles to nothing (no grant,
// not an error), a site with N subnets to N grants (the ruled resolution edges).
type SiteSubnet struct {
	SiteID uuid.UUID
	CIDR   string
}

// SiteNode binds a site to its gateway node (nodes.site_id, single-node v1). The compiler needs it to
// place a site-SOURCE grant (S8.2): a site→dst grant lands on the gateway node(s) bound to the involved
// sites — the transit endpoints whose forward chain the LAN traffic crosses. A site gateway ALSO gets a
// compiled artifact even with no local devices (so its forward chain is programmed for site traffic).
type SiteNode struct {
	SiteID   uuid.UUID
	NodeID   uuid.UUID
	Endpoint string // public WG endpoint; a non-empty endpoint makes this gateway hub-eligible (B1/Item 7)
}

// Resource is a static destination (a CIDR + optional L4 scope).
type Resource struct {
	ID       uuid.UUID
	CIDR     string
	Protocol string // any | tcp | udp
	PortLow  int    // 0 => unset
	PortHigh int    // 0 => unset
}

// ExposedService (S10.3) is a Kubernetes Service exposed to the fabric: a STABLE identity resolved to its
// CURRENT VIP at compile time. ConnectorNodeID is the one in-cluster gateway
// that performs VIP->pod DNAT, so the grant is placed there too; a same-site
// VM gateway must not be mistaken for the Kubernetes connector.
type ExposedService struct {
	ID              uuid.UUID
	VIP             string // the /32 host (without mask)
	DNSVIP          string // the cluster's reserved DNS resolver host (without mask)
	Protocol        string
	PortLow         int
	PortHigh        int
	SiteID          uuid.UUID // logical site, retained for site-source compatibility
	ConnectorNodeID uuid.UUID // zero means deliberately unassigned; no connector handoff is inferred
}

// Membership is one (group, user) pair.
type Membership struct {
	GroupID uuid.UUID
	UserID  uuid.UUID
}

// Device is an active peer: its owner, its gateway, and its assigned host address
// (no prefix). Only active devices owned by active users appear (the service query
// filters); a revoked device is simply absent, so its /32 leaves the output as both
// a source and a destination (the A1/A2 requirement — no inherited grants on IP reuse).
type Device struct {
	ID         uuid.UUID // devices.id — stamped onto each AllowEntry as src_device_id (v3, S7.5.4)
	UserID     uuid.UUID
	NodeID     uuid.UUID
	AssignedIP string
	// Kind (S15.3) — 'human' | 'agent'. Used ONLY to match a src_kind='agent' rule to the agent's own
	// device. ⚠ It never enters the enforcement projection: the artifact still emits SrcIP/DstCIDR/
	// Protocol/PortLow/PortHigh, and `hashAllow` is unchanged.
	Kind string
	// ConfigRevision is the managed agent revision captured in the same DB
	// snapshot as the device/address. It is observability metadata only; nil for
	// human devices or an agent with no runtime state.
	ConfigRevision *int64
}

// subjectAttribution projects the complete active address-bearing subject set
// into hash-excluded artifact metadata. It is deliberately independent of
// grants so a zero-grant default deny remains attributable.
func subjectAttribution(devices []Device) []policyspec.SubjectAttribution {
	out := make([]policyspec.SubjectAttribution, 0, len(devices))
	for _, d := range devices {
		if d.AssignedIP == "" || d.ID == uuid.Nil {
			continue
		}
		out = append(out, policyspec.SubjectAttribution{
			SrcIP: d.AssignedIP, DeviceID: d.ID.String(), Kind: d.Kind,
			ConfigRevision: d.ConfigRevision,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SrcIP < out[j].SrcIP })
	return out
}

// Snapshot is the full org policy state the compiler consumes.
type Snapshot struct {
	Mode            string
	Rules           []Rule
	Resources       []Resource
	ExposedServices []ExposedService // S10.3: dst_kind='k8s_service' resolution (id → current VIP)
	Memberships     []Membership
	Devices         []Device
	SiteSubnets     []SiteSubnet // S8.1: (site_id, cidr) rows for dst_kind='site' resolution
	SiteNodes       []SiteNode   // S8.2: (site_id, node_id) bindings for src_kind='site' node placement
	// ActiveHub is the DERIVED active transit hub (S8.6 REDUCE #1), THREADED IN by the caller from the ONE
	// shared derivation (nodes.deriveActive) — the SAME per-compile value that feeds the data-plane graph.
	// The compiler does NOT elect: the site→site transit grant lands on THIS node. uuid.Nil = no hub (no
	// site→site transit to place — a non-site compile, or no capable gateway).
	ActiveHub uuid.UUID
}

// Compile produces the compiled artifact for every node that has at least one
// active device in the snapshot.
//
//   - Mode "off": each node gets a blanket-mesh artifact (Mesh=true, no allows) —
//     the legacy pre-Zero-Trust behavior, so enabling the feature is opt-in.
//   - Mode "enforcing" (and, fail-closed, ANY non-"off" value): each node gets a
//     default-deny artifact (Mesh=false) whose Allow set is EXACTLY the grants that
//     resolve for the devices on that node — the empty set if none (deny-all).
//
// The enforcing path can never set Mesh=true, so it is structurally incapable of
// reproducing the wg0<->wg0 blanket accept it replaces.
func Compile(s Snapshot) map[uuid.UUID]policyspec.Compiled {
	mesh := s.Mode == ModeOff
	subjects := subjectAttribution(s.Devices)

	// Nodes in play = nodes that have at least one active device, every site-bound gateway node, and every
	// selected Kubernetes connector. A connector gets an artifact even with no local devices: it owns the
	// service VIP's last hop and must enforce the same grant as the client-facing edge.
	nodeSet := map[uuid.UUID]bool{}
	for _, d := range s.Devices {
		if d.AssignedIP == "" {
			continue
		}
		nodeSet[d.NodeID] = true
	}
	siteNode := map[uuid.UUID]uuid.UUID{} // site_id -> its bound gateway node (S8.2 src placement)
	for _, sn := range s.SiteNodes {
		if sn.NodeID == uuid.Nil {
			continue
		}
		siteNode[sn.SiteID] = sn.NodeID
		nodeSet[sn.NodeID] = true
	}
	for _, svc := range s.ExposedServices {
		if svc.ConnectorNodeID != uuid.Nil {
			nodeSet[svc.ConnectorNodeID] = true
		}
	}
	// The transit HUB is the DERIVED active hub, THREADED IN by the caller (S8.6 REDUCE #1) — the compiler is
	// structurally incapable of electing (the election + its "MUST match siteLinkGraphFrom" apology are gone;
	// the ONE derivation lives in nodes.deriveActive, fed to this compile AND the data-plane graph from the
	// SAME per-compile value, so the grant and the routing can never cite different hubs under HA). A
	// site→site grant lands on the hub too (it forwards spoke↔spoke traffic), so its default-deny forward
	// chain accepts the transited pair — without this the hub silently drops site-to-site between two spokes.
	hubNode := s.ActiveHub
	// A3b F1 (construction-over-convention, 3rd instance): SEED the hub into nodeSet HERE — the ActiveHub
	// is threaded from the one shared derivation, trusted at exactly SiteNodes' level. With devices,
	// SiteNodes, and the hub all seeded up front, EVERY placement target (devGrantNodes) is in nodeSet by
	// construction — so add() needs no lazy-admit branch, and a cross-org node reaching the output is
	// structurally impossible rather than checked-against. (A guard validating a lazy admit would be code
	// defending a state the construction should forbid.) The nodeSet-seed census red pins that these three
	// seeds are explicit and all happen before the accumulator is built.
	if hubNode != uuid.Nil {
		nodeSet[hubNode] = true
	}

	out := make(map[uuid.UUID]policyspec.Compiled, len(nodeSet))

	if mesh {
		for nodeID := range nodeSet {
			c := policyspec.Compiled{NodeID: nodeID.String(), Mode: ModeOff, Mesh: true, Allow: nil, Subjects: subjects}
			c.Version = policyspec.RequiredVersion(c) // content-derived (S8.2 D1b); mesh has no v5 feature
			out[nodeID] = c
		}
		return out
	}

	// ── enforcing: resolve grants ────────────────────────────────────────────────
	// user -> set of groups
	userGroups := map[uuid.UUID]map[uuid.UUID]bool{}
	for _, m := range s.Memberships {
		g := userGroups[m.UserID]
		if g == nil {
			g = map[uuid.UUID]bool{}
			userGroups[m.UserID] = g
		}
		g[m.GroupID] = true
	}

	resourceByID := make(map[uuid.UUID]Resource, len(s.Resources))
	for _, r := range s.Resources {
		resourceByID[r.ID] = r
	}
	// S10.3: exposed Services keyed by their STABLE id — a grant resolves to the CURRENT VIP here, never a
	// snapshotted address, so a re-allocated VIP follows the identity and a vanished Service resolves to nothing.
	serviceByID := make(map[uuid.UUID]ExposedService, len(s.ExposedServices))
	for _, es := range s.ExposedServices {
		serviceByID[es.ID] = es
	}

	// site -> sorted, de-duplicated subnet CIDRs (destination resolution for dst_kind='site', S8.1).
	// A site with zero subnets is simply absent here → its rules compile to nothing (the ruled edge).
	siteCIDRs := map[uuid.UUID][]string{}
	{
		seen := map[uuid.UUID]map[string]bool{}
		for _, ss := range s.SiteSubnets {
			if ss.CIDR == "" {
				continue
			}
			m := seen[ss.SiteID]
			if m == nil {
				m = map[string]bool{}
				seen[ss.SiteID] = m
			}
			if !m[ss.CIDR] {
				m[ss.CIDR] = true
				siteCIDRs[ss.SiteID] = append(siteCIDRs[ss.SiteID], ss.CIDR)
			}
		}
		for id := range siteCIDRs {
			sort.Strings(siteCIDRs[id])
		}
	}

	// group -> sorted, de-duplicated member device /32 hosts (destination resolution
	// for dst_kind=group). A device belongs to a group iff its OWNER is in the group.
	groupDeviceIPs := map[uuid.UUID][]string{}
	{
		seen := map[uuid.UUID]map[string]bool{}
		for _, d := range s.Devices {
			if d.AssignedIP == "" {
				continue
			}
			for g := range userGroups[d.UserID] {
				gs := seen[g]
				if gs == nil {
					gs = map[string]bool{}
					seen[g] = gs
				}
				if !gs[d.AssignedIP] {
					gs[d.AssignedIP] = true
					groupDeviceIPs[g] = append(groupDeviceIPs[g], d.AssignedIP)
				}
			}
		}
		for g := range groupDeviceIPs {
			sort.Strings(groupDeviceIPs[g])
		}
	}

	// Accumulate allows per node, de-duplicated on the ENFORCEMENT tuple ONLY (NOT
	// rule_id — that is observability, S7.5.1). If two rules produce the same grant,
	// the FIRST (in rule order) wins the rule_id stamp; the enforcement is identical
	// either way, so the hash is unaffected. Keying dedup on the full AllowEntry would
	// wrongly emit a duplicate nft rule when two rules grant the same tuple.
	type allowKey struct {
		SrcIP, DstCIDR    string
		Protocol          policyspec.Protocol
		PortLow, PortHigh int
	}
	type nodeAcc struct {
		set  map[allowKey]bool
		list []policyspec.AllowEntry
	}
	acc := map[uuid.UUID]*nodeAcc{}
	for nodeID := range nodeSet {
		acc[nodeID] = &nodeAcc{set: map[allowKey]bool{}}
	}
	add := func(nodeID uuid.UUID, e policyspec.AllowEntry) {
		// Every caller's target is in nodeSet by construction (devices + SiteNodes + the seeded hub) —
		// see the F1 seed above; no lazy admit exists, so an unknown node here would be a programming
		// error the acc lookup surfaces immediately, never a silent artifact for an unvetted node.
		a := acc[nodeID]
		k := allowKey{e.SrcIP, e.DstCIDR, e.Protocol, e.PortLow, e.PortHigh}
		if a.set[k] {
			return // first rule to grant this tuple keeps the rule_id stamp
		}
		a.set[k] = true
		a.list = append(a.list, e)
	}

	// A3b (S8.6) far-grant placement: site subnets parsed ONCE so a device→dst grant whose destination
	// lives in a SITE lands on every chain the transited packet crosses — the device's own node (entry),
	// the transit HUB, and the DESTINATION site's gateway. BOTH-ENFORCE (D-A3b-2, founder-ruled):
	// defense-in-depth at zero marginal cost (all chains compile from the same grant); forward-blind far
	// gateways would hang their security off every hub's integrity — wrong trust direction for
	// customer-operated hubs. The far counter is the attribution point; the hub counter stays the transit
	// witness. Placement mirrors the S8.2 B1 precedent (unconditional hub add, map-deduped).
	type sitePfx struct {
		site uuid.UUID
		pfx  netip.Prefix
	}
	var sitePfxs []sitePfx
	for _, ss := range s.SiteSubnets {
		if p, err := netip.ParsePrefix(ss.CIDR); err == nil {
			sitePfxs = append(sitePfxs, sitePfx{ss.SiteID, p})
		}
	}
	// siteOwning resolves a destination CIDR to the site whose approved subnet contains it (uuid.Nil =
	// no site owns it — a non-site resource, no far placement). Conservative containment: the dst's
	// network address inside the subnet AND at least as specific.
	siteOwning := func(cidr string) uuid.UUID {
		p, err := netip.ParsePrefix(cidr)
		if err != nil {
			a, aerr := netip.ParseAddr(cidr)
			if aerr != nil {
				return uuid.Nil
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		for _, sp := range sitePfxs {
			if sp.pfx.Contains(p.Addr()) && p.Bits() >= sp.pfx.Bits() {
				return sp.site
			}
		}
		return uuid.Nil
	}
	// devGrantNodes returns the enforcement nodes for a device→dst grant: always the device's node;
	// plus, when the dst resolves to a bound site, that site's gateway and the hub (both-enforce).
	// add() dedups per-node tuples, so overlapping targets (device on the hub, dst on the hub's own
	// site) never double-emit.
	devGrantNodes := func(deviceNode uuid.UUID, dstSite uuid.UUID) []uuid.UUID {
		nodes := []uuid.UUID{deviceNode}
		if dstSite != uuid.Nil {
			if n := siteNode[dstSite]; n != uuid.Nil {
				nodes = append(nodes, n)
			}
			if hubNode != uuid.Nil {
				nodes = append(nodes, hubNode)
			}
		}
		return nodes
	}

	for _, d := range s.Devices { // d is the SOURCE device
		if d.AssignedIP == "" {
			continue
		}
		owner := userGroups[d.UserID]
		for _, r := range s.Rules {
			if r.Disabled { // F3: withdrawn allow — contributes no grant (as-if-absent under default-deny)
				continue
			}
			// Source-subject match (S7.5.4): a "user" rule matches iff this device's
			// owner IS that user; a "group" rule matches iff the owner is in the group
			// (the pre-S7.5.4 path, and the default for legacy blank src_kind).
			var matched bool
			if r.SrcKind == "agent" {
				// ⛔ EXACTLY ONE DEVICE. An agent IS a peer, so the grant names it directly — naming its
				// gateway would grant every device homed there, a grant to one agent silently becoming a
				// grant to everything behind it.
				matched = r.SrcDeviceID == d.ID
			} else if r.SrcKind == "user" {
				matched = r.SrcUserID == d.UserID
			} else {
				matched = owner[r.SrcGroupID]
			}
			if !matched {
				continue
			}
			switch r.DstKind {
			case "resource":
				res, ok := resourceByID[r.DstResourceID]
				if !ok || res.CIDR == "" {
					continue
				}
				// A3b: a resource inside a site's approved subnet is site-fronted — the grant also lands
				// on that site's gateway + the hub (both-enforce). A non-site resource keeps the
				// device-node-only placement.
				for _, node := range devGrantNodes(d.NodeID, siteOwning(res.CIDR)) {
					add(node, policyspec.AllowEntry{
						SrcIP:       d.AssignedIP,
						DstCIDR:     res.CIDR,
						Protocol:    normProto(res.Protocol),
						PortLow:     res.PortLow,
						PortHigh:    res.PortHigh,
						RuleID:      r.ID.String(),
						SrcDeviceID: d.ID.String(),
					})
				}
			case "group":
				for _, dstIP := range groupDeviceIPs[r.DstGroupID] {
					if dstIP == d.AssignedIP {
						continue // a device reaching itself is meaningless
					}
					add(d.NodeID, policyspec.AllowEntry{
						SrcIP:       d.AssignedIP,
						DstCIDR:     dstIP + "/32",
						Protocol:    policyspec.ProtoAny, // device-to-device is L3
						RuleID:      r.ID.String(),
						SrcDeviceID: d.ID.String(),
					})
				}
			case "site":
				// S8.1 Option A: expand to ONE same-shape AllowEntry per the target site's subnet
				// (a plain Dst-CIDR grant — the site KIND stays CP-side, never on the wire). A
				// subnetless site yields nothing; a multi-subnet site yields one grant per subnet.
				// A3b: the grant also lands on the destination site's gateway + the hub (both-enforce)
				// — the far chain is what admits the transited device packet under enforcing.
				for _, cidr := range siteCIDRs[r.DstSiteID] {
					for _, node := range devGrantNodes(d.NodeID, r.DstSiteID) {
						add(node, policyspec.AllowEntry{
							SrcIP:       d.AssignedIP,
							DstCIDR:     cidr,
							Protocol:    policyspec.ProtoAny, // a site subnet is an L3 LAN
							RuleID:      r.ID.String(),
							SrcDeviceID: d.ID.String(),
						})
					}
				}
			case "k8s_service":
				// S10.3: resolve the Service's STABLE id -> its CURRENT VIP (never a snapshotted address).
				// An absent/deleted Service compiles to NOTHING — the honest "rule points at a vanished
				// Service" surface is the API/web slice. The device edge and explicit connector both enforce;
				// an unassigned cluster intentionally has no connector destination.
				svc, ok := serviceByID[r.DstK8sServiceID]
				if !ok || svc.VIP == "" {
					continue
				}
				nodes := map[uuid.UUID]bool{d.NodeID: true}
				if svc.ConnectorNodeID != uuid.Nil {
					nodes[svc.ConnectorNodeID] = true
				}
				for node := range nodes {
					add(node, policyspec.AllowEntry{
						SrcIP:       d.AssignedIP,
						DstCIDR:     svc.VIP + "/32",
						Protocol:    normProto(svc.Protocol),
						PortLow:     svc.PortLow,
						PortHigh:    svc.PortHigh,
						RuleID:      r.ID.String(),
						SrcDeviceID: d.ID.String(),
					})
					// The service name is resolved before the Service VIP is reached. A
					// service grant therefore also admits just this cluster's private DNS
					// VIP on the two DNS transports. The DNS listener is authoritative
					// only for the cluster zone; this does not grant VPC DNS or any
					// service VIP other than the rule's destination above.
					if svc.DNSVIP != "" {
						for _, proto := range []policyspec.Protocol{policyspec.ProtoUDP, policyspec.ProtoTCP} {
							add(node, policyspec.AllowEntry{
								SrcIP:       d.AssignedIP,
								DstCIDR:     svc.DNSVIP + "/32",
								Protocol:    proto,
								PortLow:     53,
								PortHigh:    53,
								RuleID:      r.ID.String(),
								SrcDeviceID: d.ID.String(),
							})
						}
					}
				}
			}
		}
	}

	// ── site-SOURCE grants (S8.2): a site's LAN as the SOURCE subject. No device is involved — the
	// source is the site's subnet CIDRs, and the grant lands on the gateway node(s) bound to the involved
	// sites (the source site + a site destination), the transit endpoints whose forward chain the LAN
	// traffic crosses. A subnetless source site grants nothing (symmetric to the dst edge); an unbound
	// site (no gateway) has no node to program, so it grants nothing until bound. Hub/relay transit-node
	// placement is Slice 2 (the topology graph) — Slice 1 places the endpoints, correct for the
	// co-located/direct case and provable now.
	for _, r := range s.Rules {
		if r.Disabled { // F3: withdrawn allow — no site-src/cidr placement either (as-if-absent)
			continue
		}
		// S8.7: src_kind='cidr' is site-src NARROWED to a literal CIDR — resolve the CIDR to its CONTAINING
		// site subnet and place on that site's gateway (ONE emitter, mirroring the site-src path below). A
		// CIDR in no site subnet (out-of-world, or a device-pool/routed-range address) resolves to no site →
		// no placement → compiles to nothing (the warn-not-refuse case: the rule exists + warns, enforces
		// nothing until it is in-world). Routed-range/device-pool PLACEMENT is a noted S8.7 boundary (like
		// S8.2 Slice-1 placed only the site endpoints); site-subnet-contained CIDRs are the ruled scope.
		var srcCIDRs []string
		var srcSite uuid.UUID
		switch r.SrcKind {
		case "site":
			srcSite = r.SrcSiteID
			srcCIDRs = siteCIDRs[r.SrcSiteID]
		case "cidr":
			if r.SrcCIDR == "" {
				continue
			}
			// S8.7 [0]+[9] — the ONE placement predicate (same fn the warning uses): a cidr places iff its
			// containing approved site subnet ALSO has a bound gateway. !ok → the rule places NOTHING (never
			// the [0] dst-site ACCEPT bypass a warned rule must not emit, never the [9] node-less silent no-op).
			s, ok := cidrPlacementSite(r.SrcCIDR, siteCIDRs, siteNode)
			if !ok {
				continue
			}
			srcSite = s
			srcCIDRs = []string{r.SrcCIDR}
		default:
			continue
		}
		if len(srcCIDRs) == 0 {
			continue // subnetless source site
		}
		// The SOURCE must resolve to a bound gateway to ORIGINATE — else the rule places NOTHING (the [0] fix
		// generalized: a source that can't originate must not add the dst/hub ACCEPT). cidr already ensured
		// this via cidrPlacementSite; site-src is guarded here (symmetric tightening).
		srcGw := siteNode[srcSite]
		if srcGw == uuid.Nil {
			continue
		}
		enforceNodes := map[uuid.UUID]bool{srcGw: true}
		if r.DstKind == "site" {
			if n := siteNode[r.DstSiteID]; n != uuid.Nil {
				enforceNodes[n] = true
			}
			// B1: the transit HUB forwards spoke↔spoke traffic, so it needs the grant too. The map dedups
			// when the hub IS the src or dst gateway (no duplicate emission). Site→site only — a
			// site→resource/group source egresses via its own gateway, never the hub.
			if hubNode != uuid.Nil {
				enforceNodes[hubNode] = true
			}
		}
		// Destination templates (SrcIP filled per source CIDR below), resolved once.
		var dsts []policyspec.AllowEntry
		switch r.DstKind {
		case "resource":
			if res, ok := resourceByID[r.DstResourceID]; ok && res.CIDR != "" {
				dsts = append(dsts, policyspec.AllowEntry{DstCIDR: res.CIDR, Protocol: normProto(res.Protocol), PortLow: res.PortLow, PortHigh: res.PortHigh})
			}
		case "group":
			for _, dstIP := range groupDeviceIPs[r.DstGroupID] {
				dsts = append(dsts, policyspec.AllowEntry{DstCIDR: dstIP + "/32", Protocol: policyspec.ProtoAny})
			}
		case "site":
			for _, cidr := range siteCIDRs[r.DstSiteID] {
				dsts = append(dsts, policyspec.AllowEntry{DstCIDR: cidr, Protocol: policyspec.ProtoAny})
			}
		case "k8s_service":
			// S10.3: resolve id -> CURRENT VIP; an absent Service yields nothing (compile-to-nothing). The
			// cluster gateway performs the DNAT, so entitle it too (both-enforce) alongside the source nodes.
			if svc, ok := serviceByID[r.DstK8sServiceID]; ok && svc.VIP != "" {
				dsts = append(dsts, policyspec.AllowEntry{DstCIDR: svc.VIP + "/32", Protocol: normProto(svc.Protocol), PortLow: svc.PortLow, PortHigh: svc.PortHigh})
				if svc.ConnectorNodeID != uuid.Nil {
					enforceNodes[svc.ConnectorNodeID] = true
				}
			}
		}
		for node := range enforceNodes {
			for _, sc := range srcCIDRs {
				for _, d := range dsts {
					add(node, policyspec.AllowEntry{
						SrcIP:    sc, // a CIDR — the site LAN source (the v5 content trigger, RequiredVersion)
						DstCIDR:  d.DstCIDR,
						Protocol: d.Protocol,
						PortLow:  d.PortLow,
						PortHigh: d.PortHigh,
						RuleID:   r.ID.String(),
					})
				}
			}
		}
	}

	for nodeID := range nodeSet {
		list := acc[nodeID].list
		sortAllows(list)
		c := policyspec.Compiled{NodeID: nodeID.String(), Mode: ModeEnforcing, Mesh: false, Allow: list, Subjects: subjects}
		c.Version = policyspec.RequiredVersion(c) // content-derived (S8.2 D1b): v5 iff a CIDR source present
		out[nodeID] = c
	}
	return out
}

// normProto maps a stored protocol to the wire enum, defaulting unknown/empty to
// "any" (fail-open on the L4 scope is fine — the L3 grant itself is the gate).
func normProto(p string) policyspec.Protocol {
	switch p {
	case "tcp":
		return policyspec.ProtoTCP
	case "udp":
		return policyspec.ProtoUDP
	default:
		return policyspec.ProtoAny
	}
}

// sortAllows imposes a total order so output is byte-identical for equal input.
func sortAllows(a []policyspec.AllowEntry) {
	sort.Slice(a, func(i, j int) bool {
		if a[i].SrcIP != a[j].SrcIP {
			return a[i].SrcIP < a[j].SrcIP
		}
		if a[i].DstCIDR != a[j].DstCIDR {
			return a[i].DstCIDR < a[j].DstCIDR
		}
		if a[i].Protocol != a[j].Protocol {
			return a[i].Protocol < a[j].Protocol
		}
		if a[i].PortLow != a[j].PortLow {
			return a[i].PortLow < a[j].PortLow
		}
		return a[i].PortHigh < a[j].PortHigh
	})
}
