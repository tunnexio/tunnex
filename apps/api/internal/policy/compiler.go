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
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/fqdn"
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
	SrcAgentGroupID uuid.UUID // F09: src_kind='agent_group' — current active managed-agent members
	DstKind         string    // resource | fqdn_resource | group | site | k8s_service
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

// Resource is a legacy static CIDR destination (with optional L4 scope).
// It MUST NOT carry FQDN data: FQDN resources have a separate identity and
// rule-reference relation so a hostname can never be mistaken for a CIDR.
type Resource struct {
	ID       uuid.UUID
	CIDR     string
	Protocol string // any | tcp | udp
	PortLow  int    // 0 => unset
	PortHigh int    // 0 => unset
}

// FQDNResource is the distinct S21 destination identity. Active is populated
// only from Lane 2's immutable selected Site+Gateway generation; no resolver
// state, last-good answer, or legacy Resource is accepted here.
type FQDNResource struct {
	ID       uuid.UUID
	FQDN     string
	Protocol string
	PortLow  int
	PortHigh int
	Active   *FQDNGeneration
}

type FQDNGeneration struct {
	ResourceID            uuid.UUID
	SelectedSiteID        uuid.UUID
	SelectedGatewayID     uuid.UUID
	ResolverConfigID      uuid.UUID
	ResolverProfileID     uuid.UUID
	ResolverMatchSuffix   string
	ResolverConfigVersion int64
	Answers               []string
	// ResolverAddresses contains zero or one canonical host prefix: the first
	// selected-profile UDP/53 endpoint reachable through an approved routed
	// prefix, preserving profile endpoint order. The compiler derives both DNS
	// transports for that address; it never invents a user-editable resource or
	// child policy rule.
	ResolverAddresses []string
}

// FQDNRuleReference is the owned compiler seam for Lane 1's separate
// fqdn_resource_rule_references relation. Exactly one matching reference is
// required for a fqdn_resource rule; missing or ambiguous rows withdraw it.
type FQDNRuleReference struct {
	PolicyRuleID   uuid.UUID
	FQDNResourceID uuid.UUID
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
	ConnectorNodeID uuid.UUID // zero means deliberately unassigned or an unresolved pool
	// PoolBound distinguishes an explicit pool from a legacy unassigned row.
	// Generation is CP read provenance only, never distributed fencing.
	PoolBound           bool
	ConnectorGeneration int64
}

func (s ExposedService) handoffReady() bool {
	return !s.PoolBound || (s.ConnectorNodeID != uuid.Nil && s.ConnectorGeneration > 0)
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
	Mode               string
	Rules              []Rule
	Resources          []Resource
	FQDNResources      []FQDNResource
	FQDNRuleReferences []FQDNRuleReference
	// FQDNResourcesLicensed is the entitlement decision captured with this
	// snapshot. FQDN data is never compiled unless this and the org's explicit
	// opt-in are both true; absent data therefore fails closed.
	FQDNResourcesLicensed bool
	FQDNResourcesEnabled  bool
	ExposedServices       []ExposedService // S10.3: dst_kind='k8s_service' resolution (id → current VIP)
	Memberships           []Membership
	AgentGroupMemberships []AgentGroupMembership
	Devices               []Device
	SiteSubnets           []SiteSubnet // S8.1: (site_id, cidr) rows for dst_kind='site' resolution
	SiteNodes             []SiteNode   // S8.2: (site_id, node_id) bindings for src_kind='site' node placement
	// ActiveHub is the DERIVED active transit hub (S8.6 REDUCE #1), THREADED IN by the caller from the ONE
	// shared derivation (nodes.deriveActive) — the SAME per-compile value that feeds the data-plane graph.
	// The compiler does NOT elect: the site→site transit grant lands on THIS node. uuid.Nil = no hub (no
	// site→site transit to place — a non-site compile, or no capable gateway).
	ActiveHub uuid.UUID
}

// AgentGroupMembership is the F09 agent-group compiler input. Human
// user_groups remain represented by Membership above; the models do not share
// a table or meaning.
type AgentGroupMembership struct {
	GroupID  uuid.UUID
	DeviceID uuid.UUID
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
	type siteGateway struct{ siteID, gatewayID uuid.UUID }
	// FQDN selected-context validation must not reduce a multi-gateway site to
	// one last-write-wins entry.  The generation names an exact Site/Gateway
	// authority, so retain the exact active membership supplied by SiteNodes.
	siteGateways := map[siteGateway]bool{}
	for _, sn := range s.SiteNodes {
		if sn.SiteID == uuid.Nil || sn.NodeID == uuid.Nil {
			continue
		}
		siteNode[sn.SiteID] = sn.NodeID
		siteGateways[siteGateway{siteID: sn.SiteID, gatewayID: sn.NodeID}] = true
		nodeSet[sn.NodeID] = true
	}
	for _, svc := range s.ExposedServices {
		if svc.handoffReady() && svc.ConnectorNodeID != uuid.Nil {
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
	agentGroups := map[uuid.UUID]map[uuid.UUID]bool{}
	for _, m := range s.AgentGroupMemberships {
		groups := agentGroups[m.DeviceID]
		if groups == nil {
			groups = map[uuid.UUID]bool{}
			agentGroups[m.DeviceID] = groups
		}
		groups[m.GroupID] = true
	}

	resourceByID := make(map[uuid.UUID]Resource, len(s.Resources))
	for _, r := range s.Resources {
		resourceByID[r.ID] = r
	}
	fqdnEnabled := s.FQDNResourcesLicensed && s.FQDNResourcesEnabled
	fqdnResourceByID := make(map[uuid.UUID]FQDNResource, len(s.FQDNResources))
	for _, r := range s.FQDNResources {
		// Duplicate resource identities are ambiguous input, never last-write-wins.
		if _, exists := fqdnResourceByID[r.ID]; exists {
			fqdnResourceByID[r.ID] = FQDNResource{}
			continue
		}
		fqdnResourceByID[r.ID] = r
	}
	fqdnReferenceForRule := map[uuid.UUID]uuid.UUID{}
	fqdnAmbiguousRule := map[uuid.UUID]bool{}
	for _, ref := range s.FQDNRuleReferences {
		if ref.PolicyRuleID == uuid.Nil || ref.FQDNResourceID == uuid.Nil {
			fqdnAmbiguousRule[ref.PolicyRuleID] = true
			continue
		}
		if _, exists := fqdnReferenceForRule[ref.PolicyRuleID]; exists {
			fqdnAmbiguousRule[ref.PolicyRuleID] = true
			continue
		}
		fqdnReferenceForRule[ref.PolicyRuleID] = ref.FQDNResourceID
	}
	// S10.3: exposed Services keyed by their STABLE id — a grant resolves to the CURRENT VIP here, never a
	// snapshotted address, so a re-allocated VIP follows the identity and a vanished Service resolves to nothing.
	serviceByID := make(map[uuid.UUID]ExposedService, len(s.ExposedServices))
	for _, es := range s.ExposedServices {
		if !es.handoffReady() {
			continue // unresolved pool: no client, connector, VIP, or DNS policy widening
		}
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
		set                  map[allowKey]int
		list                 []policyspec.AllowEntry
		fqdnResolverCarriage map[allowKey]bool
		generations          map[string]policyspec.FQDNGeneration
	}
	acc := map[uuid.UUID]*nodeAcc{}
	for nodeID := range nodeSet {
		acc[nodeID] = &nodeAcc{set: map[allowKey]int{}, fqdnResolverCarriage: map[allowKey]bool{}, generations: map[string]policyspec.FQDNGeneration{}}
	}
	addWithProvenance := func(nodeID uuid.UUID, e policyspec.AllowEntry, resolverCarriage bool) {
		// Every caller's target is in nodeSet by construction (devices + SiteNodes + the seeded hub) —
		// see the F1 seed above; no lazy admit exists, so an unknown node here would be a programming
		// error the acc lookup surfaces immediately, never a silent artifact for an unvetted node.
		a := acc[nodeID]
		k := allowKey{e.SrcIP, e.DstCIDR, e.Protocol, e.PortLow, e.PortHigh}
		if index, exists := a.set[k]; exists {
			// An active-generation-derived tuple wins observability provenance over
			// a redundant manual CIDR tuple regardless of rule order. Concrete
			// answers additionally carry the S21 conntrack ownership bit. Resolver
			// carriage deliberately does not: it is a normal derived policy tuple,
			// but still cites the FQDN parent while that parent is active. A fresh
			// compile after withdrawal naturally leaves only the manual provenance.
			if e.FQDNManaged && !a.list[index].FQDNManaged {
				a.list[index].FQDNManaged = true
				a.list[index].RuleID = e.RuleID
				a.list[index].SrcDeviceID = e.SrcDeviceID
			} else if resolverCarriage && !a.list[index].FQDNManaged && !a.fqdnResolverCarriage[k] {
				a.list[index].RuleID = e.RuleID
				a.list[index].SrcDeviceID = e.SrcDeviceID
				a.fqdnResolverCarriage[k] = true
			}
			return
		}
		a.set[k] = len(a.list)
		a.list = append(a.list, e)
		if resolverCarriage {
			a.fqdnResolverCarriage[k] = true
		}
	}
	add := func(nodeID uuid.UUID, e policyspec.AllowEntry) { addWithProvenance(nodeID, e, false) }
	addResolverCarriage := func(nodeID uuid.UUID, e policyspec.AllowEntry) {
		addWithProvenance(nodeID, e, true)
	}
	addGeneration := func(nodeID uuid.UUID, g policyspec.FQDNGeneration) {
		acc[nodeID].generations[g.ResourceID] = g
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
	var routedPrefixes []netip.Prefix
	for _, ss := range s.SiteSubnets {
		if p, err := netip.ParsePrefix(ss.CIDR); err == nil {
			sitePfxs = append(sitePfxs, sitePfx{ss.SiteID, p})
			routedPrefixes = append(routedPrefixes, p.Masked())
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
		deviceAgentGroups := agentGroups[d.ID]
		resolverForSuffix := make(map[string]string)
		for _, forward := range deviceFQDNForwardsFromSnapshot(s, d.ID, routedPrefixes) {
			resolverForSuffix[forward.Domain] = forward.ResolverIP
		}
		for _, r := range s.Rules {
			if r.Disabled { // F3: withdrawn allow — contributes no grant (as-if-absent under default-deny)
				continue
			}
			// Source-subject match (S7.5.4): a "user" rule matches iff this device's
			// owner IS that user; a "group" rule matches iff the owner is in the group
			// (the pre-S7.5.4 path, and the default for legacy blank src_kind).
			if !ruleMatchesDevice(r, d, owner, deviceAgentGroups) {
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
			case "fqdn_resource":
				resourceID, referenced := fqdnReferenceForRule[r.ID]
				res, found := fqdnResourceByID[resourceID]
				generation, answers, _, active := activeFQDNGeneration(res)
				if !fqdnEnabled || !referenced || fqdnAmbiguousRule[r.ID] || !found || !active || !siteGateways[siteGateway{siteID: res.Active.SelectedSiteID, gatewayID: res.Active.SelectedGatewayID}] {
					continue // missing, ambiguous, inactive, or withdrawn: default deny
				}
				// The selected resolver gateway is also the destination-path authority
				// for both the concrete answer and the DNS query. Both-enforce on the
				// source edge, active hub, and exact selected gateway.
				enforceNodes := map[uuid.UUID]bool{d.NodeID: true, res.Active.SelectedGatewayID: true}
				if hubNode != uuid.Nil {
					enforceNodes[hubNode] = true
				}
				for node := range enforceNodes {
					addGeneration(node, generation)
					for _, answer := range answers {
						add(node, policyspec.AllowEntry{SrcIP: d.AssignedIP, DstCIDR: answer, Protocol: normProto(res.Protocol), PortLow: res.PortLow, PortHigh: res.PortHigh, RuleID: r.ID.String(), SrcDeviceID: d.ID.String(), FQDNManaged: true})
					}
					matchedSuffix, _ := normalizeResolverMatchSuffix(res.Active.ResolverMatchSuffix)
					resolver := ""
					if resolverIP := resolverForSuffix[matchedSuffix]; resolverIP != "" {
						if addr, err := netip.ParseAddr(resolverIP); err == nil {
							resolver = netip.PrefixFrom(addr, addr.BitLen()).String()
						}
					}
					if resolver != "" {
						for _, proto := range []policyspec.Protocol{policyspec.ProtoUDP, policyspec.ProtoTCP} {
							addResolverCarriage(node, policyspec.AllowEntry{SrcIP: d.AssignedIP, DstCIDR: resolver, Protocol: proto, PortLow: 53, PortHigh: 53, RuleID: r.ID.String(), SrcDeviceID: d.ID.String()})
						}
					}
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
			if res, ok := resourceByID[r.DstResourceID]; ok {
				if res.CIDR != "" {
					dsts = append(dsts, policyspec.AllowEntry{DstCIDR: res.CIDR, Protocol: normProto(res.Protocol), PortLow: res.PortLow, PortHigh: res.PortHigh})
				}
			}
		case "fqdn_resource":
			resourceID, referenced := fqdnReferenceForRule[r.ID]
			res, found := fqdnResourceByID[resourceID]
			generation, answers, resolvers, active := activeFQDNGeneration(res)
			if fqdnEnabled && referenced && !fqdnAmbiguousRule[r.ID] && found && active && siteGateways[siteGateway{siteID: res.Active.SelectedSiteID, gatewayID: res.Active.SelectedGatewayID}] {
				for _, answer := range answers {
					dsts = append(dsts, policyspec.AllowEntry{DstCIDR: answer, Protocol: normProto(res.Protocol), PortLow: res.PortLow, PortHigh: res.PortHigh, FQDNManaged: true})
				}
				if resolver, ok := selectFirstReachableResolverAddress(resolvers, routedPrefixes); ok {
					for _, proto := range []policyspec.Protocol{policyspec.ProtoUDP, policyspec.ProtoTCP} {
						dsts = append(dsts, policyspec.AllowEntry{DstCIDR: resolver, Protocol: proto, PortLow: 53, PortHigh: 53})
					}
				}
				enforceNodes[res.Active.SelectedGatewayID] = true
				if hubNode != uuid.Nil {
					enforceNodes[hubNode] = true
				}
				for node := range enforceNodes {
					addGeneration(node, generation)
				}
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
					entry := policyspec.AllowEntry{
						SrcIP:       sc, // a CIDR — the site LAN source (the v5 content trigger, RequiredVersion)
						DstCIDR:     d.DstCIDR,
						Protocol:    d.Protocol,
						PortLow:     d.PortLow,
						PortHigh:    d.PortHigh,
						RuleID:      r.ID.String(),
						FQDNManaged: d.FQDNManaged,
					}
					if r.DstKind == "fqdn_resource" && !d.FQDNManaged && d.PortLow == 53 && d.PortHigh == 53 && (d.Protocol == policyspec.ProtoUDP || d.Protocol == policyspec.ProtoTCP) {
						addResolverCarriage(node, entry)
					} else {
						add(node, entry)
					}
				}
			}
		}
	}

	for nodeID := range nodeSet {
		list := acc[nodeID].list
		sortAllows(list)
		generations := make([]policyspec.FQDNGeneration, 0, len(acc[nodeID].generations))
		for _, generation := range acc[nodeID].generations {
			generations = append(generations, generation)
		}
		sort.Slice(generations, func(i, j int) bool { return generations[i].ResourceID < generations[j].ResourceID })
		c := policyspec.Compiled{NodeID: nodeID.String(), Mode: ModeEnforcing, Mesh: false, Allow: list, Subjects: subjects, FQDNGenerations: generations}
		c.Version = policyspec.RequiredVersion(c) // content-derived (S8.2 D1b): v5 iff a CIDR source present
		out[nodeID] = c
	}
	return out
}

// activeFQDNGeneration is a deliberately defensive compiler boundary. Resolver
// lifecycle code supplies only selected-context, last-known-good generations; a
// partial DB read or bad fixture must still withdraw rather than accidentally
// turn a hostname into a broad CIDR allow.
func activeFQDNGeneration(r FQDNResource) (policyspec.FQDNGeneration, []string, []string, bool) {
	if r.ID == uuid.Nil || r.FQDN == "" || r.Active == nil || r.Active.ResourceID != r.ID || r.Active.SelectedSiteID == uuid.Nil || r.Active.SelectedGatewayID == uuid.Nil || r.Active.ResolverConfigID == uuid.Nil || r.Active.ResolverProfileID == uuid.Nil || r.Active.ResolverConfigVersion < 1 || len(r.Active.Answers) == 0 || len(r.Active.Answers) > 32 || len(r.Active.ResolverAddresses) > 1 || !validFQDNL4Scope(r) {
		return policyspec.FQDNGeneration{}, nil, nil, false
	}
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(r.FQDN), "."))
	if name == "" || r.FQDN != name {
		return policyspec.FQDNGeneration{}, nil, nil, false // Lane 1 publishes normalized names only.
	}
	seen := map[string]bool{}
	answers := make([]string, 0, len(r.Active.Answers))
	for _, raw := range r.Active.Answers {
		addr, err := netip.ParseAddr(raw)
		if err != nil || !usableFQDNAnswer(addr) {
			return policyspec.FQDNGeneration{}, nil, nil, false
		}
		prefix := netip.PrefixFrom(addr, addr.BitLen()).String()
		if !seen[prefix] {
			seen[prefix] = true
			answers = append(answers, prefix)
		}
	}
	sort.Strings(answers)
	resolvers := make([]string, 0, len(r.Active.ResolverAddresses))
	for _, raw := range r.Active.ResolverAddresses {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || prefix.Bits() != prefix.Addr().BitLen() || prefix.String() != raw || !usableResolverAddress(prefix.Addr()) {
			return policyspec.FQDNGeneration{}, nil, nil, false
		}
		resolvers = append(resolvers, raw)
	}
	matchedSuffix, validSuffix := normalizeResolverMatchSuffix(r.Active.ResolverMatchSuffix)
	if !validSuffix || (matchedSuffix != "" && name != matchedSuffix && !strings.HasSuffix(name, "."+matchedSuffix)) {
		return policyspec.FQDNGeneration{}, nil, nil, false
	}
	identity := FQDNGenerationIdentityWithResolverConfig(r.ID, name, r.Active.SelectedSiteID, r.Active.SelectedGatewayID, r.Active.ResolverConfigID, r.Active.ResolverProfileID, matchedSuffix, r.Active.ResolverConfigVersion, answers)
	if identity == "" {
		return policyspec.FQDNGeneration{}, nil, nil, false
	}
	return policyspec.FQDNGeneration{ResourceID: r.ID.String(), Name: name, Generation: identity, ResolverConfigID: r.Active.ResolverConfigID.String(), ResolverConfigVersion: r.Active.ResolverConfigVersion, Answers: answers}, answers, resolvers, true
}

// normalizeResolverMatchSuffix applies the same IDNA DNS-label normalization as
// FQDN resources while allowing the one-label private suffixes supported by the
// resolver profile schema. Empty is the legacy-default provenance marker.
func normalizeResolverMatchSuffix(raw string) (string, bool) {
	if raw == "" {
		return "", true
	}
	normalized, err := fqdn.Normalize("resolver-root." + raw)
	if err != nil || !strings.HasPrefix(normalized, "resolver-root.") {
		return "", false
	}
	return strings.TrimPrefix(normalized, "resolver-root."), true
}

// FQDNGenerationIdentity binds an immutable generation to its FQDN resource,
// selected resolver authority and canonical answers. It intentionally does not
// use a sequence number or timestamp: replaying the same selected generation
// yields the same identity on every compiler.
func FQDNGenerationIdentity(resourceID uuid.UUID, fqdn string, siteID, gatewayID uuid.UUID, answers []string) string {
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(fqdn), "."))
	if resourceID == uuid.Nil || siteID == uuid.Nil || gatewayID == uuid.Nil || name == "" || fqdn != name || len(answers) == 0 || len(answers) > 32 {
		return ""
	}
	canonical := make([]string, 0, len(answers))
	seen := make(map[string]bool, len(answers))
	for _, raw := range answers {
		addr, err := netip.ParseAddr(raw)
		if err != nil || !usableFQDNAnswer(addr) {
			return ""
		}
		prefix := netip.PrefixFrom(addr, addr.BitLen()).String()
		if !seen[prefix] {
			seen[prefix] = true
			canonical = append(canonical, prefix)
		}
	}
	sort.Strings(canonical)
	return fqdnGenerationIdentity(resourceID, name, siteID, gatewayID, canonical)
}

func fqdnGenerationIdentity(resourceID uuid.UUID, fqdn string, siteID, gatewayID uuid.UUID, answers []string) string {
	parts := append([]string{resourceID.String(), strings.ToLower(strings.TrimSuffix(strings.TrimSpace(fqdn), ".")), siteID.String(), gatewayID.String()}, answers...)
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}

// fqdnGenerationIdentityWithResolverConfig additionally binds the policy
// artifact to the immutable direct-DNS configuration used to obtain the
// active answer generation. This means a configuration revision change cannot
// be treated as an identical FQDN policy even if its current answers happen to
// match; old generations are rejected by the snapshot reader until re-resolved.
func FQDNGenerationIdentityWithResolverConfig(resourceID uuid.UUID, fqdn string, siteID, gatewayID, configID, profileID uuid.UUID, matchedSuffix string, configVersion int64, answers []string) string {
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(fqdn), "."))
	normalizedSuffix, validSuffix := normalizeResolverMatchSuffix(matchedSuffix)
	if resourceID == uuid.Nil || siteID == uuid.Nil || gatewayID == uuid.Nil || configID == uuid.Nil || profileID == uuid.Nil || configVersion < 1 || name == "" || fqdn != name || !validSuffix || (normalizedSuffix != "" && name != normalizedSuffix && !strings.HasSuffix(name, "."+normalizedSuffix)) || len(answers) == 0 || len(answers) > 32 {
		return ""
	}
	canonical := make([]string, 0, len(answers))
	seen := make(map[string]bool, len(answers))
	for _, raw := range answers {
		addr, err := netip.ParseAddr(strings.TrimSuffix(raw, "/32"))
		if err != nil {
			prefix, prefixErr := netip.ParsePrefix(raw)
			if prefixErr != nil || prefix.Bits() != prefix.Addr().BitLen() {
				return ""
			}
			addr = prefix.Addr()
		}
		if !usableFQDNAnswer(addr) {
			return ""
		}
		prefix := netip.PrefixFrom(addr, addr.BitLen()).String()
		if !seen[prefix] {
			seen[prefix] = true
			canonical = append(canonical, prefix)
		}
	}
	sort.Strings(canonical)
	parts := append([]string{resourceID.String(), name, siteID.String(), gatewayID.String(), configID.String(), profileID.String(), normalizedSuffix, strconv.FormatInt(configVersion, 10)}, canonical...)
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}

// validFQDNL4Scope makes the compiler's FQDN branch default deny if a
// cross-lane read bypasses the resource validator. In particular, a malformed
// protocol must never fall through normProto's legacy CIDR compatibility default
// and become an unscoped "any" grant.
func validFQDNL4Scope(r FQDNResource) bool {
	if r.Protocol == "any" {
		return r.PortLow == 0 && r.PortHigh == 0
	}
	if r.Protocol != "tcp" && r.Protocol != "udp" {
		return false
	}
	if r.PortLow == 0 && r.PortHigh == 0 {
		return true
	}
	return r.PortLow >= 1 && r.PortLow <= r.PortHigh && r.PortHigh <= 65535
}

func usableFQDNAnswer(addr netip.Addr) bool {
	if !addr.IsValid() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified() {
		return false
	}
	// Documentation ranges must never become a real authorization from test or
	// resolver data. Metadata endpoints are rejected by the resolver lane too;
	// retaining this guard here makes compiler failure closed.
	for _, raw := range []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32", "169.254.169.254/32", "fd00:ec2::254/128"} {
		if p, err := netip.ParsePrefix(raw); err == nil && p.Contains(addr) {
			return false
		}
	}
	return true
}

// usableResolverAddress mirrors the persisted direct-endpoint safety boundary.
// Unlike answer validation, private/documentation ranges are valid here: resolver
// endpoints are tenant-selected infrastructure, not DNS-derived authorization.
func usableResolverAddress(addr netip.Addr) bool {
	return addr.IsValid() && addr.Zone() == "" && !addr.IsLoopback() && !addr.IsLinkLocalUnicast() && !addr.IsMulticast() && !addr.IsUnspecified()
}

// AgentRouteCIDRs returns canonical destination prefixes present in compiled
// policy for one managed-agent source. It projects Compile rather than adding a
// second matcher, so the runtime and gateway enforce the same authorization.
func AgentRouteCIDRs(s Snapshot, agentID uuid.UUID) []string {
	if agentID == uuid.Nil {
		return nil
	}
	seen := map[string]struct{}{}
	for _, artifact := range Compile(s) {
		for _, allow := range artifact.Allow {
			if allow.SrcDeviceID != agentID.String() {
				continue
			}
			prefix, err := netip.ParsePrefix(allow.DstCIDR)
			if err == nil {
				seen[prefix.Masked().String()] = struct{}{}
			}
		}
	}
	routes := make([]string, 0, len(seen))
	for route := range seen {
		routes = append(routes, route)
	}
	sort.Strings(routes)
	return routes
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
		if a[i].PortHigh != a[j].PortHigh {
			return a[i].PortHigh < a[j].PortHigh
		}
		return !a[i].FQDNManaged && a[j].FQDNManaged
	})
}
