// Package policyspec is the NEUTRAL (edition-agnostic) wire shape of the compiled
// Zero Trust policy artifact — the typed structure the control plane pushes to a
// node agent. It lives outside internal/enterprise so the open-build desired-state
// path (S7.2) can reference the type even though only the enterprise build ever
// produces a non-trivial value. The compiler (internal/policy) emits
// these; S7.2's agent programs them into the gateway forward chain.
//
// Contract: Compile is DETERMINISTIC — equal input DB state produces a
// byte-identical Compiled — so a steady-state reconcile is a no-op (the
// reconcile-idempotence guard). Allow entries are sorted + de-duplicated.
package policyspec

import (
	"strings"
	"time"

	"github.com/google/uuid"
)

// ResourceInput and RuleInput are the NEUTRAL CRUD payload DTOs for the policy
// API. They live here (not in internal/policy) so the open-build http
// port + handlers can reference them WITHOUT importing the enterprise package —
// which would link the enterprise compiler into the open binary and break the
// edition boundary (the SSO port takes primitives for the same reason). The
// enterprise service consumes these and does the validation.
type ResourceInput struct {
	Name     string
	CIDR     string
	Protocol string // any | tcp | udp
	PortLow  *int
	PortHigh *int
}

// RuleInput is a policy allow-rule create payload. S7.5.4: the SOURCE subject is
// a group (SrcKind="group", SrcGroupID) OR a single user (SrcKind="user",
// SrcUserID); ExpiresAt set makes it a temporary grant (nil = permanent). SrcKind
// blank is treated as "group" (back-compat with pre-S7.5.4 callers).
type RuleInput struct {
	SrcKind    string // "" | group | user | site (S8.2) | cidr (S8.7)
	SrcGroupID uuid.UUID
	SrcUserID  *uuid.UUID
	SrcSiteID  *uuid.UUID // S8.2: set iff SrcKind=="site" — a site's LAN as the policy SOURCE
	SrcCIDR    *string    // S8.7: set iff SrcKind=="cidr" — a literal source CIDR (/32-precise grants)
	// SrcAgentDeviceID (S15.3) — set iff SrcKind=="agent": the agent DEVICE whose /32 is the source.
	// ⚠ Named distinctly from AllowEntry.SrcDeviceID (observability metadata) so the two cannot be confused:
	// this one is POLICY INPUT and decides what the rule matches.
	SrcAgentDeviceID *uuid.UUID
	DstKind          string // resource | group | site (S8.1) | k8s_service (S10.3)
	DstResourceID    *uuid.UUID
	DstGroupID       *uuid.UUID
	DstSiteID        *uuid.UUID // S8.1: set iff DstKind=="site"
	DstK8sServiceID  *uuid.UUID // S10.3: set iff DstKind=="k8s_service"
	ExpiresAt        *time.Time // nil = permanent; set = temporary grant

}

// AffectedDevice is a full-tunnel device whose internet egress becomes policy-
// governed when the org enters enforcing (S7.2 decision 2a). Neutral so the open-
// build http port can name it without importing the enterprise package.
type AffectedDevice struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
}

// ProtocolVersion is the compiled-artifact wire version. Bump on any shape change.
// v2 (S7.5.1): AllowEntry gains an OBSERVABILITY-only `rule_id` (flow-log
// attribution). v3 (S7.5.4 slice 3): AllowEntry gains an OBSERVABILITY-only
// `src_device_id` (the source device's uuid) so the agent stamps flow events with
// device identity from the ARTIFACT (never an src_ip→device DB guess) and the CP
// joins device→user CP-side. Both are additive, NEVER enforcement, and EXCLUDED
// from CanonicalHash (the enforcement-only projection), so old agents ignore the
// unknown field and artifacts with identical grants enforce IDENTICALLY across
// versions. A version-number bump does re-converge the fleet ONCE on deploy
// (A-4: one version served fleet-wide) — enforcement is unchanged, only the
// metadata grows. See docs/S7.5.1-decisions.md (D2 / A-4), docs/S7.5.4-decisions.md (D4).
//
// v4 (S8.1 Slice 3, EPIC 8): sites become a policy DESTINATION KIND. Option A (ruled) — NO new wire
// field: a `device→site-subnet` grant compiles to a same-shape AllowEntry{Src, Dst: site-subnet-CIDR}
// (the KIND is a CP-side rule fact, resolved to DstCIDR at compile). The enforcement-significant change
// IS this version bump — `Version` is IN CanonicalHash (hash.go), so v4 changes every gateway's hash and
// (with S8.1 D1's gate) an agent at maxSupported<4 REFUSES it (deny-all + unsupported_policy_version)
// rather than silently mis-enforcing. This is what makes Version-in-hash safe under mixed versions —
// the A-4 warning at hash.go:25-28 fires and its answer ships here. See docs/S8.1-decisions.md D2/D3.
//
// v5 (S8.2 Slice 1, EPIC 8): a site's LAN becomes a policy SOURCE (src_kind='site'). A site→dst grant
// compiles to AllowEntry{Src: site-subnet-CIDR, Dst: ...} — the source is a CIDR, not a device /32. This
// is enforcement-significant (the agent's source match widens host→prefix), so it is gated by D1. But the
// bump is CONTENT-DERIVED (S8.2 D1b): the CP stamps Version = RequiredVersion(artifact) = 5 ONLY when the
// artifact actually carries a v5 feature (a CIDR source), else 4. So an org NOT using site-source grants
// keeps a byte-identical v4 artifact (hash unchanged, no re-converge, old agents do not refuse); only
// orgs adopting site-to-site flip to v5 and (via D1) deny-all their un-upgraded gateways loudly. The
// constant below is the CEILING — the max shape the CP can emit — not what every artifact carries.
//
// v6 (A3b, S8.6): PoolCIDR — the org device pool delivered to site gateways so the agent renders the
// pool's DOCKER-USER accepts (device transit / device↔device at the Docker tier; the ZT chain still
// adjudicates, D-transit-3 applied uniformly). An old agent would silently ignore the field and leave
// device traffic structurally dropped on Docker hosts while reporting green — the Routes precedent —
// so PoolCIDR presence triggers RequiredVersion=6 and an old gated agent refuses loudly (D1).
// v7 (S10.3): the artifact carries a VIP MAP (exposed K8s Service VIP -> Service identity). An old agent
// has no DNAT/DNS-rewrite render for it, so it would leave the exposed Service unreachable while reporting
// green (the PoolCIDR/Routes dead-while-green class) — so a non-empty VIP map triggers RequiredVersion=7
// and an old gated agent refuses loudly rather than mis-serving. Content-derived: an org with NO cluster
// emits no map, requires no bump, and its agents never see v7 (the zero-config golden).
const ProtocolVersion = 7

// SupportedWindow is the AGENT-VERSION CONTRACT the upgrade path commits to (S11 D1): the current protocol
// version and the one before it. An agent at either must be able to run against this control plane, which is
// what makes a ROLLING upgrade possible — the operator rolls the control plane without first upgrading every
// gateway.
//
// It is keepable because RequiredVersion is CONTENT-DERIVED: an org using no new-version features receives an
// old-version artifact that an N-1 agent applies correctly. TestNMinusOneAgentsCanStillApply fails if that
// ever stops being true, and `preflight` reads this constant to warn about gateways below the window BEFORE
// an operator rolls.
const SupportedWindow = 2

// RequiredVersion is the MINIMUM agent version required to correctly render this artifact (S8.2 D1b,
// content-derived version). It returns the OLDEST protocol version whose shape fully covers the
// artifact's content, so a gateway serving only pre-v5 features keeps a pre-v5 artifact (and old gated
// agents keep working) while an artifact using a v5 feature is stamped v5 (and old agents refuse it via
// D1 rather than silently mis-enforcing). Pure/deterministic — same Compiled → same version.
//
//	v5 triggers (S8.2): (1) any AllowEntry whose source is a CIDR (a site LAN) — a device source is a
//	bare host ("10.99.0.7"), a site source carries "/" ("10.1.0.0/24"), and an old agent's allowMatch
//	(ParseAddr) would SKIP it (silent under-enforcement); (2) a non-empty Routes section — an old agent
//	has no kernel-route code, so it would silently not-route. Either way the old agent must REFUSE the
//	whole artifact, not partially render it.
//
// LAW (S8.2 Slice-1): every enforcement-significant content addition MUST add its trigger here in the
// SAME change (see docs/S8.2-decisions.md). A new field that changes the wire's rendered shape but
// leaves this function untouched is a silent-accept bug — the artifact would carry new content at an old
// version and old agents would accept it. The D2 checklist asks "RequiredVersion updated? y/n".
func RequiredVersion(c Compiled) int {
	//	v7 trigger (S10.3): a non-empty VIP map — an old agent has no VIP->ClusterIP DNAT / DNS-rewrite
	//	render, so it would leave the exposed K8s Service unreachable while green (dead-while-green). REFUSE.
	if len(c.VIPMappings) > 0 || len(c.K8sDNSZones) > 0 {
		return 7
	}
	//	v6 trigger (A3b, S8.6): a non-empty PoolCIDR — an old agent has no pool-class DOCKER-USER
	//	render, so it would silently leave device transit structurally dropped on Docker hosts
	//	(dead-while-green, the Routes class). It must REFUSE the whole artifact.
	if c.PoolCIDR != "" {
		return 6
	}
	if len(c.Routes) > 0 {
		return 5
	}
	for _, e := range c.Allow {
		if strings.Contains(e.SrcIP, "/") {
			return 5
		}
	}
	return 4
}

// Protocol scopes an allow entry to an L4 protocol. "any" ignores ports.
type Protocol string

const (
	ProtoAny Protocol = "any"
	ProtoTCP Protocol = "tcp"
	ProtoUDP Protocol = "udp"
)

// AllowEntry is ONE compiled default-deny grant: the source device (its assigned
// /32 host address) may reach DstCIDR on Protocol within [PortLow,PortHigh].
// PortLow==0 means "all ports" (Protocol=="any", or an unscoped tcp/udp resource).
// S7.2 programs each entry as an accept in the gateway forward chain; anything not
// covered by an entry is dropped.
type AllowEntry struct {
	// SrcIP is the source match. A DEVICE source is a bare host address, no prefix ("10.99.0.7"). A SITE
	// source (v5, S8.2) is a LAN CIDR ("10.1.0.0/24") — the agent's allowMatch parses it as a prefix. The
	// presence of a "/" here is the content-derived v5 trigger (RequiredVersion). Kept the json tag
	// `src_ip` for wire-compat; the field name stays SrcIP though it now also holds a CIDR.
	SrcIP    string   `json:"src_ip"`
	DstCIDR  string   `json:"dst_cidr"`           // destination prefix (e.g. "10.0.5.0/24", "10.99.0.9/32", "0.0.0.0/0")
	Protocol Protocol `json:"protocol"`           // any | tcp | udp
	PortLow  int      `json:"port_low,omitempty"` // 0 => all ports
	PortHigh int      `json:"port_high,omitempty"`
	// RuleID (v2, S7.5.1) is OBSERVABILITY metadata: the CP policy_rules.uuid whose
	// grant produced this entry, so the agent stamps flow/deny events with it and the
	// conntrack-kill agrees on identity. NEVER enforcement — EXCLUDED from CanonicalHash
	// (the enforcement projection), so staleness is metadata-blind. Empty on v1 wire /
	// default-deny with no matching rule.
	RuleID string `json:"rule_id,omitempty"`
	// SrcDeviceID (v3, S7.5.4) is OBSERVABILITY metadata: the source device's uuid
	// (devices.id). The agent maps a flow's src /32 -> this id from the APPLIED artifact
	// and stamps it on the flow event, so the CP attributes flows to a device (then to a
	// user, CP-side) WITHOUT any src_ip->device DB reconstruction. NEVER enforcement —
	// EXCLUDED from CanonicalHash. Empty on v1/v2 wire / a src with no grant.
	SrcDeviceID string `json:"src_device_id,omitempty"`
}

// Route is one kernel-route intent (S8.2): the agent must program a route to DstCIDR via the tunnel
// interface (wg0) so packets destined to a remote SITE subnet reach the WG interface at all (today the
// kernel only knows the pool route). This is EXPLICIT propagation output (the overruled-into shape) —
// the agent programs it as INTENT, never inferring routes from a peer's AllowedIPs (which would fuse
// WG crypto-routing with kernel-FIB intent). D2-classified: reachability PLUMBING, NOT enforcement (the
// grant in Allow is the permission; a routed-but-ungranted subnet is DROPPED at the forward chain) —
// so Route is EXCLUDED from CanonicalHash (a flushed route self-heals on the next reconcile; a DEAD
// site link surfaces via the site_link_down/site_hub_down health kinds, wired in S8.2 — not via the
// policy-desync hash). But a Route STILL requires a v5 agent to RENDER, so its presence triggers
// RequiredVersion=5 (an old agent must REFUSE, not silently ignore the section).
type Route struct {
	DstCIDR string `json:"dst_cidr"` // a remote site subnet to route via the tunnel interface
}

// Compiled is the per-node policy artifact. It expresses BOTH modes so S7.2 has a
// single code path (mode is a compiler INPUT, not an enforcement special-case):
//
//   - Mode "off"       => Mesh=true, Allow=nil. Legacy blanket mesh: S7.2 keeps the
//     pre-Zero-Trust wg0<->wg0 accept. No behavior change on upgrade.
//   - Mode "enforcing" => Mesh=false. ONLY the entries in Allow are permitted;
//     everything else is denied (default-deny). An EMPTY Allow with Mesh=false
//     means "deny all device-to-device" — a legitimate locked-down posture, and
//     structurally NOT the same as the blanket mesh (empty != permissive).
//
// Invariant (enforced by the compiler + guarded by test): Mesh==true ONLY when
// Mode=="off". The enforcing path can never emit a blanket allow.
type Compiled struct {
	Version int          `json:"version"` // == ProtocolVersion
	NodeID  string       `json:"node_id"`
	Mode    string       `json:"mode"` // "off" | "enforcing"
	Mesh    bool         `json:"mesh"`
	Allow   []AllowEntry `json:"allow"`
	// Routes (v5, S8.2) is the site-to-site kernel-route intent — PLUMBING, out of CanonicalHash, but
	// present triggers RequiredVersion=5 (an old agent refuses rather than ignoring the routes). Carried
	// in BOTH modes: an off-mode gateway still needs the kernel route to reach a remote site subnet.
	Routes []Route `json:"routes,omitempty"`
	// LocalSubnets (S8.2c D2) is THIS gateway's OWN approved site subnets — the CP's authoritative answer
	// to "which subnet does this gateway front" (the admin advertised + approved it). The agent picks its
	// host address inside one of these as the SOURCE for its site routes (so gateway-host-originated
	// traffic sources from the site LAN, not the overlay addr). OUT OF CanonicalHash (observability
	// plumbing, not projected). Only rides WITH Routes (a remote route exists), so it inherits v5's gate;
	// an old agent that ignored it would lose ONLY the src-hint (degraded-not-broken) — no version bump.
	LocalSubnets []string `json:"local_subnets,omitempty"`
	// DNSForwards (S8.4 D1/D5) is the org's cross-site DNS forwarding table: {domain -> resolver_ip} for
	// each approved site zone, so this gateway's in-agent forwarder can send a query for a remote site's
	// domain to that site's internal resolver over the tunnel. OUT OF CanonicalHash + NO RequiredVersion
	// trigger — degraded-not-broken CONVENIENCE (unlike Routes): a DNS-blind agent serves a WORKING bridge
	// where names don't resolve (visibly degraded, user-diagnosable), never a dead bridge while green. So it
	// is neither hashed nor version-gated; a no-DNS org's artifact is byte-identical.
	DNSForwards []DNSForward `json:"dns_forwards,omitempty"`
	// PoolCIDR (v6, A3b/S8.6) is the org's device pool, delivered to SITE gateways so the agent renders
	// the pool's RELAXED DOCKER-USER accepts (fwd: oif=wg0 daddr=pool; ret: iif=wg0 saddr=pool) — lifting
	// Docker's structural FORWARD DROP for device-sourced transit AND device↔device (PD-3), while the
	// `ip tunnex` chain remains the sole adjudicator (D-transit-3 applied uniformly to the pool class:
	// enforcing-no-grant still drops AT the chain, with counter evidence). Reachability PLUMBING, so OUT
	// of CanonicalHash — but an old agent ignoring it leaves device paths dead-while-green on Docker
	// hosts, so presence triggers RequiredVersion=6 (refuse-not-silent, the Routes precedent). Rides only
	// with the site-gateway artifact (finalizeArtifact, the ONE source); non-site gateways keep Docker-
	// dark device↔device — REGISTERED PD-3 residual, trigger = first non-site device↔device walk.
	PoolCIDR string `json:"pool_cidr,omitempty"`
	// VIPMappings (v7, S10.3) is this gateway's exposed-Service table: each synthetic VIP -> the Service
	// identity (namespace + name) the agent DNATs it to (VIP -> ClusterIP, resolved in-cluster) and rewrites
	// DNS answers to. Reachability PLUMBING, so OUT of CanonicalHash (projectForHash omits it — changing the
	// map's CONTENTS at the same version never churns the policy hash); but PRESENCE triggers
	// RequiredVersion=7 (an old agent with no DNAT/DNS-rewrite would leave the Service dead-while-green, so it
	// must REFUSE — the PoolCIDR precedent). omitempty so a non-cluster gateway's artifact is byte-identical.
	VIPMappings []VIPMapping `json:"vip_mappings,omitempty"`
	// K8sDNSZones (v7, S10.3 (A1)) is the DNS-listen table for the clusters this gateway fronts: each entry
	// binds :53 on a reserved DNS VIP and serves that cluster's zone (direct-answer from the VIP map above,
	// NXDOMAIN for in-zone-but-unexposed). Same out-of-hash / v7-trigger treatment as VIPMappings.
	K8sDNSZones []K8sDNSZone `json:"k8s_dns_zones,omitempty"`
}

// VIPMapping is one exposed K8s Service: clients reach VIP (a /32 in the cluster's synthetic range); the
// gateway DNATs it to the Service's real ClusterIP (resolved from <Service>.<Namespace> in-cluster) and
// rewrites the Service's DNS A-answer to VIP. Protocol/ports scope the exposure (empty = any).
type VIPMapping struct {
	VIP       string `json:"vip"`
	Namespace string `json:"namespace"`
	Service   string `json:"service"`
	// ServiceCIDR is the cluster's Kubernetes Service CIDR — the agent classifies a resolved address with
	// it (inside = a ClusterIP to DNAT; outside = a pod IP = a headless Service with no stable VIP, refused)
	// WITHOUT the K8s API (the (A) no-API boundary). Carried per-mapping (a gateway may front >1 cluster).
	ServiceCIDR string `json:"service_cidr"`
	Protocol    string `json:"protocol,omitempty"`
	PortLow     int    `json:"port_low,omitempty"`
	PortHigh    int    `json:"port_high,omitempty"`
	// DNSName is the fully-qualified in-tunnel hostname clients use to reach this Service:
	// <service>.<namespace>.svc.<cluster>.<zone> (S10.3 (B2), always-explicit — a collapsed form
	// silently breaks on a second cluster). The gateway answers this name with VIP (A record); a name
	// inside the cluster's zone that is NOT any DNSName is NXDOMAIN, never a silent timeout.
	DNSName string `json:"dns_name,omitempty"`
}

// K8sDNSZone tells a site gateway to answer DNS on ListenVIP (the cluster's reserved DNS VIP) authoritatively
// for Zone (<cluster>.<customer-zone>). A query matching a VIPMapping.DNSName resolves to its VIP; any other
// name inside Zone is NXDOMAIN (never a silent timeout); the bind is fail-closed (S10.3 (A1)/(i)). One entry
// per cluster this gateway fronts (D1: normally exactly one).
type K8sDNSZone struct {
	ListenVIP string `json:"listen_vip"`
	Zone      string `json:"zone"`
}

// DNSForward is one forwarded zone: queries for Domain go to ResolverIP (an address inside the declaring
// site's approved subnet — validated at write time, D7). The org-wide union is compiled onto every gateway
// so any gateway can answer for any site's zone (local resolver direct; remote via the tunnel route).
type DNSForward struct {
	Domain     string `json:"domain"`
	ResolverIP string `json:"resolver_ip"`
}
