// Package nodepolicy is the agent-side mirror of the control plane's compiled Zero
// Trust policy artifact (apps/api internal/policyspec). apps/api and apps/node are
// separate modules, so — exactly as the agent already mirrors the desired-state
// Peer shape — the compiled policy rides the desired-state JSON and is decoded into
// these types. The egress package renders them into the gateway's nftables forward
// chain (S7.2 enforcement).
package nodepolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// Modes (mirror organizations.zero_trust_mode / policyspec).
const (
	ModeOff       = "off"
	ModeEnforcing = "enforcing"
)

// MaxSupportedVersion is the highest compiled-artifact Version this agent can APPLY
// (== the policyspec.ProtocolVersion it was built against). S8.1 D1 fail-closed gate:
// an artifact with Version > MaxSupportedVersion is a SEMANTIC shape the agent does not
// understand — the agent REFUSES it (deny-all, never a best-effort apply of fields it
// can't interpret) and reports the refused version so the control plane surfaces
// `unsupported_policy_version` with the "upgrade the agent" remedy. Bump this in lockstep
// with policyspec.ProtocolVersion whenever the agent gains support for the new shape.
// v4 (S8.1 Slice 3): this agent now SUPPORTS the sites bump (Option A — same-shape wire, a
// device→site-subnet grant is a plain AllowEntry), so it applies v4 rather than refusing it. An
// agent still at 3 (pre-Slice-3 binary) refuses v4 — the go-forward interlock (D1).
// v6 (A3b, S8.6): this agent renders PoolCIDR (the device pool's relaxed DOCKER-USER accepts), so it
// applies v6; an agent still at 5 refuses a pool-carrying artifact rather than silently stranding
// device transit on Docker hosts (the D1 interlock again).
// v7 (S10.3): this agent renders the VIP map (VIP->ClusterIP DNAT + DNS-rewrite), so it applies v7; an
// agent still at 6 refuses a VIP-map-carrying artifact rather than leaving the exposed Service dead-while-green.
const MaxSupportedVersion = 7

// AllowEntry is one compiled default-deny grant: SrcIP (a device /32 host) may reach
// DstCIDR on Protocol within [PortLow,PortHigh]. PortLow==0 means all ports.
type AllowEntry struct {
	SrcIP    string `json:"src_ip"`
	DstCIDR  string `json:"dst_cidr"`
	Protocol string `json:"protocol"` // any | tcp | udp
	PortLow  int    `json:"port_low,omitempty"`
	PortHigh int    `json:"port_high,omitempty"`
	// RuleID (v2, S7.5.1) is OBSERVABILITY metadata the agent captures so it can stamp
	// flow/deny events (and the conntrack-kill) with the grant identity that matched.
	// NEVER enforcement — EXCLUDED from CanonicalHash (the enforcement projection).
	RuleID string `json:"rule_id,omitempty"`
	// SrcDeviceID (v3, S7.5.4) is OBSERVABILITY metadata: the source device's uuid. The
	// agent builds a src /32 -> SrcDeviceID map from the APPLIED Allow set and stamps it
	// on flow events (device attribution without an src_ip->device DB guess). NEVER
	// enforcement — EXCLUDED from CanonicalHash. MUST mirror policyspec field order/tags.
	SrcDeviceID string `json:"src_device_id,omitempty"`
}

// Compiled is the per-node policy artifact. Mesh=true (mode off) => the agent keeps
// the legacy blanket wg0<->wg0 forward accept (no behavior change when Zero Trust is
// off). Mesh=false (enforcing) => ONLY Allow is permitted; everything else is dropped
// by the forward chain's policy-drop base (default-deny; empty Allow = deny-all).
// FIELD ORDER + TAGS MUST MATCH policyspec.Compiled EXACTLY — CanonicalHash is
// json.Marshal-based, and encoding/json emits fields in struct order, so a drift
// here silently forks the hash the control plane computes. The golden test
// (nodepolicy_test.go, same fixture + hex as policyspec's) pins this.
type Compiled struct {
	Version int          `json:"version"`
	NodeID  string       `json:"node_id"`
	Mode    string       `json:"mode"`
	Mesh    bool         `json:"mesh"`
	Allow   []AllowEntry `json:"allow"`
	// Routes (v5, S8.2) is the site-to-site kernel-route intent — reachability PLUMBING, EXCLUDED from
	// CanonicalHash (hashView omits it, like policyspec), so route drift never disturbs the policy hash.
	// The agent programs each as a kernel route via the tunnel iface. Mirror of policyspec.Compiled.
	Routes []Route `json:"routes,omitempty"`
	// LocalSubnets (S8.2c D2) — this gateway's own approved site subnets (the CP's authoritative answer).
	// The agent picks its host address inside one of these as the SOURCE for its site routes. Out-of-hash
	// plumbing; mirror of policyspec.Compiled.LocalSubnets.
	LocalSubnets []string `json:"local_subnets,omitempty"`
	// DNSForwards (S8.4) — the org cross-site DNS forwarding table {domain -> resolver_ip} the in-agent
	// forwarder serves. Out-of-hash CONVENIENCE, no version trigger; mirror of policyspec.Compiled.DNSForwards.
	DNSForwards []DNSForward `json:"dns_forwards,omitempty"`
	// PoolCIDR (v6, A3b/S8.6) — the org device pool; the agent renders its RELAXED DOCKER-USER accepts
	// (fwd: oif=wg0 daddr=pool; ret: iif=wg0 saddr=pool) so Docker's FORWARD DROP never structurally
	// swallows device transit or device↔device — the ip tunnex chain remains the sole adjudicator
	// (D-transit-3, uniform). Out-of-hash PLUMBING; presence triggers RequiredVersion=6 CP-side. Mirror
	// of policyspec.Compiled.PoolCIDR (field order + tag must match — hash is marshal-order-sensitive).
	PoolCIDR string `json:"pool_cidr,omitempty"`
	// VIPMappings (v7, S10.3) — this gateway's exposed-Service table; the agent DNATs each VIP -> the
	// Service's ClusterIP and rewrites its DNS answer to the VIP. Out-of-hash PLUMBING; presence triggers
	// RequiredVersion=7 CP-side. Mirror of policyspec.Compiled.VIPMappings (field order + tags must match).
	VIPMappings []VIPMapping `json:"vip_mappings,omitempty"`
	// K8sDNSZones (v7, S10.3) — DNS-listen table: bind :53 on each ListenVIP and serve that cluster's zone
	// (direct-answer from the VIP map, NXDOMAIN in-zone-but-unexposed). Mirror of policyspec.Compiled.K8sDNSZones.
	K8sDNSZones []K8sDNSZone `json:"k8s_dns_zones,omitempty"`
}

// VIPMapping mirrors policyspec.VIPMapping — one exposed K8s Service (VIP -> Service identity the agent
// DNATs + DNS-rewrites). Fields/tags match the CP shape exactly (marshal parity).
type VIPMapping struct {
	VIP       string `json:"vip"`
	Namespace string `json:"namespace"`
	Service   string `json:"service"`
	// ServiceCIDR — the cluster's K8s Service CIDR; the agent classifies a resolved address with it
	// (inside = ClusterIP -> DNAT; outside = pod IP = headless, refused). Mirror of policyspec.VIPMapping.
	ServiceCIDR string `json:"service_cidr"`
	Protocol    string `json:"protocol,omitempty"`
	PortLow     int    `json:"port_low,omitempty"`
	PortHigh    int    `json:"port_high,omitempty"`
	// DNSName — the FQDN <service>.<namespace>.svc.<cluster>.<zone> the gateway answers with VIP.
	// Mirror of policyspec.VIPMapping.DNSName.
	DNSName string `json:"dns_name,omitempty"`
}

// K8sDNSZone mirrors policyspec.K8sDNSZone — answer DNS on ListenVIP authoritatively for Zone.
type K8sDNSZone struct {
	ListenVIP string `json:"listen_vip"`
	Zone      string `json:"zone"`
}

// Route is one kernel-route intent (v5, S8.2): route DstCIDR via the tunnel interface so a remote site
// subnet is reachable. Mirror of policyspec.Route. PLUMBING, never in the hash.
type Route struct {
	DstCIDR string `json:"dst_cidr"`
}

// DNSForward is one forwarded zone (S8.4): queries for Domain go to ResolverIP over the tunnel. Mirror of
// policyspec.DNSForward. Convenience plumbing, never in the hash.
type DNSForward struct {
	Domain     string `json:"domain"`
	ResolverIP string `json:"resolver_ip"`
}

// hashAllow / hashView are the ENFORCEMENT-ONLY projection hashed by CanonicalHash —
// the EXACT mirror of policyspec's projection (A-1 allowlist). Observability metadata
// (rule_id) is DELIBERATELY ABSENT so staleness is metadata-blind and the v2 bump does
// not disturb existing pushed/applied hashes. Field order + tags match the v1 shape.
type hashAllow struct {
	SrcIP    string `json:"src_ip"`
	DstCIDR  string `json:"dst_cidr"`
	Protocol string `json:"protocol"`
	PortLow  int    `json:"port_low,omitempty"`
	PortHigh int    `json:"port_high,omitempty"`
}

type hashView struct {
	Version int         `json:"version"`
	NodeID  string      `json:"node_id"`
	Mode    string      `json:"mode"`
	Mesh    bool        `json:"mesh"`
	Allow   []hashAllow `json:"allow"`
}

func projectForHash(c *Compiled) hashView {
	v := hashView{Version: c.Version, NodeID: c.NodeID, Mode: c.Mode, Mesh: c.Mesh}
	if c.Allow != nil {
		v.Allow = make([]hashAllow, len(c.Allow))
		for i, e := range c.Allow {
			v.Allow[i] = hashAllow{SrcIP: e.SrcIP, DstCIDR: e.DstCIDR, Protocol: e.Protocol, PortLow: e.PortLow, PortHigh: e.PortHigh}
		}
	}
	return v
}

// CanonicalHash mirrors policyspec.CanonicalHash EXACTLY: 12 hex of SHA-256 over the
// canonical ENFORCEMENT PROJECTION of Compiled (NOT the raw struct — v2 added
// observability metadata that must not enter the hash). Both sides hash identical
// projected bytes — never their own private serialization — so pushed-vs-applied
// comparison is meaningful (staleness detection, S7.2 4b). A nil policy has no hash.
func CanonicalHash(c *Compiled) string {
	if c == nil {
		return ""
	}
	b, err := json.Marshal(projectForHash(c))
	if err != nil {
		return "" // unreachable: the projection is plain data
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:6])
}
