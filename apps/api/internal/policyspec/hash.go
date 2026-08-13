package policyspec

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// hashAllow is the ENFORCEMENT-ONLY view of an AllowEntry hashed by CanonicalHash.
// EXPLICIT ALLOWLIST (A-1): only enforcement-significant fields appear. Observability
// metadata (rule_id, src_device_id) is DELIBERATELY ABSENT — staleness must be
// metadata-blind ("observability, never semantics" at the hash layer). Field order +
// tags match the v1 AllowEntry EXACTLY, so artifacts with identical grants hash
// IDENTICALLY across the v2/v3 field additions (the added metadata never touches this).
type hashAllow struct {
	SrcIP    string   `json:"src_ip"`
	DstCIDR  string   `json:"dst_cidr"`
	Protocol Protocol `json:"protocol"`
	PortLow  int      `json:"port_low,omitempty"`
	PortHigh int      `json:"port_high,omitempty"`
}

// hashView is the enforcement projection of a whole Compiled. Same rule as hashAllow:
// enforcement fields ONLY, in the v1 field order/tags, so the byte stream is identical
// to the pre-v2 full-Compiled marshal. Version IS enforcement-significant (it gates the
// wire shape) so it stays; it is safe in the hash WHILE the CP serves a SINGLE version
// to all agents (A-4) — if that ever changes (EPIC 8), Version becomes a divergence
// source and this warning fires.
type hashView struct {
	Version int         `json:"version"`
	NodeID  string      `json:"node_id"`
	Mode    string      `json:"mode"`
	Mesh    bool        `json:"mesh"`
	Allow   []hashAllow `json:"allow"`
}

// projectForHash maps a Compiled to its enforcement-only projection. Every NEW
// Compiled/AllowEntry field MUST be classified here: enforcement → add it to the
// projection; observability → leave it out (guarded by the hash-projection reds).
func projectForHash(c Compiled) hashView {
	v := hashView{Version: c.Version, NodeID: c.NodeID, Mode: c.Mode, Mesh: c.Mesh}
	if c.Allow != nil {
		v.Allow = make([]hashAllow, len(c.Allow))
		for i, e := range c.Allow {
			v.Allow[i] = hashAllow{SrcIP: e.SrcIP, DstCIDR: e.DstCIDR, Protocol: e.Protocol, PortLow: e.PortLow, PortHigh: e.PortHigh}
		}
	}
	return v
}

// CanonicalHash is THE policy content fingerprint: 12 hex of SHA-256 over the
// canonical ENFORCEMENT PROJECTION of Compiled (NOT the raw struct — v2 added
// observability metadata that must not enter the hash). The node agent computes the
// SAME hash over the SAME projection of its mirror type (apps/node internal/nodepolicy)
// for the applied-policy status report, so pushed-vs-applied comparison is meaningful:
// both sides hash identical projected bytes, never their own private serialization. A
// cross-module golden test on each side pins the two implementations to the same output.
func CanonicalHash(c Compiled) string {
	b, err := json.Marshal(projectForHash(c))
	if err != nil {
		return "" // unreachable: the projection is plain data
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:6])
}
