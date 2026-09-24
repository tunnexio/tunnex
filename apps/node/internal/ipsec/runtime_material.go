package ipsec

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/google/uuid"
	"net/netip"
)

func runtimeDeliveryValid(d RuntimeDelivery, org, node uuid.UUID, kind string) bool {
	m := d.Manifest
	if d.ID == uuid.Nil || d.Kind != kind || d.DesiredRevision <= 0 || (kind == "apply" && m.DesiredRevision != d.DesiredRevision || kind == "cleanup" && (m.DesiredRevision <= 0 || m.DesiredRevision >= d.DesiredRevision)) || m.OrgID != org || m.NodeID != node || m.SiteID == uuid.Nil || m.ConnectionID == uuid.Nil || m.ConfigurationRevision <= 0 || m.ProfileID != "aws-static-ipv4-v1" || !validDigest(d.OwnershipDigest) {
		return false
	}
	if kind == "cleanup" {
		return true
	} // Cleanup digest binds the full lineage, checked below.
	raw, e := json.Marshal(m)
	if e != nil {
		return false
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]) == d.OwnershipDigest
}
func runtimePrefixes(raw []string) ([]netip.Prefix, bool) {
	if len(raw) == 0 || len(raw) > 64 {
		return nil, false
	}
	out := []netip.Prefix{}
	for _, s := range raw {
		p, e := netip.ParsePrefix(s)
		if e != nil || !p.Addr().Is4() || p != p.Masked() || p.Bits() == 0 || p.String() != s {
			return nil, false
		}
		for _, old := range out {
			if old.Overlaps(p) {
				return nil, false
			}
		}
		out = append(out, p)
	}
	return out, true
}
func runtimeMaterialEntry(m RuntimeMaterial, org, node uuid.UUID, ns string) (RuntimeJournalEntry, []GuardGrant, error) {
	return runtimeBuildEntry(m, org, node, ns, true)
}

func runtimeBuildEntry(m RuntimeMaterial, org, node uuid.UUID, ns string, secrets bool) (RuntimeJournalEntry, []GuardGrant, error) {
	fail := func() (RuntimeJournalEntry, []GuardGrant, error) {
		return RuntimeJournalEntry{}, nil, ErrRuntimeController
	}
	if !runtimeDeliveryValid(m.RuntimeDelivery, org, node, "apply") || m.CoversDeliveryRevision != 0 || (secrets && !validDigest(m.Policy.Hash)) || len(m.Policy.Grants) > 128 {
		return fail()
	}
	local, ok := runtimePrefixes(m.Manifest.LocalPrefixes)
	if !ok {
		return fail()
	}
	remote, ok := runtimePrefixes(m.Manifest.RemotePrefixes)
	if !ok {
		return fail()
	}
	public, e := netip.ParseAddr(m.Manifest.CustomerOutsideAddress)
	if e != nil || !public.Is4() {
		return fail()
	}
	out := RuntimeJournalEntry{DeliveryID: m.ID, SiteID: m.Manifest.SiteID, OwnershipDigest: m.OwnershipDigest, Phase: RuntimeReserved, Allocation: KernelAllocation{Namespace: ns, Generation: m.ID, ConnectionID: m.Manifest.ConnectionID}}
	for i, t := range m.Manifest.Tunnels {
		if t.Slot != i+1 || t.ID == uuid.Nil || t.SecretRevision <= 0 || t.LinkName != KernelTunnelName(t.ID) || t.XFRMID != KernelTunnelID(t.ID) || t.ReqID != t.XFRMID || t.RouteTable != 254 || t.RouteProtocol != 242 || t.RouteMetric != uint32(50001+i) || t.Selected != (i == 0) {
			return fail()
		}
		p, e := netip.ParsePrefix(t.InsideCIDR)
		if e != nil || !p.Addr().Is4() || p != p.Masked() || p.Bits() != 30 {
			return fail()
		}
		customer, e := netip.ParseAddr(t.CustomerInsideAddress)
		if e != nil || !p.Contains(customer) {
			return fail()
		}
		cloud, e := netip.ParseAddr(t.CloudInsideAddress)
		if e != nil || !p.Contains(cloud) || cloud == customer {
			return fail()
		}
		cb := cloud.As4()
		if cb[3]&3 == 0 || cb[3]&3 == 3 {
			return fail()
		}
		peer, e := netip.ParseAddr(t.OutsideAddress)
		if e != nil || !peer.Is4() {
			return fail()
		}
		out.Allocation.Tunnels[i] = KernelTunnelAllocation{TunnelID: t.ID, Slot: uint8(t.Slot), Name: t.LinkName, Alias: KernelTunnelAlias(m.ID, t.ID), XFRMID: t.XFRMID, InsideAddress: netip.PrefixFrom(customer, 30), RemotePrefixes: remote, Selected: t.Selected}
		out.Engines[i] = EngineTunnel{Binding: Binding{OrgID: org, GatewayID: node, ConnectionID: m.Manifest.ConnectionID, ConfigurationRevision: m.Manifest.ConfigurationRevision, DesiredRevision: m.DesiredRevision}, TunnelID: t.ID, SecretRevision: t.SecretRevision, XFRMID: t.XFRMID, ReqID: t.ReqID, LocalAddress: public, LocalIdentity: public, RemoteAddress: peer, RemoteIdentity: peer, LocalPrefixes: local, RemotePrefixes: remote}
		if !validEngineTunnel(out.Engines[i]) || (secrets && (m.Secrets[i].TunnelID != t.ID || m.Secrets[i].Revision != t.SecretRevision || !validEnginePSK([]byte(m.Secrets[i].PSK)))) {
			return fail()
		}
	}
	if !validKernelAllocation(out.Allocation) || out.Engines[0].RemoteAddress == out.Engines[1].RemoteAddress {
		return fail()
	}
	grants := []GuardGrant{}
	for _, g := range m.Policy.Grants {
		source, e := netip.ParsePrefix(g.Source)
		if e != nil || source != source.Masked() {
			return fail()
		}
		dest, e := netip.ParsePrefix(g.Destination)
		if e != nil || dest != dest.Masked() {
			return fail()
		}
		if !(withinPrefixes(source, local) && withinPrefixes(dest, remote) || withinPrefixes(source, remote) && withinPrefixes(dest, local)) {
			return fail()
		}
		protocol := GuardProtocol(g.Protocol)
		if protocol != GuardAny && protocol != GuardTCP && protocol != GuardUDP || g.PortLow > g.PortHigh || protocol == GuardAny && (g.PortLow != 0 || g.PortHigh != 0) {
			return fail()
		}
		grants = append(grants, GuardGrant{Source: source, Destination: dest, Protocol: protocol, PortLow: g.PortLow, PortHigh: g.PortHigh})
	}
	return out, grants, nil
}

func runtimeCleanupValid(c RuntimeCleanup, org, node uuid.UUID) bool {
	if !runtimeDeliveryValid(c.RuntimeDelivery, org, node, "cleanup") || !c.RetainGuard || len(c.Lineage) == 0 || len(c.Lineage) > 256 {
		return false
	}
	raw, e := json.Marshal(c.Lineage)
	if e != nil {
		return false
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != c.OwnershipDigest {
		return false
	}
	high := int64(0)
	var latest RuntimeManifest
	seen := map[uuid.UUID]bool{}
	for _, d := range c.Lineage {
		if !runtimeDeliveryValid(d, org, node, "apply") || d.Manifest.ConnectionID != c.Manifest.ConnectionID || seen[d.ID] {
			return false
		}
		seen[d.ID] = true
		if d.DesiredRevision > high {
			high = d.DesiredRevision
			latest = d.Manifest
		}
	}
	a, _ := json.Marshal(latest)
	b, _ := json.Marshal(c.Manifest)
	return high == c.CoversDeliveryRevision && high < c.DesiredRevision && string(a) == string(b)
}
