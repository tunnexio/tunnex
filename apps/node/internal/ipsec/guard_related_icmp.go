package ipsec

import (
	"fmt"
	"net/netip"
	"strings"
)

// Only encrypted remote fragmentation-needed replies to explicitly granted
// LOCAL-origin TCP parent connections. Router addresses must also belong to
// approved remote networks. Only /32 parent sources are supported: outer
// receiver and original parent sender both match the same constant. Broad
// source grants retain ICMP denial until exact association is qualified.
// Typed outer IPv4 router/receiver predicates establish the address family;
// native nft removes the redundant CT l3proto assertion and canonicalizes
// original addresses without a family field. CT protocol is direction-independent.
// This is not an ICMP grant or AWS PMTUD guarantee.
func guardRemoteFragmentNeeded(c GuardConnection, g GuardGrant, ingress, egress int, router netip.Prefix) guardRule {
	var b strings.Builder
	var expr []any
	fmt.Fprintf(&b, "    meta iif %d ", ingress)
	expr = append(expr, guardMatch("==", guardMeta("iif"), ingress))
	if egress > 0 {
		fmt.Fprintf(&b, "meta oif %d ", egress)
		expr = append(expr, guardMatch("==", guardMeta("oif"), egress))
	}
	fmt.Fprintf(&b, "ip saddr %s ip daddr %s icmp type 3 icmp code 4 ct state related ct direction reply ct protocol tcp ct original ip saddr %s ct original ip daddr %s ", router, g.Source, g.Source, g.Destination)
	expr = append(expr, guardMatch("==", guardPayload("ip", "saddr"), guardPrefixJSON(router)), guardMatch("==", guardPayload("ip", "daddr"), guardPrefixJSON(g.Source)), guardMatch("==", guardPayload("icmp", "type"), "destination-unreachable"), guardMatch("==", guardPayload("icmp", "code"), 4), guardMatch("in", guardCT("state"), "related"), guardMatch("==", guardCT("direction"), "reply"), guardMatch("==", guardCT("protocol"), "tcp"), guardMatch("==", guardOriginalCT("saddr", ""), guardCTPrefixJSON(g.Source)), guardMatch("==", guardOriginalCT("daddr", ""), guardCTPrefixJSON(g.Destination)))
	var port any = g.PortLow
	ports := fmt.Sprint(g.PortLow)
	if g.PortHigh != g.PortLow {
		port = map[string]any{"range": []uint16{g.PortLow, g.PortHigh}}
		ports = fmt.Sprintf("%d-%d", g.PortLow, g.PortHigh)
	}
	fmt.Fprintf(&b, "ct original proto-dst %s meta iif @%s counter accept\n", ports, guardReplyLeaseName(c.ID))
	expr = append(expr, guardMatch("==", guardOriginalCT("proto-dst", ""), port), guardMatch("==", guardMeta("iif"), "@"+guardReplyLeaseName(c.ID)), guardCounter(), guardVerdict("accept"))
	return guardRule{text: b.String(), expr: expr}
}
func guardOriginalCT(key, family string) any {
	v := map[string]any{"key": key, "dir": "original"}
	if family != "" {
		v["family"] = family
	}
	return map[string]any{"ct": v}
}
func guardCTPrefixJSON(p netip.Prefix) any {
	if p.Bits() == 32 {
		return p.Addr().String()
	}
	return guardPrefixJSON(p)
}
func addRemoteFragmentNeeded(c GuardConnection, g GuardGrant, forward, input *guardChain) {
	if c.PrefixOnly || c.PermitFor <= 0 || g.Protocol != GuardTCP || g.Source.Bits() != 32 || !withinPrefixes(g.Source, c.Local) || len(c.PermittedInterfaceIndices) == 0 {
		return
	}
	for _, tunnel := range c.ReplyIngressIndices {
		for _, router := range c.Remote {
			if g.HostOrigin {
				input.add(guardRemoteFragmentNeeded(c, g, tunnel, 0, router))
			} else {
				for _, local := range c.LocalIngressIndices {
					forward.add(guardRemoteFragmentNeeded(c, g, tunnel, local, router))
				}
			}
		}
	}
}
