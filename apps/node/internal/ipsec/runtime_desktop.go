package ipsec

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"github.com/google/uuid"
	bgpengine "github.com/tunnexio/tunnex/apps/node/internal/bgp"
	"net/netip"
	"os/exec"
	"reflect"
	"sort"
	"strings"
	"time"
)

func validDesktopKey(s string) bool {
	key, e := base64.StdEncoding.DecodeString(s)
	return e == nil && len(key) == 32 && s == base64.StdEncoding.EncodeToString(key)
}
func runtimeDesktopGrants(m RuntimeMaterial, local, remote []netip.Prefix) ([]GuardGrant, error) {
	if len(m.Policy.DesktopGrants) == 0 {
		return nil, nil
	}
	if m.Manifest.ProfileID != "aws-bgp-ipv4-v1" || m.Manifest.BGP == nil {
		return nil, ErrRuntimeController
	}
	var out []GuardGrant
	subjects := map[netip.Prefix]string{}
	for _, d := range m.Policy.DesktopGrants {
		src, e := netip.ParsePrefix(d.Source)
		if e != nil || src.Bits() != 32 || !src.Addr().Is4() || !src.Addr().IsGlobalUnicast() || withinPrefixes(src, local) || withinPrefixes(src, remote) {
			return nil, ErrRuntimeController
		}
		dst, e := netip.ParsePrefix(d.Destination)
		if e != nil || dst != dst.Masked() || !withinPrefixes(dst, remote) {
			return nil, ErrRuntimeController
		}
		id, e := uuid.Parse(d.DeviceID)
		if e != nil || id == uuid.Nil || !validDesktopKey(d.PublicKey) {
			return nil, ErrRuntimeController
		}
		if prior, ok := subjects[src]; ok && prior != d.DeviceID+":"+d.PublicKey {
			return nil, ErrRuntimeController
		}
		subjects[src] = d.DeviceID + ":" + d.PublicKey
		rule, e := uuid.Parse(d.RuleID)
		if e != nil || rule == uuid.Nil {
			return nil, ErrRuntimeController
		}
		proto := GuardProtocol(d.Protocol)
		if proto != GuardAny && proto != GuardTCP && proto != GuardUDP || d.PortLow > d.PortHigh || proto == GuardAny && (d.PortLow != 0 || d.PortHigh != 0) || proto != GuardAny && d.PortLow == 0 {
			return nil, ErrRuntimeController
		}
		var expires time.Time
		if d.ExpiresAt != nil {
			expires = *d.ExpiresAt
			if !expires.After(time.Now()) {
				return nil, ErrRuntimeController
			}
		}
		out = append(out, GuardGrant{Source: src, Destination: dst, Protocol: proto, PortLow: d.PortLow, PortHigh: d.PortHigh, DesktopDeviceID: id, DesktopPublicKey: d.PublicKey, DesktopExpiresAt: expires})
	}
	if len(subjects)+len(local) > 64 {
		return nil, ErrRuntimeController
	}
	return out, nil
}
func guardGrantIngress(c GuardConnection, g GuardGrant) []int {
	if g.DesktopDeviceID != uuid.Nil {
		return []int{g.DesktopIngressIndex}
	}
	return c.LocalIngressIndices
}
func validDesktopGuardGrant(g GuardGrant, c GuardConnection) bool {
	if g.DesktopDeviceID == uuid.Nil {
		return g.DesktopPublicKey == "" && g.DesktopIngressIndex == 0 && g.DesktopExpiresAt.IsZero()
	}
	if !validDesktopKey(g.DesktopPublicKey) || g.DesktopIngressIndex <= 0 || g.DesktopIngressIndex > 2147483647 || !g.Source.Addr().IsGlobalUnicast() || g.Source.Bits() != 32 || withinPrefixes(g.Source, c.Local) || withinPrefixes(g.Source, c.Remote) || !withinPrefixes(g.Destination, c.Remote) || g.HostOrigin || g.FQDNManaged || g.DNSResolver != (DNSResolverBinding{}) || !g.DesktopExpiresAt.IsZero() && !g.DesktopExpiresAt.After(time.Now()) {
		return false
	}
	for _, t := range c.Tunnels[:c.activeTunnelCount()] {
		if t.InterfaceIndex == g.DesktopIngressIndex {
			return false
		}
	}
	return true
}
func desktopExportPrefixes(grants []GuardGrant) []netip.Prefix {
	seen := map[netip.Prefix]bool{}
	for _, g := range grants {
		if g.DesktopDeviceID != uuid.Nil {
			seen[g.Source] = true
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]netip.Prefix, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}
func (c *RuntimeController) publishDesktopNAT(id uuid.UUID, grants []GuardGrant) {
	var entries []DesktopNATExemption
	for _, g := range grants {
		if g.DesktopDeviceID != uuid.Nil {
			entries = append(entries, DesktopNATExemption{g.Source, g.Destination})
		}
	}
	c.config.DesktopNAT.Set(id, entries)
}
func (c *RuntimeController) observeDesktopGrants(ctx context.Context, grants []GuardGrant) ([]GuardGrant, error) {
	if len(desktopExportPrefixes(grants)) == 0 {
		return grants, nil
	}
	if c.desktopObserve != nil {
		return c.desktopObserve(ctx, grants)
	}
	if c.config.DesktopNAT == nil {
		return nil, ErrRuntimeController
	}
	wg, err := exec.LookPath("wg")
	if err != nil {
		return nil, ErrRuntimeController
	}
	read := func(path string, args ...string) ([]byte, error) { return runKernelCommand(ctx, path, args...) }
	peers, err := read(wg, "show", "all", "allowed-ips")
	if err != nil {
		return nil, ErrRuntimeController
	}
	rules, err := read(c.config.NFTPath, "-j", "list", "table", "ip", "tunnex")
	if err != nil {
		return nil, ErrRuntimeController
	}
	out := append([]GuardGrant(nil), grants...)
	observedPeers := map[string]int{}
	for i, g := range out {
		if g.DesktopDeviceID == uuid.Nil {
			continue
		}
		if !g.DesktopExpiresAt.IsZero() && !g.DesktopExpiresAt.After(time.Now()) {
			return nil, ErrRuntimeController
		}
		iface, ok := desktopPeerInterface(string(peers), g.DesktopPublicKey, g.Source)
		if !ok {
			return nil, ErrRuntimeController
		}
		peerIdentity := g.Source.String() + ":" + g.DesktopPublicKey
		index := observedPeers[peerIdentity]
		if index == 0 {
			raw, err := read(c.config.IPPath, "-j", "-d", "link", "show", "dev", iface)
			if err != nil {
				return nil, ErrRuntimeController
			}
			var ok bool
			index, ok = desktopWireGuardIndex(raw, iface)
			if !ok {
				return nil, ErrRuntimeController
			}
			route, err := read(c.config.IPPath, "-j", "-4", "route", "get", g.Source.Addr().String())
			if err != nil || !desktopReturnRoute(route, iface, g.Source) {
				return nil, ErrRuntimeController
			}
			observedPeers[peerIdentity] = index
		}
		if !desktopNATExempt(rules, g.Source, g.Destination) {
			return nil, ErrRuntimeController
		}
		if g.DesktopIngressIndex != 0 && g.DesktopIngressIndex != index {
			return nil, ErrRuntimeController
		}
		out[i].DesktopIngressIndex = index
	}
	after, err := read(wg, "show", "all", "allowed-ips")
	if err != nil || string(after) != string(peers) {
		return nil, ErrRuntimeController
	}
	return out, nil
}
func (c *RuntimeController) proveDesktopGrants(ctx context.Context, grants []GuardGrant) error {
	observed, err := c.observeDesktopGrants(ctx, grants)
	if err != nil || !reflect.DeepEqual(observed, grants) {
		return ErrRuntimeController
	}
	return nil
}

// A matching enrolled key must own exactly that /32. Another peer advertising
// a broader covering range makes ownership ambiguous and is refused.
func desktopPeerInterface(raw, key string, source netip.Prefix) (string, bool) {
	found := ""
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			return "", false
		}
		for _, word := range fields[2:] {
			for _, cidr := range strings.Split(word, ",") {
				p, e := netip.ParsePrefix(cidr)
				if e != nil {
					if cidr == "(none)" {
						continue
					}
					return "", false
				}
				if !p.Overlaps(source) {
					continue
				}
				if p != source || fields[1] != key || found != "" || !validToken(fields[0]) || len(fields[0]) > 15 {
					return "", false
				}
				found = fields[0]
			}
		}
	}
	return found, found != ""
}
func desktopWireGuardIndex(raw []byte, iface string) (int, bool) {
	rows, ok := kernelObjects(raw)
	if !ok || len(rows) != 1 {
		return 0, false
	}
	row := rows[0]
	name, _ := kernelString(row, "ifname")
	index, ok := kernelNumber(row["ifindex"], 31)
	info, _ := kernelObject(row["linkinfo"])
	kind, _ := kernelString(info, "info_kind")
	flags, fok := kernelFlags(row["flags"])
	up := false
	for _, f := range flags {
		up = up || f == "UP"
	}
	return int(index), ok && fok && index > 0 && name == iface && kind == "wireguard" && up
}
func desktopReturnRoute(raw []byte, iface string, source netip.Prefix) bool {
	rows, ok := kernelObjects(raw)
	if !ok || len(rows) != 1 {
		return false
	}
	row := rows[0]
	dev, _ := kernelString(row, "dev")
	dst, _ := kernelString(row, "dst")
	if dev != iface || dst != source.Addr().String() {
		return false
	}
	for _, key := range []string{"gateway", "via", "encap", "encap_type", "nhid", "multipath", "nexthops"} {
		if _, ok := row[key]; ok {
			return false
		}
	}
	if kind, ok := row["type"]; ok && string(kind) != `"unicast"` {
		return false
	}
	if table, ok := row["table"]; ok && string(table) != `"main"` && string(table) != "254" {
		return false
	}
	return true
}
func desktopNATExempt(raw []byte, source, destination netip.Prefix) bool {
	rows, ok := runtimeCensusRows(raw)
	if !ok {
		return false
	}
	chainOwned := false
	for _, item := range rows {
		chain, ok := kernelObject(item["chain"])
		if !ok {
			continue
		}
		name, _ := kernelString(chain, "name")
		family, _ := kernelString(chain, "family")
		table, _ := kernelString(chain, "table")
		if name != "postrouting" || family != "ip" || table != "tunnex" {
			continue
		}
		kind, _ := kernelString(chain, "type")
		hook, _ := kernelString(chain, "hook")
		priority, ok := kernelNumber(chain["prio"], 32)
		if chainOwned || !ok || kind != "nat" || hook != "postrouting" || priority != 99 {
			return false
		}
		chainOwned = true
	}
	if !chainOwned {
		return false
	}
	for _, item := range rows {
		rule, ok := kernelObject(item["rule"])
		if !ok {
			continue
		}
		chain, _ := kernelString(rule, "chain")
		if chain != "postrouting" {
			continue
		}
		family, _ := kernelString(rule, "family")
		table, _ := kernelString(rule, "table")
		if family != "ip" || table != "tunnex" {
			return false
		}
		exprs, ok := kernelObjects(rule["expr"])
		if !ok {
			return false
		}
		comment, _ := kernelString(rule, "comment")
		// Require the exact bounded exemption before any action which could change
		// NAT evaluation. Earlier exemptions for different tuples are harmless.
		if comment != "tunnex_ipsec_desktop_no_snat" {
			return false
		}
		matches := map[string]netip.Prefix{}
		returned := false
		for _, expr := range exprs {
			if len(expr) != 1 {
				return false
			}
			if _, ok := expr["counter"]; ok {
				continue
			}
			if value, ok := expr["return"]; ok {
				if string(value) != "null" {
					return false
				}
				returned = true
				continue
			}
			match, ok := kernelObject(expr["match"])
			if !ok || returned {
				return false
			}
			op, _ := kernelString(match, "op")
			left, _ := kernelObject(match["left"])
			payload, _ := kernelObject(left["payload"])
			field, _ := kernelString(payload, "field")
			proto, _ := kernelString(payload, "protocol")
			if op != "==" || proto != "ip" || (field != "saddr" && field != "daddr") {
				return false
			}
			var p netip.Prefix
			if right, ok := kernelObject(match["right"]); ok {
				prefix, _ := kernelObject(right["prefix"])
				addr, _ := kernelString(prefix, "addr")
				bits, ok := kernelNumber(prefix["len"], 8)
				a, e := netip.ParseAddr(addr)
				if !ok || e != nil || !a.Is4() || bits > 32 {
					return false
				}
				p = netip.PrefixFrom(a, int(bits)).Masked()
			} else {
				var host string
				if json.Unmarshal(match["right"], &host) != nil {
					return false
				}
				a, e := netip.ParseAddr(host)
				if e != nil || !a.Is4() {
					return false
				}
				p = netip.PrefixFrom(a, 32)
			}
			if _, exists := matches[field]; exists {
				return false
			}
			matches[field] = p
		}
		if returned && len(matches) == 2 && matches["saddr"] == source && matches["daddr"] == destination {
			return true
		}
	}
	return false
}
func (c *RuntimeController) desktopBGPLocalExportProof(e RuntimeJournalEntry, cfg bgpengine.Config, env RuntimeEnvironment, grants []GuardGrant) (bgpengine.LocalExportProof, error) {
	if e.Allocation.ProfileID != "" || !e.Allocation.BGP || len(cfg.DesktopPrefixes) == 0 || !reflect.DeepEqual(cfg.DesktopPrefixes, desktopExportPrefixes(grants)) {
		return nil, ErrRuntimeController
	}
	inspector, ok := c.config.Environment.(interface {
		ObserveLocalExports(context.Context, KernelAllocation, [2]EngineTunnel) (RuntimeEnvironment, error)
	})
	if !ok {
		return nil, ErrRuntimeController
	}
	expected := append(append([]netip.Prefix(nil), cfg.LocalPrefixes...), cfg.DesktopPrefixes...)
	return func(ctx context.Context, prefixes []netip.Prefix) error {
		if !reflect.DeepEqual(prefixes, expected) || c.proveDesktopGrants(ctx, grants) != nil {
			return ErrRuntimeController
		}
		fresh, err := inspector.ObserveLocalExports(ctx, e.Allocation, e.Engines)
		if err != nil || !reflect.DeepEqual(fresh, env) {
			return ErrRuntimeController
		}
		return nil
	}, nil
}

// The ordinary lease owns every desktop export. Denial is committed before
// stopping processes; durable cleanup identity remains for exact recovery.
func (c *RuntimeController) stopUnleasedDesktopExports(entries []RuntimeJournalEntry, active map[uuid.UUID]runtimeActive) error {
	for _, entry := range entries {
		if len(c.bgpDesktopExports[entry.DeliveryID]) == 0 {
			continue
		}
		if _, live := active[entry.Allocation.ConnectionID]; live {
			continue
		}
		if process := c.bgpProcesses[entry.DeliveryID]; process != nil {
			if process.Close() != nil {
				return ErrRuntimeController
			}
			delete(c.bgpProcesses, entry.DeliveryID)
		}
	}
	return nil
}

// Reporting protocol support requires the actual source-preserving NAT bridge
// and independent BGP runtime qualification. Every device still needs live proof.
func (c *RuntimeController) DesktopTransitCapability() int {
	if c == nil || c.config.DesktopNAT == nil {
		return 0
	}
	return c.BGPCapability()
}
