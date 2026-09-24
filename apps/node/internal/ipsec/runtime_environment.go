package ipsec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
)

var ErrRuntimeEnvironment = errors.New("IPsec local environment unavailable")

type runtimeEnvironmentInspector struct {
	ip, nft   func(context.Context, ...string) ([]byte, error)
	namespace func() (string, error)
	drain     func(context.Context, []RuntimeJournalEntry) error
}

func NewRuntimeEnvironmentInspector(ipPath, nftPath string) (RuntimeEnvironmentInspector, error) {
	if !filepath.IsAbs(ipPath) || !filepath.IsAbs(nftPath) {
		return nil, ErrRuntimeEnvironment
	}
	return &runtimeEnvironmentInspector{ip: func(c context.Context, a ...string) ([]byte, error) { return runKernelCommand(c, ipPath, a...) }, nft: func(c context.Context, a ...string) ([]byte, error) { return runKernelCommand(c, nftPath, a...) }, namespace: func() (string, error) { return os.Readlink("/proc/self/ns/net") }, drain: runtimeDrainConntrack}, nil
}
func (r *runtimeEnvironmentInspector) Drain(ctx context.Context, entries []RuntimeJournalEntry) error {
	if r == nil || r.drain == nil || len(entries) == 0 {
		return ErrRuntimeEnvironment
	}
	return r.drain(ctx, entries)
}
func runtimeJSONObject(raw []byte) (map[string]json.RawMessage, bool) {
	if len(raw) > kernelOutputLimit {
		return nil, false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if !kernelJSONValue(d, 0) {
		return nil, false
	}
	if _, e := d.Token(); e != io.EOF {
		return nil, false
	}
	return kernelObject(raw)
}
func runtimeDefaultRules(raw []byte) bool {
	rows, ok := kernelObjects(raw)
	if !ok || len(rows) < 3 {
		return false
	}
	expected := map[uint64]string{0: "local", 32766: "main", 32767: "default"}
	for _, row := range rows {
		n, ok := kernelNumber(row["priority"], 32)
		if !ok {
			return false
		}
		table, ok := kernelString(row, "table")
		if !ok {
			return false
		}
		if n == 100 && table == "main" {
			dst, _ := kernelString(row, "dst")
			p, e := netip.ParsePrefix(dst)
			if e != nil || !p.Addr().Is4() || p != p.Masked() {
				return false
			}
		} else if expected[n] != table {
			return false
		}
		delete(expected, n)
		for k := range row {
			switch k {
			case "priority", "src", "table", "protocol":
			case "dst":
				if n != 100 {
					return false
				}
			default:
				return false
			}
		}
		src, ok := kernelString(row, "src")
		if !ok || src != "all" {
			return false
		}
	}
	return len(expected) == 0
}

// A filter ACCEPT cannot skip later base hooks. Only side-effect-free filter
// statements are admitted outside our separately verified guard. NAT must be
// source scoped to a range disjoint from all protected payload addresses.
func runtimeHookCensus(raw []byte, protected []netip.Prefix) bool {
	root, ok := runtimeJSONObject(raw)
	if !ok || len(root) != 1 {
		return false
	}
	rows, ok := kernelObjects(root["nftables"])
	if !ok {
		return false
	}
	for _, item := range rows {
		if len(item) != 1 {
			return false
		}
		for kind, value := range item {
			if kind == "metainfo" {
				continue
			}
			o, ok := kernelObject(value)
			if !ok {
				return false
			}
			family, _ := kernelString(o, "family")
			table, _ := kernelString(o, "table")
			if kind == "table" {
				table, _ = kernelString(o, "name")
			}
			own := family == "inet" && table == "tunnex_ipsec"
			baseline := (family == "ip" || family == "ip6") && table == "tunnex"
			if !own && !baseline {
				return false
			}
			switch kind {
			case "table":
			case "chain":
				hook, exists := o["hook"]
				if !exists {
					continue
				}
				var h string
				if json.Unmarshal(hook, &h) != nil {
					return false
				}
				var prio int
				if json.Unmarshal(o["prio"], &prio) != nil {
					return false
				}
				typ, _ := kernelString(o, "type")
				policy, _ := kernelString(o, "policy")
				if own {
					if typ != "filter" || policy != "accept" || !((h == "forward" || h == "input" || h == "output") && prio == -10 || h == "postrouting" && (prio == 90 || prio == 300)) {
						return false
					}
				} else if !((h == "forward" && prio == 0 && typ == "filter" && policy == "drop") || (h == "postrouting" && prio == 99 && typ == "nat" && policy == "accept")) {
					return false
				}
			case "rule":
				if own {
					continue
				}
				exprs, ok := kernelObjects(o["expr"])
				if !ok {
					return false
				}
				masq := false
				var source netip.Prefix
				for _, e := range exprs {
					if len(e) != 1 {
						return false
					}
					for op, v := range e {
						switch op {
						case "match":
							m, ok := kernelObject(v)
							if !ok {
								return false
							}
							left, _ := kernelObject(m["left"])
							payload, _ := kernelObject(left["payload"])
							field, _ := kernelString(payload, "field")
							protocol, _ := kernelString(payload, "protocol")
							operation, _ := kernelString(m, "op")
							if field == "saddr" && protocol == "ip" && operation == "==" {
								right, _ := kernelObject(m["right"])
								p, _ := kernelObject(right["prefix"])
								address, _ := kernelString(p, "addr")
								length, ok := kernelNumber(p["len"], 8)
								a, err := netip.ParseAddr(address)
								if ok && err == nil && a.Is4() && length <= 32 {
									source = netip.PrefixFrom(a, int(length)).Masked()
								}
							}
						case "mangle":
							m, ok := kernelObject(v)
							if !ok || len(m) != 2 {
								return false
							}
							key, _ := kernelObject(m["key"])
							opt, _ := kernelObject(key["tcp option"])
							value, _ := kernelObject(m["value"])
							rt, _ := kernelObject(value["rt"])
							name, _ := kernelString(opt, "name")
							field, _ := kernelString(opt, "field")
							rtkey, _ := kernelString(rt, "key")
							if len(key) != 1 || len(opt) != 2 || len(value) != 1 || len(rt) != 1 || name != "maxseg" || field != "size" || rtkey != "mtu" {
								return false
							}
						case "masquerade":
							if masq || family != "ip" || !source.IsValid() {
								return false
							}
							for _, p := range protected {
								if source.Overlaps(p) {
									return false
								}
							}
							masq = true
						case "counter", "accept", "drop", "reject", "return", "jump", "goto", "log", "limit":
						default:
							return false
						}
					}
				}
				if masq {
					if family != "ip" || !source.IsValid() {
						return false
					}
					for _, p := range protected {
						if source.Overlaps(p) {
							return false
						}
					}
				}
			case "set", "element":
				if !own {
					return false
				}
			default:
				return false
			}
		}
	}
	return true
}
func (r *runtimeEnvironmentInspector) Observe(ctx context.Context, a KernelAllocation, engines [2]EngineTunnel) (RuntimeEnvironment, error) {
	fail := func() (RuntimeEnvironment, error) { return RuntimeEnvironment{}, ErrRuntimeEnvironment }
	if r == nil || r.ip == nil || r.nft == nil || r.namespace == nil || !validKernelAllocation(a) {
		return fail()
	}
	ctx, cancel := context.WithTimeout(ctx, kernelReadTimeout)
	defer cancel()
	ns, e := r.namespace()
	if e != nil || ns != a.Namespace {
		return fail()
	}
	protected := append(append([]netip.Prefix{}, engines[0].LocalPrefixes...), engines[0].RemotePrefixes...)
	if len(engines[0].LocalPrefixes) == 0 || !sameEnginePrefixes(engines[0].LocalPrefixes, engines[1].LocalPrefixes) {
		return fail()
	}
	nft, e := r.nft(ctx, "-j", "list", "ruleset")
	if e != nil || !runtimeHookCensus(nft, protected) {
		return fail()
	}
	rules, e := r.ip(ctx, "-j", "-4", "rule", "show")
	if e != nil || !runtimeDefaultRules(rules) {
		return fail()
	}
	links, e := r.ip(ctx, "-j", "-d", "link", "show")
	if e != nil {
		return fail()
	}
	objects, ok := kernelObjects(links)
	if !ok {
		return fail()
	}
	physical := map[string]int{}
	indices := map[uint64]bool{}
	for _, o := range objects {
		name, _ := kernelString(o, "ifname")
		idx, ok := kernelNumber(o["ifindex"], 31)
		if !ok || idx == 0 || indices[idx] {
			return fail()
		}
		indices[idx] = true
		flags, fok := kernelFlags(o["flags"])
		typ, _ := kernelString(o, "link_type")
		info, _ := kernelObject(o["linkinfo"])
		kind, _ := kernelString(info, "info_kind")
		up := false
		for _, f := range flags {
			up = up || f == "UP"
		}
		if ok && fok && idx > 0 && up && typ == "ether" && (kind == "" || kind == "veth") {
			if _, dup := physical[name]; dup {
				return fail()
			}
			physical[name] = int(idx)
		}
	}
	routes, e := r.ip(ctx, "-j", "-4", "route", "show", "table", "main")
	if e != nil {
		return fail()
	}
	routeRows, ok := kernelObjects(routes)
	if !ok {
		return fail()
	}
	addresses, e := r.ip(ctx, "-j", "-4", "address", "show")
	if e != nil {
		return fail()
	}
	addressRows, ok := kernelObjects(addresses)
	if !ok {
		return fail()
	}
	assigned := map[string]map[netip.Addr]bool{}
	for _, row := range addressRows {
		name, _ := kernelString(row, "ifname")
		infos, ok := kernelObjects(row["addr_info"])
		if !ok {
			return fail()
		}
		assigned[name] = map[netip.Addr]bool{}
		for _, info := range infos {
			value, _ := kernelString(info, "local")
			addr, err := netip.ParseAddr(value)
			if err == nil && addr.Is4() {
				assigned[name][addr] = true
			}
		}
	}
	out := RuntimeEnvironment{Namespace: ns}
	local := map[int]bool{}
	for _, prefix := range engines[0].LocalPrefixes {
		if !prefix.IsValid() || !prefix.Addr().Is4() || prefix != prefix.Masked() {
			return fail()
		}
		found := 0
		for _, row := range routeRows {
			for _, bad := range []string{"encap", "encap_type", "nhid", "multipath", "nexthops"} {
				if _, present := row[bad]; present {
					return fail()
				}
			}
			if typ, present := row["type"]; present && string(typ) != `"unicast"` {
				return fail()
			}
			if flags, present := row["flags"]; present {
				f, ok := kernelFlags(flags)
				if !ok || len(f) != 0 {
					return fail()
				}
			}
			dst, _ := kernelString(row, "dst")
			p, err := netip.ParsePrefix(dst)
			if err != nil || !p.Overlaps(prefix) {
				continue
			}
			dev, _ := kernelString(row, "dev")
			index := physical[dev]
			if index == 0 || p.Bits() > prefix.Bits() {
				return fail()
			}
			if found != 0 && found != index {
				return fail()
			}
			found = index
		}
		if found == 0 {
			return fail()
		}
		local[found] = true
	}
	if len(local) != 1 {
		return fail()
	}
	for index := range local {
		out.LocalIngressIndices = append(out.LocalIngressIndices, index)
	}
	sort.Ints(out.LocalIngressIndices)
	peerReads := [2][]byte{}
	for i, engine := range engines {
		if engine.TunnelID != a.Tunnels[i].TunnelID || engine.XFRMID != a.Tunnels[i].XFRMID || engine.Binding.ConnectionID != a.ConnectionID || !engine.RemoteAddress.Is4() {
			return fail()
		}
		raw, e := r.ip(ctx, "-j", "-4", "route", "get", engine.RemoteAddress.String())
		if e != nil {
			return fail()
		}
		peerReads[i] = raw
		rows, ok := kernelObjects(raw)
		if !ok || len(rows) != 1 {
			return fail()
		}
		row := rows[0]
		target, _ := kernelString(row, "dst")
		targetAddr, targetErr := netip.ParseAddr(target)
		if targetErr != nil || targetAddr != engine.RemoteAddress {
			return fail()
		}
		dev, _ := kernelString(row, "dev")
		src, _ := kernelString(row, "prefsrc")
		address, e := netip.ParseAddr(src)
		if e != nil || !address.Is4() || physical[dev] == 0 || !assigned[dev][address] {
			return fail()
		}
		for _, bad := range []string{"encap", "nhid", "multipath"} {
			if _, present := row[bad]; present {
				return fail()
			}
		}
		out.Underlays[i] = RuntimeUnderlay{InterfaceIndex: physical[dev], LocalAddress: address}
	}
	// Re-read independent interface and policy inventories before returning facts.
	again, e := r.ip(ctx, "-j", "-d", "link", "show")
	if e != nil || !bytes.Equal(again, links) {
		return fail()
	}
	again, e = r.ip(ctx, "-j", "-4", "rule", "show")
	if e != nil || !bytes.Equal(again, rules) {
		return fail()
	}
	again, e = r.nft(ctx, "-j", "list", "ruleset")
	if e != nil || !runtimeHookCensus(again, protected) {
		return fail()
	}
	again, e = r.ip(ctx, "-j", "-4", "route", "show", "table", "main")
	if e != nil || !bytes.Equal(again, routes) {
		return fail()
	}
	again, e = r.ip(ctx, "-j", "-4", "address", "show")
	if e != nil || !bytes.Equal(again, addresses) {
		return fail()
	}
	for i, engine := range engines {
		again, e = r.ip(ctx, "-j", "-4", "route", "get", engine.RemoteAddress.String())
		if e != nil || !bytes.Equal(again, peerReads[i]) {
			return fail()
		}
	}
	after, e := r.namespace()
	if e != nil || after != ns || ctx.Err() != nil {
		return fail()
	}
	return out, nil
}
