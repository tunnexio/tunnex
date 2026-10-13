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
	"reflect"
	"sort"
	"time"
	"unicode/utf8"
)

var ErrRuntimeEnvironment = errors.New("IPsec local environment unavailable")

type runtimeEnvironmentInspector struct {
	diagnostic func(RuntimeDiagnostic)
	nftPath    string
	ip, nft    func(context.Context, ...string) ([]byte, error)
	namespace  func() (string, error)
	drain      func(context.Context, []RuntimeJournalEntry) error
}

func NewRuntimeEnvironmentInspector(ipPath, nftPath string) (RuntimeEnvironmentInspector, error) {
	return NewRuntimeEnvironmentInspectorWithDiagnostics(ipPath, nftPath, nil)
}

// NewRuntimeEnvironmentInspectorWithDiagnostics reports fixed observation stages only.
func NewRuntimeEnvironmentInspectorWithDiagnostics(ipPath, nftPath string, diagnostic func(RuntimeDiagnostic)) (RuntimeEnvironmentInspector, error) {
	if !filepath.IsAbs(ipPath) || !filepath.IsAbs(nftPath) {
		return nil, ErrRuntimeEnvironment
	}
	return &runtimeEnvironmentInspector{diagnostic: diagnostic, nftPath: nftPath, ip: func(c context.Context, a ...string) ([]byte, error) { return runKernelCommand(c, ipPath, a...) }, nft: func(c context.Context, a ...string) ([]byte, error) { return runKernelCommand(c, nftPath, a...) }, namespace: func() (string, error) { return os.Readlink("/proc/self/ns/net") }, drain: runtimeDrainConntrack}, nil
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
	rows, ok := runtimeCensusRows(raw)
	return ok && runtimeHookCensusRows(rows, protected)
}

// Rows remain local to one freshly bounded, strictly validated snapshot.
func runtimeCensusRows(raw []byte) ([]map[string]json.RawMessage, bool) {
	root, ok := runtimeJSONObject(raw)
	if !ok || len(root) != 1 {
		return nil, false
	}
	data := root["nftables"]
	if len(data) > kernelDumpLimit || !utf8.Valid(data) {
		return nil, false
	}
	// runtimeJSONObject already walked this entire subtree, rejecting duplicate
	// keys, excessive depth and malformed JSON. Keep kernelObjects' remaining
	// array, count and row-shape checks without walking those tokens again.
	var values []json.RawMessage
	if json.Unmarshal(data, &values) != nil || values == nil || len(values) > kernelEntryLimit {
		return nil, false
	}
	objects := make([]map[string]json.RawMessage, 0, len(values))
	for _, value := range values {
		object, ok := kernelObject(value)
		if !ok {
			return nil, false
		}
		objects = append(objects, object)
	}
	return objects, true
}

func runtimeHookCensusRows(rows []map[string]json.RawMessage, protected []netip.Prefix) bool {
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
							chain, _ := kernelString(o, "chain")
							if (family == "ip" || family == "ip6") && table == "tunnex" && chain == "forward" && runtimeFQDNConntrackMark(v) {
								continue
							}
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
	return r.observe(ctx, a, engines, false)
}
func (r *runtimeEnvironmentInspector) observeTimed(ctx context.Context, a KernelAllocation, engines [2]EngineTunnel, observe func(runtimeEnvironmentTiming)) (RuntimeEnvironment, error) {
	return r.observeWithCommands(ctx, a, engines, observe, runKernelCommand)
}
func (r *runtimeEnvironmentInspector) observeWithCommands(ctx context.Context, a KernelAllocation, engines [2]EngineTunnel, observe func(runtimeEnvironmentTiming), hookRun func(context.Context, string, ...string) ([]byte, error)) (RuntimeEnvironment, error) {
	return r.observeQualified(ctx, a, engines, observe, hookRun, false)
}
func (r *runtimeEnvironmentInspector) ObserveLocalExports(ctx context.Context, a KernelAllocation, engines [2]EngineTunnel) (RuntimeEnvironment, error) {
	if a.ProfileID != GCPHABGPProfile || !a.BGP {
		return RuntimeEnvironment{}, ErrRuntimeEnvironment
	}
	return r.observe(ctx, a, engines, true)
}
func (r *runtimeEnvironmentInspector) observe(ctx context.Context, a KernelAllocation, engines [2]EngineTunnel, localExports bool) (RuntimeEnvironment, error) {
	return r.observeQualified(ctx, a, engines, nil, runKernelCommand, localExports)
}
func (r *runtimeEnvironmentInspector) observeQualified(ctx context.Context, a KernelAllocation, engines [2]EngineTunnel, observe func(runtimeEnvironmentTiming), hookRun func(context.Context, string, ...string) ([]byte, error), localExports bool) (RuntimeEnvironment, error) {
	// Residual verification includes namespace checks and millisecond rounding; it is not pure parser CPU.
	var timing runtimeEnvironmentCommandTiming
	started := time.Now()
	if observe != nil {
		defer func() {
			measured := timing.result()
			measured.VerificationMillis = time.Since(started).Milliseconds() - measured.CommandMillis
			if measured.VerificationMillis < 0 {
				measured.VerificationMillis = 0
			}
			observe(measured)
		}()
	}
	stage := "env_input"
	fail := func() (RuntimeEnvironment, error) {
		if r != nil {
			emitRuntimeDiagnostic(r.diagnostic, ctx, "environment_observe", stage, a.ConnectionID, started, true)
		}
		return RuntimeEnvironment{}, ErrRuntimeEnvironment
	}
	if r == nil || r.ip == nil || r.nft == nil || r.namespace == nil || !validKernelAllocation(a) {
		return fail()
	}
	wrap := func(run func(context.Context, ...string) ([]byte, error)) func(context.Context, ...string) ([]byte, error) {
		return func(ctx context.Context, args ...string) ([]byte, error) {
			if ctx.Err() != nil {
				return nil, ErrRuntimeEnvironment
			}
			start := time.Now()
			raw, err := run(ctx, args...)
			if observe != nil {
				timing.record(start, time.Now())
			}
			return raw, err
		}
	}
	ip, nftRun := wrap(r.ip), wrap(r.nft)
	original := hookRun
	hookRun = func(ctx context.Context, path string, args ...string) ([]byte, error) {
		return wrap(func(c context.Context, a ...string) ([]byte, error) { return original(c, path, a...) })(ctx, args...)
	}
	ctx, cancel := context.WithTimeout(ctx, kernelReadTimeout)
	defer cancel()
	stage = "env_namespace_before"
	ns, e := r.namespace()
	if e != nil || ns != a.Namespace {
		return fail()
	}
	stage = "env_material"
	protected := append(append([]netip.Prefix{}, engines[0].LocalPrefixes...), engines[0].RemotePrefixes...)
	if engineTunnelCount(engines) != a.activeTunnelCount() || (a.activeTunnelCount() == 1 && !emptyEngineTunnel(engines[1])) || len(engines[0].LocalPrefixes) == 0 || (a.activeTunnelCount() == 2 && !sameEnginePrefixes(engines[0].LocalPrefixes, engines[1].LocalPrefixes)) {
		return fail()
	}
	for i, engine := range engines[:engineTunnelCount(engines)] {
		if engine.ProfileID != a.ProfileID || engine.TunnelID != a.Tunnels[i].TunnelID || engine.XFRMID != a.Tunnels[i].XFRMID || engine.Binding.ConnectionID != a.ConnectionID || !engine.RemoteAddress.Is4() {
			return fail()
		}
	}
	var addressReadStarted time.Time
	snapshotIP := func(ctx context.Context, args ...string) ([]byte, error) {
		if len(args) == 4 && args[0] == "-j" && args[1] == "-4" && args[2] == "address" && args[3] == "show" && addressReadStarted.IsZero() {
			addressReadStarted = time.Now()
		}
		return ip(ctx, args...)
	}
	readSnapshot := func() (runtimeEnvironmentSnapshot, bool) {
		return runtimeReadEnvironmentSnapshot(ctx, snapshotIP, func(c context.Context) ([]byte, error) {
			raw, err := nftRun(c, "-j", "list", "ruleset")
			if err != nil || !runtimeQualifiedHookCensusWithCommands(c, r.nftPath, raw, protected, hookRun) {
				return nil, ErrRuntimeEnvironment
			}
			return raw, nil
		}, engines)
	}
	first, valid := readSnapshot()
	if !valid {
		return fail()
	}
	rules, links := first.rules, first.links
	if !runtimeDefaultRules(rules) {
		return fail()
	}
	objects, ok := kernelObjects(links)
	if !ok {
		return fail()
	}
	physical := map[string]int{}
	downBridges := map[string]bool{}
	physicalMTU := map[string]uint32{}
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
		state, _ := kernelString(o, "operstate")
		noCarrier, lowerUp := false, false
		for _, f := range flags {
			noCarrier = noCarrier || f == "NO-CARRIER"
			lowerUp = lowerUp || f == "LOWER_UP"
		}
		if fok && typ == "ether" && kind == "bridge" && state == "DOWN" && !lowerUp && (!up || noCarrier) {
			downBridges[name] = true
		}
		if ok && fok && idx > 0 && up && typ == "ether" && (kind == "" || kind == "veth") {
			if _, dup := physical[name]; dup {
				return fail()
			}
			physical[name] = int(idx)
			mtu, valid := kernelNumber(o["mtu"], 32)
			if !valid || mtu < 68 || mtu > 65535 {
				return fail()
			}
			physicalMTU[name] = uint32(mtu)
		}
	}
	routes := first.routes
	routeRows, ok := kernelObjects(routes)
	if !ok {
		return fail()
	}
	addresses := first.addresses
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
	stage = "env_local_coverage"
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
			p, valid := runtimeMainRoutePrefix(row)
			dev, deviceOK := kernelString(row, "dev")
			if !valid || !deviceOK || dev == "" {
				return fail()
			}
			gcp := a.ProfileID == GCPHABGPProfile || a.ProfileID == GCPClassicStaticProfile
			if flags, present := row["flags"]; present {
				f, ok := kernelFlags(flags)
				// An unrelated, assigned Docker bridge may be down. It cannot
				// supply LAN or underlay identity, and protected routes still refuse.
				disjointBridge := gcp && len(f) == 1 && f[0] == "linkdown" && runtimeDisjointDownBridge(row, p, protected, downBridges, assigned)
				if !ok || (len(f) != 0 && !disjointBridge) {
					return fail()
				}
			}
			if !p.IsValid() || !p.Overlaps(prefix) {
				continue
			}
			index := physical[dev]
			if index == 0 {
				return fail()
			}
			if p.Bits() > prefix.Bits() {
				if !gcp || !runtimeRoutedGatewayHost(row, p, prefix, routeRows, physical, assigned) {
					return fail()
				}
				continue // A gateway host is never proof of prefix coverage.
			}
			if _, routed := row["gateway"]; gcp && routed && !runtimeRoutedLocalPrefix(row, p, prefix, routeRows, physical, assigned) {
				return fail()
			}
			if localExports && (p != prefix || !runtimeLocalExportProtocol(row["protocol"])) {
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
	peerReads := first.peers
	for i, engine := range engines[:engineTunnelCount(engines)] {
		if engine.ProfileID != a.ProfileID || engine.TunnelID != a.Tunnels[i].TunnelID || engine.XFRMID != a.Tunnels[i].XFRMID || engine.Binding.ConnectionID != a.ConnectionID || !engine.RemoteAddress.Is4() {
			return fail()
		}
		raw := peerReads[i]
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
		outerMTU, valid := runtimeOuterMTU(physicalMTU[dev], row)
		if !valid {
			return fail()
		}
		out.Underlays[i] = RuntimeUnderlay{InterfaceIndex: physical[dev], LocalAddress: address, OuterMTU: outerMTU}
	}
	// The first complete snapshot is fully validated before any second-snapshot read.
	second, valid := readSnapshot()
	if !valid || !bytes.Equal(second.links, links) || !bytes.Equal(second.rules, rules) || !bytes.Equal(second.routes, routes) || !runtimeAddressBracket(addresses, second.addresses, time.Since(addressReadStarted)) {
		return fail()
	}
	for i := range engines[:engineTunnelCount(engines)] {
		if !bytes.Equal(second.peers[i], peerReads[i]) {
			return fail()
		}
	}
	stage = "env_namespace_after"
	after, e := r.namespace()
	if e != nil || after != ns || ctx.Err() != nil {
		return fail()
	}
	emitRuntimeDiagnostic(r.diagnostic, ctx, "environment_observe", "env_complete", a.ConnectionID, started, false)
	return out, nil
}

// iproute2 renders a host destination without /32. Do not silently hide an
// overlapping host or malformed destination while proving a protected prefix.
func runtimeMainRoutePrefix(row map[string]json.RawMessage) (netip.Prefix, bool) {
	for _, field := range []string{"gateway", "prefsrc"} {
		if _, present := row[field]; present {
			value, ok := kernelString(row, field)
			a, err := netip.ParseAddr(value)
			if !ok || err != nil || !a.Is4() {
				return netip.Prefix{}, false
			}
		}
	}
	dst, ok := kernelString(row, "dst")
	if !ok {
		return netip.Prefix{}, false
	}
	if dst == "default" {
		return netip.Prefix{}, true
	}
	if p, err := netip.ParsePrefix(dst); err == nil {
		return p, p.Addr().Is4() && p == p.Masked()
	}
	a, err := netip.ParseAddr(dst)
	if err != nil || !a.Is4() {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(a, 32), true
}

// The only narrow GCP route exception is the on-link gateway for one exact
// approved routed prefix. A default route, another host, or another interface
// cannot manufacture local coverage. Route order has no effect.
func runtimeRoutedGatewayHost(host map[string]json.RawMessage, p, prefix netip.Prefix, rows []map[string]json.RawMessage, physical map[string]int, assigned map[string]map[netip.Addr]bool) bool {
	if p.Bits() != 32 {
		return false
	}
	dev, _ := kernelString(host, "dev")
	scope, _ := kernelString(host, "scope")
	source, sourceOK := kernelString(host, "prefsrc")
	src, err := netip.ParseAddr(source)
	if scope != "link" || physical[dev] == 0 || !sourceOK || err != nil || !src.Is4() || !prefix.Contains(src) || !assigned[dev][src] {
		return false
	}
	if _, via := host["gateway"]; via {
		return false
	}
	matches := 0
	for _, route := range rows {
		covering, valid := runtimeMainRoutePrefix(route)
		if !valid || covering != prefix {
			continue
		}
		routeDev, _ := kernelString(route, "dev")
		gateway, _ := kernelString(route, "gateway")
		routeSource, _ := kernelString(route, "prefsrc")
		gw, err := netip.ParseAddr(gateway)
		if routeDev != dev || routeSource != source || err != nil || gw != p.Addr() {
			return false
		}
		matches++
	}
	return matches == 1
}

func runtimeDisjointDownBridge(row map[string]json.RawMessage, p netip.Prefix, protected []netip.Prefix, down map[string]bool, assigned map[string]map[netip.Addr]bool) bool {
	if !p.IsValid() {
		return false
	}
	for _, prefix := range protected {
		if p.Overlaps(prefix) {
			return false
		}
	}
	dev, _ := kernelString(row, "dev")
	scope, _ := kernelString(row, "scope")
	value, _ := kernelString(row, "prefsrc")
	src, err := netip.ParseAddr(value)
	if !down[dev] || scope != "link" || err != nil || !p.Contains(src) || !assigned[dev][src] {
		return false
	}
	_, via := row["gateway"]
	return !via
}

func runtimeRoutedLocalPrefix(route map[string]json.RawMessage, p, approved netip.Prefix, rows []map[string]json.RawMessage, physical map[string]int, assigned map[string]map[netip.Addr]bool) bool {
	if p != approved {
		return false
	}
	gateway, _ := kernelString(route, "gateway")
	gw, err := netip.ParseAddr(gateway)
	if err != nil || !approved.Contains(gw) {
		return false
	}
	matches := 0
	for _, host := range rows {
		hp, valid := runtimeMainRoutePrefix(host)
		if valid && hp.IsValid() && hp.Bits() == 32 && hp.Addr() == gw && runtimeRoutedGatewayHost(host, hp, approved, rows, physical, assigned) {
			matches++
		}
	}
	return matches == 1
}

func runtimeLocalExportProtocol(raw json.RawMessage) bool {
	var named string
	if json.Unmarshal(raw, &named) == nil {
		switch named {
		case "kernel", "static", "boot", "2", "3", "4", "242":
			return true
		}
		return false
	}
	n, ok := kernelNumber(raw, 32)
	return ok && (n == 2 || n == 3 || n == 4 || n == 242)
}

// Admit only the production S21 conntrack ownership transform, in its native
// canonical form. It cannot alter packet routing marks or unrelated ct bits.
func runtimeFQDNConntrackMark(raw json.RawMessage) bool {
	var actual, expected any
	if _, ok := runtimeJSONObject(raw); !ok {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&actual) != nil {
		return false
	}
	const canonical = `{"key":{"ct":{"key":"mark"}},"value":{"|":[{"&":[{"ct":{"key":"mark"}},4060086271]},16777216]}}`
	decoder = json.NewDecoder(bytes.NewBufferString(canonical))
	decoder.UseNumber()
	if decoder.Decode(&expected) != nil {
		return false
	}
	return reflect.DeepEqual(actual, expected)
}
