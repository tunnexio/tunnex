package ipsec

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Frozen pre-refactor validators are the differential oracle, not production paths.
func frozenRuntimeHookCensus(raw []byte, protected []netip.Prefix) bool {
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
func frozenRuntimeDockerDNSCensus(raw, listing []byte, protected []netip.Prefix) bool {
	ports, ok := runtimeDockerDNSPorts(listing)
	if !ok {
		return false
	}
	loopback := netip.MustParsePrefix("127.0.0.0/8")
	for _, p := range protected {
		if !p.IsValid() || p.Overlaps(loopback) {
			return false
		}
	}
	root, ok := runtimeJSONObject(raw)
	if !ok || len(root) != 1 {
		return false
	}
	rows, ok := kernelObjects(root["nftables"])
	if !ok {
		return false
	}
	remaining := []map[string]json.RawMessage{}
	tables := 0
	chains := map[string]bool{}
	rules := map[string]bool{}
	match := func(proto, field string, right any) any {
		return map[string]any{"match": map[string]any{"op": "==", "left": map[string]any{"payload": map[string]any{"protocol": proto, "field": field}}, "right": right}}
	}
	equal := func(value any, want any) bool {
		encoded, _ := json.Marshal(want)
		var decoded any
		if json.Unmarshal(encoded, &decoded) != nil {
			return false
		}
		return reflect.DeepEqual(value, decoded)
	}
	for _, row := range rows {
		if len(row) != 1 {
			return false
		}
		for kind, value := range row {
			o, ok := kernelObject(value)
			if !ok {
				return false
			}
			family, _ := kernelString(o, "family")
			table, _ := kernelString(o, "table")
			if kind == "table" {
				table, _ = kernelString(o, "name")
			}
			if family != "ip" || table != "nat" {
				remaining = append(remaining, row)
				continue
			}
			var obj map[string]any
			if json.Unmarshal(value, &obj) != nil {
				return false
			}
			if h, exists := o["handle"]; exists {
				if _, ok := kernelNumber(h, 64); !ok {
					return false
				}
				delete(obj, "handle")
			}
			switch kind {
			case "table":
				tables++
				if !equal(obj, map[string]any{"family": "ip", "name": "nat"}) {
					return false
				}
			case "chain":
				name, _ := kernelString(o, "name")
				if chains[name] {
					return false
				}
				chains[name] = true
				want := map[string]any{"family": "ip", "table": "nat", "name": name}
				switch name {
				case "DOCKER_OUTPUT", "DOCKER_POSTROUTING":
				case "OUTPUT":
					want["type"] = "nat"
					want["hook"] = "output"
					want["prio"] = -100
					want["policy"] = "accept"
				case "POSTROUTING":
					want["type"] = "nat"
					want["hook"] = "postrouting"
					want["prio"] = 100
					want["policy"] = "accept"
				default:
					return false
				}
				if !equal(obj, want) {
					return false
				}
			case "rule":
				chain, _ := kernelString(o, "chain")
				expressions, ok := kernelObjects(o["expr"])
				if !ok {
					return false
				}
				clean := []any{}
				for _, expr := range expressions {
					if counter, exists := expr["counter"]; exists {
						counts, ok := kernelObject(counter)
						if !ok || len(expr) != 1 || len(counts) != 2 {
							return false
						}
						for _, k := range []string{"packets", "bytes"} {
							if _, ok := kernelNumber(counts[k], 64); !ok {
								return false
							}
						}
						continue
					}
					data, _ := json.Marshal(expr)
					var decoded any
					if json.Unmarshal(data, &decoded) != nil {
						return false
					}
					clean = append(clean, decoded)
				}
				obj["expr"] = clean
				var key string
				var expected []any
				switch chain {
				case "OUTPUT", "POSTROUTING":
					key = chain
					target := "DOCKER_OUTPUT"
					if chain == "POSTROUTING" {
						target = "DOCKER_POSTROUTING"
					}
					expected = []any{match("ip", "daddr", "127.0.0.11"), map[string]any{"jump": map[string]any{"target": target}}}
				case "DOCKER_OUTPUT", "DOCKER_POSTROUTING":
					for _, proto := range []string{"tcp", "udp"} {
						field, port, address, target := "dport", 53, "daddr", "DNAT"
						if chain == "DOCKER_POSTROUTING" {
							field, port, address, target = "sport", ports[proto], "saddr", "SNAT"
						}
						candidate := []any{match("ip", address, "127.0.0.11"), match(proto, field, port), map[string]any{"xt": map[string]any{"type": "target", "name": target}}}
						if equal(clean, candidate) {
							key = chain + ":" + proto
							expected = candidate
						}
						// Some nft/iptables versions expose the protocol port matcher
						// opaquely. Admit only its exact protocol-matched shape;
						// the independent iptables-save census proves the hidden
						// source/destination ports and translation for all six rules.
						opaque := []any{
							map[string]any{"match": map[string]any{"op": "==", "left": map[string]any{"meta": map[string]any{"key": "l4proto"}}, "right": proto}},
							match("ip", address, "127.0.0.11"),
							map[string]any{"xt": map[string]any{"type": "match", "name": proto}},
							map[string]any{"xt": map[string]any{"type": "target", "name": target}},
						}
						if equal(clean, opaque) {
							key = chain + ":" + proto
							expected = opaque
						}
					}
				default:
					return false
				}
				if key == "" || rules[key] || !equal(obj, map[string]any{"family": "ip", "table": "nat", "chain": chain, "expr": expected}) {
					return false
				}
				rules[key] = true
			default:
				return false
			}
		}
	}
	if tables != 1 || len(chains) != 4 || len(rules) != 6 {
		return false
	}
	filtered, err := json.Marshal(map[string]any{"nftables": remaining})
	return err == nil && frozenRuntimeHookCensus(filtered, protected)
}

func TestRuntimeCensusSnapshotDifferential(t *testing.T) {
	listing, e := os.ReadFile("testdata/runtime-docker-dns-save.txt")
	if e != nil {
		t.Fatal(e)
	}
	paths, _ := filepath.Glob("testdata/*docker*nft*.json")
	paths = append(paths, "testdata/docker-dns-native/nft.json")
	if len(paths) == 0 {
		t.Fatal("fixtures")
	}
	for _, path := range paths {
		if strings.Contains(path, "docker-dns-native") {
			listing, e = os.ReadFile("testdata/docker-dns-native/iptables-save.txt")
			if e != nil {
				t.Fatal(e)
			}
		}
		raw, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		cases := [][]byte{raw, []byte(`{"nftables":[],"extra":1}`), []byte(`{"nftables":[],"nftables":[]}`), []byte(`{"nftables":[{"table":{"name":"a","name":"b"}}]}`), []byte(`{"nftables":[`), []byte(`{"nftables":[{"unexpected":{}}]}`), append(append([]byte{}, raw...), []byte(` {}`)...), bytes.Repeat([]byte(" "), kernelOutputLimit+1)}
		for _, pair := range [][2]string{{`"DNAT"`, `"REDIRECT"`}, {`"udp"`, `"icmp"`}, {`"nat"`, `"foreign"`}, {`"127.0.0.11"`, `"10.20.0.2"`}, {`40101`, `40102`}} {
			cases = append(cases, []byte(strings.ReplaceAll(string(raw), pair[0], pair[1])))
		}
		var doc map[string][]map[string]any
		if json.Unmarshal(raw, &doc) != nil {
			t.Fatal("fixture")
		}
		doc["nftables"] = append(doc["nftables"], map[string]any{"chain": map[string]any{"family": "ip", "table": "foreign", "name": "forward", "type": "filter", "hook": "forward", "prio": 0, "policy": "accept"}})
		foreign, _ := json.Marshal(doc)
		cases = append(cases, foreign)
		for i, data := range cases {
			for _, protected := range [][]netip.Prefix{nil, {netip.MustParsePrefix("10.20.0.0/24")}, {netip.MustParsePrefix("127.0.0.0/8")}} {
				if runtimeHookCensus(data, protected) != frozenRuntimeHookCensus(data, protected) {
					t.Fatalf("hook %s/%d", path, i)
				}
				for _, save := range [][]byte{listing, nil, bytes.Repeat([]byte(" "), 65537), []byte(strings.ReplaceAll(string(listing), "40101", "40102")), append(append([]byte{}, listing...), []byte("*filter\nCOMMIT\n")...)} {
					if runtimeDockerDNSCensus(data, save, protected) != frozenRuntimeDockerDNSCensus(data, save, protected) {
						t.Fatalf("docker %s/%d", path, i)
					}
				}
			}
		}
	}
}
func BenchmarkRuntimeCensusFreshSnapshot(b *testing.B) {
	raw, e := os.ReadFile("testdata/runtime-docker-dns-nft.json")
	if e != nil {
		b.Fatal(e)
	}
	listing, e := os.ReadFile("testdata/runtime-docker-dns-save.txt")
	if e != nil {
		b.Fatal(e)
	}
	var doc map[string][]map[string]any
	if json.Unmarshal(raw, &doc) != nil {
		b.Fatal("fixture")
	}
	for i := 0; i < 200; i++ {
		doc["nftables"] = append(doc["nftables"], map[string]any{"rule": map[string]any{"family": "inet", "table": "tunnex_ipsec", "chain": "forward", "expr": []any{map[string]any{"counter": map[string]any{"packets": 0, "bytes": 0}}}}})
	}
	raw, _ = json.Marshal(doc)
	b.Run("frozen", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if frozenRuntimeHookCensus(raw, nil) || !frozenRuntimeDockerDNSCensus(raw, listing, nil) {
				b.Fatal("fixture")
			}
		}
	})
	b.Run("snapshot", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			rows, ok := runtimeCensusRows(raw)
			if !ok || runtimeHookCensusRows(rows, nil) || !runtimeDockerDNSCensusRows(rows, listing, nil) {
				b.Fatal("fixture")
			}
		}
	})
}

func TestRuntimeCensusEscapedFilteredSizeBoundary(t *testing.T) {
	raw, e := os.ReadFile("testdata/runtime-docker-dns-nft.json")
	if e != nil {
		t.Fatal(e)
	}
	listing, e := os.ReadFile("testdata/runtime-docker-dns-save.txt")
	if e != nil {
		t.Fatal(e)
	}
	var doc map[string][]map[string]any
	if json.Unmarshal(raw, &doc) != nil {
		t.Fatal("fixture")
	}
	doc["nftables"] = append(doc["nftables"], map[string]any{"table": map[string]any{"family": "inet", "name": "tunnex_ipsec", "comment": strings.Repeat("<", 200000)}})
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if encoder.Encode(doc) != nil {
		t.Fatal("encode")
	}
	data := encoded.Bytes()
	if len(data) >= kernelOutputLimit {
		t.Fatal("raw must fit")
	}
	if frozenRuntimeDockerDNSCensus(data, listing, nil) {
		t.Fatal("old filtered size bound must refuse")
	}
	if runtimeDockerDNSCensus(data, listing, nil) {
		t.Fatal("escaped filtered size bound lost")
	}
}
