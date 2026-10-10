package ipsec

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"
)

// Docker's opaque xt targets need independent nft-backed iptables semantics.
// Only its complete loopback DNS topology is admitted; table names are not proof.
func runtimeQualifiedHookCensus(ctx context.Context, nftPath string, raw []byte, protected []netip.Prefix) bool {
	if runtimeHookCensus(raw, protected) {
		return true
	}
	root, ok := runtimeJSONObject(raw)
	if !ok {
		return false
	}
	rows, ok := kernelObjects(root["nftables"])
	if !ok {
		return false
	}
	present := false
	for _, row := range rows {
		for kind, value := range row {
			o, ok := kernelObject(value)
			if !ok {
				continue
			}
			family, _ := kernelString(o, "family")
			table, _ := kernelString(o, "table")
			if kind == "table" {
				table, _ = kernelString(o, "name")
			}
			present = present || (family == "ip" && table == "nat")
		}
	}
	if !present || !filepath.IsAbs(nftPath) {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	path := filepath.Join(filepath.Dir(nftPath), "iptables-nft-save")
	version, err := runKernelCommand(ctx, path, "-V")
	if err != nil || !strings.HasPrefix(strings.TrimSpace(string(version)), "iptables-nft-save v") || !strings.HasSuffix(strings.TrimSpace(string(version)), " (nf_tables)") {
		return false
	}
	listing, err := runKernelCommand(ctx, path, "-t", "nat")
	return err == nil && runtimeDockerDNSCensus(raw, listing, protected)
}

func runtimeDockerDNSPorts(listing []byte) (map[string]int, bool) {
	if len(listing) > 65536 {
		return nil, false
	}
	ports := map[string]int{}
	rules := map[string]int{}
	chains := map[string]bool{}
	opened, committed := false, false
	for _, line := range strings.Split(string(listing), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line == "*nat" && !opened && !committed {
			opened = true
			continue
		}
		if !opened || committed {
			return nil, false
		}
		if line == "COMMIT" {
			committed = true
			continue
		}
		fields := strings.Fields(line)
		if strings.HasPrefix(line, ":") {
			if len(fields) != 3 {
				return nil, false
			}
			name := strings.TrimPrefix(fields[0], ":")
			policy := "ACCEPT"
			if name == "DOCKER_OUTPUT" || name == "DOCKER_POSTROUTING" {
				policy = "-"
			}
			if name != "PREROUTING" && name != "INPUT" && name != "OUTPUT" && name != "POSTROUTING" && name != "DOCKER_OUTPUT" && name != "DOCKER_POSTROUTING" || chains[name] || fields[1] != policy {
				return nil, false
			}
			counter := strings.TrimSuffix(strings.TrimPrefix(fields[2], "["), "]")
			values := strings.Split(counter, ":")
			if len(values) != 2 || fields[2] != "["+counter+"]" {
				return nil, false
			}
			for _, v := range values {
				if _, err := strconv.ParseUint(v, 10, 64); err != nil {
					return nil, false
				}
			}
			chains[name] = true
			continue
		}
		normalized := strings.Join(fields, " ")
		rules[normalized]++
		if len(fields) == 14 && fields[0] == "-A" && fields[1] == "DOCKER_OUTPUT" && fields[2] == "-d" && fields[3] == "127.0.0.11/32" && fields[4] == "-p" && (fields[5] == "tcp" || fields[5] == "udp") && fields[6] == "-m" && fields[7] == fields[5] && fields[8] == "--dport" && fields[9] == "53" && fields[10] == "-j" && fields[11] == "DNAT" && fields[12] == "--to-destination" {
			text := strings.TrimPrefix(fields[13], "127.0.0.11:")
			port, err := strconv.Atoi(text)
			if err != nil || port < 1024 || port > 65535 || fields[13] != "127.0.0.11:"+strconv.Itoa(port) || ports[fields[5]] != 0 {
				return nil, false
			}
			ports[fields[5]] = port
		}
	}
	if !committed || len(chains) != 6 || len(ports) != 2 || len(rules) != 6 {
		return nil, false
	}
	expected := []string{"-A OUTPUT -d 127.0.0.11/32 -j DOCKER_OUTPUT", "-A POSTROUTING -d 127.0.0.11/32 -j DOCKER_POSTROUTING"}
	for _, proto := range []string{"tcp", "udp"} {
		expected = append(expected, fmt.Sprintf("-A DOCKER_OUTPUT -d 127.0.0.11/32 -p %s -m %s --dport 53 -j DNAT --to-destination 127.0.0.11:%d", proto, proto, ports[proto]), fmt.Sprintf("-A DOCKER_POSTROUTING -s 127.0.0.11/32 -p %s -m %s --sport %d -j SNAT --to-source :53", proto, proto, ports[proto]))
	}
	for _, line := range expected {
		if rules[line] != 1 {
			return nil, false
		}
	}
	return ports, true
}

func runtimeDockerDNSCensus(raw, listing []byte, protected []netip.Prefix) bool {
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
	return err == nil && runtimeHookCensus(filtered, protected)
}
