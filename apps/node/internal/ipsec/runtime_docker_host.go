package ipsec

import (
	"context"
	"encoding/json"
	"net/netip"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// This is the standalone Docker default-bridge contract, not an allowance for
// arbitrary filter/nat tables. Published ports, extra bridges and unknown rules
// remain unsupported. The save views prove every opaque xt match and target.
type runtimeDockerHostSave struct {
	chains map[string]string
	rules  map[string][]string
}

var runtimeDockerHostCounter = regexp.MustCompile(`^\[[0-9]+:[0-9]+\]$`)
var runtimeDockerHostIface = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,15}$`)

func runtimeDockerHostSaveTable(raw []byte, table string) (runtimeDockerHostSave, bool) {
	out := runtimeDockerHostSave{chains: map[string]string{}, rules: map[string][]string{}}
	if len(raw) == 0 || len(raw) > kernelOutputLimit {
		return out, false
	}
	opened, committed := false, false
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line == "*"+table && !opened && !committed {
			opened = true
			continue
		}
		if !opened || committed {
			return out, false
		}
		if line == "COMMIT" {
			committed = true
			continue
		}
		f := strings.Fields(line)
		if strings.HasPrefix(line, ":") {
			if len(f) != 3 || !runtimeDockerHostCounter.MatchString(f[2]) {
				return out, false
			}
			name := strings.TrimPrefix(f[0], ":")
			if _, exists := out.chains[name]; exists {
				return out, false
			}
			out.chains[name] = f[1]
		} else {
			if len(f) < 4 || f[0] != "-A" {
				return out, false
			}
			if _, exists := out.chains[f[1]]; !exists {
				return out, false
			}
			out.rules[f[1]] = append(out.rules[f[1]], strings.Join(f, " "))
		}
	}
	return out, opened && committed
}

type runtimeDockerHostTable struct {
	chains map[string]map[string]any
	rules  map[string][]map[string]any
}

func runtimeDockerHostTableKey(kind string, o map[string]json.RawMessage) string {
	family, _ := kernelString(o, "family")
	table, _ := kernelString(o, "table")
	if kind == "table" {
		table, _ = kernelString(o, "name")
	}
	if (family == "ip" || family == "ip6") && (table == "nat" || table == "filter") {
		return family + "/" + table
	}
	return ""
}

// Counters may advance during an inspection; handles, rule order and every
// semantic expression must remain identical across the independent save reads.
func runtimeDockerHostClean(value json.RawMessage, stripHandle bool) (map[string]any, bool) {
	o, ok := kernelObject(value)
	if !ok {
		return nil, false
	}
	var out map[string]any
	if json.Unmarshal(value, &out) != nil {
		return nil, false
	}
	if handle, exists := o["handle"]; exists {
		n, valid := kernelNumber(handle, 64)
		if !valid || n == 0 {
			return nil, false
		}
		if stripHandle {
			delete(out, "handle")
		} else {
			// Preserve all 64 bits in the ownership fence; float64 can merge
			// distinct handles even though the validated JSON numbers differ.
			out["handle"] = n
		}
	}
	if expr, exists := o["expr"]; exists {
		expressions, valid := kernelObjects(expr)
		if !valid {
			return nil, false
		}
		clean := []any{}
		counters := 0
		for _, expression := range expressions {
			if counter, exists := expression["counter"]; exists {
				counts, valid := kernelObject(counter)
				if !valid || len(expression) != 1 || len(counts) != 2 {
					return nil, false
				}
				for _, key := range []string{"packets", "bytes"} {
					if _, valid := kernelNumber(counts[key], 64); !valid {
						return nil, false
					}
				}
				counters++
				if counters > 1 {
					return nil, false
				}
				continue
			}
			encoded, _ := json.Marshal(expression)
			var decoded any
			if json.Unmarshal(encoded, &decoded) != nil {
				return nil, false
			}
			clean = append(clean, decoded)
		}
		out["expr"] = clean
	}
	return out, true
}

func runtimeDockerHostEqual(a, b any) bool {
	raw, err := json.Marshal(b)
	var decoded any
	return err == nil && json.Unmarshal(raw, &decoded) == nil && reflect.DeepEqual(a, decoded)
}

func runtimeDockerHostMatch(left any, op string, right any) any {
	return map[string]any{"match": map[string]any{"op": op, "left": left, "right": right}}
}
func runtimeDockerHostMeta(key, op, value string) any {
	return runtimeDockerHostMatch(map[string]any{"meta": map[string]any{"key": key}}, op, value)
}
func runtimeDockerHostAddress(family, field, op string, p netip.Prefix) any {
	var right any = map[string]any{"prefix": map[string]any{"addr": p.Addr().String(), "len": p.Bits()}}
	if p.Bits() == p.Addr().BitLen() {
		right = p.Addr().String()
	}
	return runtimeDockerHostMatch(map[string]any{"payload": map[string]any{"protocol": family, "field": field}}, op, right)
}
func runtimeDockerHostJump(target string) any {
	return map[string]any{"jump": map[string]any{"target": target}}
}
func runtimeDockerHostXT(typ, name string) any {
	return map[string]any{"xt": map[string]any{"type": typ, "name": name}}
}

func runtimeDockerHostPrefix(value string) (netip.Prefix, bool) {
	p, err := netip.ParsePrefix(value)
	return p, err == nil && p.Addr().Is4() && p.Bits() > 0 && p == p.Masked() && p.String() == value
}

func runtimeDockerHostRule(family, table, chain, comment string, expressions ...any) map[string]any {
	o := map[string]any{"family": family, "table": table, "chain": chain, "expr": expressions}
	if comment != "" {
		o["comment"] = comment
	}
	return o
}

// Known WireGuard accepts remain one-interface/one-prefix rules. A comment
// alone never grants admission, and all other DOCKER-USER rules are refused.
func runtimeDockerHostWGRule(rule map[string]any) (string, bool) {
	if rule["comment"] != "tunnex-site-fwd" {
		return "", false
	}
	expr, ok := rule["expr"].([]any)
	if !ok || len(expr) != 3 {
		return "", false
	}
	for _, iface := range []string{"iifname", "oifname"} {
		for _, field := range []string{"saddr", "daddr"} {
			data, _ := json.Marshal(expr[1])
			var m struct {
				Match struct {
					Right json.RawMessage `json:"right"`
				} `json:"match"`
			}
			if json.Unmarshal(data, &m) != nil {
				return "", false
			}
			p, valid := runtimeDockerHostNFTPrefix(m.Match.Right)
			if !valid {
				return "", false
			}
			want := runtimeDockerHostRule("ip", "filter", "DOCKER-USER", "tunnex-site-fwd", runtimeDockerHostMeta(iface, "==", "wg0"), runtimeDockerHostAddress("ip", field, "==", p), map[string]any{"accept": nil})
			if runtimeDockerHostEqual(rule, want) {
				dir, address := "-i", "-s"
				if iface == "oifname" {
					dir = "-o"
				}
				if field == "daddr" {
					address = "-d"
				}
				return "-A DOCKER-USER " + address + " " + p.String() + " " + dir + " wg0 -m comment --comment tunnex-site-fwd -j ACCEPT", true
			}
		}
	}
	return "", false
}

func runtimeDockerHostNFTPrefix(raw json.RawMessage) (netip.Prefix, bool) {
	var address string
	if json.Unmarshal(raw, &address) == nil {
		a, err := netip.ParseAddr(address)
		return netip.PrefixFrom(a, 32), err == nil && a.Is4() && a.String() == address
	}
	var obj struct {
		Prefix struct {
			Addr string `json:"addr"`
			Len  int    `json:"len"`
		} `json:"prefix"`
	}
	if json.Unmarshal(raw, &obj) != nil {
		return netip.Prefix{}, false
	}
	return runtimeDockerHostPrefix(obj.Prefix.Addr + "/" + strconv.Itoa(obj.Prefix.Len))
}

func runtimeDockerHostCensusRows(rows []map[string]json.RawMessage, listings map[string][]byte, protected []netip.Prefix) ([]any, bool) {
	tables := map[string]*runtimeDockerHostTable{}
	remaining := []map[string]json.RawMessage{}
	fence := []any{}
	for _, row := range rows {
		if len(row) != 1 {
			return nil, false
		}
		for kind, value := range row {
			o, ok := kernelObject(value)
			if !ok {
				return nil, false
			}
			key := runtimeDockerHostTableKey(kind, o)
			if key == "" {
				remaining = append(remaining, row)
				continue
			}
			clean, ok := runtimeDockerHostClean(value, true)
			stable, stableOK := runtimeDockerHostClean(value, false)
			if !ok || !stableOK {
				return nil, false
			}
			fence = append(fence, map[string]any{kind: stable})
			family, table, _ := strings.Cut(key, "/")
			view := tables[key]
			switch kind {
			case "table":
				if view != nil || !runtimeDockerHostEqual(clean, map[string]any{"family": family, "name": table}) {
					return nil, false
				}
				tables[key] = &runtimeDockerHostTable{chains: map[string]map[string]any{}, rules: map[string][]map[string]any{}}
			case "chain":
				name, _ := kernelString(o, "name")
				if view == nil || view.chains[name] != nil {
					return nil, false
				}
				view.chains[name] = clean
			case "rule":
				chain, _ := kernelString(o, "chain")
				if view == nil || view.chains[chain] == nil {
					return nil, false
				}
				view.rules[chain] = append(view.rules[chain], clean)
			default:
				return nil, false
			}
		}
	}
	if len(tables) != 4 || !runtimeHookCensusRows(remaining, protected) {
		return nil, false
	}
	for _, p := range protected {
		if !p.IsValid() {
			return nil, false
		}
	}
	for _, family := range []string{"ip", "ip6"} {
		for _, table := range []string{"nat", "filter"} {
			key := family + "/" + table
			view := tables[key]
			save, ok := runtimeDockerHostSaveTable(listings[key], table)
			if !ok || view == nil {
				return nil, false
			}
			if !runtimeDockerHostTableCensus(family, table, view, save, protected) {
				return nil, false
			}
		}
	}
	return fence, true
}

func runtimeDockerHostTableCensus(family, table string, view *runtimeDockerHostTable, save runtimeDockerHostSave, protected []netip.Prefix) bool {
	chains := map[string]string{}
	want := map[string][]map[string]any{}
	lines := map[string][]string{}
	add := func(chain, line string, expressions ...any) {
		want[chain] = append(want[chain], runtimeDockerHostRule(family, table, chain, "", expressions...))
		lines[chain] = append(lines[chain], "-A "+chain+" "+line)
	}
	if table == "nat" {
		chains = map[string]string{"PREROUTING": "ACCEPT", "INPUT": "ACCEPT", "OUTPUT": "ACCEPT", "POSTROUTING": "ACCEPT", "DOCKER": "-"}
		add("PREROUTING", "-m addrtype --dst-type LOCAL -j DOCKER", runtimeDockerHostXT("match", "addrtype"), runtimeDockerHostJump("DOCKER"))
		loopback := netip.MustParsePrefix("127.0.0.0/8")
		if family == "ip6" {
			loopback = netip.MustParsePrefix("::1/128")
		}
		add("OUTPUT", "! -d "+loopback.String()+" -m addrtype --dst-type LOCAL -j DOCKER", runtimeDockerHostAddress(family, "daddr", "!=", loopback), runtimeDockerHostXT("match", "addrtype"), runtimeDockerHostJump("DOCKER"))
		if family == "ip" {
			if len(save.rules["POSTROUTING"]) != 1 {
				return false
			}
			f := strings.Fields(save.rules["POSTROUTING"][0])
			if len(f) != 9 {
				return false
			}
			p, ok := runtimeDockerHostPrefix(f[3])
			if !ok || !p.Addr().IsPrivate() {
				return false
			}
			for _, protected := range protected {
				if p.Overlaps(protected) {
					return false
				}
			}
			add("POSTROUTING", "-s "+p.String()+" ! -o docker0 -j MASQUERADE", runtimeDockerHostAddress("ip", "saddr", "==", p), runtimeDockerHostMeta("oifname", "!=", "docker0"), runtimeDockerHostXT("target", "MASQUERADE"))
		}
	} else {
		chains = map[string]string{"INPUT": "ACCEPT", "OUTPUT": "ACCEPT", "FORWARD": "ACCEPT", "DOCKER": "-", "DOCKER-BRIDGE": "-", "DOCKER-CT": "-", "DOCKER-FORWARD": "-", "DOCKER-INTERNAL": "-", "DOCKER-USER": "-"}
		if family == "ip" {
			chains["FORWARD"] = "DROP"
		}
		add("FORWARD", "-j DOCKER-USER", runtimeDockerHostJump("DOCKER-USER"))
		add("FORWARD", "-j DOCKER-FORWARD", runtimeDockerHostJump("DOCKER-FORWARD"))
		for _, chain := range []string{"DOCKER-CT", "DOCKER-INTERNAL", "DOCKER-BRIDGE"} {
			add("DOCKER-FORWARD", "-j "+chain, runtimeDockerHostJump(chain))
		}
		if family == "ip" {
			add("DOCKER", "! -i docker0 -o docker0 -j DROP", runtimeDockerHostMeta("iifname", "!=", "docker0"), runtimeDockerHostMeta("oifname", "==", "docker0"), map[string]any{"drop": nil})
			add("DOCKER-BRIDGE", "-o docker0 -j DOCKER", runtimeDockerHostMeta("oifname", "==", "docker0"), runtimeDockerHostJump("DOCKER"))
			add("DOCKER-CT", "-o docker0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT", runtimeDockerHostMeta("oifname", "==", "docker0"), runtimeDockerHostXT("match", "conntrack"), map[string]any{"accept": nil})
			add("DOCKER-FORWARD", "-i docker0 -j ACCEPT", runtimeDockerHostMeta("iifname", "==", "docker0"), map[string]any{"accept": nil})
			seen := map[string]bool{}
			for _, rule := range view.rules["DOCKER-USER"] {
				line, ok := runtimeDockerHostWGRule(rule)
				if !ok || seen[line] {
					return false
				}
				seen[line] = true
				want["DOCKER-USER"] = append(want["DOCKER-USER"], rule)
				lines["DOCKER-USER"] = append(lines["DOCKER-USER"], line)
			}
			// Part B's marked tail has its own strict schema and owner verification.
			for i, rule := range view.rules["FORWARD"] {
				if i < 2 {
					continue
				}
				line, ok := runtimeDockerHostForwardSave(rule)
				if !ok || seen[line] {
					return false
				}
				seen[line] = true
				want["FORWARD"] = append(want["FORWARD"], rule)
				lines["FORWARD"] = append(lines["FORWARD"], line)
			}
		}
	}
	if !reflect.DeepEqual(save.chains, chains) || !reflect.DeepEqual(save.rules, lines) {
		return false
	}
	for name, policy := range chains {
		chain, exists := view.chains[name]
		optional := name == "INPUT" || (table == "filter" && name == "OUTPUT") || (table == "nat" && family == "ip6" && name == "POSTROUTING")
		if !exists {
			if optional {
				continue
			}
			return false
		}
		expected := map[string]any{"family": family, "table": table, "name": name}
		if policy != "-" {
			expected["type"], expected["hook"], expected["policy"] = table, strings.ToLower(name), strings.ToLower(policy)
			priority := 0
			if table == "nat" {
				priority = -100
				if name == "POSTROUTING" || name == "INPUT" {
					priority = 100
				}
			}
			expected["prio"] = priority
		}
		if !runtimeDockerHostEqual(chain, expected) {
			return false
		}
	}
	for name := range view.chains {
		if _, exists := chains[name]; !exists {
			return false
		}
	}
	if len(view.rules) != len(want) {
		return false
	}
	for chain, rules := range want {
		if len(view.rules[chain]) != len(rules) {
			return false
		}
		for i, rule := range rules {
			if !runtimeDockerHostEqual(view.rules[chain][i], rule) {
				return false
			}
		}
	}
	return true
}

func runtimeDockerHostForwardSave(rule map[string]any) (string, bool) {
	// Restore the semantically irrelevant counter expected by the mutation-side
	// shared validator. This function only consumes an already normalized rule.
	raw, _ := json.Marshal(rule)
	o, ok := kernelObject(raw)
	if !ok {
		return "", false
	}
	expr, ok := rule["expr"].([]any)
	if !ok || len(expr) != 5 {
		return "", false
	}
	full := append(append([]any{}, expr[:4]...), map[string]any{"counter": map[string]any{"packets": 0, "bytes": 0}}, expr[4])
	o["expr"], _ = json.Marshal(full)
	if !runtimeDockerForwardRule(o) {
		return "", false
	}
	values := make([]json.RawMessage, 4)
	for i := range values {
		data, _ := json.Marshal(expr[i])
		var v struct {
			Match struct {
				Right json.RawMessage `json:"right"`
			} `json:"match"`
		}
		if json.Unmarshal(data, &v) != nil {
			return "", false
		}
		values[i] = v.Match.Right
	}
	var in, out string
	if json.Unmarshal(values[0], &in) != nil || json.Unmarshal(values[1], &out) != nil || !runtimeDockerHostIface.MatchString(in) || !runtimeDockerHostIface.MatchString(out) {
		return "", false
	}
	source, sok := runtimeDockerHostNFTPrefix(values[2])
	destination, dok := runtimeDockerHostNFTPrefix(values[3])
	if !sok || !dok {
		return "", false
	}
	comment, _ := rule["comment"].(string)
	// iptables-nft-save quotes the colon-bearing canonical owner marker. The
	// shared schema has already excluded quotes, whitespace and extra tokens.
	return "-A FORWARD -s " + source.String() + " -d " + destination.String() + " -i " + in + " -o " + out + " -m comment --comment \"" + comment + "\" -j ACCEPT", true
}

func runtimeQualifiedDockerHostCensus(ctx context.Context, nftPath string, rows []map[string]json.RawMessage, protected []netip.Prefix, run func(context.Context, string, ...string) ([]byte, error)) bool {
	if !filepath.IsAbs(nftPath) {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var versions [2][]byte
	var outputs [2][2][]byte
	tasks := []func(context.Context) error{}
	for family, binary := range []string{"iptables-nft-save", "ip6tables-nft-save"} {
		path := filepath.Join(filepath.Dir(nftPath), binary)
		tasks = append(tasks, func(c context.Context) error { var err error; versions[family], err = run(c, path, "-V"); return err })
		for table, name := range []string{"nat", "filter"} {
			tasks = append(tasks, func(c context.Context) error {
				var err error
				outputs[family][table], err = run(c, path, "-t", name)
				return err
			})
		}
	}
	if !runtimeEnvironmentReadPool(ctx, tasks) {
		return false
	}
	listings := map[string][]byte{}
	for i, family := range []string{"ip", "ip6"} {
		binary := "iptables-nft-save"
		if i == 1 {
			binary = "ip6tables-nft-save"
		}
		version := strings.TrimSpace(string(versions[i]))
		if !strings.HasPrefix(version, binary+" v") || !strings.HasSuffix(version, " (nf_tables)") {
			return false
		}
		for j, table := range []string{"nat", "filter"} {
			listings[family+"/"+table] = outputs[i][j]
		}
	}
	before, ok := runtimeDockerHostCensusRows(rows, listings, protected)
	if !ok {
		return false
	}
	raw, err := run(ctx, nftPath, "-j", "list", "ruleset")
	if err != nil || ctx.Err() != nil {
		return false
	}
	afterRows, ok := runtimeCensusRows(raw)
	if !ok {
		return false
	}
	after, ok := runtimeDockerHostCensusRows(afterRows, listings, protected)
	return ok && reflect.DeepEqual(before, after)
}
