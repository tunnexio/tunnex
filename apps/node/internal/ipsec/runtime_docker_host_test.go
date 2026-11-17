package ipsec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func dockerHostFixture(t *testing.T) ([]byte, map[string][]byte) {
	t.Helper()
	raw, err := os.ReadFile("testdata/runtime-docker-host-nft.json")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("testdata/runtime-docker-host-save.json")
	if err != nil {
		t.Fatal(err)
	}
	var saved map[string]struct {
		ExitCode int    `json:"exit_code"`
		Stdout   string `json:"stdout"`
	}
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatal(err)
	}
	commands := map[string][]byte{}
	for key, value := range saved {
		if value.ExitCode != 0 {
			t.Fatal("failed capture", key)
		}
		commands[key] = []byte(value.Stdout)
	}
	return raw, commands
}

func dockerHostRunner(raw []byte, commands map[string][]byte) func(context.Context, string, ...string) ([]byte, error) {
	return func(_ context.Context, path string, args ...string) ([]byte, error) {
		key := filepath.Base(path) + " " + strings.Join(args, " ")
		if key == "nft -j list ruleset" {
			return raw, nil
		}
		if value, ok := commands[key]; ok {
			return value, nil
		}
		return nil, fmt.Errorf("unexpected fixture read %s", key)
	}
}

func TestDockerHostCapturedFreshGateway(t *testing.T) {
	raw, commands := dockerHostFixture(t)
	if !runtimeQualifiedHookCensusWithCommands(context.Background(), "/usr/sbin/nft", raw, []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24"), netip.MustParsePrefix("10.30.0.0/24")}, dockerHostRunner(raw, commands)) {
		t.Fatal("captured fresh Docker host with scoped WireGuard rules was refused")
	}
}

type dockerHostDocument struct {
	NFT []map[string]map[string]any `json:"nftables"`
}

func dockerHostEdit(t *testing.T, raw []byte, edit func(*dockerHostDocument)) []byte {
	t.Helper()
	var doc dockerHostDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	edit(&doc)
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func dockerHostRules(doc *dockerHostDocument, family, table, chain string) []map[string]any {
	var out []map[string]any
	for _, row := range doc.NFT {
		if rule := row["rule"]; rule != nil && rule["family"] == family && rule["table"] == table && rule["chain"] == chain {
			out = append(out, rule)
		}
	}
	return out
}

func TestDockerHostRefusesUnknownAndChangedSemantics(t *testing.T) {
	raw, commands := dockerHostFixture(t)
	for name, edit := range map[string]func(*dockerHostDocument){
		"blanket foreign accept": func(d *dockerHostDocument) {
			r := dockerHostRules(d, "ip", "filter", "DOCKER-USER")[0]
			r["expr"] = []any{map[string]any{"accept": nil}}
		},
		"marked foreign NAT": func(d *dockerHostDocument) {
			r := dockerHostRules(d, "ip", "filter", "DOCKER-USER")[0]
			r["expr"].([]any)[3] = map[string]any{"masquerade": nil}
		},
		"foreign interface": func(d *dockerHostDocument) {
			r := dockerHostRules(d, "ip", "filter", "DOCKER-USER")[0]
			r["expr"].([]any)[0].(map[string]any)["match"].(map[string]any)["right"] = "eth0"
		},
		"wrong Docker jump order": func(d *dockerHostDocument) {
			r := dockerHostRules(d, "ip", "filter", "FORWARD")
			r[0]["expr"], r[1]["expr"] = r[1]["expr"], r[0]["expr"]
		},
		"early return": func(d *dockerHostDocument) {
			r := dockerHostRules(d, "ip", "filter", "FORWARD")[0]
			r["expr"] = []any{map[string]any{"return": nil}}
		},
		"unknown chain": func(d *dockerHostDocument) {
			d.NFT = append(d.NFT, map[string]map[string]any{"chain": {"family": "ip", "table": "filter", "name": "FOREIGN"}})
		},
		"unknown table": func(d *dockerHostDocument) {
			d.NFT = append(d.NFT, map[string]map[string]any{"table": {"family": "inet", "name": "foreign"}})
		},
		"IPv6 hook priority": func(d *dockerHostDocument) {
			for _, row := range d.NFT {
				if c := row["chain"]; c != nil && c["family"] == "ip6" && c["name"] == "FORWARD" {
					c["prio"] = -20
				}
			}
		},
		"forward policy broadened": func(d *dockerHostDocument) {
			for _, row := range d.NFT {
				if c := row["chain"]; c != nil && c["family"] == "ip" && c["name"] == "FORWARD" {
					c["policy"] = "accept"
				}
			}
		},
		"duplicate WG rule": func(d *dockerHostDocument) {
			r := dockerHostRules(d, "ip", "filter", "DOCKER-USER")[0]
			d.NFT = append(d.NFT, map[string]map[string]any{"rule": r})
		},
		"opaque translation changed": func(d *dockerHostDocument) {
			r := dockerHostRules(d, "ip", "nat", "POSTROUTING")[0]
			r["expr"].([]any)[3] = map[string]any{"xt": map[string]any{"type": "target", "name": "SNAT"}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := dockerHostEdit(t, raw, edit)
			if runtimeQualifiedHookCensusWithCommands(context.Background(), "/usr/sbin/nft", changed, nil, dockerHostRunner(changed, commands)) {
				t.Fatal("unsafe or foreign rules accepted")
			}
		})
	}
	for _, tc := range []struct{ name, key, old, replacement string }{
		{"opaque conntrack NEW", "iptables-nft-save -t filter", "RELATED,ESTABLISHED", "NEW,RELATED,ESTABLISHED"},
		{"opaque address type broadened", "iptables-nft-save -t nat", "--dst-type LOCAL", "--src-type LOCAL"},
		{"NAT unscoped", "iptables-nft-save -t nat", "172.17.0.0/16", "0.0.0.0/0"},
		{"NAT changed interface", "iptables-nft-save -t nat", "! -o docker0", "! -o eth0"},
		{"foreign published port", "iptables-nft-save -t nat", "COMMIT", "-A DOCKER -p tcp --dport 443 -j DNAT --to-destination 172.17.0.2:443\nCOMMIT"},
		{"IPv6 foreign accept", "ip6tables-nft-save -t filter", "COMMIT", "-A DOCKER-USER -j ACCEPT\nCOMMIT"},
		{"save ordering differs", "iptables-nft-save -t filter", "-A FORWARD -j DOCKER-USER\n-A FORWARD -j DOCKER-FORWARD", "-A FORWARD -j DOCKER-FORWARD\n-A FORWARD -j DOCKER-USER"},
		{"save legacy backend", "iptables-nft-save -V", "nf_tables", "legacy"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copy := map[string][]byte{}
			for key, value := range commands {
				copy[key] = value
			}
			copy[tc.key] = []byte(strings.ReplaceAll(string(copy[tc.key]), tc.old, tc.replacement))
			if string(copy[tc.key]) == string(commands[tc.key]) {
				t.Fatal("mutation did not match")
			}
			if runtimeQualifiedHookCensusWithCommands(context.Background(), "/usr/sbin/nft", raw, nil, dockerHostRunner(raw, copy)) {
				t.Fatal("independent unsafe semantics accepted")
			}
		})
	}
}

func TestDockerHostProtectedNATCheckedOnEveryObservation(t *testing.T) {
	raw, commands := dockerHostFixture(t)
	run := dockerHostRunner(raw, commands)
	if !runtimeQualifiedHookCensusWithCommands(context.Background(), "/usr/sbin/nft", raw, nil, run) {
		t.Fatal("initial capability probe")
	}
	for _, protected := range [][]netip.Prefix{{netip.MustParsePrefix("172.17.2.0/24")}, {netip.MustParsePrefix("172.0.0.0/8")}, {netip.MustParsePrefix("0.0.0.0/0")}, {{}}} {
		if runtimeQualifiedHookCensusWithCommands(context.Background(), "/usr/sbin/nft", raw, protected, run) {
			t.Fatal("later protected overlap or invalid prefix accepted")
		}
	}
}

func TestDockerHostBracketsSemanticsAndIgnoresOnlyCounters(t *testing.T) {
	raw, commands := dockerHostFixture(t)
	for name, tc := range map[string]struct {
		edit func(*dockerHostDocument)
		want bool
	}{
		"traffic counters": {func(d *dockerHostDocument) {
			for _, row := range d.NFT {
				if r := row["rule"]; r != nil {
					for _, expr := range r["expr"].([]any) {
						if c := expr.(map[string]any)["counter"]; c != nil {
							c.(map[string]any)["packets"] = float64(100)
							c.(map[string]any)["bytes"] = float64(6400)
						}
					}
				}
			}
		}, true},
		"replacement during saves": {func(d *dockerHostDocument) {
			dockerHostRules(d, "ip", "filter", "FORWARD")[0]["handle"] = float64(10000)
		}, false},
		"foreign rule during saves": {func(d *dockerHostDocument) {
			d.NFT = append(d.NFT, map[string]map[string]any{"rule": {"family": "ip", "table": "filter", "chain": "DOCKER-USER", "expr": []any{map[string]any{"accept": nil}}}})
		}, false},
		"rule reorder during saves": {func(d *dockerHostDocument) {
			r := dockerHostRules(d, "ip", "filter", "FORWARD")
			r[0]["expr"], r[1]["expr"] = r[1]["expr"], r[0]["expr"]
		}, false},
	} {
		t.Run(name, func(t *testing.T) {
			after := dockerHostEdit(t, raw, tc.edit)
			base := dockerHostRunner(after, commands)
			var completed atomic.Int32
			run := func(c context.Context, path string, args ...string) ([]byte, error) {
				if filepath.Base(path) == "nft" && completed.Load() != 6 {
					return nil, errors.New("fence before independent read barrier")
				}
				out, err := base(c, path, args...)
				if filepath.Base(path) != "nft" {
					completed.Add(1)
				}
				return out, err
			}
			if got := runtimeQualifiedHookCensusWithCommands(context.Background(), "/usr/sbin/nft", raw, nil, run); got != tc.want {
				t.Fatalf("snapshot bracket accepted=%v want=%v", got, tc.want)
			}
		})
	}
}

func TestDockerHostReadFailureAndCancellationDrain(t *testing.T) {
	raw, commands := dockerHostFixture(t)
	for _, mode := range []string{"command_failure", "deadline", "readback_failure"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
			defer cancel()
			base := dockerHostRunner(raw, commands)
			var entered, finished, inflight, peak atomic.Int32
			run := func(c context.Context, path string, args ...string) ([]byte, error) {
				entered.Add(1)
				n := inflight.Add(1)
				defer func() { inflight.Add(-1); finished.Add(1) }()
				for current := peak.Load(); n > current && !peak.CompareAndSwap(current, n); current = peak.Load() {
				}
				if mode == "deadline" {
					<-c.Done()
					return nil, c.Err()
				}
				if mode == "command_failure" && strings.Join(args, " ") == "-t nat" || mode == "readback_failure" && filepath.Base(path) == "nft" {
					return nil, errors.New("fixture failure")
				}
				return base(c, path, args...)
			}
			if runtimeQualifiedHookCensusWithCommands(ctx, "/usr/sbin/nft", raw, nil, run) || entered.Load() != finished.Load() || inflight.Load() != 0 || peak.Load() > 2 {
				t.Fatal("failed read accepted or command workers escaped bounded drain")
			}
		})
	}
}

func TestDockerHostBracketPreservesFullHandleIdentity(t *testing.T) {
	raw, commands := dockerHostFixture(t)
	before := dockerHostEdit(t, raw, func(d *dockerHostDocument) {
		dockerHostRules(d, "ip", "filter", "FORWARD")[0]["handle"] = json.Number("9007199254740992")
	})
	after := dockerHostEdit(t, raw, func(d *dockerHostDocument) {
		dockerHostRules(d, "ip", "filter", "FORWARD")[0]["handle"] = json.Number("9007199254740993")
	})
	if runtimeQualifiedHookCensusWithCommands(context.Background(), "/usr/sbin/nft", before, nil, dockerHostRunner(after, commands)) {
		t.Fatal("distinct uint64 rule handles were rounded into the same identity")
	}
}

func TestDockerHostMarkedForwardTailKeepsExactScopeAndOrder(t *testing.T) {
	raw, commands := dockerHostFixture(t)
	const comment = "tunnex-ipsec-fwd:11111111-2222-4333-8444-555555555555"
	// iptables-nft-save quotes this colon-bearing comment in the native readback.
	const saved = "-A FORWARD -s 10.20.0.0/24 -d 10.30.0.0/24 -i eth0 -o tx123 -m comment --comment \"" + comment + "\" -j ACCEPT"
	var tail map[string]any
	if err := json.Unmarshal([]byte(`{"family":"ip","table":"filter","chain":"FORWARD","handle":100,"comment":"`+comment+`","expr":[{"match":{"op":"==","left":{"meta":{"key":"iif"}},"right":"eth0"}},{"match":{"op":"==","left":{"meta":{"key":"oif"}},"right":"tx123"}},{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":{"prefix":{"addr":"10.20.0.0","len":24}}}},{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":{"prefix":{"addr":"10.30.0.0","len":24}}}},{"counter":{"packets":2,"bytes":128}},{"accept":null}]}`), &tail); err != nil {
		t.Fatal(err)
	}
	withTail := dockerHostEdit(t, raw, func(d *dockerHostDocument) { d.NFT = append(d.NFT, map[string]map[string]any{"rule": tail}) })
	commands["iptables-nft-save -t filter"] = []byte(strings.Replace(string(commands["iptables-nft-save -t filter"]), "-A FORWARD -j DOCKER-FORWARD\n", "-A FORWARD -j DOCKER-FORWARD\n"+saved+"\n", 1))
	if !runtimeQualifiedHookCensusWithCommands(context.Background(), "/usr/sbin/nft", withTail, []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}, dockerHostRunner(withTail, commands)) {
		t.Fatal("exact owned structural tail refused")
	}
	for name, edit := range map[string]func(*dockerHostDocument){
		"missing destination": func(d *dockerHostDocument) {
			r := dockerHostRules(d, "ip", "filter", "FORWARD")[2]
			e := r["expr"].([]any)
			r["expr"] = append(e[:3], e[4:]...)
		},
		"default prefix": func(d *dockerHostDocument) {
			r := dockerHostRules(d, "ip", "filter", "FORWARD")[2]
			r["expr"].([]any)[2].(map[string]any)["match"].(map[string]any)["right"] = map[string]any{"prefix": map[string]any{"addr": "0.0.0.0", "len": 0}}
		},
		"before Docker user chain": func(d *dockerHostDocument) {
			r := dockerHostRules(d, "ip", "filter", "FORWARD")
			r[0]["expr"], r[2]["expr"] = r[2]["expr"], r[0]["expr"]
		},
		"forged marker": func(d *dockerHostDocument) {
			dockerHostRules(d, "ip", "filter", "FORWARD")[2]["comment"] = "tunnex-ipsec-fwd:not-a-gateway"
		},
		"wildcard interface": func(d *dockerHostDocument) {
			r := dockerHostRules(d, "ip", "filter", "FORWARD")[2]
			r["expr"].([]any)[0].(map[string]any)["match"].(map[string]any)["right"] = "eth+"
		},
		"opaque extra operation": func(d *dockerHostDocument) {
			r := dockerHostRules(d, "ip", "filter", "FORWARD")[2]
			r["expr"].([]any)[5] = map[string]any{"xt": map[string]any{"type": "target", "name": "ACCEPT"}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := dockerHostEdit(t, withTail, edit)
			if runtimeQualifiedHookCensusWithCommands(context.Background(), "/usr/sbin/nft", changed, nil, dockerHostRunner(changed, commands)) {
				t.Fatal("invalid structural rule accepted")
			}
		})
	}
}
