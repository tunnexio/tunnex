package ipsec

import (
	"context"
	"encoding/json"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

type dockerWithdrawalFixture struct {
	raw      []byte
	commands map[string][]byte
	links    []GuardInterface
	view     *runtimeDockerWithdrawalView
	plan     *runtimeDockerForwardPlan
	intent   GuardIntent
	manifest GuardManifest
	prior    *runtimeGuardTemplate
}

func newDockerWithdrawalFixture(t *testing.T) dockerWithdrawalFixture {
	t.Helper()
	raw, commands := dockerHostFixture(t)
	intent := guardFixture()
	intent.Connections[0].LocalIngressIndices = []int{13}
	old, err := RenderGuard(intent)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := runtimeDockerForwardRules(old.ExpectedJSON, old.OwnerID)
	if err != nil || len(rules) != 2 {
		t.Fatal("expected two structural tuples", err)
	}
	lines := []string{}
	for i, rule := range rules {
		rule["handle"] = i + 900
		exprs := rule["expr"].([]any)
		for _, rawExpr := range exprs[:2] {
			match := rawExpr.(map[string]any)["match"].(map[string]any)
			if match["right"] == json.Number("13") {
				match["right"] = "13" // nft's preserved deleted-interface index
			} else {
				match["right"] = "tnxi-a"
			}
		}
		exprs[4] = map[string]any{"counter": map[string]any{"packets": 0, "bytes": 0}}
		encoded, _ := json.Marshal(rule)
		clean, _ := runtimeDockerHostClean(encoded, false)
		line, ok := runtimeDockerHostForwardSave(clean)
		if !ok {
			t.Fatal("fixture rule")
		}
		// Independently observed native save behavior: omit the orphan option.
		line = strings.ReplaceAll(strings.ReplaceAll(line, " -i 13", ""), " -o 13", "")
		lines = append(lines, line)
	}
	raw = dockerHostEdit(t, raw, func(doc *dockerHostDocument) {
		for _, rule := range rules {
			doc.NFT = append(doc.NFT, map[string]map[string]any{"rule": rule})
		}
	})
	key := "iptables-nft-save -t filter"
	commands[key] = []byte(strings.Replace(string(commands[key]), "-A FORWARD -j DOCKER-FORWARD\n", "-A FORWARD -j DOCKER-FORWARD\n"+strings.Join(lines, "\n")+"\n", 1))
	links := []GuardInterface{{Name: "ens5", Index: 2}, {Name: "tnxi-a", Index: 10}, {Name: "tnxi-b", Index: 11}}
	prior := &runtimeGuardTemplate{Namespace: old.Namespace, Revision: old.Revision, Digest: old.Digest, ExpectedJSON: old.ExpectedJSON}
	intent = legacyCTRefusal(intent)
	manifest, err := RenderGuard(intent)
	if err != nil {
		t.Fatal(err)
	}
	rows, _ := runtimeCensusRows(raw)
	plan, err := runtimeDockerForwardPlanForSnapshot(manifest, prior, rows, links)
	if err != nil || len(plan.rules) != 0 || len(plan.remove) != 2 {
		t.Fatal("journal-bound removal plan", err)
	}
	view, ok := runtimeDockerWithdrawalViewForSnapshot(rows, intent.OwnerID, plan.remove, links)
	if !ok || view.count != 2 {
		t.Fatal("orphan projection refused exact native shape")
	}
	return dockerWithdrawalFixture{raw, commands, links, view, plan, intent, manifest, prior}
}

func (f dockerWithdrawalFixture) qualify(raw []byte, commands map[string][]byte) bool {
	return runtimeQualifiedDockerWithdrawalCensusWithCommands(context.Background(), "/usr/sbin/nft", f.view, f.intent.OwnerID, f.plan.remove, f.links, f.intent.Connections[0].Remote, dockerHostRunner(raw, commands))
}

func TestDockerWithdrawalOrphanRequiresExactPermanentRefusal(t *testing.T) {
	f := newDockerWithdrawalFixture(t)
	if runtimeQualifiedHookCensusWithCommands(context.Background(), "/usr/sbin/nft", f.raw, nil, dockerHostRunner(f.raw, f.commands)) {
		t.Fatal("ordinary census admitted lossy interface listing")
	}
	if !runtimeDockerPermanentRefusal(f.intent, f.manifest, f.prior) || !f.qualify(f.raw, f.commands) {
		t.Fatal("exact refusal-only removal failed qualification")
	}
	positive := guardFixture()
	manifest, _ := RenderGuard(positive)
	if runtimeDockerPermanentRefusal(positive, manifest, f.prior) || runtimeDockerPermanentRefusal(f.intent, manifest, f.prior) || runtimeDockerPermanentRefusal(f.intent, f.manifest, nil) {
		t.Fatal("permitting or unowned projection accepted")
	}
	missing := f.intent
	missing.Connections = append([]GuardConnection(nil), missing.Connections...)
	missing.Connections[0].Remote = []netip.Prefix{netip.MustParsePrefix("10.21.0.0/24")}
	manifest, _ = RenderGuard(missing)
	if runtimeDockerPermanentRefusal(missing, manifest, f.prior) {
		t.Fatal("lost permanent prefix protection")
	}
	transaction, err := f.plan.transaction(f.manifest.NFTJSON)
	var doc struct {
		NFTables []map[string]map[string]map[string]json.RawMessage `json:"nftables"`
	}
	if err != nil || json.Unmarshal([]byte(transaction), &doc) != nil {
		t.Fatal("invalid atomic refusal transaction", err)
	}
	deletes := 0
	for _, command := range doc.NFTables {
		if rule := command["delete"]["rule"]; rule != nil {
			deletes++
		}
		if rule := command["add"]["rule"]; rule != nil && strings.Contains(string(rule["expr"]), `"accept"`) {
			t.Fatal("refusal transaction added a permitting rule")
		}
	}
	if deletes != 2 {
		t.Fatal("withdrawal was not one zero-add atomic refusal transaction")
	}
}

func TestDockerWithdrawalRefusesChangedOwnedAndForeignNative(t *testing.T) {
	for name, edit := range map[string]func(*dockerHostDocument){
		"handle": func(d *dockerHostDocument) { dockerHostRules(d, "ip", "filter", "FORWARD")[2]["handle"] = 999 },
		"order": func(d *dockerHostDocument) {
			r := dockerHostRules(d, "ip", "filter", "FORWARD")
			r[2]["handle"], r[3]["handle"] = r[3]["handle"], r[2]["handle"]
		},
		"tuple": func(d *dockerHostDocument) {
			dockerHostRules(d, "ip", "filter", "FORWARD")[2]["expr"].([]any)[2].(map[string]any)["match"].(map[string]any)["right"] = "10.22.0.1"
		},
		"interface reappeared": func(d *dockerHostDocument) {
			for _, r := range dockerHostRules(d, "ip", "filter", "FORWARD")[2:] {
				for _, raw := range r["expr"].([]any)[:2] {
					m := raw.(map[string]any)["match"].(map[string]any)
					if m["right"] == "13" {
						m["right"] = "wg0"
					}
				}
			}
		},
		"foreign rule": func(d *dockerHostDocument) {
			d.NFT = append(d.NFT, map[string]map[string]any{"rule": {"family": "ip", "table": "filter", "chain": "DOCKER-USER", "expr": []any{map[string]any{"accept": nil}}}})
		},
		"foreign policy": func(d *dockerHostDocument) {
			for _, row := range d.NFT {
				if chain := row["chain"]; chain != nil && chain["family"] == "ip" && chain["name"] == "FORWARD" {
					chain["policy"] = "accept"
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newDockerWithdrawalFixture(t)
			if f.qualify(dockerHostEdit(t, f.raw, edit), f.commands) {
				t.Fatal("snapshot change hidden by projection")
			}
		})
	}
}

func TestDockerWithdrawalRefusesLossyOrExtraSaveLines(t *testing.T) {
	for _, change := range []string{"live interface omitted", "extra line", "order", "foreign rule"} {
		t.Run(change, func(t *testing.T) {
			f := newDockerWithdrawalFixture(t)
			key := "iptables-nft-save -t filter"
			listing := string(f.commands[key])
			switch change {
			case "live interface omitted":
				listing = strings.ReplaceAll(strings.ReplaceAll(listing, " -i tnxi-a", ""), " -o tnxi-a", "")
			case "extra line":
				listing = strings.Replace(listing, "COMMIT", f.view.lines[0]+"\nCOMMIT", 1)
			case "order":
				listing = strings.Replace(listing, strings.Join(f.view.lines, "\n"), f.view.lines[1]+"\n"+f.view.lines[0], 1)
			case "foreign rule":
				listing = strings.Replace(listing, "COMMIT", "-A DOCKER-USER -j ACCEPT\nCOMMIT", 1)
			}
			f.commands[key] = []byte(listing)
			if f.qualify(f.raw, f.commands) {
				t.Fatal("independent save disagreement admitted")
			}
		})
	}
}

func TestDockerWithdrawalPreservesNumericNamesAndHandlePrecision(t *testing.T) {
	f := newDockerWithdrawalFixture(t)
	rows, _ := runtimeCensusRows(f.raw)
	links := append(append([]GuardInterface{}, f.links...), GuardInterface{Name: "13", Index: 20})
	view, ok := runtimeDockerWithdrawalViewForSnapshot(rows, f.intent.OwnerID, f.plan.remove, links)
	if !ok || view.count != 0 {
		t.Fatal("live numeric interface name treated as an orphan")
	}
	links = append(append([]GuardInterface{}, f.links...), GuardInterface{Name: "wg0", Index: 13})
	if _, ok = runtimeDockerWithdrawalViewForSnapshot(rows, f.intent.OwnerID, f.plan.remove, links); ok {
		t.Fatal("present interface index treated as missing")
	}
	// The full owned fence must retain exact 64-bit native handles.
	large := uint64(1<<53 + 1)
	encoded := strings.Replace(string(f.raw), `"handle":900`, `"handle":`+strconv.FormatUint(large, 10), 1)
	rows, _ = runtimeCensusRows([]byte(encoded))
	view, ok = runtimeDockerWithdrawalViewForSnapshot(rows, f.intent.OwnerID, []uint64{large, 901}, f.links)
	if !ok || reflect.DeepEqual(view.owned, f.view.owned) {
		t.Fatal("large native handle lost precision")
	}
}
