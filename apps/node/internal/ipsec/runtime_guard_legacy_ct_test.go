package ipsec

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// Recreate the pre-fix renderer and independently observed nft 1.1.6 output.
// The native experiment also covered /25, /31 and /32: those do not undergo
// this byte-aligned prefix-to-host corruption and must not be generalized.
func legacyCTGuardFixture(t *testing.T) (GuardManifest, GuardIntent, []byte) {
	t.Helper()
	in := guardFixture()
	in.Revision = 30092
	in.Connections[0].ReplyIngressIndices = []int{10}
	in.Connections[0].Grants[0].Source = netip.MustParsePrefix("10.10.0.7/32")
	in.Connections[0].Remote = []netip.Prefix{netip.MustParsePrefix("10.182.0.0/16")}
	in.Connections[0].Grants[0].Destination = netip.MustParsePrefix("10.182.10.0/24")
	in.Connections[0].BGPPeers = []GuardBGPPeer{{Local: netip.MustParseAddr("169.254.1.1"), Remote: netip.MustParseAddr("169.254.1.2"), InterfaceIndex: 10}}
	m, err := RenderGuard(in)
	if err != nil {
		t.Fatal(err)
	}
	doc := legacyCTTestDocument(t, []byte(m.ExpectedJSON))
	changed := 0
	for _, raw := range doc["nftables"].([]any) {
		rule, _ := raw.(map[string]any)["rule"].(map[string]any)
		exprs, _ := rule["expr"].([]any)
		for _, rawExpr := range exprs {
			expr := rawExpr.(map[string]any)
			match, _ := expr["match"].(map[string]any)
			left, _ := match["left"].(map[string]any)
			ct, _ := left["ct"].(map[string]any)
			if ct["key"] == "ip daddr" && ct["dir"] == "original" && rule["chain"] == "forward_guard" && len(exprs) == 15 {
				ct["key"] = "daddr"
				changed++
			}
		}
	}
	if changed != 1 {
		t.Fatalf("expected one related-ICMP rule, got %d", changed)
	}
	m.ExpectedJSON = string(legacyCTTestJSON(t, doc))
	for _, raw := range doc["nftables"].([]any) {
		rule, _ := raw.(map[string]any)["rule"].(map[string]any)
		exprs, _ := rule["expr"].([]any)
		for _, rawExpr := range exprs {
			match, _ := rawExpr.(map[string]any)["match"].(map[string]any)
			left, _ := match["left"].(map[string]any)
			ct, _ := left["ct"].(map[string]any)
			if ct["key"] == "daddr" && ct["dir"] == "original" {
				match["right"] = "0.10.182.10"
			}
		}
	}
	return m, in, legacyCTTestJSON(t, doc)
}

func legacyCTTestDocument(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var doc map[string]any
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.UseNumber()
	if err := d.Decode(&doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func legacyCTTestJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func legacyCTRefusal(in GuardIntent) GuardIntent {
	in.Revision++
	old := in.Connections[0]
	peers := append([]GuardBGPPeer(nil), old.BGPPeers...)
	for i := range peers {
		peers[i].InterfaceIndex = 0
	}
	in.Connections = []GuardConnection{{ID: old.ID, PrefixOnly: true, Local: old.Local, Remote: old.Remote, BGPPeers: peers}}
	return in
}

func TestRuntimeGuardLegacyCTRefusalTwoTemplates(t *testing.T) {
	legacy, intent, actual := legacyCTGuardFixture(t)
	if VerifyGuardReadback([]byte(legacy.ExpectedJSON), actual) == nil || VerifyGuardWithdrawal([]byte(legacy.ExpectedJSON), actual, nil) == nil {
		t.Fatal("malformed native rule became ordinary authority")
	}
	denial := legacyCTRefusal(intent)
	next, err := RenderGuard(denial)
	if err != nil {
		t.Fatal(err)
	}
	j, err := OpenRuntimeJournal(journalDir(t), intent.OwnerID)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	priorIntent := guardFixture()
	priorIntent.Revision = 30087
	prior, _ := RenderGuard(priorIntent)
	if j.prepareGuard(prior) != nil || j.finishGuard(prior) != nil || j.prepareGuard(legacy) != nil {
		t.Fatal("cannot prepare interrupted two-template state")
	}
	applyCount := 0
	reader := &GuardReader{
		namespace:  func() (string, error) { return intent.Namespace, nil },
		interfaces: func() ([]GuardInterface, error) { return nil, nil },
		run: func(_ context.Context, args ...string) ([]byte, error) {
			if reflect.DeepEqual(args, []string{"-j", "list", "tables"}) {
				return []byte(`{"nftables":[{"table":{"family":"inet","name":"tunnex_ipsec"}}]}`), nil
			}
			return actual, nil
		},
	}
	guard := &RuntimeGuard{journal: j, reader: reader, apply: func(_ context.Context, raw []byte) error {
		applyCount++
		guards, _, err := j.guardTemplates()
		if err != nil || len(guards) != 2 || guards[0].ExpectedJSON != legacy.ExpectedJSON || guards[1].ExpectedJSON != next.ExpectedJSON {
			t.Fatal("exact legacy duty and successor were not durable before mutation")
		}
		if string(raw) != next.NFTJSON {
			t.Fatal("recovery did not use the ordinary atomic refusal transaction")
		}
		actual = []byte(next.ExpectedJSON)
		return nil
	}}
	if _, err = guard.Replace(context.Background(), denial); err != nil || applyCount != 1 {
		t.Fatalf("known interrupted guard did not recover to denial: %v applies=%d", err, applyCount)
	}
	guards, _, err := j.guardTemplates()
	if err != nil || len(guards) != 1 || guards[0].ExpectedJSON != next.ExpectedJSON {
		t.Fatal("denial was not finalized after strict readback")
	}
}

var errLegacyCTInjected = errors.New("injected legacy guard failure")

func legacyCTTestRule(t *testing.T, doc map[string]any) map[string]any {
	t.Helper()
	for _, raw := range doc["nftables"].([]any) {
		rule, _ := raw.(map[string]any)["rule"].(map[string]any)
		exprs, _ := rule["expr"].([]any)
		if rule["chain"] == "forward_guard" && len(exprs) == 15 {
			return rule
		}
	}
	t.Fatal("missing related-ICMP rule")
	return nil
}

func TestRuntimeGuardLegacyCTRejectsAlteredNativeState(t *testing.T) {
	legacy, intent, actual := legacyCTGuardFixture(t)
	denial := legacyCTRefusal(intent)
	next, _ := RenderGuard(denial)
	candidate := runtimeGuardTemplate{Namespace: legacy.Namespace, Revision: legacy.Revision, Digest: legacy.Digest, ExpectedJSON: legacy.ExpectedJSON}
	for name, mutate := range map[string]func(map[string]any){
		"foreign rule": func(d map[string]any) {
			d["nftables"] = append(d["nftables"].([]any), map[string]any{"rule": map[string]any{"family": "inet", "table": "tunnex_ipsec", "chain": "forward_guard", "expr": []any{map[string]any{"accept": nil}}}})
		},
		"missing rule": func(d map[string]any) {
			d["nftables"] = d["nftables"].([]any)[:len(d["nftables"].([]any))-1]
		},
		"rule order": func(d map[string]any) {
			rows := d["nftables"].([]any)
			for i := range rows {
				if rule, ok := rows[i].(map[string]any)["rule"].(map[string]any); ok && rule["chain"] == "forward_guard" {
					rows[i], rows[i+1] = rows[i+1], rows[i]
					break
				}
			}
		},
		"wrong scalar": func(d map[string]any) {
			legacyCTTestRule(t, d)["expr"].([]any)[10].(map[string]any)["match"].(map[string]any)["right"] = "0.10.182.11"
		},
		"port widened": func(d map[string]any) {
			legacyCTTestRule(t, d)["expr"].([]any)[11].(map[string]any)["match"].(map[string]any)["right"] = json.Number("80")
		},
		"counter shape": func(d map[string]any) {
			legacyCTTestRule(t, d)["expr"].([]any)[13].(map[string]any)["counter"] = map[string]any{"packets": json.Number("0"), "bytes": json.Number("0"), "extra": true}
		},
		"counter negative": func(d map[string]any) {
			legacyCTTestRule(t, d)["expr"].([]any)[13].(map[string]any)["counter"] = map[string]any{"packets": json.Number("-1"), "bytes": json.Number("0")}
		},
		"extra set member": func(d map[string]any) {
			for _, raw := range d["nftables"].([]any) {
				if set, ok := raw.(map[string]any)["set"].(map[string]any); ok && strings.HasPrefix(set["name"].(string), "reply_lease_") {
					members := set["elem"].([]any)
					member := legacyCTTestDocument(t, legacyCTTestJSON(t, members[0]))
					member["elem"].(map[string]any)["val"] = json.Number("99")
					set["elem"] = append(members, member)
				}
			}
		},
		"other owner": func(d map[string]any) {
			for _, raw := range d["nftables"].([]any) {
				if chain, ok := raw.(map[string]any)["chain"].(map[string]any); ok && chain["name"] == "owner" {
					chain["comment"] = strings.Replace(chain["comment"].(string), intent.OwnerID.String(), uuid.New().String(), 1)
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			doc := legacyCTTestDocument(t, actual)
			mutate(doc)
			if verifyLegacyCTGuardRefusal(candidate, denial, next, legacyCTTestJSON(t, doc), nil) == nil {
				t.Fatal("altered native state acquired withdrawal ownership")
			}
		})
	}
	for _, name := range []string{"namespace", "revision", "digest", "typed candidate", "unknown recipe"} {
		t.Run(name, func(t *testing.T) {
			copy := candidate
			switch name {
			case "namespace":
				copy.Namespace = "net:[9999]"
			case "revision":
				copy.Revision++
			case "digest":
				copy.Digest = strings.Repeat("0", 64)
			case "typed candidate":
				copy.ExpectedJSON = strings.Replace(copy.ExpectedJSON, `"key":"daddr"`, `"key":"ip daddr"`, 1)
			case "unknown recipe":
				doc := legacyCTTestDocument(t, []byte(copy.ExpectedJSON))
				legacyCTTestRule(t, doc)["expr"].([]any)[7].(map[string]any)["match"].(map[string]any)["right"] = "original"
				copy.ExpectedJSON = string(legacyCTTestJSON(t, doc))
			}
			if verifyLegacyCTGuardRefusal(copy, denial, next, actual, nil) == nil {
				t.Fatal("unsupported candidate accepted")
			}
		})
	}
	// Real counters may advance and already-authorized members may expire.
	doc := legacyCTTestDocument(t, actual)
	legacyCTTestRule(t, doc)["expr"].([]any)[13].(map[string]any)["counter"] = map[string]any{"packets": json.Number("19"), "bytes": json.Number("2000")}
	for _, raw := range doc["nftables"].([]any) {
		if set, ok := raw.(map[string]any)["set"].(map[string]any); ok {
			delete(set, "elem")
		}
	}
	if verifyLegacyCTGuardRefusal(candidate, denial, next, legacyCTTestJSON(t, doc), nil) != nil {
		t.Fatal("counter growth/expired original members blocked refusal")
	}
}

func TestRuntimeGuardLegacyCTRejectsPermittingOrIncompleteTarget(t *testing.T) {
	legacy, intent, actual := legacyCTGuardFixture(t)
	candidate := runtimeGuardTemplate{Namespace: legacy.Namespace, Revision: legacy.Revision, Digest: legacy.Digest, ExpectedJSON: legacy.ExpectedJSON}
	for name, mutate := range map[string]func(*GuardIntent){
		"application grant": func(in *GuardIntent) { in.Connections[0].Grants = intent.Connections[0].Grants },
		"lease":             func(in *GuardIntent) { in.Connections[0].PermitFor = intent.Connections[0].PermitFor },
		"BGP permit": func(in *GuardIntent) {
			in.Connections[0].BGPPeers = []GuardBGPPeer{{Local: netip.MustParseAddr("169.254.1.1"), Remote: netip.MustParseAddr("169.254.1.2"), InterfaceIndex: 10}}
		},
		"reply lease": func(in *GuardIntent) { in.Connections[0].ReplyIngressIndices = []int{10} },
		"SA lease":    func(in *GuardIntent) { in.Connections[0].EncryptedEgress = []GuardEncryptedEgress{{ReqID: 20}} },
		"omitted prefix": func(in *GuardIntent) {
			in.Connections[0].Remote = []netip.Prefix{netip.MustParsePrefix("10.183.0.0/16")}
		},
		"positive target": func(in *GuardIntent) { *in = intent },
	} {
		t.Run(name, func(t *testing.T) {
			in := legacyCTRefusal(intent)
			mutate(&in)
			m, _ := RenderGuard(in)
			if verifyLegacyCTGuardRefusal(candidate, in, m, actual, nil) == nil {
				t.Fatal("non-refusal target accepted")
			}
		})
	}
	denial := legacyCTRefusal(intent)
	positive, _ := RenderGuard(intent)
	if verifyLegacyCTGuardRefusal(candidate, denial, positive, actual, nil) == nil {
		t.Fatal("positive manifest accepted even with refusal intent")
	}
	for _, name := range []string{"NAT", "BGP peer"} {
		t.Run("missing "+name+" refusal", func(t *testing.T) {
			next, _ := RenderGuard(denial)
			doc := legacyCTTestDocument(t, []byte(next.ExpectedJSON))
			rows := doc["nftables"].([]any)
			removed := false
			for i, row := range rows {
				rule, ok := row.(map[string]any)["rule"].(map[string]any)
				if !ok {
					continue
				}
				text := string(legacyCTTestJSON(t, rule))
				if name == "NAT" && strings.Contains(text, `"status"`) || name == "BGP peer" && strings.Contains(text, "169.254.1.2") {
					doc["nftables"] = append(rows[:i], rows[i+1:]...)
					removed = true
					break
				}
			}
			if !removed {
				t.Fatal("fixture did not contain expected denial")
			}
			next.ExpectedJSON = string(legacyCTTestJSON(t, doc))
			if verifyLegacyCTGuardRefusal(candidate, denial, next, actual, nil) == nil {
				t.Fatal("recovery removed a permanent protection")
			}
		})
	}
}

func TestRuntimeGuardLegacyCTInterruptedReplacementAndFences(t *testing.T) {
	for _, failure := range []string{"before apply", "after apply", "readback", "native drift", "interface drift", "namespace drift", "journal drift", "ambiguous", "positive"} {
		t.Run(failure, func(t *testing.T) {
			legacy, intent, actual := legacyCTGuardFixture(t)
			denial := legacyCTRefusal(intent)
			next, _ := RenderGuard(denial)
			j, err := OpenRuntimeJournal(journalDir(t), intent.OwnerID)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { j.Close() }()
			prior, _ := RenderGuard(guardFixture())
			if j.prepareGuard(prior) != nil || j.finishGuard(prior) != nil || j.prepareGuard(legacy) != nil {
				t.Fatal("cannot prepare journal")
			}
			if failure == "ambiguous" {
				j.payload.Guards[0] = j.payload.Guards[1]
			}
			before, _, _ := j.guardTemplates()
			applies, reads, namespaces := 0, 0, 0
			failing := true
			reader := &GuardReader{
				namespace: func() (string, error) {
					namespaces++
					if failing && failure == "namespace drift" && namespaces >= 3 {
						return "net:[9999]", nil
					}
					return intent.Namespace, nil
				},
				interfaces: func() ([]GuardInterface, error) {
					if failing && failure == "interface drift" && reads >= 2 {
						return []GuardInterface{{Name: "changed", Index: 5}}, nil
					}
					return nil, nil
				},
				run: func(_ context.Context, args ...string) ([]byte, error) {
					if reflect.DeepEqual(args, []string{"-j", "list", "tables"}) {
						return []byte(`{"nftables":[{"table":{"family":"inet","name":"tunnex_ipsec"}}]}`), nil
					}
					reads++
					if failing && reads == 2 {
						if failure == "native drift" {
							return []byte(strings.Replace(string(actual), "0.10.182.10", "0.10.182.11", 1)), nil
						}
						if failure == "journal drift" {
							j.payload.Sequence++
						}
					}
					if failing && failure == "readback" && applies > 0 {
						return nil, errLegacyCTInjected
					}
					return actual, nil
				},
			}
			guard := &RuntimeGuard{journal: j, reader: reader, apply: func(_ context.Context, _ []byte) error {
				applies++
				guards, _, _ := j.guardTemplates()
				if !failing || (len(guards) == 2 && guards[0].ExpectedJSON == legacy.ExpectedJSON && guards[1].ExpectedJSON == next.ExpectedJSON) {
				} else {
					t.Fatal("successor/legacy not durable before mutation")
				}
				if failing && failure == "before apply" {
					return errLegacyCTInjected
				}
				actual = []byte(next.ExpectedJSON)
				if failing && failure == "after apply" {
					return errLegacyCTInjected
				}
				return nil
			}}
			target := denial
			if failure == "positive" {
				target = intent
			}
			if _, err = guard.Replace(context.Background(), target); err == nil {
				t.Fatal("injected failure was accepted")
			}
			guards, _, _ := j.guardTemplates()
			if failure != "before apply" && failure != "after apply" && failure != "readback" {
				if applies != 0 || !reflect.DeepEqual(guards, before) {
					t.Fatal("failed precondition changed guard or ownership templates")
				}
				return
			}
			if len(guards) != 2 || guards[0].ExpectedJSON != legacy.ExpectedJSON || guards[1].ExpectedJSON != next.ExpectedJSON {
				t.Fatal("interrupted replacement lost a potential obligation")
			}
			// A process restart must recover both possible native outcomes.
			dir := j.dir
			if j.Close() != nil {
				t.Fatal("close interrupted journal")
			}
			j, err = OpenRuntimeJournal(dir, intent.OwnerID)
			if err != nil {
				t.Fatal(err)
			}
			guard.journal = j
			failing = false
			if _, err = guard.Replace(context.Background(), denial); err != nil {
				t.Fatal("restart could not converge to strict refusal", err)
			}
			guards, _, _ = j.guardTemplates()
			if len(guards) != 1 || guards[0].ExpectedJSON != next.ExpectedJSON {
				t.Fatal("restart did not finalize strict refusal")
			}
		})
	}
	if !validRuntimeDiagnostic("guard_replace", "guard_legacy_refusal_fence") || validRuntimeDiagnostic("apply", "guard_legacy_refusal_fence") {
		t.Fatal("recovery diagnostic escaped its fixed operation")
	}
}
