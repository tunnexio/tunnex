package ipsec

import (
	"encoding/json"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func dockerForwardTestRules(t *testing.T) []map[string]any {
	t.Helper()
	manifest, err := RenderGuard(guardFixture())
	if err != nil {
		t.Fatal(err)
	}
	rules, err := runtimeDockerForwardRules(manifest.ExpectedJSON, manifest.OwnerID)
	if err != nil || len(rules) != 2 {
		t.Fatalf("expected only forward and return grant tuples: %d %v", len(rules), err)
	}
	return rules
}

func TestDockerForwardDerivesOnlyRenderedGrants(t *testing.T) {
	rules := dockerForwardTestRules(t)
	for _, rule := range rules {
		raw, _ := json.Marshal(rule)
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil || !runtimeDockerForwardRule(fields) {
			t.Fatal("renderer produced noncanonical Docker tuple", string(raw))
		}
		if strings.Contains(string(raw), "@lease") || strings.Contains(string(raw), "port") {
			t.Fatal("structural tuple incorrectly copied authority")
		}
	}
	for _, change := range []func(*GuardIntent){
		func(i *GuardIntent) { i.Connections[0].Grants = nil },
		func(i *GuardIntent) { i.Connections[0].PermitFor = 0 },
		func(i *GuardIntent) { i.Connections[0].PermittedInterfaceIndices = nil },
		func(i *GuardIntent) { i.Connections[0].Grants[0].HostOrigin = true },
	} {
		intent := guardFixture()
		change(&intent)
		manifest, err := RenderGuard(intent)
		if err != nil {
			t.Fatal(err)
		}
		got, err := runtimeDockerForwardRules(manifest.ExpectedJSON, intent.OwnerID)
		if err != nil || len(got) != 0 {
			t.Fatalf("non-forward authority created Docker exceptions: %d %v", len(got), err)
		}
	}
}

func TestDockerForwardSchemaRejectsWidenedAndUnownedRules(t *testing.T) {
	base, _ := json.Marshal(dockerForwardTestRules(t)[0])
	mutations := map[string]func(map[string]any){
		"marker": func(r map[string]any) { r["comment"] = "tunnex-site-fwd" },
		"owner": func(r map[string]any) {
			r["comment"] = runtimeDockerForwardComment + "00000000-0000-0000-0000-000000000000"
		},
		"chain":             func(r map[string]any) { r["chain"] = "DOCKER-USER" },
		"extra":             func(r map[string]any) { r["position"] = 1 },
		"missing-interface": func(r map[string]any) { r["expr"] = r["expr"].([]any)[1:] },
		"negated-interface": func(r map[string]any) { r["expr"].([]any)[0].(map[string]any)["match"].(map[string]any)["op"] = "!=" },
		"zero-interface":    func(r map[string]any) { r["expr"].([]any)[0].(map[string]any)["match"].(map[string]any)["right"] = 0 },
		"set-interface": func(r map[string]any) {
			r["expr"].([]any)[0].(map[string]any)["match"].(map[string]any)["right"] = "@lease_fake"
		},
		"unnormalized-prefix": func(r map[string]any) {
			r["expr"].([]any)[2].(map[string]any)["match"].(map[string]any)["right"] = map[string]any{"prefix": map[string]any{"addr": "10.10.0.1", "len": 24}}
		},
		"blanket-prefix": func(r map[string]any) {
			r["expr"].([]any)[2].(map[string]any)["match"].(map[string]any)["right"] = map[string]any{"prefix": map[string]any{"addr": "0.0.0.0", "len": 0}}
		},
		"verdict": func(r map[string]any) { r["expr"].([]any)[5] = map[string]any{"return": nil} },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			var rule map[string]any
			_ = json.Unmarshal(base, &rule)
			mutate(rule)
			raw, _ := json.Marshal(rule)
			var fields map[string]json.RawMessage
			_ = json.Unmarshal(raw, &fields)
			if runtimeDockerForwardRule(fields) {
				t.Fatal("unsafe or foreign rule admitted")
			}
		})
	}
}

func TestDockerForwardRendererDriftFailsClosed(t *testing.T) {
	manifest, err := RenderGuard(guardFixture())
	if err != nil {
		t.Fatal(err)
	}
	changed := strings.ReplaceAll(manifest.ExpectedJSON, `"key":"iif"`, `"key":"unexpected"`)
	if _, err = runtimeDockerForwardRules(changed, manifest.OwnerID); err == nil {
		t.Fatal("unknown forward ACCEPT shape silently skipped")
	}
}

func TestDockerForwardPreservesExistingForwardGrantVariants(t *testing.T) {
	cases := map[string]func(*GuardIntent){
		"udp": func(in *GuardIntent) { in.Connections[0].Grants[0].Protocol = GuardUDP },
		"any": func(in *GuardIntent) {
			in.Connections[0].Grants[0].Protocol = GuardAny
			in.Connections[0].Grants[0].PortLow, in.Connections[0].Grants[0].PortHigh = 0, 0
		},
		"remote-origin": func(in *GuardIntent) {
			c := &in.Connections[0]
			c.ReplyIngressIndices = []int{10, 11}
			c.Grants[0].Source, c.Grants[0].Destination = c.Grants[0].Destination, c.Grants[0].Source
		},
		"related-fragment-needed": func(in *GuardIntent) {
			in.Connections[0].ReplyIngressIndices = []int{10, 11}
			in.Connections[0].Grants[0].Source = netip.MustParsePrefix("10.10.0.2/32")
		},
		"desktop": func(in *GuardIntent) {
			d := desktopGrantFixture()
			in.Connections[0].ReplyIngressIndices = []int{10}
			in.Connections[0].Grants = []GuardGrant{{Source: netip.MustParsePrefix(d.Source), Destination: netip.MustParsePrefix(d.Destination), Protocol: GuardTCP, PortLow: 443, PortHigh: 443, DesktopDeviceID: uuid.MustParse(d.DeviceID), DesktopPublicKey: d.PublicKey, DesktopIngressIndex: 7}}
		},
		"fqdn-v2": func(in *GuardIntent) {
			_, grant, _ := v2FQDNFixture(t)
			grant.FQDN.SelectedGatewayID = in.OwnerID
			grant.FQDN.ConnectionID = in.Connections[0].ID
			grant.FQDNPermitFor = 20 * time.Second
			in.Connections[0].Grants = []GuardGrant{grant}
		},
	}
	for name, configure := range cases {
		t.Run(name, func(t *testing.T) {
			intent := guardFixture()
			configure(&intent)
			manifest, err := RenderGuard(intent)
			if err != nil {
				t.Fatal(err)
			}
			rules, err := runtimeDockerForwardRules(manifest.ExpectedJSON, manifest.OwnerID)
			if err != nil || len(rules) < 2 {
				t.Fatalf("supported grant variant lost structural forwarding: %d %v", len(rules), err)
			}
			for _, rule := range rules {
				raw, _ := json.Marshal(rule)
				if strings.Contains(string(raw), "mangle") || strings.Contains(string(raw), "@fqdn") {
					t.Fatal("structural exception acquired independent FQDN authority")
				}
			}
		})
	}
}

func TestDockerForwardReadbackNormalizesNativeInterfacesAndHostPrefixes(t *testing.T) {
	intent := guardFixture()
	intent.Connections[0].Grants[0].Source = netip.MustParsePrefix("10.10.0.2/32")
	manifest, err := RenderGuard(intent)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := runtimeDockerForwardRules(manifest.ExpectedJSON, intent.OwnerID)
	if err != nil || len(rules) != 2 {
		t.Fatal(err)
	}
	for _, rule := range rules {
		want, _, err := runtimeDockerForwardKey(rule, nil, false)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(rule)
		observed, _ := runtimeDockerForwardObject(raw)
		exprs := observed["expr"].([]any)
		for _, value := range exprs[:4] {
			match := value.(map[string]any)["match"].(map[string]any)
			if index, ok := match["right"].(json.Number); ok {
				if index == "2" {
					match["right"] = "eth0"
				} else {
					match["right"] = "tnxi-a"
				}
			}
			if prefix, ok := match["right"].(map[string]any); ok && prefix["prefix"].(map[string]any)["len"] == json.Number("32") {
				match["right"] = "10.10.0.2"
			}
		}
		observed["handle"] = json.Number("71")
		exprs[4] = map[string]any{"counter": map[string]any{"packets": 4, "bytes": 100}}
		got, handle, err := runtimeDockerForwardKey(observed, map[string]int{"eth0": 2, "tnxi-a": 10}, false)
		if err != nil || got != want || handle != 71 {
			t.Fatalf("native readback differs: %v %d\n%s\n%s", err, handle, got, want)
		}
		if _, _, err = runtimeDockerForwardKey(observed, map[string]int{"eth0": 2}, false); err == nil {
			t.Fatal("unbound native interface accepted")
		}
	}
}

func TestDockerForwardAtomicReplacementPreservesForeignRules(t *testing.T) {
	rules := dockerForwardTestRules(t)
	plan := &runtimeDockerForwardPlan{rules: rules, remove: []uint64{123, 124}}
	guard := `{"nftables":[{"flush":{"table":{"family":"inet","name":"tunnex_ipsec"}}}]}`
	raw, err := plan.transaction(guard)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	if json.Unmarshal([]byte(raw), &doc) != nil || len(doc.NFTables) != 5 {
		t.Fatal("expected single atomic guard + delete-owned + append-owned transaction", raw)
	}
	for _, command := range doc.NFTables[1:3] {
		if len(command) != 1 || command["delete"] == nil || !strings.Contains(string(command["delete"]), `"handle":12`) {
			t.Fatal("withdrawal was not exact-handle deletion")
		}
	}
	for _, command := range doc.NFTables[3:] {
		if len(command) != 1 || command["add"] == nil || strings.Contains(string(command["add"]), "position") {
			t.Fatal("exception must append after foreign policy")
		}
	}
	refused := &runtimeDockerForwardPlan{remove: []uint64{123, 124}}
	withdrawn, err := refused.transaction(guard)
	if err != nil || strings.Contains(withdrawn, `"accept"`) || strings.Contains(withdrawn, `"flush":{"chain"`) {
		t.Fatal("refusal did not only remove exact owned exceptions")
	}
}

func TestDockerForwardSnapshotPreservesForeignDeniesAndRejectsOwnerDrift(t *testing.T) {
	rules := dockerForwardTestRules(t)
	rules[0]["handle"] = 10
	foreignRule := map[string]any{"rule": map[string]any{"family": "ip", "table": "filter", "chain": "DOCKER-USER", "handle": 5, "expr": []any{map[string]any{"counter": map[string]any{"packets": 1, "bytes": 10}}, map[string]any{"drop": nil}}}}
	doc := map[string]any{"nftables": []any{foreignRule, map[string]any{"rule": rules[0]}}}
	raw, _ := json.Marshal(doc)
	rows, ok := runtimeCensusRows(raw)
	if !ok {
		t.Fatal("fixture")
	}
	current, foreign, err := runtimeDockerForwardSnapshot(rows, guardFixture().OwnerID, nil, true)
	if err != nil || len(current) != 1 || !strings.Contains(foreign, `"drop":null`) || strings.Contains(foreign, runtimeDockerForwardComment) {
		t.Fatalf("foreign policy lost: %v %s", err, foreign)
	}
	foreignRule["rule"].(map[string]any)["expr"].([]any)[0].(map[string]any)["counter"] = map[string]any{"packets": 99, "bytes": 999}
	raw, _ = json.Marshal(doc)
	rows, _ = runtimeCensusRows(raw)
	_, after, err := runtimeDockerForwardSnapshot(rows, guardFixture().OwnerID, nil, true)
	if err != nil || !reflect.DeepEqual(foreign, after) {
		t.Fatal("traffic counters changed foreign ownership snapshot")
	}
	rules[0]["comment"] = runtimeDockerForwardComment + "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	raw, _ = json.Marshal(doc)
	rows, _ = runtimeCensusRows(raw)
	if _, _, err = runtimeDockerForwardSnapshot(rows, guardFixture().OwnerID, nil, true); err == nil {
		t.Fatal("another owner's exception adopted")
	}
}

func TestDockerForwardJournalBoundRenewalRepairAndWithdrawal(t *testing.T) {
	intent := guardFixture()
	manifest, err := RenderGuard(intent)
	if err != nil {
		t.Fatal(err)
	}
	prior := &runtimeGuardTemplate{Namespace: manifest.Namespace, Revision: manifest.Revision, Digest: manifest.Digest, ExpectedJSON: manifest.ExpectedJSON}
	rules := dockerForwardTestRules(t)
	objects := []any{map[string]any{"table": map[string]any{"family": "ip", "name": "filter", "handle": 1}}}
	for index, rule := range rules {
		rule["handle"] = index + 11
		objects = append(objects, map[string]any{"rule": rule})
	}
	raw, _ := json.Marshal(map[string]any{"nftables": objects})
	rows, _ := runtimeCensusRows(raw)
	plan, err := runtimeDockerForwardPlanForSnapshot(manifest, prior, rows, nil)
	if err != nil || len(plan.rules) != 2 || !reflect.DeepEqual(plan.remove, []uint64{11, 12}) {
		t.Fatalf("renewal ownership failed: %+v %v", plan, err)
	}
	if _, err = runtimeDockerForwardPlanForSnapshot(manifest, nil, rows, nil); err == nil {
		t.Fatal("marker-only orphan was adopted without prior journal")
	}
	// Docker can recreate its own chain. Missing structural tuples may be
	// repaired only while the independently rendered current guard permits them.
	plan, err = runtimeDockerForwardPlanForSnapshot(manifest, prior, rows[:1], nil)
	if err != nil || len(plan.rules) != 2 || len(plan.remove) != 0 {
		t.Fatal("Docker restart did not repair exact fresh grants", err)
	}
	intent.Revision++
	intent.Connections[0].PermitFor = 0
	intent.Connections[0].PermittedInterfaceIndices = nil
	refusal, err := RenderGuard(intent)
	if err != nil {
		t.Fatal(err)
	}
	plan, err = runtimeDockerForwardPlanForSnapshot(refusal, prior, rows, nil)
	if err != nil || len(plan.rules) != 0 || !reflect.DeepEqual(plan.remove, []uint64{11, 12}) {
		t.Fatal("restart/refusal did not withdraw old structural accepts", err)
	}
	// A shape that merely retains our comment cannot broaden its journal-bound
	// source, destination or interface and then be treated as owned cleanup.
	rules[0]["expr"].([]any)[0].(map[string]any)["match"].(map[string]any)["right"] = 99
	raw, _ = json.Marshal(map[string]any{"nftables": objects})
	rows, _ = runtimeCensusRows(raw)
	if _, err = runtimeDockerForwardPlanForSnapshot(refusal, prior, rows, nil); err == nil {
		t.Fatal("foreign tuple with copied marker accepted for deletion")
	}
}

func TestDockerForwardOwnExceptionCannotPrecedeForeignPolicy(t *testing.T) {
	rule := dockerForwardTestRules(t)[0]
	rule["handle"] = 10
	foreign := map[string]any{"rule": map[string]any{"family": "ip", "table": "filter", "chain": "FORWARD", "handle": 11, "expr": []any{map[string]any{"drop": nil}}}}
	raw, _ := json.Marshal(map[string]any{"nftables": []any{map[string]any{"rule": rule}, foreign}})
	rows, _ := runtimeCensusRows(raw)
	if _, _, err := runtimeDockerForwardSnapshot(rows, guardFixture().OwnerID, nil, true); err == nil {
		t.Fatal("structural exception moved ahead of foreign deny")
	}
}
