package ipsec

import (
	"encoding/json"
	"testing"
)

func TestGuardReadbackSetDeclarationOrderIsNotRuleOrder(t *testing.T) {
	m, e := RenderGuard(guardFixture())
	if e != nil {
		t.Fatal(e)
	}
	var doc map[string][]map[string]json.RawMessage
	if json.Unmarshal([]byte(m.ExpectedJSON), &doc) != nil {
		t.Fatal("fixture")
	}
	positions := []int{}
	for i, o := range doc["nftables"] {
		if _, ok := o["set"]; ok {
			positions = append(positions, i)
		}
	}
	if len(positions) != 3 {
		t.Fatal("fixture requires three independent set definitions")
	}
	a, b := positions[0], positions[1]
	doc["nftables"][a], doc["nftables"][b] = doc["nftables"][b], doc["nftables"][a]
	raw, _ := json.Marshal(doc)
	if VerifyGuardReadback([]byte(m.ExpectedJSON), raw) != nil {
		t.Fatal("same independent set definitions refused in kernel creation order")
	}
	// Rule order remains semantic even after set declaration canonicalization.
	rules := []int{}
	for i, o := range doc["nftables"] {
		if _, ok := o["rule"]; ok {
			rules = append(rules, i)
		}
	}
	a, b = rules[0], rules[1]
	doc["nftables"][a], doc["nftables"][b] = doc["nftables"][b], doc["nftables"][a]
	raw, _ = json.Marshal(doc)
	if VerifyGuardReadback([]byte(m.ExpectedJSON), raw) == nil {
		t.Fatal("changed rule order accepted")
	}
}
