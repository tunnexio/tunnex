package ipsec

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGuardPostNATRefusalHasNoPermitAuthority(t *testing.T) {
	got, err := RenderGuard(guardFixture())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got.NFT, "chain postnat_guard {\n    type filter hook postrouting priority 300; policy accept;") {
		t.Fatal("late NAT refusal hook missing")
	}
	var doc struct {
		Objects []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(got.ExpectedJSON), &doc); err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, object := range doc.Objects {
		var r struct {
			Chain string                       `json:"chain"`
			Expr  []map[string]json.RawMessage `json:"expr"`
		}
		if json.Unmarshal(object["rule"], &r) != nil || r.Chain != "postnat_guard" {
			continue
		}
		count++
		for _, expr := range r.Expr {
			if _, ok := expr["accept"]; ok {
				t.Fatal("late hook granted traffic")
			}
		}
		raw := string(object["rule"])
		if !strings.Contains(raw, `"drop"`) || !strings.Contains(raw, `"status"`) {
			t.Fatal("late rule not translation refusal")
		}
	}
	if count != 8 {
		t.Fatalf("wanted all original/current source/destination DNAT/SNAT guards, got %d", count)
	}
}
