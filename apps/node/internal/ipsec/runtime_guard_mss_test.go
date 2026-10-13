package ipsec

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestGuardMSSScopedDecrementOnly(t *testing.T) {
	for _, mtu := range []uint16{1422, 1300} {
		intent := guardFixture()
		c := &intent.Connections[0]
		c.TunnelMTUs = []GuardTunnelMTU{{10, mtu}, {11, 1422}}
		c.ReplyIngressIndices = []int{10, 11}
		got, err := RenderGuard(intent)
		if err != nil {
			t.Fatal(err)
		}
		want := "> 1382 tcp option maxseg size set 1382"
		if mtu == 1300 {
			want = "> 1260 tcp option maxseg size set 1260"
		}
		if !strings.Contains(got.NFT, want) || strings.Count(got.NFT, "tcp flags & (syn | rst) == syn") != 3 {
			t.Fatal("missing exact outbound/reply SYN clamp", got.NFT)
		}
		for _, line := range strings.Split(got.NFT, "\n") {
			if strings.Contains(line, "maxseg") {
				if !strings.Contains(line, "ip saddr ") || !strings.Contains(line, "ip daddr ") || (!strings.Contains(line, "@lease_") && !strings.Contains(line, "@reply_lease_")) || strings.Contains(line, "accept") {
					t.Fatal("clamp lacks authority or contains verdict", line)
				}
			}
		}
		if !strings.Contains(got.NFT, "ct direction reply ct state established") {
			t.Fatal("reply predicate weakened")
		}
		var doc any
		if json.Unmarshal([]byte(got.NFTJSON), &doc) != nil {
			t.Fatal("invalid document")
		}
	}
}
func TestGuardMSSNoNewAuthority(t *testing.T) {
	for _, which := range []string{"no-grants", "UDP", "no-mtu", "no-permitted", "no-lease"} {
		i := guardFixture()
		c := &i.Connections[0]
		c.TunnelMTUs = []GuardTunnelMTU{{10, 1422}}
		switch which {
		case "no-grants":
			c.Grants = nil
		case "UDP":
			c.Grants[0].Protocol = GuardUDP
		case "no-mtu":
			c.TunnelMTUs = nil
		case "no-lease":
			c.PermitFor = 0
		case "no-permitted":
			c.PermittedInterfaceIndices = nil
		}
		got, err := RenderGuard(i)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(got.NFT, "maxseg") {
			t.Fatalf("%s manufactured clamp", which)
		}
	}
}
func TestGuardMSSRejectsForeignOrInvalidMTU(t *testing.T) {
	for _, m := range []GuardTunnelMTU{{99, 1422}, {10, 1500}, {10, 0}, {10, 67}} {
		i := guardFixture()
		i.Connections[0].TunnelMTUs = []GuardTunnelMTU{m}
		if _, err := RenderGuard(i); err == nil {
			t.Fatal("unsafe MTU accepted", m)
		}
	}
	i := guardFixture()
	i.Connections[0].TunnelMTUs = []GuardTunnelMTU{{10, 1422}, {10, 1300}}
	if _, err := RenderGuard(i); err == nil {
		t.Fatal("duplicate MTU accepted")
	}
}
func TestGuardMSSFreshOwnedProjection(t *testing.T) {
	c, f, _, _ := bgpControllerFixture(t, false)
	entries, _ := c.journal.Entries()
	e := entries[0]
	f.mtu[0] = 1300
	f.down = 1
	got, err := c.guardTunnelMTUs(context.Background(), e, RuntimeEnvironment{Underlays: [2]RuntimeUnderlay{{OuterMTU: 1500}, {OuterMTU: 1500}}}, []int{e.Observed[0].InterfaceIndex})
	if err != nil || len(got) != 1 || got[0].MTU != 1300 {
		t.Fatal("healthy smaller MTU not projected", got, err)
	}
	for _, m := range []uint64{0, 1500} {
		f.mtu[0] = m
		if _, err = c.guardTunnelMTUs(context.Background(), e, RuntimeEnvironment{Underlays: [2]RuntimeUnderlay{{OuterMTU: 1500}, {OuterMTU: 1500}}}, []int{e.Observed[0].InterfaceIndex}); err == nil {
			t.Fatal("invalid current MTU accepted", m)
		}
	}
	f.mtu[0] = 1422
	if _, err = c.guardTunnelMTUs(context.Background(), e, RuntimeEnvironment{Underlays: [2]RuntimeUnderlay{{OuterMTU: 1500}, {OuterMTU: 1500}}}, []int{e.Observed[1].InterfaceIndex}); err == nil {
		t.Fatal("down positive path accepted")
	}
	if _, err = c.guardTunnelMTUs(context.Background(), e, RuntimeEnvironment{Underlays: [2]RuntimeUnderlay{{OuterMTU: 1500}, {OuterMTU: 1500}}}, []int{99}); err == nil {
		t.Fatal("foreign positive path accepted")
	}
}

func TestGuardMSSReadbackRejectsWidenedMangling(t *testing.T) {
	i := guardFixture()
	i.Connections[0].TunnelMTUs = []GuardTunnelMTU{{10, 1422}}
	m, err := RenderGuard(i)
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"flags", "bound", "value", "lease"} {
		var doc map[string]any
		if json.Unmarshal([]byte(m.ExpectedJSON), &doc) != nil {
			t.Fatal("fixture JSON")
		}
		changed := false
		for _, raw := range doc["nftables"].([]any) {
			rule, ok := raw.(map[string]any)["rule"].(map[string]any)
			if !ok {
				continue
			}
			expr := rule["expr"].([]any)
			mangled := false
			for _, raw := range expr {
				if _, ok := raw.(map[string]any)["mangle"]; ok {
					mangled = true
				}
			}
			if !mangled {
				continue
			}
			switch scenario {
			case "flags":
				expr[len(expr)-4].(map[string]any)["match"].(map[string]any)["left"] = map[string]any{"&": []any{guardPayload("tcp", "flags"), map[string]any{"|": []any{"syn", "fin"}}}}
			case "bound":
				expr[len(expr)-3].(map[string]any)["match"].(map[string]any)["right"] = 1200
			case "value":
				expr[len(expr)-2].(map[string]any)["mangle"].(map[string]any)["value"] = 1500
			case "lease":
				rule["expr"] = append(expr[:len(expr)-5], expr[len(expr)-4:]...)
			}
			changed = true
			break
		}
		if !changed {
			t.Fatal("no actual clamp fixture")
		}
		observed, _ := json.Marshal(doc)
		if VerifyGuardReadback([]byte(m.ExpectedJSON), observed) == nil {
			t.Fatal("widened or changed MSS semantics accepted", scenario)
		}
	}
}
