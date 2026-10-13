package ipsec

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestGuardFQDNMarkCanonicalNativeMaskPreservesOwnedBits(t *testing.T) {
	mask := ^fqdnConntrackMarkMask | fqdnConntrackMark
	if mask != 0xf1ffffff || fqdnConntrackMark != 0x01000000 {
		t.Fatal("captured native mask changed")
	}
	values := []uint32{0, 0xffffffff, 0xaaaaaaaa, 0x55555555}
	for bit := uint(0); bit < 32; bit++ {
		values = append(values, 1<<bit, ^(uint32(1) << bit))
	}
	for _, v := range values {
		old := (v &^ fqdnConntrackMarkMask) | fqdnConntrackMark
		got := (v & mask) | fqdnConntrackMark
		if got != old || got&^fqdnConntrackMarkMask != v&^fqdnConntrackMarkMask || got&fqdnConntrackMarkMask != fqdnConntrackMark {
			t.Fatal("mark authority or outside bits changed")
		}
	}
	_, g, _ := v2FQDNFixture(t)
	r := guardAllow(g, 2, 10, false, "lease_owned", "oif")
	raw, _ := json.Marshal(r.expr)
	if !strings.Contains(r.text, "ct mark & 0xf1ffffff") || !strings.Contains(string(raw), "4060086271") {
		t.Fatal("emitter not native canonical")
	}
	in := guardFixture()
	g.FQDN.SelectedGatewayID = in.OwnerID
	g.FQDN.ConnectionID = in.Connections[0].ID
	g.FQDNPermitFor = 20 * time.Second
	in.Connections[0].Grants = append(in.Connections[0].Grants, g)
	m, e := RenderGuard(in)
	if e != nil {
		t.Fatal(e)
	}
	if VerifyGuardReadback([]byte(m.ExpectedJSON), []byte(m.ExpectedJSON)) != nil {
		t.Fatal("exact expected table refused")
	}
	for _, change := range [][2]string{{"4060086271", "4043309055"}, {"4060086271", "4060086270"}, {"16777216", "33554432"}} {
		actual := strings.Replace(m.ExpectedJSON, change[0], change[1], 1)
		if actual == m.ExpectedJSON {
			t.Fatal("negative did not alter expression")
		}
		if VerifyGuardReadback([]byte(m.ExpectedJSON), []byte(actual)) == nil {
			t.Fatal("changed native mark accepted")
		}
	}
}
