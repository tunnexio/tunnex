package ipsec

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestGuardFQDNRelatedLookupTypedIPv4PreservesScalarGrammar(t *testing.T) {
	in := guardFixture()
	c := &in.Connections[0]
	c.ReplyIngressIndices = []int{10}
	_, g, _ := v2FQDNFixture(t)
	g.FQDN.ConnectionID = c.ID
	g.FQDN.SelectedGatewayID = in.OwnerID
	g.FQDNPermitFor = 3 * time.Second
	ordinary := g
	ordinary.FQDNManaged = false
	ordinary.FQDN = FQDNGrantBinding{}
	ordinary.FQDNPermitFor = 0
	scalar := guardRemoteFragmentNeeded(*c, ordinary, 10, 2, c.Remote[0])
	related := guardRemoteFragmentNeeded(*c, g, 10, 2, c.Remote[0])
	if !reflect.DeepEqual(scalar.expr[:len(scalar.expr)-2], related.expr[:len(scalar.expr)-2]) {
		t.Fatal("ordinary scalar parent grammar changed")
	}
	lookup, _ := json.Marshal(related.expr[len(related.expr)-3])
	want := `{"match":{"left":{"ct":{"dir":"original","key":"ip daddr"}},"op":"==","right":"@` + guardFQDNSetName(g) + `"}}`
	if string(lookup) != want {
		t.Fatal("timed lookup lost exact original IPv4 binding")
	}
	c.Grants = append(c.Grants, g)
	m, err := RenderGuard(in)
	if err != nil {
		t.Fatal(err)
	}
	if VerifyGuardReadback([]byte(m.ExpectedJSON), []byte(m.ExpectedJSON)) != nil {
		t.Fatal("exact expected table refused")
	}
	if strings.Count(m.ExpectedJSON, want) != 1 || strings.Count(m.NFTJSON, want) != 1 {
		t.Fatal("typed lookup not emitted exactly once")
	}
	for name, replacement := range map[string]string{"untyped": strings.Replace(want, `"ip daddr"`, `"daddr"`, 1), "ipv6": strings.Replace(want, `"ip daddr"`, `"ip6 daddr"`, 1), "direction": strings.Replace(want, `"original"`, `"reply"`, 1), "foreign-set": strings.Replace(want, guardFQDNSetName(g), "fqdn_"+strings.Repeat("0", 64), 1)} {
		t.Run(name, func(t *testing.T) {
			observed := strings.Replace(m.ExpectedJSON, want, replacement, 1)
			if VerifyGuardReadback([]byte(m.ExpectedJSON), []byte(observed)) == nil {
				t.Fatal("altered timed parent binding accepted")
			}
			if VerifyGuardWithdrawal([]byte(m.ExpectedJSON), []byte(observed), nil) == nil {
				t.Fatal("altered timed parent binding accepted for withdrawal")
			}
		})
	}
}
