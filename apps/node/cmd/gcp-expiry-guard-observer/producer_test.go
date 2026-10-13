package main

import (
	"encoding/json"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/node/internal/ipsec"
	"net/netip"
	"testing"
	"time"
)

func fixture(t *testing.T, grants []ipsec.GuardGrant, duration ...time.Duration) capture {
	t.Helper()
	p := netip.MustParsePrefix
	permit := 30 * time.Second
	if len(duration) == 1 {
		permit = duration[0]
	}
	cl := ipsec.GuardConnection{ID: uuid.MustParse("b79d7eda-fafe-41cf-af2c-4115d4ef32c6"), TunnelCount: 1, Local: []netip.Prefix{p("10.70.0.0/24")}, Remote: []netip.Prefix{p("10.81.0.0/24")}, Tunnels: [2]ipsec.Ownership{{Namespace: namespace, InterfaceName: "txe936e4aecebb", InterfaceIndex: 8, XFRMID: 108}}, PermitFor: permit, PermittedInterfaceIndices: []int{8}, ReplyIngressIndices: []int{8}, LocalIngressIndices: []int{2}, Grants: grants, EncryptedEgress: []ipsec.GuardEncryptedEgress{{TunnelInterfaceIndex: 8, ReqID: 108, Peer: netip.MustParseAddr("34.131.214.202"), UnderlayInterfaceIndex: 2}}}
	ha := cl
	ha.ID = uuid.MustParse("80c20667-8d84-4dd8-8e51-ae4a10445cbb")
	ha.TunnelCount = 0
	ha.Remote = []netip.Prefix{p("10.80.0.0/24")}
	ha.Grants = nil
	ha.Tunnels = [2]ipsec.Ownership{{Namespace: namespace, InterfaceName: "tx21ee6734e2de", InterfaceIndex: 6, XFRMID: 106}, {Namespace: namespace, InterfaceName: "tx8dbedcc23523", InterfaceIndex: 7, XFRMID: 107}}
	ha.PermittedInterfaceIndices = []int{6}
	ha.ReplyIngressIndices = []int{6, 7}
	ha.EncryptedEgress = []ipsec.GuardEncryptedEgress{{TunnelInterfaceIndex: 6, ReqID: 106, Peer: netip.MustParseAddr("34.153.32.207"), UnderlayInterfaceIndex: 2}}
	m, e := ipsec.RenderGuard(ipsec.GuardIntent{Namespace: namespace, OwnerID: uuid.MustParse(owner), Revision: 99, Connections: []ipsec.GuardConnection{cl, ha}})
	if e != nil {
		t.Fatal(e)
	}
	c := capture{Source: source, Container: container, Image: image, Boot: boot, Before: namespace, After: namespace, HostBefore: namespace, HostAfter: namespace, Stable: true, Reader: reader, Actual: json.RawMessage(m.ExpectedJSON)}
	c.Expected.ExpectedJSON = m.ExpectedJSON
	c.Expected.Namespace = namespace
	c.Expected.Revision = 99
	c.Expected.Digest = m.Digest
	for _, l := range []struct {
		n string
		i int
	}{{"ens4", 2}, {"txe936e4aecebb", 8}, {"tx21ee6734e2de", 6}, {"tx8dbedcc23523", 7}} {
		n, _ := json.Marshal(l.n)
		i, _ := json.Marshal(l.i)
		c.Links = append(c.Links, map[string]json.RawMessage{"ifname": n, "ifindex": i})
	}
	return c
}
func grants() []ipsec.GuardGrant {
	p := netip.MustParsePrefix
	return []ipsec.GuardGrant{{Source: p("10.70.0.0/24"), Destination: p("10.81.0.10/32"), Protocol: ipsec.GuardTCP, PortLow: 8080, PortHigh: 8080}, {Source: p("10.70.0.0/24"), Destination: p("10.81.0.10/32"), Protocol: ipsec.GuardUDP, PortLow: 9000, PortHigh: 9000}}
}
func edit(t *testing.T, c capture, f func(map[string]any)) capture {
	m, e := decode(c.Actual)
	if e != nil {
		t.Fatal(e)
	}
	for _, r := range m["nftables"].([]any) {
		f(object(r))
	}
	c.Actual, _ = json.Marshal(m)
	return c
}
func TestProducerAllowDenyAndWiderGrants(t *testing.T) {
	c := fixture(t, grants())
	for _, p := range []string{"tcp", "udp"} {
		if _, e := verify(c, "allow", p); e != nil {
			t.Fatalf("allow %s %v", p, e)
		}
	}
	c = fixture(t, grants()[:1])
	if _, e := verify(c, "deny", "udp"); e != nil {
		t.Fatal(e)
	}
	if _, e := verify(c, "allow", "tcp"); e != nil {
		t.Fatal(e)
	}
	if _, e := verify(c, "deny", "tcp"); e == nil {
		t.Fatal("live rule ignored")
	}
	for _, kind := range []string{"any", "range", "source", "destination"} {
		g := grants()[1]
		switch kind {
		case "any":
			g.Protocol = ipsec.GuardAny
			g.PortLow = 0
			g.PortHigh = 0
		case "range":
			g.PortLow = 8999
			g.PortHigh = 9001
		case "source":
			g.Source = netip.MustParsePrefix("10.70.0.10/32")
		case "destination":
			g.Destination = netip.MustParsePrefix("10.81.0.0/24")
		}
		c = fixture(t, []ipsec.GuardGrant{g})
		for _, mode := range []string{"allow", "deny"} {
			if _, e := verify(c, mode, "udp"); e == nil {
				t.Fatalf("%s %s accepted", kind, mode)
			}
		}
	}
}
func TestProducerExpiryCannotProveRuleAbsence(t *testing.T) {
	for _, name := range []string{lease, "lease_80c206678d844dd88e51ae4a10445cbb"} {
		c := edit(t, fixture(t, grants()), func(o map[string]any) {
			s := object(o["set"])
			if s["name"] == name {
				for _, r := range s["elem"].([]any) {
					object(object(r)["elem"])["expires"] = json.Number("0")
				}
			}
		})
		for _, mode := range []string{"allow", "deny"} {
			if _, e := verify(c, mode, "udp"); e == nil {
				t.Fatal("zero-life member supplied proof")
			}
		}
	}
	c := edit(t, fixture(t, grants()[:1]), func(o map[string]any) {
		s := object(o["set"])
		if s["name"] == lease {
			delete(s, "elem")
		}
	})
	r, e := verify(c, "deny", "udp")
	if e != nil || r.Readback != "withdrawal structure only" {
		t.Fatal(e)
	}
}
func TestProducerNativeTimedInterfaceNames(t *testing.T) {
	c := edit(t, fixture(t, grants()), func(o map[string]any) {
		s := object(o["set"])
		if s["name"] == lease || s["name"] == reply {
			for _, r := range s["elem"].([]any) {
				e := object(object(r)["elem"])
				e["val"] = "txe936e4aecebb"
				e["expires"] = json.Number("17")
			}
		}
	})
	if _, e := verify(c, "allow", "udp"); e != nil {
		t.Fatal(e)
	}
}
func TestProducerUnknownAndMalformedCaptureRefuse(t *testing.T) {
	for _, kind := range []string{"accept", "drop", "timeout", "owner", "churn", "namespace"} {
		c := edit(t, fixture(t, grants()[:1]), func(o map[string]any) {
			r := object(o["rule"])
			s := object(o["set"])
			ch := object(o["chain"])
			switch kind {
			case "accept":
				if r["chain"] == "forward_guard" {
					r["expr"] = []any{map[string]any{"accept": nil}}
				}
			case "drop":
				if r["chain"] == "postrouting_guard" {
					r["expr"] = []any{map[string]any{"drop": nil}}
				}
			case "timeout":
				if s["name"] == lease {
					s["timeout"] = json.Number("61")
				}
			case "owner":
				if ch["name"] == "owner" {
					ch["comment"] = "foreign"
				}
			}
		})
		if kind == "churn" {
			c.Stable = false
		}
		if kind == "namespace" {
			c.After = "net:[42]"
		}
		if _, e := verify(c, "deny", "udp"); e == nil {
			t.Fatalf("unsafe %s", kind)
		}
	}
}

func TestProducerNativeInheritedDefaultTimeout(t *testing.T) {
	c := edit(t, fixture(t, grants(), 60*time.Second), func(o map[string]any) {
		s := object(o["set"])
		if s["name"] == lease || s["name"] == reply || s["name"] == saLease {
			for _, r := range s["elem"].([]any) {
				e := object(object(r)["elem"])
				delete(e, "timeout")
				e["expires"] = json.Number("17")
			}
		}
	})
	if _, e := verify(c, "allow", "udp"); e != nil {
		t.Fatal("native omitted equal default timeout", e)
	}
}
