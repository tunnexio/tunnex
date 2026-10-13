package main

import (
	"encoding/json"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/node/internal/ipsec"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T, live ...bool) capture {
	t.Helper()
	intent := ipsec.GuardIntent{Namespace: "net:[4026531840]", OwnerID: uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"), Revision: 1}
	for i, v := range []struct {
		id, remote string
		count      uint8
	}{{"80c20667-8d84-4dd8-8e51-ae4a10445cbb", "10.80.0.0/24", 2}, {"b79d7eda-fafe-41cf-af2c-4115d4ef32c6", "10.81.0.0/24", 1}} {
		c := ipsec.GuardConnection{ID: uuid.MustParse(v.id), TunnelCount: func() uint8 {
			if v.count == 1 {
				return 1
			}
			return 0
		}(), Local: []netip.Prefix{netip.MustParsePrefix("10.70.0.0/24")}, Remote: []netip.Prefix{netip.MustParsePrefix(v.remote)}, LocalIngressIndices: []int{2}}
		for s := uint8(0); s < v.count; s++ {
			idx := 6 + i*2 + int(s)
			c.Tunnels[s] = ipsec.Ownership{Namespace: intent.Namespace, InterfaceName: []string{"tx-a", "tx-b", "tx-c", "tx-d"}[i*2+int(s)], InterfaceIndex: idx, XFRMID: uint32(100 + idx)}
		}
		if len(live) > 0 && live[0] {
			c.PermitFor = 30 * time.Second
			c.PermittedInterfaceIndices = []int{c.Tunnels[0].InterfaceIndex}
			c.ReplyIngressIndices = []int{c.Tunnels[0].InterfaceIndex}
		}
		intent.Connections = append(intent.Connections, c)
	}
	m, e := ipsec.RenderGuard(intent)
	if e != nil {
		t.Fatal(e)
	}
	c := capture{Source: source, Image: "sha256:9a051bbdc9eed316bfabf2914e26a1c5f454927665902b0c7e0d2ded8a5374d7", Reader: reader, Namespace: intent.Namespace, After: intent.Namespace, GuardStable: true, Actual: json.RawMessage(m.ExpectedJSON), JournalSHA: strings.Repeat("a", 64)}
	c.Expected.ExpectedJSON = m.ExpectedJSON
	c.Expected.Digest = m.Digest
	c.Expected.Revision = 1
	c.Expected.Namespace = m.Namespace
	return c
}
func TestActualEmptyMixedCardinalityTable(t *testing.T) {
	if e := verify(fixture(t)); e != nil {
		t.Fatal(e)
	}
}
func TestRejectNonemptyEvenZeroExpiryAndForeignRule(t *testing.T) {
	for _, kind := range []string{"live", "zero", "null", "foreign-drop", "missing-drop", "namespace", "reader", "unstable"} {
		t.Run(kind, func(t *testing.T) {
			c := fixture(t)
			switch kind {
			case "namespace":
				c.After = "net:[5]"
			case "reader":
				c.Reader = strings.Repeat("b", 64)
			case "unstable":
				c.GuardStable = false
			default:
				var d map[string][]map[string]map[string]any
				if json.Unmarshal(c.Actual, &d) != nil {
					t.Fatal("parse")
				}
				for _, o := range d["nftables"] {
					if s, ok := o["set"]; ok && s["name"] == "lease_b79d7edafafe41cfaf2c4115d4ef32c6" {
						if kind == "null" {
							s["elem"] = nil
						} else if kind == "live" || kind == "zero" {
							n := 30
							if kind == "zero" {
								n = 0
							}
							s["elem"] = []any{map[string]any{"elem": map[string]any{"val": 8, "timeout": 30, "expires": n}}}
						}
					}
					if r, ok := o["rule"]; ok && r["chain"] == "forward_guard" && strings.Contains(string(mustJSON(r)), "10.81.0.0") {
						if kind == "foreign-drop" {
							r["chain"] = "foreign"
						}
						if kind == "missing-drop" {
							r["expr"] = []any{map[string]any{"accept": nil}}
						}
					}
				}
				c.Actual = mustJSON(d)
			}
			if verify(c) == nil {
				t.Fatal("unsafe observation accepted")
			}
		})
	}
}
func mustJSON(v any) []byte {
	b, e := json.Marshal(v)
	if e != nil {
		panic(e)
	}
	return b
}

func TestWithdrawalAloneDoesNotProveEmptyPermitSets(t *testing.T) {
	c := fixture(t, true)
	var d map[string][]map[string]map[string]any
	if json.Unmarshal(c.Actual, &d) != nil {
		t.Fatal("parse")
	}
	for _, o := range d["nftables"] {
		if set, ok := o["set"]; ok && (strings.HasPrefix(set["name"].(string), "lease_") || strings.HasPrefix(set["name"].(string), "reply_lease_") || strings.HasPrefix(set["name"].(string), "sa_lease_")) {
			set["elem"] = []any{}
		}
	}
	for _, o := range d["nftables"] {
		if set, ok := o["set"]; ok && set["name"] == "lease_b79d7edafafe41cfaf2c4115d4ef32c6" {
			set["elem"] = []any{map[string]any{"elem": map[string]any{"val": 8, "timeout": 30, "expires": 0}}}
		}
	}
	c.Actual = mustJSON(d)
	if ipsec.VerifyGuardWithdrawal([]byte(c.Expected.ExpectedJSON), c.Actual, nil) != nil {
		t.Fatal("known zero remaining member must match bounded withdrawal grammar")
	}
	if verify(c) == nil {
		t.Fatal("withdrawal structure alone falsely declared empty prefix refusal")
	}
	for _, o := range d["nftables"] {
		if set, ok := o["set"]; ok && set["name"] == "lease_b79d7edafafe41cfaf2c4115d4ef32c6" {
			set["elem"] = []any{}
		}
	}
	c.Actual = mustJSON(d)
	if verify(c) != nil {
		t.Fatal("actual empty permit table refused")
	}
}

func TestRejectStaleSourceAndImageBindings(t *testing.T) {
	for _, kind := range []string{"source", "image"} {
		c := fixture(t)
		if kind == "source" {
			c.Source = "4143d866ab97386411ff1ac4705aaa0e4579bcf6"
		} else {
			c.Image = "sha256:347bcb66318aa1b8ef1e949c6f57e28506e56a1497f2f4ae15b9ab74b8fed4c6"
		}
		if verify(c) == nil {
			t.Fatal("stale binding accepted", kind)
		}
	}
}
