package ipsec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func frozenVerifyGuardWithdrawal(expected, observed []byte, links []GuardInterface) error {
	mapping := map[string]int{}
	indices := map[int]bool{}
	for _, l := range links {
		if l.Name == "" || l.Index <= 0 || mapping[l.Name] != 0 || indices[l.Index] {
			return ErrGuardReadback
		}
		mapping[l.Name] = l.Index
		indices[l.Index] = true
	}
	want, ok := normalizedGuardObjects(expected)
	if !ok {
		return ErrGuardReadback
	}
	got, ok := normalizedGuardWithdrawalObjectsWithInterfaces(observed, mapping)
	if !ok || len(want) != len(got) {
		return ErrGuardReadback
	}
	for i, w := range want {
		wf := w.(map[string]any)
		gf := got[i].(map[string]any)
		ws, isSet := wf["set"].(map[string]any)
		if !isSet {
			if !reflect.DeepEqual(wf, gf) {
				return ErrGuardReadback
			}
			continue
		}
		gs, ok := gf["set"].(map[string]any)
		if !ok {
			return ErrGuardReadback
		}
		allowed := map[string]any{}
		if elems, ok := ws["elem"].([]any); ok {
			for _, v := range elems {
				e := v.(map[string]any)["elem"].(map[string]any)
				allowed[e["val"].(json.Number).String()] = v
			}
		}
		if elems, ok := gs["elem"].([]any); ok {
			for _, v := range elems {
				e := v.(map[string]any)["elem"].(map[string]any)
				if !reflect.DeepEqual(allowed[e["val"].(json.Number).String()], v) {
					return ErrGuardReadback
				}
			}
		}
		delete(ws, "elem")
		delete(gs, "elem")
		if !reflect.DeepEqual(ws, gs) {
			return ErrGuardReadback
		}
	}
	return nil
}

func frozenVerifyGuardConnectionReadback(expected, observed []byte, links []GuardInterface, id uuid.UUID) error {
	if id == uuid.Nil || frozenVerifyGuardWithdrawal(expected, observed, links) != nil {
		return ErrGuardReadback
	}
	want, ok := normalizedGuardObjects(expected)
	if !ok {
		return ErrGuardReadback
	}
	required := map[string]any{guardLeaseName(id): nil, guardReplyLeaseName(id): nil, guardSALeaseName(id): nil}
	for _, object := range want {
		if set, ok := object.(map[string]any)["set"].(map[string]any); ok {
			name, _ := set["name"].(string)
			if _, needed := required[name]; needed {
				members, ok := set["elem"].([]any)
				if !ok || len(members) == 0 {
					return errGuardConnectionNotPermitted
				}
				required[name] = set
			}
		}
	}
	for _, set := range required {
		if set == nil {
			return ErrGuardReadback
		}
	}
	// Parse the SAME bounded raw listing again: withdrawal normalization erased
	// expires, so it must not be reused as a positive target proof.
	decoder := json.NewDecoder(bytes.NewReader(observed))
	decoder.UseNumber()
	var env map[string]any
	if decoder.Decode(&env) != nil {
		return ErrGuardReadback
	}
	mapping := map[string]int{}
	for _, link := range links {
		mapping[link.Name] = link.Index
	}
	for _, object := range env["nftables"].([]any) {
		set, ok := object.(map[string]any)["set"].(map[string]any)
		if !ok {
			continue
		}
		name, _ := set["name"].(string)
		target, needed := required[name]
		if !needed {
			continue
		}
		if !translateGuardSet(set, mapping) || !normalizeGuardSetObserved(set, false) {
			return errGuardConnectionNotPermitted
		}
		// Drop only metadata already independently bounded by full-table ownership.
		delete(set, "handle")
		if !reflect.DeepEqual(target, set) {
			return errGuardConnectionNotPermitted
		}
		delete(required, name)
	}
	if len(required) != 0 {
		return ErrGuardReadback
	}
	return nil
}

func guardParserBenchmarkFixture(b testing.TB) ([]byte, uuid.UUID) {
	return guardParserFixture(b, 12)
}
func guardParserFixture(b testing.TB, count int) ([]byte, uuid.UUID) {
	i := guardFixture()
	i.Connections[0].ReplyIngressIndices = []int{10}
	i.Connections[0].EncryptedEgress = []GuardEncryptedEgress{{TunnelInterfaceIndex: 10, ReqID: 100, Peer: netip.MustParseAddr("198.51.100.1"), UnderlayInterfaceIndex: 2}}
	target := i.Connections[0].ID
	original := i.Connections[0]
	for n := 1; n < count; n++ {
		c := original
		c.ID = uuid.New()
		c.Remote = []netip.Prefix{netip.MustParsePrefix(fmt.Sprintf("10.20.%d.0/24", n))}
		c.Grants = append([]GuardGrant(nil), original.Grants...)
		c.Grants[0].Destination = c.Remote[0]
		c.Tunnels = original.Tunnels
		for j := range c.Tunnels {
			c.Tunnels[j].InterfaceIndex += n * 2
			c.Tunnels[j].XFRMID += uint32(n * 2)
			c.Tunnels[j].InterfaceName = "tnxi-" + c.ID.String()[:8] + string(rune('a'+j))
		}
		c.PermittedInterfaceIndices = []int{c.Tunnels[0].InterfaceIndex}
		c.ReplyIngressIndices = append([]int(nil), c.PermittedInterfaceIndices...)
		c.EncryptedEgress = []GuardEncryptedEgress{{TunnelInterfaceIndex: c.Tunnels[0].InterfaceIndex, ReqID: uint32(100 + n), Peer: netip.MustParseAddr("198.51.100.1"), UnderlayInterfaceIndex: 2}}
		i.Connections = append(i.Connections, c)
	}
	raw, e := RenderGuard(i)
	if e != nil {
		b.Fatal(e)
	}
	return []byte(raw.ExpectedJSON), target
}
func BenchmarkGuardConnectionSnapshot(b *testing.B) {
	raw, id := guardParserBenchmarkFixture(b)
	b.Run("frozen", func(b *testing.B) {
		b.ReportAllocs()
		for n := 0; n < b.N; n++ {
			if frozenVerifyGuardConnectionReadback(raw, raw, nil, id) != nil {
				b.Fatal("fixture")
			}
		}
	})
	b.Run("candidate", func(b *testing.B) {
		b.ReportAllocs()
		for n := 0; n < b.N; n++ {
			if verifyGuardConnectionReadback(raw, raw, nil, id) != nil {
				b.Fatal("fixture")
			}
		}
	})
}

func TestGuardConnectionSnapshotDifferential(t *testing.T) {
	raw, id := guardParserFixture(t, 2)
	cases := [][]byte{raw, []byte(strings.ReplaceAll(string(raw), "tunnex_ipsec", `tunnex_\u0069psec`)), []byte(`{"nftables":[]}`), []byte(`{"nftables":[],"nftables":[]}`), append(append([]byte{}, raw...), []byte(` {}`)...), bytes.Repeat([]byte(" "), kernelDumpLimit+1), []byte(`{"nftables":[`), []byte(`{"nftables":[{"table":{"name":"a","name":"b"}}]}`), []byte(`{"nftables":[],"unknown":true}`), {0xff}}
	for _, target := range []bool{false, true} {
		for _, expiry := range []any{nil, json.Number("0"), json.Number("0.001"), json.Number("30000"), json.Number("30001"), json.Number("-1"), "unknown"} {
			changed := guardTableFixtureEdit(t, raw, func(object map[string]any) {
				set, ok := object["set"].(map[string]any)
				if !ok {
					return
				}
				name, _ := set["name"].(string)
				own := name == guardLeaseName(id) || name == guardReplyLeaseName(id) || name == guardSALeaseName(id)
				if own != target {
					return
				}
				if expiry == nil {
					delete(set, "elem")
					return
				}
				elements, _ := set["elem"].([]any)
				for _, v := range elements {
					v.(map[string]any)["elem"].(map[string]any)["expires"] = expiry
				}
			})
			cases = append(cases, changed)
		}
	}
	cases = append(cases, guardTableFixtureEdit(t, raw, func(o map[string]any) {
		if r, ok := o["rule"].(map[string]any); ok {
			r["unknown"] = true
		}
	}))
	for i, observed := range cases {
		for _, target := range []uuid.UUID{id, uuid.Nil, uuid.New()} {
			for _, links := range [][]GuardInterface{nil, {{Name: "x", Index: 10}, {Name: "x", Index: 11}}} {
				old := frozenVerifyGuardConnectionReadback(raw, observed, links, target)
				next := verifyGuardConnectionReadback(raw, observed, links, target)
				if old != next {
					t.Fatalf("case %d error classification changed: %v/%v", i, old, next)
				}
				if frozenVerifyGuardWithdrawal(raw, observed, links) != VerifyGuardWithdrawal(raw, observed, links) {
					t.Fatalf("withdrawal case %d changed", i)
				}
			}
		}
	}
	for i, expected := range cases {
		if frozenVerifyGuardConnectionReadback(expected, raw, nil, id) != verifyGuardConnectionReadback(expected, raw, nil, id) {
			t.Fatalf("expectedcase %d changed", i)
		}
	}
}
