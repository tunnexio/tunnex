package ipsec

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"reflect"
	"strconv"
	"testing"
)

func (v *runtimeDNSOwnerView) frozenResolverGuardPermitsStage(ctx context.Context, entry RuntimeJournalEntry, index int, reqid uint32) (bool, string) {
	stage := "dns_guard_template"
	if v == nil || v.observer.guardReader == nil {
		return false, stage
	}
	g := v.guard
	if g.Namespace != entry.Allocation.Namespace {
		return false, stage
	}
	objects, ok := normalizedGuardObjects([]byte(g.ExpectedJSON))
	if !ok {
		return false, stage
	}
	stage = "dns_guard_required"
	required := map[string]string{guardLeaseName(entry.Allocation.ConnectionID): strconv.Itoa(index), guardReplyLeaseName(entry.Allocation.ConnectionID): strconv.Itoa(index), guardSALeaseName(entry.Allocation.ConnectionID): strconv.FormatUint(uint64(reqid), 10)}
	for _, object := range objects {
		fields, ok := object.(map[string]any)
		if !ok {
			return false, stage
		}
		set, ok := fields["set"].(map[string]any)
		if !ok {
			continue
		}
		name, _ := set["name"].(string)
		want, needed := required[name]
		if !needed {
			continue
		}
		members, ok := set["elem"].([]any)
		if !ok {
			return false, stage
		}
		found := false
		for _, m := range members {
			member, ok := m.(map[string]any)
			if !ok {
				return false, stage
			}
			element, ok := member["elem"].(map[string]any)
			if !ok {
				return false, stage
			}
			value, ok := element["val"].(json.Number)
			if !ok {
				return false, stage
			}
			if value.String() == want {
				found = true
			}
		}
		if !found {
			return false, stage
		}
		delete(required, name)
	}
	if len(required) != 0 {
		return false, stage
	}
	return v.observer.guardReader.check(ctx, GuardManifest{Namespace: g.Namespace, ExpectedJSON: g.ExpectedJSON}, func(expected, observed []byte, links []GuardInterface) error {
		return frozenDNSVerifyGuardConnectionReadback(expected, observed, links, entry.Allocation.ConnectionID)
	}) == nil, "dns_guard_full_read"
}

func dnsParseReuseView(raw, expected []byte) *runtimeDNSOwnerView {
	ns := guardFixture().Namespace
	r := &GuardReader{namespace: func() (string, error) { return ns, nil }, interfaces: func() ([]GuardInterface, error) { return nil, nil }, run: func(context.Context, ...string) ([]byte, error) { return raw, nil }}
	objects, _ := normalizedGuardObjects(expected)
	return &runtimeDNSOwnerView{expected: guardExpectedSnapshot{raw: string(expected), objects: objects}, guard: GuardManifest{Namespace: ns, ExpectedJSON: string(expected)}, observer: runtimeDNSObserver{guardReader: r}}
}
func TestDNSExpectedSnapshotFrozenDifferential(t *testing.T) {
	raw, id := guardParserFixture(t, 2)
	entry := RuntimeJournalEntry{Allocation: KernelAllocation{ConnectionID: id, Namespace: guardFixture().Namespace}}
	cases := map[string][]byte{"valid": raw, "trailing": append(append([]byte{}, raw...), []byte(` {}`)...), "duplicate": []byte(`{"nftables":[],"nftables":[]}`), "malformed": []byte(`{"nftables":[`), "oversize": bytes.Repeat([]byte(" "), kernelDumpLimit+1)}
	for _, kind := range []string{"zero", "missing", "foreign"} {
		cases[kind] = guardTableFixtureEdit(t, raw, func(o map[string]any) {
			if s, ok := o["set"].(map[string]any); ok && s["name"] == guardLeaseName(id) {
				if kind == "missing" {
					delete(s, "elem")
				} else {
					for _, m := range s["elem"].([]any) {
						e := m.(map[string]any)["elem"].(map[string]any)
						if kind == "zero" {
							e["expires"] = json.Number("0")
						} else {
							e["val"] = json.Number("999")
						}
					}
				}
			}
		})
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			for _, expected := range []bool{false, true} {
				v := dnsParseReuseView(data, raw)
				if expected {
					v = dnsParseReuseView(raw, data)
				}
				a, as := v.frozenResolverGuardPermitsStage(context.Background(), entry, 10, 100)
				b, bs := v.resolverGuardPermitsStage(context.Background(), entry, 10, 100)
				if a != b || as != bs {
					t.Fatal("frozen mismatch", expected, a, b, as, bs)
				}
				if !expected && (name == "valid" && !b || name != "valid" && b) {
					t.Fatal("verdict")
				}
			}
		})
	}
	objects, ok := normalizedGuardObjects(raw)
	if !ok {
		t.Fatal("fixture")
	}
	v := dnsParseReuseView(raw, raw)
	for _, bad := range []guardExpectedSnapshot{{raw: "different", objects: objects}, {raw: string(raw)}} {
		if v.observer.guardReader.checkConnectionSnapshot(context.Background(), v.guard, id, bad) == nil {
			t.Fatal("snapshot identity accepted")
		}
	}
	if v.observer.guardReader.checkConnectionSnapshot(context.Background(), v.guard, uuid.Nil, guardExpectedSnapshot{raw: string(raw), objects: objects}) == nil {
		t.Fatal("nil target accepted")
	}
}
func BenchmarkDNSResolverGuardBracket(b *testing.B) {
	raw, id := guardParserFixture(b, 12)
	entry := RuntimeJournalEntry{Allocation: KernelAllocation{ConnectionID: id, Namespace: guardFixture().Namespace}}
	for _, old := range []bool{true, false} {
		name := "candidate"
		if old {
			name = "frozen"
		}
		b.Run(name, func(b *testing.B) {
			v := dnsParseReuseView(raw, raw)
			b.ReportAllocs()
			for n := 0; n < b.N; n++ {
				var ok bool
				if old {
					ok, _ = v.frozenResolverGuardPermitsStage(context.Background(), entry, 10, 100)
				} else {
					ok, _ = v.resolverGuardPermitsStage(context.Background(), entry, 10, 100)
				}
				if !ok {
					b.Fatal("fixture")
				}
			}
		})
	}
}

func TestDNSExpectedSnapshotPreservesFreshBrackets(t *testing.T) {
	raw, id := guardParserFixture(t, 2)
	entry := RuntimeJournalEntry{Allocation: KernelAllocation{ConnectionID: id, Namespace: guardFixture().Namespace}}
	for _, frozen := range []bool{false, true} {
		v := dnsParseReuseView(raw, raw)
		ns, links, reads := 0, 0, 0
		v.observer.guardReader.namespace = func() (string, error) { ns++; return v.guard.Namespace, nil }
		v.observer.guardReader.interfaces = func() ([]GuardInterface, error) { links++; return nil, nil }
		v.observer.guardReader.run = func(context.Context, ...string) ([]byte, error) { reads++; return raw, nil }
		var ok bool
		if frozen {
			ok, _ = v.frozenResolverGuardPermitsStage(context.Background(), entry, 10, 100)
		} else {
			ok, _ = v.resolverGuardPermitsStage(context.Background(), entry, 10, 100)
		}
		if !ok || ns != 2 || links != 2 || reads != 1 {
			t.Fatal("fresh brackets changed", frozen, ns, links, reads)
		}
	}
	objects, ok := normalizedGuardObjects(raw)
	if !ok {
		t.Fatal("fixture")
	}
	before, _ := json.Marshal(objects)
	v := dnsParseReuseView(raw, raw)
	if v.observer.guardReader.checkConnectionSnapshot(context.Background(), v.guard, id, guardExpectedSnapshot{raw: string(raw), objects: objects}) != nil {
		t.Fatal("positive fixture")
	}
	after, _ := json.Marshal(objects)
	if !bytes.Equal(before, after) {
		t.Fatal("local expected intent mutated")
	}
}

func frozenDNSVerifyGuardConnectionReadback(expected, observed []byte, links []GuardInterface, id uuid.UUID) error {
	if id == uuid.Nil {
		return ErrGuardReadback
	}
	want, err := verifyGuardWithdrawalSnapshot(expected, observed, links)
	if err != nil {
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
