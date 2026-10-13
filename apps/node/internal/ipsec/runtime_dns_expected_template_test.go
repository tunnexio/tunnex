package ipsec

import (
	"context"
	"encoding/json"
	"reflect"
	"strconv"
	"sync"
	"testing"
)

func TestDNSPublishedExpectedTemplateReuse(t *testing.T) {
	raw, id := guardParserFixture(t, 12)
	v := dnsParseReuseView(raw, raw)
	e := RuntimeJournalEntry{Allocation: KernelAllocation{ConnectionID: id, Namespace: guardFixture().Namespace}}
	before, _ := normalizedGuardObjects(raw)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 4; j++ {
				if ok, _ := v.resolverGuardPermitsStage(context.Background(), e, 10, 100); !ok {
					t.Error("exact template refused")
				}
			}
		}()
	}
	wg.Wait()
	if !reflect.DeepEqual(before, v.expected.objects) {
		t.Fatal("expected snapshot mutated")
	}
	v.guard.ExpectedJSON += " "
	if ok, _ := v.resolverGuardPermitsStage(context.Background(), e, 10, 100); ok {
		t.Fatal("raw mismatch accepted")
	}
	v.guard.ExpectedJSON = string(raw)
	v.expected = guardExpectedSnapshot{}
	if ok, _ := v.resolverGuardPermitsStage(context.Background(), e, 10, 100); ok {
		t.Fatal("missing snapshot accepted")
	}
}

func (v *runtimeDNSOwnerView) originalResolverGuardPermitsStageObserved(ctx context.Context, entry RuntimeJournalEntry, index int, reqid uint32, observe func(guardReadTiming)) (bool, string) {
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
	return v.observer.guardReader.checkConnectionSnapshotObserved(ctx, GuardManifest{Namespace: g.Namespace, ExpectedJSON: g.ExpectedJSON}, entry.Allocation.ConnectionID, guardExpectedSnapshot{raw: g.ExpectedJSON, objects: objects}, observe) == nil, "dns_guard_full_read"
}

// revalidateDNSGuardSnapshot retries only an independently published newer
// template once. It cannot manufacture a grant, change owner epoch, extend
// original/current authority, or continue through another digest change.
func BenchmarkDNSImmutableExpectedTemplate(b *testing.B) {
	raw, id := guardParserFixture(b, 36)
	e := RuntimeJournalEntry{Allocation: KernelAllocation{ConnectionID: id, Namespace: guardFixture().Namespace}}
	for _, old := range []bool{true, false} {
		name := "candidate"
		if old {
			name = "original"
		}
		b.Run(name, func(b *testing.B) {
			v := dnsParseReuseView(raw, raw)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				var ok bool
				if old {
					ok, _ = v.originalResolverGuardPermitsStageObserved(context.Background(), e, 10, 100, nil)
				} else {
					ok, _ = v.resolverGuardPermitsStageObserved(context.Background(), e, 10, 100, nil)
				}
				if !ok {
					b.Fatal("fixture")
				}
			}
		})
	}
}

func TestDNSOriginalRepeatedTemplateDecodeCausal(t *testing.T) {
	raw, id := guardParserFixture(t, 36)
	v := dnsParseReuseView(raw, raw)
	e := RuntimeJournalEntry{Allocation: KernelAllocation{ConnectionID: id, Namespace: guardFixture().Namespace}}
	v.expected = guardExpectedSnapshot{}
	if ok, _ := v.originalResolverGuardPermitsStageObserved(context.Background(), e, 10, 100, nil); !ok {
		t.Fatal("original no-snapshot path did not parse")
	}
	if ok, _ := v.resolverGuardPermitsStageObserved(context.Background(), e, 10, 100, nil); ok {
		t.Fatal("candidate bypassed published snapshot")
	}
}
func TestDNSExpectedTemplateAllocationRegression(t *testing.T) {
	raw, id := guardParserFixture(t, 12)
	v := dnsParseReuseView(raw, raw)
	e := RuntimeJournalEntry{Allocation: KernelAllocation{ConnectionID: id, Namespace: guardFixture().Namespace}}
	original := testing.AllocsPerRun(2, func() {
		if ok, _ := v.originalResolverGuardPermitsStageObserved(context.Background(), e, 10, 100, nil); !ok {
			t.Fatal("original")
		}
	})
	candidate := testing.AllocsPerRun(2, func() {
		if ok, _ := v.resolverGuardPermitsStageObserved(context.Background(), e, 10, 100, nil); !ok {
			t.Fatal("candidate")
		}
	})
	if candidate >= original {
		t.Fatalf("repeated expected parsing not removed: %g >= %g", candidate, original)
	}
}
func TestDNSExpectedTemplateActualOwnerPublication(t *testing.T) {
	f := newDNSOwnerViewFixture(t, func(context.Context) error { return nil })
	f.c.publishDNSOwnerView(f.manifest)
	v := f.c.dnsView.Load()
	if v == nil || v.expected.raw != f.manifest.ExpectedJSON || len(v.expected.objects) == 0 {
		t.Fatal("real publication did not retain validated expected snapshot")
	}
	want, ok := normalizedGuardObjects([]byte(f.manifest.ExpectedJSON))
	if !ok || !reflect.DeepEqual(want, v.expected.objects) {
		t.Fatal("publication snapshot differs from exact validated template")
	}
	id := f.material.Manifest.ConnectionID
	old, ok := v.entries[id]
	if !ok {
		t.Fatal("published owner target missing")
	}
	f.c.withdrawDNSOwnerView(id)
	next := f.c.dnsView.Load()
	if !old.epoch.revoked.Load() {
		t.Fatal("withdrawal did not revoke original epoch")
	}
	if next == nil {
		t.Fatal("single-owner withdrawal unexpectedly removed entire immutable view")
	}
	if _, ok := next.entries[id]; ok {
		t.Fatal("withdrawal retained target")
	}
	if !reflect.DeepEqual(next.expected, v.expected) {
		t.Fatal("withdrawal changed immutable expected snapshot")
	}
}
