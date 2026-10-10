package ipsec

import (
	"context"
	"encoding/json"
	"testing"
)

func TestGuardFailureClassificationPreservesRefusal(t *testing.T) {
	m, e := RenderGuard(guardFixture())
	if e != nil {
		t.Fatal(e)
	}
	want, ok := normalizedGuardObjects([]byte(m.ExpectedJSON))
	if !ok {
		t.Fatal("fixture")
	}
	for _, kind := range []string{"observed_invalid", "object_count", "nonset_mismatch", "set_metadata_mismatch", "set_member_mismatch"} {
		t.Run(kind, func(t *testing.T) {
			got, _ := normalizedGuardObjects([]byte(m.ExpectedJSON))
			switch kind {
			case "object_count":
				got = got[:len(got)-1]
			case "nonset_mismatch":
				for _, x := range got {
					if r, ok := x.(map[string]any)["rule"].(map[string]any); ok {
						r["comment"] = "changed"
						break
					}
				}
			case "set_metadata_mismatch":
				for _, x := range got {
					if r, ok := x.(map[string]any)["set"].(map[string]any); ok {
						r["timeout"] = json.Number("59")
						break
					}
				}
			case "set_member_mismatch":
				for _, x := range got {
					if r, ok := x.(map[string]any)["set"].(map[string]any); ok {
						if es, ok := r["elem"].([]any); ok && len(es) > 0 {
							es[0].(map[string]any)["elem"].(map[string]any)["val"] = json.Number("999")
							break
						}
					}
				}
			}
			raw, _ := json.Marshal(map[string]any{"nftables": got})
			if kind == "observed_invalid" {
				raw = []byte(`{"nftables":[]}`)
			}
			class := ""
			_, plain := verifyGuardWithdrawalObjectsSnapshot(want, raw, nil)
			_, diag := verifyGuardWithdrawalObjectsSnapshotClass(want, raw, nil, func(v string) { class = v })
			if plain != ErrGuardReadback || diag != plain || class != kind {
				t.Fatalf("plain=%v diag=%v class=%s", plain, diag, class)
			}
		})
	}
}

func TestDNSGuardKernelSuccessorBeforePublicationRefused(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		f := newDNSOwnerViewFixture(t, nil)
		f.c.config.DNSReadTiming = enabled
		old := f.c.dnsView.Load()
		changed := guardTableFixtureEdit(t, []byte(f.observed.Load().(string)), func(o map[string]any) {
			if chain, ok := o["chain"].(map[string]any); ok && chain["name"] == "owner" {
				chain["comment"] = "tunnex-ipsec:successor"
			}
		})
		f.observed.Store(string(changed))
		if _, err := f.prove(context.Background()); err == nil {
			t.Fatal("unpublished kernel successor authorized")
		}
		if f.c.dnsView.Load() != old {
			t.Fatal("diagnostic published authority")
		}
	}
}
