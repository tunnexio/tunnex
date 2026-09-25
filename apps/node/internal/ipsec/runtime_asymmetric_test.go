package ipsec

import (
	"context"
	"reflect"
	"testing"
	"time"
)

func TestRuntimeReplyIngressRequiresFreshUpObservation(t *testing.T) {
	for _, alternate := range []string{"up", "down", "unknown"} {
		t.Run(alternate, func(t *testing.T) {
			r := newRecoveryTestRig(t)
			r.status = [2]string{"up", alternate}
			original := r.c.replace
			var replies []int
			r.c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
				if !in.Connections[0].PrefixOnly {
					replies = append([]int(nil), in.Connections[0].ReplyIngressIndices...)
					if in.Connections[0].PermitFor <= 0 || in.Connections[0].PermitFor > 60*time.Second {
						t.Fatal("invalid authority timeout")
					}
				}
				return original(ctx, in)
			}
			err := r.apply()
			if alternate == "unknown" {
				if err == nil || len(replies) != 0 {
					t.Fatal("unknown observation granted authority")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			want := []int{10}
			if alternate == "up" {
				want = append(want, 11)
			}
			if !reflect.DeepEqual(replies, want) {
				t.Fatalf("reply authority %v want %v", replies, want)
			}
		})
	}
}

func TestRuntimeReplyIngressRejectsInstallationTimeLoss(t *testing.T) {
	for name, changed := range map[string][2]string{"selected down": {"down", "up"}, "selected unknown": {"unknown", "up"}, "alternate unknown": {"up", "unknown"}, "both unknown": {"unknown", "unknown"}} {
		t.Run(name, func(t *testing.T) {
			r := newRecoveryTestRig(t)
			r.status = [2]string{"up", "up"}
			changedObserved := false
			r.c.recoveryObserve = func(context.Context, RuntimeJournalEntry) [2]string {
				if len(r.c.active) > 0 {
					changedObserved = true
					return changed
				}
				return r.status
			}
			original := r.c.replace
			permits := 0
			refusals := 0
			r.c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
				if in.Connections[0].PrefixOnly {
					refusals++
				} else {
					permits++
				}
				return original(ctx, in)
			}
			err := r.apply()
			if !changedObserved {
				t.Fatal("installation-time observation not exercised")
			}
			if err == nil || permits != 0 || refusals == 0 || len(r.c.active) != 0 {
				t.Fatalf("unsafe installation: err=%v permits=%d refusals=%d active=%d", err, permits, refusals, len(r.c.active))
			}
		})
	}
}
