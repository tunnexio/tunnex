package ipsec_test

import (
	"context"
	"github.com/tunnexio/tunnex/apps/node/internal/control"
	"github.com/tunnexio/tunnex/apps/node/internal/ipsec"
	"testing"
)

func TestFQDNPolicyTransitionDeferredPollComposition(t *testing.T) {
	for _, producer := range []string{"upfront", "conflict"} {
		for _, mixed := range []bool{false, true} {
			name := producer + "/pending_only"
			if mixed {
				name = producer + "/mixed"
			}
			t.Run(name, func(t *testing.T) {
				f := ipsec.NewFQDNDeferredPollFixture(t, mixed, producer == "upfront")
				for n := 0; n < 2; n++ {
					validated, err := control.PollIPsecRuntimeValidated(context.Background(), f, f)
					if !validated {
						f.ValidateCore(t)
					}
					f.AssertPending(t)
					want := 0
					if mixed {
						want = n + 1
					}
					if err != nil || validated != mixed || f.Pending != n+1 || f.ApplyCalls != 0 || f.ACKs != want || f.Reports != want {
						t.Fatalf("pending poll fell through or emitted positive result: err=%v validated=%t apply=%d ACK=%d reports=%d", err, validated, f.ApplyCalls, f.ACKs, f.Reports)
					}
				}
				f.CatchUp()
				if validated, err := control.PollIPsecRuntimeValidated(context.Background(), f, f); err != nil || !validated {
					t.Fatal("fresh catch-up", validated, err)
				}
				f.AssertRestored(t)
				want := 1
				if mixed {
					want = 4
				}
				if f.ACKs != want || f.ApplyCalls != 0 {
					t.Fatal("catch-up ACK/fallback mismatch", f.ACKs, f.ApplyCalls)
				}
			})
		}
	}
}
func TestFQDNPolicyTransitionDeferredPollRejectsLostAuthority(t *testing.T) {
	for _, mode := range []string{"expired", "changed-owner"} {
		t.Run(mode, func(t *testing.T) {
			f := ipsec.NewFQDNDeferredPollFixture(t, false, false)
			if _, err := control.PollIPsecRuntimeValidated(context.Background(), f, f); err != nil {
				t.Fatal("initial pending", err)
			}
			f.AssertPending(t)
			if mode == "expired" {
				f.ExpireOriginal()
			} else {
				f.ChangeOriginal()
			}
			if validated, err := control.PollIPsecRuntimeValidated(context.Background(), f, f); err == nil || validated {
				t.Fatal("lost original authority deferred", validated, err)
			}
			f.AssertDenied(t)
		})
	}
}
