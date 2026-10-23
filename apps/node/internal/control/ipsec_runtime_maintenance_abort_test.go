package control

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/tunnexio/tunnex/apps/node/internal/ipsec"
)

type scopedMaintenanceAbortFixture bool

func (e scopedMaintenanceAbortFixture) Error() string                      { return ipsec.ErrRuntimeController.Error() }
func (e scopedMaintenanceAbortFixture) Unwrap() error                      { return ipsec.ErrRuntimeController }
func (e scopedMaintenanceAbortFixture) IPsecMaintenanceBatchAborted() bool { return bool(e) }

// The runtime separately proves native target denial. This normal poll regression
// proves its classified abort cannot replay either owner's stale page material.
func TestIPsecMaintenanceScopedAbortWaitsForFreshPage(t *testing.T) {
	for _, wrapped := range []bool{false, true} {
		t.Run(fmt.Sprint("wrapped=", wrapped), func(t *testing.T) {
			f := newMaintenancePollFake(t) // unrelated A and conflicted B on one page
			var conflict error = scopedMaintenanceAbortFixture(true)
			if wrapped {
				conflict = fmt.Errorf("runtime boundary: %w", conflict)
			}
			f.change = func([]ipsec.RuntimeMaintenanceResult) ([]ipsec.RuntimeMaintenanceResult, error) { return nil, conflict }
			valid, err := PollIPsecRuntimeValidated(context.Background(), f, f)
			if !errors.Is(err, ErrIPsecControl) || valid || f.applyCount != 0 || f.acks != 0 || len(f.reports) != 0 || f.maintainCount != 1 {
				t.Fatalf("scoped withdrawal replayed stale page: valid=%v err=%v Apply=%d ACK=%d reports=%d maintenance=%d", valid, err, f.applyCount, f.acks, len(f.reports), f.maintainCount)
			}
			assertMaintenanceSecretsCleared(t, f)
			// No delivery is remembered as accepted or deferred: a new normal pass
			// must fetch both materials again and may succeed under fresh proof.
			f.change = nil
			valid, err = PollIPsecRuntimeValidated(context.Background(), f, f)
			materialReads := 0
			for _, event := range f.events {
				if event == "material" {
					materialReads++
				}
			}
			if err != nil || !valid || f.maintainCount != 2 || materialReads != 4 || f.applyCount != 0 || f.acks != 2 || len(f.reports) != 2 {
				t.Fatalf("fresh ordinary pass not preserved: valid=%v err=%v reads=%d maintenance=%d Apply=%d ACK=%d", valid, err, materialReads, f.maintainCount, f.applyCount, f.acks)
			}
			assertMaintenanceSecretsCleared(t, f)
		})
	}
}

func TestIPsecMaintenanceUnclassifiedErrorsKeepOrdinaryFallback(t *testing.T) {
	for name, failure := range map[string]error{"generic": errors.New("refused"), "classification_false": scopedMaintenanceAbortFixture(false)} {
		t.Run(name, func(t *testing.T) {
			f := newMaintenancePollFake(t)
			f.change = func([]ipsec.RuntimeMaintenanceResult) ([]ipsec.RuntimeMaintenanceResult, error) { return nil, failure }
			valid, err := PollIPsecRuntimeValidated(context.Background(), f, f)
			if !errors.Is(err, ErrIPsecControl) || valid || f.applyCount != 2 || f.acks != 2 || len(f.reports) != 2 || f.maintainCount != 1 {
				t.Fatalf("unclassified maintenance behavior changed: valid=%v err=%v Apply=%d ACK=%d reports=%d", valid, err, f.applyCount, f.acks, len(f.reports))
			}
			assertMaintenanceSecretsCleared(t, f)
		})
	}
}

func TestIPsecMaintenanceScopedAbortCannotPublishPartialResult(t *testing.T) {
	f := newMaintenancePollFake(t)
	f.change = func(results []ipsec.RuntimeMaintenanceResult) ([]ipsec.RuntimeMaintenanceResult, error) {
		return results[:1], scopedMaintenanceAbortFixture(true)
	}
	valid, err := PollIPsecRuntimeValidated(context.Background(), f, f)
	if !errors.Is(err, ErrIPsecControl) || valid || f.applyCount != 0 || f.acks != 0 || len(f.reports) != 0 {
		t.Fatal("partial aborted result escaped through report/ACK/fallback")
	}
	assertMaintenanceSecretsCleared(t, f)
}
