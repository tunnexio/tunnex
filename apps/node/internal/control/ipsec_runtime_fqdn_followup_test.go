package control

import (
	"context"
	"github.com/tunnexio/tunnex/apps/node/internal/ipsec"
	"reflect"
	"testing"
)

type fqdnPriorityPollFake struct {
	*priorityPollFake
	refuseFollowup bool
}

func (f *fqdnPriorityPollFake) FollowupFQDNMaintenanceObserved(ctx context.Context, publish func(context.Context, ipsec.RuntimeDelivery, ipsec.RuntimeStatusReport) error, pulse func(context.Context, ipsec.RuntimeRecoveryHeartbeat) error) error {
	f.order = append(f.order, "bounded_fqdn_followup")
	if f.refuseFollowup {
		return ErrIPsecControl
	}
	return nil
}
func TestIPsecFQDNFollowupBeforeStatusDoesNotSuppressDiscovery(t *testing.T) {
	for _, refused := range []bool{false, true} {
		f := &fqdnPriorityPollFake{priorityPollFake: &priorityPollFake{recoveryObservedPollFake: newRecoveryObservedPollFake(t, "positive")}, refuseFollowup: refused}
		err := RefreshIPsecRuntimePriority(context.Background(), f, f)
		if refused != (err != nil) {
			t.Fatalf("refused=%v err=%v", refused, err)
		}
		if !reflect.DeepEqual(f.order, []string{"fresh_active_renewal", "bounded_fqdn_followup", "original_status"}) || f.acks != 0 || f.applyCount != 0 {
			t.Fatal("followup altered ordinary caller order/authority", f.order)
		}
	}
}
func TestIPsecFQDNPostPollFollowupDoesNotRenewUnrelatedOwners(t *testing.T) {
	f := &fqdnPriorityPollFake{priorityPollFake: &priorityPollFake{recoveryObservedPollFake: newRecoveryObservedPollFake(t, "positive")}}
	if err := RefreshIPsecRuntimeFQDNFollowup(context.Background(), f, f); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.order, []string{"bounded_fqdn_followup"}) || f.acks != 0 || f.applyCount != 0 {
		t.Fatal("followup performed ordinary polling/status", f.order)
	}
}
