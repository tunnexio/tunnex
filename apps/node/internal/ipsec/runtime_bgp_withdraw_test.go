package ipsec

import (
	"bytes"
	"context"
	"testing"
)

func TestBGPWithdrawalConsumesCrashUnionWithoutLease(t *testing.T) {
	e, f, j := bgpRouteWriterFixture(t)
	old := routeTupleFixture(e, 1)
	next := routeTupleFixture(e, 2)
	if err := ReconcileBGPRoutes(context.Background(), j, f.applier(), e.DeliveryID.String(), []RuntimeBGPRouteTuple{old}); err != nil {
		t.Fatal(err)
	}
	entries, _ := j.Entries()
	entries[0].BGPRoutes = &RuntimeBGPRoutes{Sequence: 2, Stage: "pending", Owned: []RuntimeBGPRouteTuple{old}, Target: []RuntimeBGPRouteTuple{next}}
	if err := j.Save(entries); err != nil {
		t.Fatal(err)
	}
	f.routes[1][next.Prefix.String()] = true
	f.down = 0
	if err := WithdrawBGPRoutes(context.Background(), j, f.applier(), e.DeliveryID.String()); err != nil {
		t.Fatal(err)
	}
	entries, _ = j.Entries()
	duty := entries[0].BGPRoutes
	if !duty.Withdrawal || duty.Stage != "completed" || len(duty.Owned) != 0 || len(duty.Target) != 0 || f.routes[0][old.Prefix.String()] || f.routes[1][next.Prefix.String()] {
		t.Fatal("crash union retained or obligation forgotten")
	}
	before := f.mutations
	if err := WithdrawBGPRoutes(context.Background(), j, f.applier(), e.DeliveryID.String()); err != nil || f.mutations != before {
		t.Fatal("completed withdrawal not idempotent", err)
	}
	if err := ReconcileBGPRoutes(context.Background(), j, f.applier(), e.DeliveryID.String(), []RuntimeBGPRouteTuple{next}); err != nil {
		t.Fatal("fresh successor after proven cleanup", err)
	}
}

func TestBGPWithdrawalForeignTupleRetainsDuty(t *testing.T) {
	e, f, j := bgpRouteWriterFixture(t)
	tuple := routeTupleFixture(e, 1)
	if err := ReconcileBGPRoutes(context.Background(), j, f.applier(), e.DeliveryID.String(), []RuntimeBGPRouteTuple{tuple}); err != nil {
		t.Fatal(err)
	}
	a := f.applier()
	base := a.run
	a.run = func(ctx context.Context, args ...string) ([]byte, error) {
		raw, err := base(ctx, args...)
		return bytes.ReplaceAll(raw, []byte(`"ifindex":10`), []byte(`"ifindex":20`)), err
	}
	before := f.mutations
	if err := WithdrawBGPRoutes(context.Background(), j, a, e.DeliveryID.String()); err == nil {
		t.Fatal("foreign replacement cleanup accepted")
	}
	entries, _ := j.Entries()
	if !entries[0].BGPRoutes.Withdrawal || entries[0].BGPRoutes.Stage != "pending" || f.mutations != before || !f.routes[0][tuple.Prefix.String()] {
		t.Fatal("foreign replacement touched or durable duty lost")
	}
}

func TestBGPWithdrawalFailuresRetainCrashUnion(t *testing.T) {
	for _, finalReadback := range []bool{false, true} {
		t.Run(map[bool]string{false: "delete-failure", true: "final-readback-failure"}[finalReadback], func(t *testing.T) {
			e, f, j := bgpRouteWriterFixture(t)
			old, next := routeTupleFixture(e, 1), routeTupleFixture(e, 2)
			if err := ReconcileBGPRoutes(context.Background(), j, f.applier(), e.DeliveryID.String(), []RuntimeBGPRouteTuple{old}); err != nil {
				t.Fatal(err)
			}
			entries, _ := j.Entries()
			entries[0].BGPRoutes = &RuntimeBGPRoutes{Sequence: 2, Stage: "pending", Owned: []RuntimeBGPRouteTuple{old}, Target: []RuntimeBGPRouteTuple{next}}
			if err := j.Save(entries); err != nil {
				t.Fatal(err)
			}
			f.routes[1][next.Prefix.String()] = true
			a := f.applier()
			before := f.mutations
			if finalReadback {
				base := a.run
				a.run = func(ctx context.Context, args ...string) ([]byte, error) {
					raw, err := base(ctx, args...)
					if f.mutations >= before+2 && len(args) > 3 && args[0] == "-j" && args[2] == "link" {
						return []byte(`[]`), nil
					}
					return raw, err
				}
			} else {
				f.failAt = before + 1
			}
			if err := WithdrawBGPRoutes(context.Background(), j, a, e.DeliveryID.String()); err == nil {
				t.Fatal("failed absence proof accepted")
			}
			entries, _ = j.Entries()
			duty := entries[0].BGPRoutes
			if !duty.Withdrawal || duty.Stage != "pending" || len(duty.Owned) != 1 || duty.Owned[0] != old || len(duty.Target) != 1 || duty.Target[0] != next {
				t.Fatal("pending crash union forgotten")
			}
			if finalReadback && (f.routes[0][old.Prefix.String()] || f.routes[1][next.Prefix.String()]) {
				t.Fatal("fixture did not reach final readback after deletion")
			}
		})
	}
}
