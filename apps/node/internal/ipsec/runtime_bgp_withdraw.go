package ipsec

import (
	"context"
	"fmt"
)

// WithdrawBGPRoutes consumes durable cleanup duties without acquiring a lease.
// It preserves the possible crash union before deleting any exact owned tuple.
func WithdrawBGPRoutes(ctx context.Context, j *RuntimeJournal, a *KernelApplier, deliveryID string) error {
	entries, err := j.Entries()
	if err != nil {
		return err
	}
	pos := -1
	for i := range entries {
		if entries[i].DeliveryID.String() == deliveryID {
			pos = i
		}
	}
	if pos < 0 {
		return ErrRuntimeJournal
	}
	e := entries[pos]
	if e.ContractVersion != 3 || !validJournalBGP(e) || !validBGPRoutes(e) {
		return ErrRuntimeJournal
	}
	if e.BGPRoutes == nil {
		return nil
	}
	s := *e.BGPRoutes
	if s.Withdrawal && s.Stage == "completed" {
		return nil
	}
	if !s.Withdrawal {
		if s.Stage == "completed" {
			if s.Sequence == ^uint64(0) {
				return ErrRuntimeJournal
			}
			s.Sequence++
			s.Stage = "pending"
			s.Target = []RuntimeBGPRouteTuple{}
		}
		s.Withdrawal = true
		e.BGPRoutes = &s
		entries[pos] = e
		if err = j.Save(entries); err != nil {
			return err
		}
	}
	union := bgpRouteUnion(&s)
	snapshot, err := a.snapshotBGPRoutes(ctx, e.Allocation, union)
	if err != nil {
		return err
	}
	for i, owned := range snapshot.ownership {
		if owned.InterfaceIndex != 0 && owned != e.Observed[i] {
			return ErrKernelApply
		}
	}
	for _, tuple := range union {
		slot := tuple.Slot - 1
		if !snapshot.routes[slot][tuple.Prefix] {
			continue
		}
		if snapshot.ownership[slot] != e.Observed[slot] || tuple.InterfaceIndex != snapshot.ownership[slot].InterfaceIndex {
			return ErrKernelApply
		}
		fresh, readErr := a.snapshotBGPRoutes(ctx, e.Allocation, union)
		if readErr != nil || fresh.ownership[slot] != snapshot.ownership[slot] {
			return ErrKernelApply
		}
		if !fresh.routes[slot][tuple.Prefix] {
			continue
		}
		if err = a.mutate(ctx, e.Allocation, "-4", "route", "del", tuple.Prefix.String(), "dev", e.Allocation.Tunnels[slot].Name, "table", fmt.Sprint(tuple.Table), "proto", fmt.Sprint(tuple.Protocol), "metric", fmt.Sprint(tuple.Metric)); err != nil {
			return err
		}
	}
	snapshot, err = a.snapshotBGPRoutes(ctx, e.Allocation, union)
	if err != nil {
		return err
	}
	for i, owned := range snapshot.ownership {
		if owned.InterfaceIndex != 0 && owned != e.Observed[i] {
			return ErrKernelApply
		}
	}
	for _, tuple := range union {
		if snapshot.routes[tuple.Slot-1][tuple.Prefix] {
			return ErrKernelApply
		}
	}
	e.BGPRoutes = &RuntimeBGPRoutes{Sequence: s.Sequence, Stage: "completed", Withdrawal: true, Owned: []RuntimeBGPRouteTuple{}, Target: []RuntimeBGPRouteTuple{}}
	entries[pos] = e
	return j.Save(entries)
}
