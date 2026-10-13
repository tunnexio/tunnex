package ipsec

import (
	"context"
	"fmt"
	"net/netip"
	"reflect"
	"sort"
)

// RuntimeBGPRouteTuple is a cleanup obligation, never an authorization grant.
type RuntimeBGPRouteTuple struct {
	Prefix                  netip.Prefix
	Slot                    uint8
	InterfaceIndex          int
	Table, Protocol, Metric uint32
}
type RuntimeBGPRoutes struct {
	Sequence      uint64
	Stage         string
	Withdrawal    bool `json:",omitempty"`
	Owned, Target []RuntimeBGPRouteTuple
}

func validBGPRoutes(e RuntimeJournalEntry) bool {
	s := e.BGPRoutes
	if s == nil {
		return true
	}
	if e.ContractVersion != 3 || e.BGP == nil || s.Sequence == 0 || (s.Stage != "completed" && s.Stage != "pending") {
		return false
	}
	validate := func(routes []RuntimeBGPRouteTuple) bool {
		if routes == nil || len(routes) > len(e.Allocation.Tunnels[0].RemotePrefixes) {
			return false
		}
		prior := ""
		for _, r := range routes {
			if r.Slot < 1 || r.Slot > 2 || r.InterfaceIndex <= 0 || r.InterfaceIndex != e.Observed[r.Slot-1].InterfaceIndex || r.Table != 254 || r.Protocol != 242 || r.Metric != 50000+uint32(r.Slot) || !r.Prefix.IsValid() || !r.Prefix.Addr().Is4() || r.Prefix != r.Prefix.Masked() || r.Prefix.Bits() == 0 || r.Prefix.String() <= prior {
				return false
			}
			allowed := false
			for _, p := range e.Allocation.Tunnels[r.Slot-1].RemotePrefixes {
				allowed = allowed || p == r.Prefix
			}
			if !allowed {
				return false
			}
			prior = r.Prefix.String()
		}
		return true
	}
	if s.Withdrawal && s.Stage == "completed" {
		return s.Owned != nil && s.Target != nil && len(s.Owned) == 0 && len(s.Target) == 0
	}
	return validate(s.Owned) && validate(s.Target) && (s.Stage != "completed" || reflect.DeepEqual(s.Owned, s.Target))
}
func validBGPRoutesSuccessor(before, after RuntimeJournalEntry) bool {
	b, a := before.BGPRoutes, after.BGPRoutes
	if handled, valid := validBGPRouteWithdrawalSuccessor(before, after); handled {
		return valid && validBGPRoutes(after)
	}
	if b == nil {
		return a == nil || (after.ContractVersion == 3 && a.Stage == "pending" && a.Sequence == 1 && len(a.Owned) == 0)
	}
	if a == nil || !validBGPRoutes(after) {
		return false
	}
	if reflect.DeepEqual(b, a) {
		return true
	}
	if b.Stage == "completed" {
		return a.Stage == "pending" && a.Sequence == b.Sequence+1 && reflect.DeepEqual(a.Owned, b.Owned)
	}
	return a.Stage == "completed" && a.Sequence == b.Sequence && reflect.DeepEqual(a.Owned, b.Target) && reflect.DeepEqual(a.Target, b.Target)
}
func bgpRouteUnion(s *RuntimeBGPRoutes) []RuntimeBGPRouteTuple {
	if s == nil {
		return nil
	}
	out := append([]RuntimeBGPRouteTuple{}, s.Owned...)
	if s.Stage == "pending" {
		for _, r := range s.Target {
			found := false
			for _, old := range out {
				found = found || old == r
			}
			if !found {
				out = append(out, r)
			}
		}
	}
	return out
}

// ReconcileBGPRoutes journals both possible sets before any mutation. A failed
// readback retains the pending union for exact recovery; it never adopts routes.
func ReconcileBGPRoutes(ctx context.Context, j *RuntimeJournal, a *KernelApplier, deliveryID string, target []RuntimeBGPRouteTuple) error {
	return reconcileBGPRoutesPermit(ctx, j, a, deliveryID, target, nil)
}
func reconcileBGPRoutesPermit(ctx context.Context, j *RuntimeJournal, a *KernelApplier, deliveryID string, target []RuntimeBGPRouteTuple, permit func() error) error {
	entries, err := j.Entries()
	if err != nil {
		return err
	}
	pos := -1
	for i, e := range entries {
		if e.DeliveryID.String() == deliveryID {
			pos = i
		}
	}
	if pos < 0 {
		return ErrRuntimeJournal
	}
	e := entries[pos]
	if e.ContractVersion != 3 || e.Phase != RuntimeApplied || e.AbsenceOnly || !validJournalBGP(e) {
		return ErrKernelApply
	}
	sort.Slice(target, func(i, k int) bool { return target[i].Prefix.String() < target[k].Prefix.String() })
	if target == nil {
		target = []RuntimeBGPRouteTuple{}
	}
	if e.BGPRoutes != nil && e.BGPRoutes.Stage == "pending" {
		return ErrKernelApply
	}
	prior := []RuntimeBGPRouteTuple{}
	seq := uint64(1)
	if e.BGPRoutes != nil {
		prior = append(prior, e.BGPRoutes.Owned...)
		if e.BGPRoutes.Sequence == ^uint64(0) {
			return ErrRuntimeJournal
		}
		seq = e.BGPRoutes.Sequence + 1
	}
	e.BGPRoutes = &RuntimeBGPRoutes{Sequence: seq, Stage: "pending", Owned: prior, Target: target}
	if !validBGPRoutes(e) {
		return ErrKernelApply
	}
	// The pre-save snapshot admits only already committed tuples, never the target.
	if err = a.verifyBGPRoutes(ctx, e.Allocation, e.Observed, prior, true); err != nil {
		return err
	}
	entries[pos] = e
	if err = j.Save(entries); err != nil {
		return err
	}
	if err = a.reconcileBGPRoutes(ctx, e, permit); err != nil {
		return err
	}
	e.BGPRoutes = &RuntimeBGPRoutes{Sequence: seq, Stage: "completed", Owned: append([]RuntimeBGPRouteTuple{}, target...), Target: append([]RuntimeBGPRouteTuple{}, target...)}
	entries[pos] = e
	return j.Save(entries)
}
func (a *KernelApplier) verifyBGPRoutes(ctx context.Context, p KernelAllocation, owned [2]Ownership, routes []RuntimeBGPRouteTuple, exact bool) error {
	s, err := a.snapshotBGPRoutes(ctx, p, routes)
	if err != nil {
		return err
	}
	for i, t := range p.Tunnels {
		if s.ownership[i] != owned[i] || owned[i].InterfaceIndex == 0 || !s.address[i] {
			return ErrKernelApply
		}
		if !s.routes[i][netip.PrefixFrom(t.BGP.Peer, 32)] {
			return ErrKernelApply
		}
	}
	for _, r := range routes {
		if r.InterfaceIndex != owned[r.Slot-1].InterfaceIndex || (exact && !s.routes[r.Slot-1][r.Prefix]) {
			return ErrKernelApply
		}
	}
	return nil
}
func (a *KernelApplier) reconcileBGPRoutes(ctx context.Context, e RuntimeJournalEntry, permit func() error) error {
	s := e.BGPRoutes
	union := bgpRouteUnion(s)
	if a.verifyBGPRoutes(ctx, e.Allocation, e.Observed, union, false) != nil {
		return ErrKernelApply
	}
	contains := func(routes []RuntimeBGPRouteTuple, r RuntimeBGPRouteTuple) bool {
		for _, v := range routes {
			if v == r {
				return true
			}
		}
		return false
	}
	mutate := func(r RuntimeBGPRouteTuple, action string) error {
		if action == "add" && permit != nil && permit() != nil {
			return ErrKernelApply
		}
		t := e.Allocation.Tunnels[r.Slot-1]
		return a.mutate(ctx, e.Allocation, "-4", "route", action, r.Prefix.String(), "dev", t.Name, "table", fmt.Sprint(r.Table), "proto", fmt.Sprint(r.Protocol), "metric", fmt.Sprint(r.Metric))
	}
	for _, r := range s.Owned {
		if !contains(s.Target, r) {
			if mutate(r, "del") != nil {
				return ErrKernelApply
			}
		}
	}
	for _, r := range s.Target {
		fresh, err := a.snapshotBGPRoutes(ctx, e.Allocation, union)
		if err != nil || !fresh.up[r.Slot-1] {
			return ErrKernelApply
		}
		if !contains(s.Owned, r) {
			if mutate(r, "add") != nil {
				return ErrKernelApply
			}
		}
	}
	return a.verifyBGPRoutes(ctx, e.Allocation, e.Observed, s.Target, true)
}
