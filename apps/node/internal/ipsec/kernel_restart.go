package ipsec

import "context"

// RestartNeedsRecreation is a read-only census, not ownership or authority.
// Only total absence in the original namespace permits exclusive new creation.
// Surviving objects must retain the exact journaled interface indices. A partial
// survivor, renamed object, namespace change or any residual XFRM state refuses.
// Caller holds the journal lock and verified prefix refusal throughout, obtains
// fresh CP authority, repeats this census, and persists new ownership before use.
func (a *KernelApplier) RestartNeedsRecreation(ctx context.Context, p KernelAllocation, previous [2]Ownership) (bool, error) {
	for pass := 0; pass < 2; pass++ {
		s, err := a.snapshotSelection(ctx, p, true)
		if err != nil {
			return false, ErrKernelApply
		}
		if s.ownership == previous && previous[0].InterfaceIndex > 0 && previous[1].InterfaceIndex > 0 {
			return false, nil
		}
		if s.ownership != ([2]Ownership{}) {
			return false, ErrKernelApply
		}
		links, err := a.run(ctx, "-j", "-d", "link", "show")
		if err != nil {
			return false, ErrKernelApply
		}
		addresses, err := a.run(ctx, "-j", "addr", "show")
		if err != nil || !resetExtraObjectsAbsent(RuntimeJournalEntry{Allocation: p}, links, addresses) {
			return false, ErrKernelApply
		}
		x, err := (&XFRMReader{run: a.run, namespace: a.namespace}).Read(ctx)
		if err != nil || len(x.States) != 0 || len(x.Policies) != 0 || a.check(ctx, p) != nil {
			return false, ErrKernelApply
		}
	}
	return true, nil
}
