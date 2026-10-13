package ipsec

import "reflect"

// validBGPRouteWithdrawalSuccessor preserves the full possible route union while
// cleanup is pending. Cleanup completion forgets tuples only after kernel proof;
// it never installs a new route or manufactures a fresh lease.
func validBGPRouteWithdrawalSuccessor(before, after RuntimeJournalEntry) (handled, valid bool) {
	b, a := before.BGPRoutes, after.BGPRoutes
	if (b == nil || !b.Withdrawal) && (a == nil || !a.Withdrawal) {
		return false, false
	}
	if b == nil || a == nil {
		return true, false
	}
	if reflect.DeepEqual(b, a) {
		return true, true
	}
	empty := func(routes []RuntimeBGPRouteTuple) bool { return routes != nil && len(routes) == 0 }
	advance := b.Sequence != ^uint64(0) && a.Sequence == b.Sequence+1
	switch {
	case b.Stage == "pending" && !b.Withdrawal:
		return true, a.Stage == "pending" && a.Withdrawal && a.Sequence == b.Sequence && reflect.DeepEqual(a.Owned, b.Owned) && reflect.DeepEqual(a.Target, b.Target)
	case b.Stage == "pending" && b.Withdrawal:
		return true, a.Stage == "completed" && a.Withdrawal && a.Sequence == b.Sequence && empty(a.Owned) && empty(a.Target)
	case b.Stage == "completed" && !b.Withdrawal:
		return true, a.Stage == "pending" && a.Withdrawal && advance && reflect.DeepEqual(a.Owned, b.Owned) && empty(a.Target)
	case b.Stage == "completed" && b.Withdrawal:
		return true, a.Stage == "pending" && !a.Withdrawal && advance && empty(b.Owned) && empty(b.Target) && reflect.DeepEqual(a.Owned, b.Owned)
	default:
		return true, false
	}
}
