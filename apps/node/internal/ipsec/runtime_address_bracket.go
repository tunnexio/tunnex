package ipsec

import (
	"bytes"
	"encoding/json"
	"reflect"
	"time"
)

// Address lifetimes count down while the independent reads run. Only a bounded
// positive monotonic countdown may differ; every other captured field is exact.
func runtimeAddressBracket(before, after []byte, elapsed time.Duration) bool {
	if bytes.Equal(before, after) {
		return true
	}
	if elapsed <= 0 || elapsed > kernelReadTimeout {
		return false
	}
	left, lok := kernelObjects(before)
	right, rok := kernelObjects(after)
	if !lok || !rok || len(left) != len(right) {
		return false
	}
	maxDrop := uint64((elapsed + time.Second - 1) / time.Second)
	changed := false
	for i, l := range left {
		r := right[i]
		la, lp := l["addr_info"]
		ra, rp := r["addr_info"]
		if !lp || !rp {
			return false
		}
		delete(l, "addr_info")
		delete(r, "addr_info")
		if !reflect.DeepEqual(l, r) {
			return false
		}
		a, aok := kernelObjects(la)
		b, bok := kernelObjects(ra)
		if !aok || !bok || len(a) != len(b) {
			return false
		}
		for j, x := range a {
			y := b[j]
			if reflect.DeepEqual(x, y) {
				continue
			}
			xv, xvp := x["valid_life_time"]
			xp, xpp := x["preferred_life_time"]
			yv, yvp := y["valid_life_time"]
			yp, ypp := y["preferred_life_time"]
			if !xvp || !xpp || !yvp || !ypp {
				return false
			}
			delete(x, "valid_life_time")
			delete(x, "preferred_life_time")
			delete(y, "valid_life_time")
			delete(y, "preferred_life_time")
			if !reflect.DeepEqual(x, y) {
				return false
			}
			validBefore, vb := runtimeAddressLifetime(xv)
			preferredBefore, pb := runtimeAddressLifetime(xp)
			validAfter, va := runtimeAddressLifetime(yv)
			preferredAfter, pa := runtimeAddressLifetime(yp)
			if !vb || !pb || !va || !pa || preferredBefore > validBefore || preferredAfter > validAfter {
				return false
			}
			if ((validBefore == uint64(^uint32(0)) || validAfter == uint64(^uint32(0))) && !bytes.Equal(xv, yv)) || ((preferredBefore == uint64(^uint32(0)) || preferredAfter == uint64(^uint32(0))) && !bytes.Equal(xp, yp)) {
				return false
			}
			if !runtimeLifetimeCountdown(validBefore, validAfter, maxDrop) || !runtimeLifetimeCountdown(preferredBefore, preferredAfter, maxDrop) {
				return false
			}
			changed = true
		}
	}
	return changed
}
func runtimeAddressLifetime(raw json.RawMessage) (uint64, bool) {
	if bytes.Equal(raw, []byte(`"forever"`)) {
		return uint64(^uint32(0)), true
	}
	n, ok := kernelNumber(raw, 32)
	return n, ok && n > 0
}
func runtimeLifetimeCountdown(before, after, maxDrop uint64) bool {
	forever := uint64(^uint32(0))
	if before == forever || after == forever {
		return before == after
	}
	return after <= before && before-after <= maxDrop
}
