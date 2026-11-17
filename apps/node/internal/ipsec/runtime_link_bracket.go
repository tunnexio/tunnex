package ipsec

import (
	"bytes"
	"encoding/json"
	"math"
	"reflect"
)

// The bridge garbage-collection timer is operational countdown state and may
// reset without a link or forwarding configuration change. Ignore only a
// present, finite nonnegative numeric timer on a typed bridge. Identity, MTU,
// flags, bridge configuration, field presence and every other field stay exact.
func runtimeLinkBracket(before, after []byte) bool {
	if bytes.Equal(before, after) {
		return true
	}
	left, lok := kernelObjects(before)
	right, rok := kernelObjects(after)
	if !lok || !rok || len(left) != len(right) {
		return false
	}
	for i, l := range left {
		r := right[i]
		if reflect.DeepEqual(l, r) {
			continue
		}
		li, liok := kernelObject(l["linkinfo"])
		ri, riok := kernelObject(r["linkinfo"])
		lk, _ := kernelString(li, "info_kind")
		rk, _ := kernelString(ri, "info_kind")
		ld, ldok := kernelObject(li["info_data"])
		rd, rdok := kernelObject(ri["info_data"])
		if !liok || !riok || lk != "bridge" || rk != "bridge" || !ldok || !rdok || !runtimeBridgeTimer(ld["gc_timer"]) || !runtimeBridgeTimer(rd["gc_timer"]) {
			return false
		}
		delete(l, "linkinfo")
		delete(r, "linkinfo")
		delete(li, "info_data")
		delete(ri, "info_data")
		delete(ld, "gc_timer")
		delete(rd, "gc_timer")
		if !reflect.DeepEqual(l, r) || !reflect.DeepEqual(li, ri) || !reflect.DeepEqual(ld, rd) {
			return false
		}
	}
	return true
}

func runtimeBridgeTimer(raw json.RawMessage) bool {
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return false
	}
	n, ok := value.(float64)
	return ok && n >= 0 && !math.IsInf(n, 0) && !math.IsNaN(n)
}
