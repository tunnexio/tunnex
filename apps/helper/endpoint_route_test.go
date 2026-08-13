package helper

import (
	"net/netip"
	"testing"
)

func TestSelectPhysicalDefaultRouteUsesEffectiveMetric(t *testing.T) {
	// Windows routing priority is route metric + interface metric. The lower
	// route metric alone belongs to the worse physical route here.
	route, ok := selectPhysicalDefaultRoute([]physicalDefaultRoute{
		{EffectiveMetric: 31, LUID: 1, NextHop: netip.MustParseAddr("192.0.2.1"), Up: true},
		{EffectiveMetric: 20, LUID: 2, NextHop: netip.MustParseAddr("198.51.100.1"), Up: true},
	})
	if !ok || route.LUID != 2 || route.NextHop != netip.MustParseAddr("198.51.100.1") {
		t.Fatalf("selected %#v, %v; want operational lowest-effective route on LUID 2", route, ok)
	}
}

func TestSelectPhysicalDefaultRouteSkipsDownInterfaces(t *testing.T) {
	route, ok := selectPhysicalDefaultRoute([]physicalDefaultRoute{
		{EffectiveMetric: 1, LUID: 1, NextHop: netip.MustParseAddr("192.0.2.1"), Up: false},
		{EffectiveMetric: 100, LUID: 2, NextHop: netip.MustParseAddr("198.51.100.1"), Up: true},
	})
	if !ok || route.LUID != 2 {
		t.Fatalf("selected %#v, %v; want the only operational route", route, ok)
	}
	if _, ok := selectPhysicalDefaultRoute([]physicalDefaultRoute{{EffectiveMetric: 1, Up: false}}); ok {
		t.Fatal("down-only route set must have no physical default")
	}
}
