package main

import "testing"

func TestReportLoopReadsAppliedMTUSource(t *testing.T) {
	current := 1380
	source := []func() int{func() int { return current }}
	if observedWireGuardMTU(source) != 1380 {
		t.Fatal("current applied observation missing")
	}
	current = 0
	if observedWireGuardMTU(source) != 0 {
		t.Fatal("failed configure observation cached")
	}
	current = 1420
	if observedWireGuardMTU(source) != 1420 {
		t.Fatal("underlay recovery observation cached")
	}
	if observedWireGuardMTU(nil) != 0 || observedWireGuardMTU([]func() int{nil}) != 0 {
		t.Fatal("legacy report invented observation")
	}
}
