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

func TestConfiguredWireGuardMTUCap(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want int
	}{{"", 0}, {"  ", 0}, {"1280", 1280}, {"1380", 1380}, {" 1392 ", 1392}, {"1420", 1420}} {
		got, err := configuredWireGuardMTUCap(tc.raw)
		if err != nil || got != tc.want {
			t.Fatalf("%q: got %d, %v; want %d", tc.raw, got, err, tc.want)
		}
	}
	for _, raw := range []string{"0", "-1", "1279", "1421", "1500", "1380.0", "auto", "0x564", "999999999999999999999999"} {
		if got, err := configuredWireGuardMTUCap(raw); err == nil || got != 0 {
			t.Fatalf("invalid cap %q accepted: %d %v", raw, got, err)
		}
	}
}
