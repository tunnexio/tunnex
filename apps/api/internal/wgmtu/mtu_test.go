package wgmtu

import (
	"testing"
	"time"
)

func TestFreshAppliedMTUAndConservativeFallback(t *testing.T) {
	now := time.Date(2026, time.October, 17, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name     string
		caps     string
		age      time.Duration
		noReport bool
		want     int
	}{
		{name: "minimum valid", caps: `{"wireguard_applied_mtu":1280}`, want: 1280},
		{name: "conservative observed", caps: `{"wireguard_applied_mtu":1380}`, want: 1380},
		{name: "fresh verified maximum remains valid", caps: `{"wireguard_applied_mtu":1420}`, age: time.Second, want: 1420},
		{name: "ninety seconds remains fresh", caps: `{"wireguard_applied_mtu":1420}`, age: 90 * time.Second, want: 1420},
		{name: "just stale", caps: `{"wireguard_applied_mtu":1420}`, age: 90*time.Second + time.Nanosecond, want: 1380},
		{name: "future", caps: `{"wireguard_applied_mtu":1420}`, age: -time.Nanosecond, want: 1380},
		{name: "zero report time", caps: `{"wireguard_applied_mtu":1420}`, noReport: true, want: 1380},
		{name: "missing capabilities", want: 1380},
		{name: "missing observation", caps: `{}`, want: 1380},
		{name: "zero observation", caps: `{"wireguard_applied_mtu":0}`, want: 1380},
		{name: "below minimum", caps: `{"wireguard_applied_mtu":1279}`, want: 1380},
		{name: "above maximum", caps: `{"wireguard_applied_mtu":1421}`, want: 1380},
		{name: "negative", caps: `{"wireguard_applied_mtu":-1}`, want: 1380},
		{name: "boolean", caps: `{"wireguard_applied_mtu":true}`, want: 1380},
		{name: "string", caps: `{"wireguard_applied_mtu":"1420"}`, want: 1380},
		{name: "fractional", caps: `{"wireguard_applied_mtu":1380.5}`, want: 1380},
		{name: "malformed", caps: `{"wireguard_applied_mtu":`, want: 1380},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reported := now.Add(-tc.age)
			if tc.noReport {
				reported = time.Time{}
			}
			if got := Applied([]byte(tc.caps), reported, now); got != tc.want {
				t.Fatalf("Applied() = %d, want %d", got, tc.want)
			}
		})
	}
}
