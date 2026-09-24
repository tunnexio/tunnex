package ipsec

import (
	"testing"
	"time"
)

func TestGatewayEligibilityBoundary(t *testing.T) {
	now := time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		age  time.Duration
		want string
	}{{0, "eligible"}, {90 * time.Second, "eligible"}, {90*time.Second + time.Nanosecond, "report_stale"}, {-time.Nanosecond, "report_stale"}} {
		reported := now.Add(-tc.age)
		if got := gatewayEligibilityReason("active", "serial", nil, &reported, []byte(`{"ipsec_config_version":1}`), now); got != tc.want {
			t.Fatalf("age%s reason%s want%s", tc.age, got, tc.want)
		}
	}
}
