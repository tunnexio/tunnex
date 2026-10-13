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

func TestGatewayBGPReportedCapabilityAndReadiness(t *testing.T) {
	now := time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct{ name, caps, want string }{
		{"qualified numeric", `{"ipsec_config_version":1,"ipsec_bgp_version":1}`, "eligible"},
		{"string", `{"ipsec_config_version":1,"ipsec_bgp_version":"1"}`, "unsupported"},
		{"future", `{"ipsec_config_version":1,"ipsec_bgp_version":2}`, "unsupported"},
		{"absent", `{"ipsec_config_version":1}`, "unsupported"},
		{"without base", `{"ipsec_bgp_version":1}`, "unsupported"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := gatewayBGPEligibilityReason("active", "serial", nil, &now, []byte(tc.caps), now); got != tc.want {
				t.Fatalf("got %s want %s", got, tc.want)
			}
		})
	}
	stale := now.Add(-91 * time.Second)
	if got := gatewayBGPEligibilityReason("active", "serial", nil, &stale, []byte(`{"ipsec_config_version":1,"ipsec_bgp_version":1}`), now); got != "report_stale" {
		t.Fatal(got)
	}
	if got := gatewayBGPEligibilityReason("active", "serial", &now, &now, []byte(`{"ipsec_config_version":1,"ipsec_bgp_version":1}`), now); got != "gateway_unavailable" {
		t.Fatal(got)
	}
	got := advisoryEligibility("eligible", "eligible")
	if !got.Eligible || got.Reason != "eligible" || got.BGP == nil || !got.BGP.Eligible || got.BGP.Reason != "eligible" || got.BGP.BGP != nil {
		t.Fatal("qualified reported readiness misrepresented", got)
	}
	for _, reason := range []string{"opt_in_required", "gateway_unavailable", "report_stale", "unsupported"} {
		got := advisoryEligibility(reason, reason)
		if got.Eligible || got.BGP == nil || got.BGP.Eligible || got.BGP.Reason != reason {
			t.Fatal("base reason lost", got)
		}
	}
}
