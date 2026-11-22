package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/tunnexio/tunnex/apps/operator/internal/cp"
)

func TestValidateControlPlaneConfig(t *testing.T) {
	validOrg := "11111111-1111-1111-1111-111111111111"
	for _, tc := range []struct {
		name  string
		url   string
		org   string
		valid bool
	}{
		{name: "dns", url: "https://internal.tunnex.app", org: validOrg, valid: true},
		{name: "port and path", url: "https://cp.example.com:8443/base", org: validOrg, valid: true},
		{name: "missing host", url: "https://", org: validOrg},
		{name: "http", url: "http://cp.example.com", org: validOrg},
		{name: "userinfo", url: "https://user@cp.example.com", org: validOrg},
		{name: "bad org", url: "https://cp.example.com", org: "not-a-uuid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateControlPlaneConfig(tc.url, tc.org)
			if tc.valid && err != nil {
				t.Fatalf("valid config rejected: %v", err)
			}
			if !tc.valid && err == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
}

// The pod's log must say why it is not ready; a 401 has four causes and the control plane names none.
func TestReadinessReasonNamesWhatToCheck(t *testing.T) {
	if got := readinessReason(nil); got != "" {
		t.Fatalf("ready reported a reason: %q", got)
	}
	unauthorized := readinessReason(&cp.APIError{Status: 401, Code: "unauthenticated"})
	for _, want := range []string{"401", "no owner assigned", "revoked", "wrong or incomplete"} {
		if !strings.Contains(unauthorized, want) {
			t.Errorf("401 reason lacks %q: %s", want, unauthorized)
		}
	}
	if got := readinessReason(&cp.APIError{Status: 404, Code: "org_not_found"}); !strings.Contains(got, "organizationID") {
		t.Errorf("404 reason: %s", got)
	}
	if got := readinessReason(errors.New("dial tcp: i/o timeout")); !strings.Contains(got, "cannot reach the control plane") {
		t.Errorf("transport reason: %s", got)
	}
}
