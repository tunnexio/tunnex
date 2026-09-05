package main

import "testing"

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
