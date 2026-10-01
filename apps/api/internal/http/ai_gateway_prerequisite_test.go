package http

import (
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"testing"
)

func TestAIGatewayDeploymentPrerequisite(t *testing.T) {
	for _, tc := range []struct {
		name, base           string
		installed, available bool
		reason               api.AIGatewaySettingsUnavailableReason
	}{
		{"http_sandbox_backend_installed", "http://sandbox.example.com", true, false, api.HttpsRequired},
		{"http_sandbox_backend_absent", "http://sandbox.example.com", false, false, api.HttpsRequired},
		{"https_missing_engine", "https://vpn.example.com", false, false, api.EngineNotConfigured},
		{"localhost_development", "http://localhost:8080", false, false, api.EngineNotConfigured},
		{"loopback_development", "http://127.0.0.1:8080", false, false, api.EngineNotConfigured},
		{"available", "https://vpn.example.com", true, true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := apiServer{appBaseURL: tc.base, aiEngineInstalled: tc.installed}
			v := s.aiGatewaySettings(false, tc.available, 4)
			if v.Enabled || v.Available != tc.available || v.EngineInstalled == nil || *v.EngineInstalled != tc.installed || v.Revision != 4 {
				t.Fatalf("deployment metadata changed access: %+v", v)
			}
			if tc.reason == "" {
				if v.UnavailableReason != nil {
					t.Fatal("available engine has a prerequisite")
				}
			} else if v.UnavailableReason == nil || *v.UnavailableReason != tc.reason {
				t.Fatal("incorrect deployment prerequisite")
			}
		})
	}
	t.Run("explicit_private_http_policy", func(t *testing.T) {
		s := apiServer{appBaseURL: "http://172.31.20.253", aiEngineInstalled: true, aiAllowPrivateHTTP: true}
		v := s.aiGatewaySettings(false, true, 4)
		if !v.Available || v.Enabled || v.PrivateHttpAllowed == nil || !*v.PrivateHttpAllowed || v.UnavailableReason != nil {
			t.Fatal("explicit operator policy did not preserve independent organization access")
		}
		s.aiEngineInstalled = false
		v = s.aiGatewaySettings(false, false, 4)
		if v.UnavailableReason == nil || *v.UnavailableReason != api.EngineNotConfigured {
			t.Fatal("HTTP opt-in fabricated a configured engine")
		}
	})
}
