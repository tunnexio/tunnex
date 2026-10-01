package http

import (
	"context"
	"errors"
	"github.com/tunnexio/tunnex/apps/api/internal/aitransport"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"testing"
)

func TestAIGatewayDeploymentPrerequisite(t *testing.T) {
	for _, tc := range []struct {
		name                                                     string
		secure, allow, installed, engineAvailable, wantAvailable bool
		reason                                                   api.AIGatewaySettingsUnavailableReason
	}{
		{"HTTP installed defaults off", false, false, true, true, false, api.HttpsRequired},
		{"HTTP absent defaults off", false, false, false, false, false, api.HttpsRequired},
		{"HTTPS engine absent", true, false, false, false, false, api.EngineNotConfigured},
		{"HTTPS always usable", true, false, true, true, true, ""},
		{"HTTP explicit opt-in", false, true, true, true, true, ""},
		{"HTTP opt-in does not install engine", false, true, false, false, false, api.EngineNotConfigured},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.WithValue(context.Background(), requestTransportKey{}, requestTransportState{secure: tc.secure})
			// Neither an advertised HTTPS URL nor the old environment opt-in
			// may override the observed HTTP request and saved OFF setting.
			s := apiServer{appBaseURL: "https://vpn.example.com", aiAllowPrivateHTTP: true, aiEngineInstalled: tc.installed, aiTransport: &aiTransportStub{value: aitransport.Settings{AllowHTTP: tc.allow, Revision: 1}}}
			v, err := s.aiGatewaySettings(ctx, true, tc.engineAvailable, 4)
			if err != nil || !v.Enabled || v.Available != tc.wantAvailable || v.EngineInstalled == nil || *v.EngineInstalled != tc.installed || v.Revision != 4 || v.HttpAllowed == nil || *v.HttpAllowed != tc.allow || v.PrivateHttpAllowed == nil || *v.PrivateHttpAllowed != tc.allow {
				t.Fatalf("metadata %+v: %v", v, err)
			}
			if tc.reason == "" {
				if v.UnavailableReason != nil {
					t.Fatal("available engine has prerequisite")
				}
			} else if v.UnavailableReason == nil || *v.UnavailableReason != tc.reason {
				t.Fatal("incorrect prerequisite")
			}
		})
	}
	s := apiServer{aiTransport: &aiTransportStub{failure: errors.New("database password=secret")}}
	if _, err := s.aiGatewaySettings(context.Background(), true, true, 4); err == nil || err.Error() == "database password=secret" {
		t.Fatal("policy read failure not reported safely")
	}
}
