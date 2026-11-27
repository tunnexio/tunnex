package http

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/aigateway"
	"github.com/tunnexio/tunnex/apps/api/internal/aitransport"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"reflect"
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

// AI-UX-1: one reason, in a fixed order, with the control that fixes it.
func TestAIGatewayStatusReason(t *testing.T) {
	working := aiGatewayStatusInput{Manageable: true, Enabled: true, TransportOK: true, ProviderKnown: true, HasProvider: true, EngineAvailable: true}
	if got := aiGatewayStatus(working); !got.On || got.Reason != nil || got.Fix != nil {
		t.Fatalf("a working gateway has no reason and no fix: %+v", got)
	}
	for _, tc := range []struct {
		name        string
		change      func(*aiGatewayStatusInput)
		reason      api.AIGatewayStatusReason
		fix         api.AIGatewayFixKind
		href        string
		serverAdmin bool
	}{
		{"not enabled", func(in *aiGatewayStatusInput) { in.Enabled = false }, api.AIGatewayOffNotEnabled, api.AIGatewayFixEnable, "/ai-gateway/settings", false},
		{"transport required", func(in *aiGatewayStatusInput) { in.TransportOK = false }, api.AIGatewayOffTransportRequired, api.AIGatewayFixChooseTransport, "/settings?section=ai-transport", true},
		{"no provider", func(in *aiGatewayStatusInput) { in.HasProvider = false }, api.AIGatewayOffNoProvider, api.AIGatewayFixAddProvider, "/ai-gateway/models/new", false},
		{"engine not installed", func(in *aiGatewayStatusInput) { in.EngineAvailable = false }, api.AIGatewayOffEngineNotInstalled, api.AIGatewayFixInstallEngine, "", true},
		{"no backend wired", func(in *aiGatewayStatusInput) { in.Manageable, in.Enabled = false, false }, api.AIGatewayOffEngineNotInstalled, api.AIGatewayFixInstallEngine, "", true},
		{"everything wrong reports the switch first", func(in *aiGatewayStatusInput) {
			in.Enabled, in.TransportOK, in.HasProvider, in.EngineAvailable = false, false, false, false
		}, api.AIGatewayOffNotEnabled, api.AIGatewayFixEnable, "/ai-gateway/settings", false},
		{"transport before provider and engine", func(in *aiGatewayStatusInput) {
			in.TransportOK, in.HasProvider, in.EngineAvailable = false, false, false
		}, api.AIGatewayOffTransportRequired, api.AIGatewayFixChooseTransport, "/settings?section=ai-transport", true},
		{"provider before engine", func(in *aiGatewayStatusInput) { in.HasProvider, in.EngineAvailable = false, false }, api.AIGatewayOffNoProvider, api.AIGatewayFixAddProvider, "/ai-gateway/models/new", false},
		{"unknown provider store never claims a missing provider", func(in *aiGatewayStatusInput) {
			in.ProviderKnown, in.HasProvider, in.EngineAvailable = false, false, false
		}, api.AIGatewayOffEngineNotInstalled, api.AIGatewayFixInstallEngine, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := working
			tc.change(&in)
			got := aiGatewayStatus(in)
			if got.On || got.Reason == nil || *got.Reason != tc.reason || got.Fix == nil || got.Fix.Kind != tc.fix {
				t.Fatalf("status %+v fix %+v", got, got.Fix)
			}
			if (tc.href == "") != (got.Fix.Href == nil) || (got.Fix.Href != nil && *got.Fix.Href != tc.href) {
				t.Fatalf("fix pointer: %+v", got.Fix)
			}
			if serverAdmin := got.Fix.RequiresServerAdmin != nil && *got.Fix.RequiresServerAdmin; serverAdmin != tc.serverAdmin {
				t.Fatalf("server administrator flag: %+v", got.Fix)
			}
		})
	}
}

// The status is added beside the existing fields, which stay exactly as before.
func TestAIGatewaySettingsStatusKeepsExistingFields(t *testing.T) {
	org := uuid.New()
	for _, tc := range []struct {
		name            string
		secure, enabled bool
		engine          bool
		reason          api.AIGatewayStatusReason
	}{
		{"HTTP without opt-in", false, true, true, api.AIGatewayOffTransportRequired},
		{"switch off", true, false, true, api.AIGatewayOffNotEnabled},
		{"engine absent", true, true, false, api.AIGatewayOffEngineNotInstalled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.WithValue(context.Background(), requestTransportKey{}, requestTransportState{secure: tc.secure})
			// An empty credentials service only marks the switch as manageable; no provider store is wired.
			s := apiServer{aiCredentials: &aigateway.Credentials{}, aiEngineInstalled: tc.engine, aiTransport: &aiTransportStub{value: aitransport.Settings{Revision: 1}}}
			before, err := s.aiGatewaySettings(ctx, tc.enabled, tc.engine, 7)
			if err != nil {
				t.Fatal(err)
			}
			after := s.withAIGatewayStatus(ctx, org, before, tc.engine)
			if after.Status == nil || after.Status.On || after.Status.Reason == nil || *after.Status.Reason != tc.reason {
				t.Fatalf("status: %+v", after.Status)
			}
			after.Status = nil
			if !reflect.DeepEqual(before, after) {
				t.Fatalf("existing fields changed:\n%+v\n%+v", before, after)
			}
		})
	}
}

// A person who may use a model but may not read the settings is told only whether the gateway works and
// the one reason: no control, no link into settings and none of the settings themselves.
func TestAIGatewayStatusForAModelUserCarriesOnlyTheReason(t *testing.T) {
	href := "/settings?section=ai-transport"
	admin := true
	reason := api.AIGatewayOffTransportRequired
	full := api.AIGatewayStatus{On: false, Reason: &reason, Fix: &api.AIGatewayFix{Kind: api.AIGatewayFixChooseTransport, Href: &href, RequiresServerAdmin: &admin}}
	got := aiGatewayStatusReasonOnly(full)
	if got.On || got.Reason == nil || *got.Reason != reason || got.Fix != nil {
		t.Fatalf("status = %+v", got)
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	for name, value := range fields {
		if name != "on" && name != "reason" && value != nil {
			t.Fatalf("unexpected field %q in %s", name, raw)
		}
	}
	if on := aiGatewayStatusReasonOnly(api.AIGatewayStatus{On: true}); !on.On || on.Reason != nil || on.Fix != nil {
		t.Fatalf("on = %+v", on)
	}
	// The same reason the settings page reports, computed from the same inputs.
	ctx := context.WithValue(context.Background(), requestTransportKey{}, requestTransportState{secure: true})
	s := apiServer{aiCredentials: &aigateway.Credentials{}, aiEngineInstalled: true, aiTransport: &aiTransportStub{value: aitransport.Settings{Revision: 1}}}
	settings, err := s.aiGatewaySettings(ctx, false, true, 1)
	if err != nil {
		t.Fatal(err)
	}
	status := aiGatewayStatusReasonOnly(*s.withAIGatewayStatus(ctx, uuid.New(), settings, true).Status)
	if status.On || status.Reason == nil || *status.Reason != api.AIGatewayOffNotEnabled || status.Fix != nil {
		t.Fatalf("switch off = %+v", status)
	}
}
