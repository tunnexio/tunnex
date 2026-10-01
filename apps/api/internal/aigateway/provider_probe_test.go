package aigateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

func TestAIProviderProbeEndpointSetupWithoutNativeRequest(t *testing.T) {
	calls := 0
	s := catalogPolicies(t, func(http.ResponseWriter, *http.Request) { calls++ })
	closedPolicy := customFixturePolicy(t)
	engine := s.engine.(*Engine)
	for _, tc := range []struct{ provider, endpoint string }{
		{"azure_foundry", "https://resource.services.ai.azure.com/anthropic"},
		{"custom", "http://unapproved.internal:8080"},
		{"sagemaker", "https://runtime.us-east-1.amazonaws.com"},
	} {
		t.Run(tc.provider, func(t *testing.T) {
			for _, setup := range []string{"missing_policy", "missing_proxy", "denied"} {
				s.customPolicy = nil
				engine.customProxy = nil
				wantStatus, wantCode := 503, "ai_provider_egress_unavailable"
				if setup != "missing_policy" {
					s.customPolicy = closedPolicy
				}
				if setup == "denied" {
					if err := engine.ConfigureCustomProxy("http://fixture-user:fixture-password@proxy:8190"); err != nil {
						t.Fatal(err)
					}
					wantStatus, wantCode = 403, "ai_provider_endpoint_denied"
				}
				_, err := s.ProbeProvider(context.Background(), uuid.New(), uuid.New(), ProviderProbeInput{Provider: tc.provider, EndpointURL: &tc.endpoint, Model: "deployment", Mode: ModeChat, Secret: "PRIVATE_KEY_MUST_NOT_APPEAR"})
				out, ok := err.(*apierr.Error)
				if !ok || out.Status != wantStatus || out.Code != wantCode || strings.Contains(out.Error(), "PRIVATE_KEY_MUST_NOT_APPEAR") {
					t.Fatalf("unsafe setup result: %v", err)
				}
			}
		})
	}
	s.customPolicy = nil
	for _, endpoint := range []string{"http://resource.services.ai.azure.com/anthropic", "https://127.0.0.1/anthropic", "https://user:pass@resource.services.ai.azure.com/anthropic", "https://resource.services.ai.azure.com/anthropic?override=x"} {
		_, err := s.ProbeProvider(context.Background(), uuid.New(), uuid.New(), ProviderProbeInput{Provider: "azure_foundry", EndpointURL: &endpoint, Model: "deployment", Secret: "fixture"})
		if usageStatus(err) != 400 {
			t.Fatalf("invalid endpoint no longer rejected: %v", err)
		}
	}
	if calls != 0 || s.probes.active != 0 || len(s.probes.windows) != 0 {
		t.Fatal("unapproved test invoked the engine or consumed provider admission")
	}
}

func TestAIProviderProbe(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/api/tunnex/test-connection" || !testEngineAdminAuth(r) {
			t.Error("engine auth/path")
		}
		var p map[string]any
		json.NewDecoder(r.Body).Decode(&p)
		if p["model"] != "openai/test-model" || p["api_key"] != "private-fixture" {
			t.Error("payload")
		}
		w.Write([]byte(`{"status":"success","duration_ms":12,"raw_secret":"never forward"}`))
	}))
	defer srv.Close()
	s := &Policies{providerManagement: true}
	if err := configureNativeTestEngine(s, srv.URL); err != nil {
		t.Fatal(err)
	}
	org, actor := uuid.New(), uuid.New()
	in := ProviderProbeInput{Provider: "openai", Model: "openai/test-model", Secret: "private-fixture"}
	for i := 0; i < 6; i++ {
		r, e := s.ProbeProvider(context.Background(), org, actor, in)
		if e != nil || r.Status != "success" {
			t.Fatal(r, e)
		}
	}
	if _, e := s.ProbeProvider(context.Background(), org, actor, in); usageStatus(e) != 429 || calls != 6 {
		t.Fatal("rate cap", e, calls)
	}
	in.Model = "anthropic/test"
	if _, e := s.ProbeProvider(context.Background(), uuid.New(), actor, in); usageStatus(e) != 400 || calls != 6 {
		t.Fatal("cross provider")
	}

}
func TestAIProviderProbeBounds(t *testing.T) {
	b := &providerOperations{windows: map[uuid.UUID]probeWindow{}}
	now := time.Now()
	org := uuid.New()
	if !b.admit(org, now) || b.admit(org, now) {
		t.Fatal("per org")
	}
	ids := []uuid.UUID{org}
	for i := 0; i < 7; i++ {
		id := uuid.New()
		ids = append(ids, id)
		if !b.admit(id, now) {
			t.Fatal("global premature")
		}
	}
	if b.admit(uuid.New(), now) {
		t.Fatal("global overflow")
	}
	for _, id := range ids {
		b.release(id)
	}
	if !b.admit(org, now.Add(time.Minute)) {
		t.Fatal("window recovery")
	}
	b.release(org)
	b.windows = map[uuid.UUID]probeWindow{}
	for i := 0; i < 4096; i++ {
		b.windows[uuid.New()] = probeWindow{start: now, attempts: 6}
	}
	if b.admit(uuid.New(), now) {
		t.Fatal("map overflow")
	}
	if !b.admit(uuid.New(), now.Add(time.Minute)) {
		t.Fatal("map expiry")
	}
}
func TestAIProviderProbeSanitized(t *testing.T) {
	for _, body := range []string{`{"status":"other","error":"private-key"}`, `not-json private-key`, strings.Repeat("x", 4097)} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
		s := &Policies{providerManagement: true}
		configureNativeTestEngine(s, srv.URL)
		_, err := s.ProbeProvider(context.Background(), uuid.New(), uuid.New(), ProviderProbeInput{Provider: "openai", Model: "openai/test", Secret: "private-key"})
		if usageStatus(err) != 503 || strings.Contains(err.Error(), "private-key") {
			t.Fatal("unsafe result", err)
		}
		srv.Close()
	}
}

func TestAIProviderProbeCancellationAdmission(t *testing.T) {
	arrived := make(chan struct{}, 1)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arrived <- struct{}{}
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer srv.Close()
	defer close(release)
	s := &Policies{providerManagement: true}
	configureNativeTestEngine(s, srv.URL)
	org, actor := uuid.New(), uuid.New()
	in := ProviderProbeInput{Provider: "openai", Model: "openai/test", Secret: "fixture-key"}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, e := s.ProbeProvider(ctx, org, actor, in); done <- e }()
	select {
	case <-arrived:
	case <-time.After(time.Second):
		t.Fatal("request missing")
	}
	if _, err := s.ProbeProvider(context.Background(), org, actor, in); usageStatus(err) != 429 {
		t.Fatal("overlap admitted", err)
	}
	cancel()
	if err := <-done; usageStatus(err) != 503 {
		t.Fatal("cancellation", err)
	}
	if !s.probes.admit(org, time.Now()) {
		t.Fatal("cancellation leaked slot")
	}
	s.probes.release(org)
}

func configureNativeTestEngine(s *Policies, raw string) error {
	engine, err := NewEngine(raw, "fixture-admin", "fixture-admin-password")
	if err != nil {
		return err
	}
	s.engine = engine
	return s.ConfigureNativeProviderOperations()
}
func testEngineAdminAuth(r *http.Request) bool {
	user, password, ok := r.BasicAuth()
	return ok && user == "fixture-admin" && password == "fixture-admin-password"
}
