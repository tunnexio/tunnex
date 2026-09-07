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
)

func TestAIProviderProbe(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/test-connection" || r.Header.Get("Authorization") != "Bearer fixture-admin-token" {
			t.Error("bridge auth/path")
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
	if err := s.ConfigureLiteLLMBridge(srv.URL, "fixture-admin-token"); err != nil {
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
	for _, raw := range []string{"http://public.example", "https://user:pass@example.com", "https://example.com/path", "https://example.com?x=y"} {
		if s.ConfigureLiteLLMBridge(raw, "fixture-admin-token") == nil {
			t.Fatal("bad URL admitted")
		}
	}
}
func TestAIProviderProbeBounds(t *testing.T) {
	b := &providerBridge{windows: map[uuid.UUID]probeWindow{}}
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
		s.ConfigureLiteLLMBridge(srv.URL, "fixture-admin-token")
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
	s.ConfigureLiteLLMBridge(srv.URL, "fixture-admin-token")
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
	if !s.bridge.admit(org, time.Now()) {
		t.Fatal("cancellation leaked slot")
	}
	s.bridge.release(org)
}
