package k8sendpoint

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type serviceFixture struct {
	mu       sync.Mutex
	token    string
	response string
	status   int
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func (f *serviceFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if got := r.Header.Get("Authorization"); got != "Bearer "+f.token {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.URL.Path != "/api/v1/namespaces/tunnex-system/services/gateway-wg" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if f.status != 0 {
		w.WriteHeader(f.status)
	}
	_, _ = w.Write([]byte(f.response))
}

func newFixtureDiscoverer(t *testing.T, fixture *serviceFixture, changed *[]Snapshot) (*Discoverer, string) {
	t.Helper()
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte(fixture.token), 0o600); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		recorder := httptest.NewRecorder()
		fixture.serve(recorder, request)
		return recorder.Result(), nil
	})}
	discoverer, err := newDiscoverer(Config{Namespace: "tunnex-system", Service: "gateway-wg", Port: 51820}, "https://kubernetes.test", tokenPath, client, func(snapshot Snapshot) {
		*changed = append(*changed, snapshot)
	})
	if err != nil {
		t.Fatal(err)
	}
	return discoverer, tokenPath
}

func TestDiscovererPublishesExactUDPServiceEndpointAndReloadsToken(t *testing.T) {
	fixture := &serviceFixture{
		token: "token-one",
		response: `{"spec":{"type":"LoadBalancer","ports":[{"protocol":"UDP","port":51820}]},` +
			`"status":{"loadBalancer":{"ingress":[{"ip":"20.85.230.33"}]}}}`,
	}
	var changed []Snapshot
	discoverer, tokenPath := newFixtureDiscoverer(t, fixture, &changed)
	first := discoverer.Refresh(t.Context())
	if !first.Reportable() || first.Endpoint != "20.85.230.33:51820" || first.Generation != 1 {
		t.Fatalf("first snapshot=%+v", first)
	}

	fixture.mu.Lock()
	fixture.token = "token-two"
	fixture.response = `{"spec":{"type":"LoadBalancer","ports":[{"protocol":"UDP","port":51820}]},` +
		`"status":{"loadBalancer":{"ingress":[{"hostname":"GW.EXAMPLE.COM."}]}}}`
	fixture.mu.Unlock()
	if err := os.WriteFile(tokenPath, []byte("token-two"), 0o600); err != nil {
		t.Fatal(err)
	}
	second := discoverer.Refresh(t.Context())
	if !second.Reportable() || second.Endpoint != "gw.example.com:51820" || second.Generation != 2 {
		t.Fatalf("second snapshot=%+v", second)
	}
	if len(changed) != 2 {
		t.Fatalf("change notifications=%d, want 2", len(changed))
	}
}

func TestDiscovererKeepsPendingAndBlockedDistinct(t *testing.T) {
	tests := []struct {
		name     string
		response string
		want     State
		reason   string
	}{
		{
			name: "load balancer pending",
			response: `{"spec":{"type":"LoadBalancer","ports":[{"protocol":"UDP","port":51820}]},` +
				`"status":{"loadBalancer":{"ingress":[]}}}`,
			want: StatePending, reason: "load_balancer_ingress_pending",
		},
		{
			name: "node port requires explicit endpoint",
			response: `{"spec":{"type":"NodePort","ports":[{"protocol":"UDP","port":51820}]},` +
				`"status":{"loadBalancer":{"ingress":[]}}}`,
			want: StateBlocked, reason: "service_is_not_load_balancer",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := &serviceFixture{token: "token", response: tt.response}
			var changed []Snapshot
			discoverer, _ := newFixtureDiscoverer(t, fixture, &changed)
			got := discoverer.Refresh(t.Context())
			if got.State != tt.want || got.Reason != tt.reason || got.Reportable() {
				t.Fatalf("snapshot=%+v, want state=%s reason=%s", got, tt.want, tt.reason)
			}
		})
	}
}

func TestDiscovererSelectsFirstValidIngressInAPIOrderIPBeforeHostname(t *testing.T) {
	fixture := &serviceFixture{
		token: "token",
		response: `{"spec":{"type":"LoadBalancer","ports":[{"protocol":"UDP","port":51820}]},` +
			`"status":{"loadBalancer":{"ingress":[` +
			`{"ip":"not an ip","hostname":"FIRST.EXAMPLE.COM."},` +
			`{"ip":"20.0.0.2","hostname":"second.example.com"},` +
			`{"ip":"20.0.0.1"}]}}}`,
	}
	var changed []Snapshot
	discoverer, _ := newFixtureDiscoverer(t, fixture, &changed)
	got := discoverer.Refresh(t.Context())
	if !got.Reportable() || got.Endpoint != "first.example.com:51820" {
		t.Fatalf("first valid API-order candidate not selected: %+v", got)
	}

	fixture.mu.Lock()
	fixture.response = `{"spec":{"type":"LoadBalancer","ports":[{"protocol":"UDP","port":51820}]},` +
		`"status":{"loadBalancer":{"ingress":[` +
		`{"ip":"20.0.0.2","hostname":"first.example.com"},` +
		`{"ip":"20.0.0.1"}]}}}`
	fixture.mu.Unlock()
	got = discoverer.Refresh(t.Context())
	if !got.Reportable() || got.Endpoint != "20.0.0.2:51820" {
		t.Fatalf("IP did not win before hostname in the same ingress: %+v", got)
	}
}

func TestDiscovererClearsReportabilityWhenAPITruthIsLost(t *testing.T) {
	fixture := &serviceFixture{
		token: "token",
		response: `{"spec":{"type":"LoadBalancer","ports":[{"protocol":"UDP","port":51820}]},` +
			`"status":{"loadBalancer":{"ingress":[{"ip":"20.85.230.33"}]}}}`,
	}
	var changed []Snapshot
	discoverer, _ := newFixtureDiscoverer(t, fixture, &changed)
	if got := discoverer.Refresh(t.Context()); !got.Reportable() {
		t.Fatalf("initial snapshot=%+v", got)
	}
	fixture.mu.Lock()
	fixture.status = http.StatusForbidden
	fixture.response = `{}`
	fixture.mu.Unlock()
	got := discoverer.Refresh(t.Context())
	if got.State != StateBlocked || got.Endpoint != "" || got.Generation != 2 {
		t.Fatalf("lost API truth must clear reportability: %+v", got)
	}
}

func TestDiscovererRejectsInvalidConfigurationBeforeRequest(t *testing.T) {
	for _, config := range []Config{
		{Namespace: "", Service: "gateway-wg", Port: 51820},
		{Namespace: "tunnex-system", Service: "BAD_NAME", Port: 51820},
		{Namespace: "tunnex-system", Service: "gateway-wg", Port: 0},
	} {
		if _, err := newDiscoverer(config, "http://example", "/token", http.DefaultClient, nil); err == nil {
			t.Fatalf("invalid config accepted: %+v", config)
		}
	}
}

func TestReasonsRemainBoundedAndDoNotContainResponseBody(t *testing.T) {
	fixture := &serviceFixture{token: "token", status: http.StatusInternalServerError, response: strings.Repeat("secret", 1000)}
	var changed []Snapshot
	discoverer, _ := newFixtureDiscoverer(t, fixture, &changed)
	got := discoverer.Refresh(t.Context())
	if len(got.Reason) > maxReasonBytes || strings.Contains(got.Reason, "secret") {
		t.Fatalf("unsafe reason=%q", got.Reason)
	}
}

func TestDiscovererRefusesRedirectWithoutForwardingServiceAccountBearer(t *testing.T) {
	var mu sync.Mutex
	targetCalls := 0
	targetAuthorization := ""
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		targetCalls++
		targetAuthorization = r.Header.Get("Authorization")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	sourceAuthorization := ""
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		sourceAuthorization = r.Header.Get("Authorization")
		mu.Unlock()
		http.Redirect(w, r, target.URL+"/credential-leak", http.StatusTemporaryRedirect)
	}))
	defer source.Close()

	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("projected-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	client := source.Client()
	client.CheckRedirect = refuseK8sAPIRedirect
	discoverer, err := newDiscoverer(
		Config{Namespace: "tunnex-system", Service: "gateway-wg", Port: 51820},
		source.URL,
		tokenPath,
		client,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	got := discoverer.Refresh(t.Context())
	if got.State != StateBlocked || got.Reason != "kubernetes_api_status_307" || got.Reportable() {
		t.Fatalf("redirect snapshot=%+v, want blocked 307", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if sourceAuthorization != "Bearer projected-secret" {
		t.Fatalf("source bearer=%q, want projected credential", sourceAuthorization)
	}
	if targetCalls != 0 || targetAuthorization != "" {
		t.Fatalf("redirect target calls=%d authorization=%q; projected bearer must never leave the API origin", targetCalls, targetAuthorization)
	}
}
