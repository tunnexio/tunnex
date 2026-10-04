package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/packages/apptransport/authoritywire"
)

type domainFixture struct {
	deniedAuthority
	domains      func(context.Context) (DomainConfig, error)
	routes       map[string]Route
	domainCalls  atomic.Int32
	lookupCalls  atomic.Int32
	pendingCalls atomic.Int32
}

func (a *domainFixture) Domains(ctx context.Context) (DomainConfig, error) {
	a.domainCalls.Add(1)
	return a.domains(ctx)
}
func (a *domainFixture) Lookup(_ context.Context, host string) (Route, error) {
	a.lookupCalls.Add(1)
	if route, ok := a.routes[host]; ok {
		return route, nil
	}
	return Route{}, ErrDenied
}
func (a *domainFixture) Pending(_ context.Context, in PendingInput) (PendingResult, error) {
	a.pendingCalls.Add(1)
	if route, ok := a.routes[in.Binding.Hostname]; !ok || route.Binding != in.Binding {
		return PendingResult{}, ErrDenied
	}
	return PendingResult{ExpiresAt: time.Now().Add(5 * time.Minute)}, nil
}

func domainRoute(host string) Route {
	binding := launchBinding()
	binding.Hostname = host
	return Route{Binding: authoritywire.AppProxyRouteBinding(binding)}
}

func TestAuthorityClientDomainsUsesPrivateAuthenticatedContract(t *testing.T) {
	server, config := authorityFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if r.URL.Path != "/internal/app-access/domains" || r.Method != "POST" || r.Header.Get("Authorization") != "AppProxy "+testProxyCredential() || r.Header.Get("Cookie") != "" || json.NewDecoder(r.Body).Decode(&body) != nil || len(body) != 0 {
			t.Error("domain configuration did not use the private authenticated contract")
		}
		_ = json.NewEncoder(w).Encode(DomainConfig{"https://internal.tunnex.app", "internal.tunnex.app"})
	}))
	client, err := NewClient(server.URL, testProxyCredential(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer client.http.CloseIdleConnections()
	got, err := client.Domains(context.Background())
	if err != nil || got.PortalURL != "https://internal.tunnex.app" || got.AppBaseDomain != "internal.tunnex.app" {
		t.Fatalf("domain response: %+v, %v", got, err)
	}
}

func TestAuthorityClientDomainsRefusesInvalidOrUnavailableConfiguration(t *testing.T) {
	for _, payload := range []string{
		`{}`, `{"portal_url":"https://console.tunnex.app","app_base_domain":"internal.tunnex.app"}`,
		`{"portal_url":"http://internal.tunnex.app","app_base_domain":"internal.tunnex.app"}`,
		`{"portal_url":"https://16.192.177.77","app_base_domain":"16.192.177.77"}`,
		`{"portal_url":"https://internal.tunnex.app","app_base_domain":"internal.tunnex.app","extra":true}`,
		`{"portal_url":"https://internal.tunnex.app","app_base_domain":"internal.tunnex.app"} {}`,
		"unavailable",
	} {
		t.Run(payload, func(t *testing.T) {
			server, config := authorityFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if payload == "unavailable" {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				_, _ = w.Write([]byte(payload))
			}))
			client, err := NewClient(server.URL, testProxyCredential(), config)
			if err != nil {
				t.Fatal(err)
			}
			defer client.http.CloseIdleConnections()
			if _, err := client.Domains(context.Background()); err == nil {
				t.Fatal("untrusted configuration accepted")
			}
		})
	}
}

func TestDynamicLaunchKeepsPublishedHostsAndUsesFreshConsole(t *testing.T) {
	current := DomainConfig{"https://internal.tunnex.app", "internal.tunnex.app"}
	var configErr error
	authority := &domainFixture{
		domains: func(context.Context) (DomainConfig, error) { return current, configErr },
		routes:  map[string]Route{"app.apps.example.net": domainRoute("app.apps.example.net"), "test.internal.tunnex.app": domainRoute("test.internal.tunnex.app")},
	}
	handler := NewHandler("apps.example.net", authority, nil)
	handler.Console, _ = ConsoleURL("https://old.example.com", "apps.example.net")
	for _, host := range []string{"app.apps.example.net", "test.internal.tunnex.app"} {
		request := appRequest("GET", StartPath, "")
		request.Host = host
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		location, err := url.Parse(response.Header().Get("Location"))
		if err != nil || response.Code != http.StatusSeeOther || location.Host != "internal.tunnex.app" || len(response.Result().Cookies()) != 1 {
			t.Fatalf("published host %q did not use new portal: %d %v", host, response.Code, location)
		}
	}
	current = DomainConfig{"https://second.example.org", "second.example.org"}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, appRequest("GET", StartPath, ""))
	if response.Code != http.StatusSeeOther || !strings.HasPrefix(response.Header().Get("Location"), "https://second.example.org/app-access/launch?") {
		t.Fatal("launch reused stale domain configuration")
	}
	configErr = ErrDenied
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, appRequest("GET", StartPath, ""))
	if response.Code != http.StatusForbidden || response.Header().Get("Location") != "" || len(response.Result().Cookies()) != 0 {
		t.Fatal("domain error fell back to static configuration")
	}
	if authority.domainCalls.Load() != 4 || authority.pendingCalls.Load() != 3 || handler.Console.Host != "old.example.com" || handler.BaseDomain != "apps.example.net" {
		t.Fatal("launch did not use fresh immutable per-request configuration")
	}
}

func TestDynamicHostStillRequiresExactPublishedAuthority(t *testing.T) {
	authority := &domainFixture{domains: func(context.Context) (DomainConfig, error) {
		return DomainConfig{"https://internal.tunnex.app", "internal.tunnex.app"}, nil
	}, routes: map[string]Route{"test.internal.tunnex.app": domainRoute("other.internal.tunnex.app")}}
	handler := NewHandler("apps.example.net", authority, nil)
	for _, host := range []string{"unknown.internal.tunnex.app", "test.internal.tunnex.app", "internal.tunnex.app", "16.192.177.77", "test.internal.tunnex.app:443"} {
		for _, path := range []string{"/", StartPath} {
			request := appRequest("GET", path, "")
			request.Host = host
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusForbidden || response.Header().Get("Location") != "" || len(response.Result().Cookies()) != 0 {
				t.Fatalf("unbound host %q gained access: %d", host, response.Code)
			}
		}
	}
	if authority.pendingCalls.Load() != 0 {
		t.Fatal("unknown or mismatched host acquired pending launch")
	}
}

func TestConcurrentLaunchConfigurationsDoNotShareMutableConsole(t *testing.T) {
	type consoleKey struct{}
	authority := &domainFixture{domains: func(ctx context.Context) (DomainConfig, error) {
		host := ctx.Value(consoleKey{}).(string)
		return DomainConfig{"https://" + host, host}, nil
	}, routes: map[string]Route{"app.apps.example.net": domainRoute("app.apps.example.net")}}
	handler := NewHandler("apps.example.net", authority, nil)
	var wait sync.WaitGroup
	for _, host := range []string{"internal.tunnex.app", "second.example.org"} {
		for i := 0; i < 8; i++ {
			wait.Add(1)
			go func() {
				defer wait.Done()
				request := appRequest("GET", StartPath, "").WithContext(context.WithValue(context.Background(), consoleKey{}, host))
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				location, err := url.Parse(response.Header().Get("Location"))
				if err != nil || response.Code != http.StatusSeeOther || location.Host != host {
					t.Errorf("launch crossed configuration snapshots: wanted %s, got %d %v", host, response.Code, location)
				}
			}()
		}
	}
	wait.Wait()
	if handler.Console != nil || handler.BaseDomain != "apps.example.net" {
		t.Fatal("shared handler configuration mutated")
	}
}
