package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func consoleRouterFixture(t *testing.T, authority *domainFixture, handler http.Handler) (*ConsoleRouter, *httptest.Server) {
	t.Helper()
	upstream := httptest.NewTLSServer(handler)
	t.Cleanup(upstream.Close)
	roots := x509.NewCertPool()
	roots.AddCert(upstream.Certificate())
	applications := NewHandler("apps.example.net", authority, nil)
	router, err := NewConsoleRouter(applications, upstream.URL, &tls.Config{RootCAs: roots})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(router.CloseIdleConnections)
	return router, upstream
}

func parentPortalAuthority() *domainFixture {
	return &domainFixture{
		domains: func(context.Context) (DomainConfig, error) {
			return DomainConfig{"https://internal.tunnex.app", "internal.tunnex.app"}, nil
		},
		routes: map[string]Route{"test.internal.tunnex.app": domainRoute("test.internal.tunnex.app")},
	}
}

func consoleRequest(method, path, host string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	r.Host = host
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
	r.RemoteAddr = "192.0.2.25:49152"
	return r
}

func TestConsoleRouterPreservesAuthAndReplacesForwardedClaims(t *testing.T) {
	authority := parentPortalAuthority()
	var calls atomic.Int32
	router, _ := consoleRouterFixture(t, authority, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.TLS == nil || r.TLS.Version != tls.VersionTLS13 || r.Host != "internal.tunnex.app" || r.URL.Path != "/api/v1/auth/login" || r.URL.RawQuery != "next=%2Fapp-access%2Fmy-apps" {
			t.Errorf("console destination/transport changed: %s %s", r.Host, r.URL.RequestURI())
		}
		for name, expected := range map[string]string{"Cookie": "__Host-tunnex_session=portal-token", "Origin": "https://internal.tunnex.app", "X-Tunnex-Csrf": "1", "Authorization": "Bearer user-credential", "X-Forwarded-For": "192.0.2.25", "X-Real-Ip": "192.0.2.25", "X-Forwarded-Host": "internal.tunnex.app", "X-Forwarded-Proto": "https"} {
			if r.Header.Get(name) != expected {
				t.Errorf("%s: wanted %q, got %q", name, expected, r.Header.Get(name))
			}
		}
		for _, name := range []string{"Forwarded", "True-Client-IP", "CF-Connecting-IP", "Client-IP", "Proxy-Authorization", "X-Forwarded-Port", "X-Forwarded-Server"} {
			if r.Header.Get(name) != "" {
				t.Errorf("caller forwarding claim survived: %s", name)
			}
		}
		w.Header().Set("Set-Cookie", "__Host-tunnex_session=new-portal-token; Path=/; Secure; HttpOnly; SameSite=Lax")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("Location", "https://identity.example.org/authorize")
		w.WriteHeader(http.StatusFound)
	}))
	request := consoleRequest("POST", "/api/v1/auth/login?next=%2Fapp-access%2Fmy-apps", "internal.tunnex.app")
	for name, value := range map[string]string{"Cookie": "__Host-tunnex_session=portal-token", "Origin": "https://internal.tunnex.app", "X-Tunnex-Csrf": "1", "Authorization": "Bearer user-credential", "X-Forwarded-For": "attacker", "X-Real-Ip": "attacker", "X-Forwarded-Host": "evil.example", "X-Forwarded-Proto": "http", "Forwarded": "host=evil.example;proto=http", "True-Client-IP": "attacker", "CF-Connecting-IP": "attacker", "Client-IP": "attacker", "Proxy-Authorization": "AppProxy must-not-forward", "X-Forwarded-Port": "80", "X-Forwarded-Server": "evil.example"} {
		request.Header.Set(name, value)
	}
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusFound || response.Header().Get("Location") != "https://identity.example.org/authorize" {
		t.Fatal("console SSO redirect was treated as a private app redirect", response.Code)
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "__Host-tunnex_session" || cookies[0].Value != "new-portal-token" || cookies[0].Domain != "" || !cookies[0].Secure || !cookies[0].HttpOnly {
		t.Fatal("console session cookie changed")
	}
	if response.Header().Get("Origin-Agent-Cluster") != "?1" || response.Header().Get("X-Frame-Options") != "DENY" || len(response.Header().Values("Content-Security-Policy")) != 2 {
		t.Fatal("console policy was lost")
	}
	if calls.Load() != 1 || authority.lookupCalls.Load() != 0 {
		t.Fatal("portal request entered app authority")
	}
}

func TestConsoleRouterNeverSendsApplicationOrUnknownHostToConsole(t *testing.T) {
	authority := parentPortalAuthority()
	var upstreamCalls atomic.Int32
	router, _ := consoleRouterFixture(t, authority, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { upstreamCalls.Add(1) }))
	for _, tc := range []struct {
		host   string
		status int
	}{{"test.internal.tunnex.app", http.StatusSeeOther}, {"unknown.internal.tunnex.app", http.StatusForbidden}, {"internal.tunnex.app.evil.com", http.StatusForbidden}, {"internal.tunnex.app:9443", http.StatusForbidden}} {
		request := consoleRequest("GET", "/", tc.host)
		request.Header.Set("X-Forwarded-Host", "internal.tunnex.app")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != tc.status {
			t.Errorf("%s: %d", tc.host, response.Code)
		}
		if response.Header().Get("X-Frame-Options") != "" {
			t.Fatal("console-only response policy reached application dispatch")
		}
	}
	if upstreamCalls.Load() != 0 {
		t.Fatal("application/unknown hostname reached console upstream")
	}
}

func TestConsoleRouterUsesCurrentExactPortalAndFixedUpstream(t *testing.T) {
	authority := parentPortalAuthority()
	current := "https://internal.tunnex.app"
	var configurationError error
	authority.domains = func(context.Context) (DomainConfig, error) {
		return DomainConfig{current, "internal.tunnex.app"}, configurationError
	}
	var upstreamCalls atomic.Int32
	router, upstream := consoleRouterFixture(t, authority, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		_, _ = io.WriteString(w, "fixed console")
	}))
	for _, host := range []string{"internal.tunnex.app", "internal.tunnex.app:443"} {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, consoleRequest("GET", "/?upstream=https://evil.example&host=evil.example", host))
		if response.Code != http.StatusOK || response.Body.String() != "fixed console" {
			t.Fatal("fixed portal dispatch failed")
		}
	}
	current = "https://16.192.177.77"
	old := httptest.NewRecorder()
	router.ServeHTTP(old, consoleRequest("GET", "/", "internal.tunnex.app"))
	if old.Code != http.StatusForbidden {
		t.Fatal("old portal hostname still selected console upstream")
	}
	newPortal := httptest.NewRecorder()
	router.ServeHTTP(newPortal, consoleRequest("GET", "/", "16.192.177.77"))
	if newPortal.Code != http.StatusOK || newPortal.Body.String() != "fixed console" {
		t.Fatal("current IP portal did not use same operator destination")
	}
	configurationError = ErrDenied
	failed := httptest.NewRecorder()
	router.ServeHTTP(failed, consoleRequest("GET", "/", "16.192.177.77"))
	if failed.Code != http.StatusForbidden || upstreamCalls.Load() != 3 {
		t.Fatal("authority error reused stale portal or upstream changed")
	}
	upstream.Close()
	configurationError = nil
	unavailable := httptest.NewRecorder()
	router.ServeHTTP(unavailable, consoleRequest("GET", "/?code=secret", "16.192.177.77"))
	if unavailable.Code != http.StatusServiceUnavailable || strings.Contains(unavailable.Body.String(), "secret") || strings.Contains(unavailable.Body.String(), upstream.URL) {
		t.Fatal("upstream error leaked private request/destination")
	}
}

func TestConsoleRouterRejectsAmbiguousAuthorityAndForgedTransport(t *testing.T) {
	authority := parentPortalAuthority()
	var upstreamCalls atomic.Int32
	router, _ := consoleRouterFixture(t, authority, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { upstreamCalls.Add(1) }))
	for _, mutate := range []func(*http.Request){
		func(r *http.Request) { r.Host = "internal.tunnex.app@evil.example" },
		func(r *http.Request) { r.Host = "internal.tunnex.app." },
		func(r *http.Request) { r.Host = "internal.tunnex.app:0443" },
		func(r *http.Request) { r.Host = "internal.tunnex.app/path" },
		func(r *http.Request) { r.Header.Add("Host", "internal.tunnex.app") },
		func(r *http.Request) { r.TLS = nil; r.Header.Set("X-Forwarded-Proto", "https") },
		func(r *http.Request) { r.URL.Scheme = "https"; r.URL.Host = "evil.example" },
		func(r *http.Request) { r.Method = "CONNECT" },
	} {
		request := consoleRequest("GET", "/", "internal.tunnex.app")
		mutate(request)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusForbidden {
			t.Fatal("ambiguous request accepted", response.Code)
		}
	}
	if upstreamCalls.Load() != 0 || authority.domainCalls.Load() != 0 {
		t.Fatal("malformed request reached console or domain authority")
	}
}

func TestConsoleUpstreamIsFixedVerifiedHTTPS(t *testing.T) {
	applications := NewHandler("apps.example.net", parentPortalAuthority(), nil)
	for _, endpoint := range []string{"", "http://console:8080", "https://user:pass@console", "https://console/path", "https://console?next=other", "https://console#", "https://console:", "https://console:0", "https://console:0443"} {
		if _, err := NewConsoleRouter(applications, endpoint, nil); err == nil {
			t.Fatalf("invalid operator destination accepted: %s", endpoint)
		}
	}
	for _, config := range []*tls.Config{{InsecureSkipVerify: true}, {MaxVersion: tls.VersionTLS12}} {
		if _, err := NewConsoleRouter(applications, "https://console:8446", config); err == nil {
			t.Fatal("unverified/obsolete upstream TLS accepted")
		}
	}
	var calls atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer upstream.Close()
	router, err := NewConsoleRouter(applications, upstream.URL, &tls.Config{RootCAs: x509.NewCertPool()})
	if err != nil {
		t.Fatal(err)
	}
	defer router.CloseIdleConnections()
	response := httptest.NewRecorder()
	router.ServeHTTP(response, consoleRequest("GET", "/", "internal.tunnex.app"))
	if response.Code != http.StatusServiceUnavailable || calls.Load() != 0 {
		t.Fatal("upstream certificate failure bypassed verification")
	}
}
