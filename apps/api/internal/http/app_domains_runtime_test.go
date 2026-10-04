package http

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/api/internal/appdomains"
	"github.com/tunnexio/tunnex/apps/api/internal/publicurl"
)

type runtimeDomainStub struct {
	config appdomains.Config
	err    error
	calls  int
}

type blockedDomainStub struct{}

func (blockedDomainStub) Effective(ctx context.Context) (appdomains.Config, error) {
	<-ctx.Done()
	return appdomains.Config{}, ctx.Err()
}

func TestDomainRuntimeHonorsRequestDeadline(t *testing.T) {
	h := appDomainRuntimeMiddleware(blockedDomainStub{})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("unavailable settings reached downstream handler")
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	r := httptest.NewRequest("GET", "/api/v1/auth/me", nil).WithContext(ctx)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 503 || ctx.Err() == nil {
		t.Fatalf("deadline did not bound lookup: %d", w.Code)
	}
}

func TestSSOUsesCanonicalPortalAuthority(t *testing.T) {
	transport, _ := newRequestTransport(nil)
	for _, target := range []string{"https://portal.example.com", "https://portal.example.com:443", "https://192.0.2.15", "https://old.example.com", "https://portal.example.com:9443"} {
		h := transport.middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			err := requireSSOCallbackTransport(r.Context(), "https://portal.example.com")
			if (err == nil) != (target == "https://portal.example.com" || target == "https://portal.example.com:443") {
				t.Fatalf("unexpected canonical portal admission for %s: %v", target, err)
			}
		}))
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", target+"/api/v1/auth/sso/google/start", nil))
	}
}

func TestConsoleOriginPreservesNondefaultPorts(t *testing.T) {
	transport, _ := newRequestTransport(nil)
	h := transport.middleware(csrfGuard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })))
	for _, tc := range []struct {
		target, origin string
		want           int
	}{
		{"https://internal.example.com:443", "https://internal.example.com", 204},
		{"https://internal.example.com:9443", "https://internal.example.com:9443", 204},
		{"https://internal.example.com:9443", "https://internal.example.com", 403},
		{"http://192.0.2.15:80", "http://192.0.2.15", 204},
		{"http://192.0.2.15:8080", "http://192.0.2.15:8080", 204},
		{"http://192.0.2.15:8080", "http://192.0.2.15", 403},
	} {
		r := httptest.NewRequest("POST", tc.target+"/api/v1/auth/login", nil)
		r.Header.Set("Origin", tc.origin)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("target=%q origin=%q status=%d want=%d", tc.target, tc.origin, w.Code, tc.want)
		}
	}
}

func (s *runtimeDomainStub) Effective(context.Context) (appdomains.Config, error) {
	s.calls++
	return s.config, s.err
}

func TestDomainRuntimeSnapshotChangesBetweenRequestsAndFailsClosed(t *testing.T) {
	store := &runtimeDomainStub{config: appdomains.Config{PortalURL: "https://internal.example.com", AppBaseDomain: "internal.example.com"}}
	var urls []string
	h := appDomainRuntimeMiddleware(store)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		urls = append(urls, publicurl.From(r.Context(), "https://old.example.net"))
		w.WriteHeader(204)
	}))
	request := func() int {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/auth/me", nil))
		return w.Code
	}
	if request() != 204 {
		t.Fatal("initial request failed")
	}
	store.config.PortalURL = "https://next.example.com"
	if request() != 204 || len(urls) != 2 || urls[0] != "https://internal.example.com" || urls[1] != "https://next.example.com" || store.calls != 2 {
		t.Fatal("runtime update did not apply to subsequent request")
	}
	store.err = errors.New("database unavailable")
	if request() != 503 || len(urls) != 2 {
		t.Fatal("configuration failure fell back to old public address")
	}
}

func TestDirectHTTPSAlwaysUsesHostBoundAuthorityCookies(t *testing.T) {
	transport, _ := newRequestTransport(nil)
	h := transport.middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if sessionCookieName(r.Context()) != "__Host-tunnex_session" || connectionFlowCookieName(r.Context()) != "__Host-tnx_oidc_flow" || !requestCookieSecure(r.Context(), false) {
			t.Fatal("direct TLS did not isolate authoritative cookies")
		}
		if connectionFlowBinding(r.Context(), nil) != "bound-browser" {
			t.Fatal("direct TLS lost SSO browser binding")
		}
		w.WriteHeader(204)
	}))
	r := httptest.NewRequest("GET", "https://internal.example.com/api/v1/auth/me", nil)
	r.AddCookie(&http.Cookie{Name: "__Host-tnx_oidc_flow", Value: "bound-browser"})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 204 {
		t.Fatal(w.Code)
	}
}

func TestConsoleRejectsSiblingOriginEvenWithoutSessionCookie(t *testing.T) {
	transport, _ := newRequestTransport(nil)
	h := transport.middleware(csrfGuard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })))
	for _, tc := range []struct {
		origin, site string
		cookie       bool
		want         int
	}{
		{"https://test.internal.example.com", "same-site", false, 403},
		{"https://test.internal.example.com", "same-site", true, 403},
		{"null", "cross-site", false, 403},
		{"", "same-site", false, 403},
		{"https://internal.example.com", "same-origin", true, 204},
		{"", "", false, 204},
	} {
		r := httptest.NewRequest("POST", "https://internal.example.com/api/v1/auth/login", nil)
		if tc.origin != "" {
			r.Header.Set("Origin", tc.origin)
		}
		if tc.site != "" {
			r.Header.Set("Sec-Fetch-Site", tc.site)
		}
		if tc.cookie {
			r.AddCookie(&http.Cookie{Name: "__Host-tunnex_session", Value: "session"})
		}
		r.Header.Set("X-Tunnex-CSRF", "browser")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("origin=%q site=%q cookie=%v status=%d want=%d", tc.origin, tc.site, tc.cookie, w.Code, tc.want)
		}
	}
}
