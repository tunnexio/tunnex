package http

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/session"
)

func TestRequestTransportTrustsOnlyExplicitImmediatePeers(t *testing.T) {
	for _, tc := range []struct {
		name       string
		peers      []string
		remote     string
		proto      []string
		tls        bool
		wantStatus int
		wantSecure bool
	}{
		{name: "native TLS", remote: "198.51.100.1:1234", tls: true, wantStatus: 204, wantSecure: true},
		{name: "native TLS ignores spoofed downgrade", remote: "198.51.100.1:1234", proto: []string{"http"}, tls: true, peers: []string{"192.0.2.1"}, wantStatus: 204, wantSecure: true},
		{name: "unconfigured forwarded header ignored", remote: "192.0.2.1:1234", proto: []string{"https"}, wantStatus: 204},
		{name: "trusted exact peer HTTPS", peers: []string{"192.0.2.1"}, remote: "192.0.2.1:1234", proto: []string{"https"}, wantStatus: 204, wantSecure: true},
		{name: "TLS proxy hop does not hide HTTP client", peers: []string{"192.0.2.1"}, remote: "192.0.2.1:1234", proto: []string{"http"}, tls: true, wantStatus: 204},
		{name: "trusted exact peer HTTP", peers: []string{"192.0.2.1"}, remote: "192.0.2.1:1234", proto: []string{"http"}, wantStatus: 204},
		{name: "trusted explicit subnet", peers: []string{"192.0.2.0/24"}, remote: "192.0.2.5:1234", proto: []string{"https"}, wantStatus: 204, wantSecure: true},
		{name: "private network is not implicit trust", peers: []string{"192.0.2.1"}, remote: "172.18.0.4:1234", proto: []string{"https"}, wantStatus: 400},
		{name: "public peer cannot spoof", peers: []string{"192.0.2.1"}, remote: "198.51.100.1:1234", proto: []string{"https"}, wantStatus: 400},
		{name: "missing scheme from configured proxy fails closed", peers: []string{"192.0.2.1"}, remote: "192.0.2.1:1234", wantStatus: 400},
		{name: "comma chain rejected", peers: []string{"192.0.2.1"}, remote: "192.0.2.1:1234", proto: []string{"https,http"}, wantStatus: 400},
		{name: "duplicate headers rejected", peers: []string{"192.0.2.1"}, remote: "192.0.2.1:1234", proto: []string{"https", "http"}, wantStatus: 400},
		{name: "invalid scheme rejected", peers: []string{"192.0.2.1"}, remote: "192.0.2.1:1234", proto: []string{"ftp"}, wantStatus: 400},
		{name: "whitespace ambiguity rejected", peers: []string{"192.0.2.1"}, remote: "192.0.2.1:1234", proto: []string{" https"}, wantStatus: 400},
		{name: "IPv6 explicit peer", peers: []string{"2001:db8::1"}, remote: "[2001:db8::1]:1234", proto: []string{"https"}, wantStatus: 204, wantSecure: true},
		{name: "mapped IPv4", peers: []string{"192.0.2.1"}, remote: "[::ffff:192.0.2.1]:1234", proto: []string{"https"}, wantStatus: 204, wantSecure: true},
		{name: "direct HTTP without spoofed headers", peers: []string{"192.0.2.1"}, remote: "198.51.100.1:1234", wantStatus: 204},
	} {
		t.Run(tc.name, func(t *testing.T) {
			transport, err := newRequestTransport(tc.peers)
			if err != nil {
				t.Fatal(err)
			}
			called := false
			h := transport.middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				secure, known := requestHTTPS(r.Context())
				if !known || secure != tc.wantSecure {
					t.Fatalf("transport secure=%v known=%v", secure, known)
				}
				w.WriteHeader(204)
			}))
			r := httptest.NewRequest("GET", "http://console.example/", nil)
			r.RemoteAddr = tc.remote
			if tc.tls {
				r.TLS = &tls.ConnectionState{}
			}
			for _, p := range tc.proto {
				r.Header.Add("X-Forwarded-Proto", p)
			}
			// These caller-controlled headers must never confer proxy trust.
			r.Header.Set("X-Forwarded-For", "192.0.2.1")
			r.Header.Set("X-Real-IP", "192.0.2.1")
			r.Header.Set("Forwarded", "for=192.0.2.1;proto=https")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.wantStatus || called != (tc.wantStatus == 204) {
				t.Fatalf("status=%d called=%v body=%s", w.Code, called, w.Body.String())
			}
		})
	}
}

func TestRequestTransportResolvesCurrentExplicitDNSPeerAndFailsClosed(t *testing.T) {
	transport, err := newRequestTransport([]string{"nginx"})
	if err != nil {
		t.Fatal(err)
	}
	current := netip.MustParseAddr("192.0.2.1")
	var resolveErr error
	transport.lookup = func(ctx context.Context, network, name string) ([]netip.Addr, error) {
		if network != "ip" || name != "nginx" {
			t.Fatal("unexpected DNS lookup")
		}
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > time.Second {
			t.Fatal("DNS lookup lacks bounded deadline")
		}
		return []netip.Addr{current}, resolveErr
	}
	if !transport.trusted(context.Background(), "192.0.2.1:80") {
		t.Fatal("explicit DNS peer not trusted")
	}
	current = netip.MustParseAddr("192.0.2.2")
	if transport.trusted(context.Background(), "192.0.2.1:80") {
		t.Fatal("old container IP retained trust")
	}
	if !transport.trusted(context.Background(), "192.0.2.2:80") {
		t.Fatal("recreated proxy not recognized")
	}
	resolveErr = errors.New("lookup failed")
	if transport.trusted(context.Background(), "192.0.2.2:80") {
		t.Fatal("DNS failure retained stale trust")
	}
	for _, invalid := range []string{"", "https://nginx", "*", "192.0.2.0/33", "name;directive", "bad..name"} {
		if _, err := newRequestTransport([]string{invalid}); err == nil {
			t.Fatalf("accepted invalid proxy %q", invalid)
		}
	}
}

func requestTransportTestContext(secure bool) context.Context {
	return context.WithValue(context.Background(), requestTransportKey{}, requestTransportState{secure: secure, splitCookies: true})
}

func TestTransportSessionCookiesAndCSRFStaySeparated(t *testing.T) {
	for _, secure := range []bool{false, true} {
		ctx := requestTransportTestContext(secure)
		name := sessionCookieName(ctx)
		if requestCookieSecure(ctx, !secure) != secure {
			t.Fatal("deployment default overrode request transport")
		}
		wantName := "tunnex_session_http"
		wrongName := "__Host-tunnex_session"
		if secure {
			wantName, wrongName = wrongName, wantName
		}
		if name != wantName {
			t.Fatal("wrong transport cookie")
		}
		r := httptest.NewRequest("POST", "http://console.example/api/v1/auth/logout", nil).WithContext(ctx)
		r.AddCookie(&http.Cookie{Name: wrongName, Value: "other-transport"})
		r.AddCookie(&http.Cookie{Name: session.CookieName, Value: "legacy-injected"})
		// A mismatched or legacy cookie must not reach the session store at all.
		if SessionAuth(nil, nil)(r) != nil {
			t.Fatal("wrong transport cookie authenticated")
		}
		h := csrfGuard(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
		r.AddCookie(&http.Cookie{Name: name, Value: "current"})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal("new transport session bypassed CSRF")
		}
		r.Header.Set("X-Tunnex-CSRF", "browser")
		w = httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 204 {
			t.Fatal("legitimate state change rejected")
		}
	}
	if sessionCookieName(context.Background()) != session.CookieName || !requestCookieSecure(context.Background(), true) {
		t.Fatal("legacy cookie mode changed")
	}
}

func TestAllLoginResponsesSetSelectedTransportCookie(t *testing.T) {
	sess := session.Session{ID: "fresh-session", ExpiresAt: time.Now().Add(time.Hour)}
	for _, secure := range []bool{false, true} {
		ctx := requestTransportTestContext(secure)
		name := sessionCookieName(ctx)
		for _, kind := range []string{"password", "mfa", "sso", "sso-connection"} {
			w := httptest.NewRecorder()
			var err error
			switch kind {
			case "password":
				err = (loginResponse{sess: sess, setCookie: true, secure: secure, cookieName: name}).VisitLoginResponse(w)
			case "mfa":
				err = (mfaVerifyResponse{body: api.AuthUser{Email: "user@example.com"}, sess: sess, secure: secure, cookieName: name}).VisitMfaVerifyResponse(w)
			case "sso":
				err = (ssoCallbackResponse{sess: sess, setCookie: true, secure: secure, cookieName: name}).VisitSsoCallbackResponse(w)
			case "sso-connection":
				err = (connectionCallbackResponse{sess: sess, login: true, secure: secure, cookieName: name, flowCookieName: connectionFlowCookieName(ctx)}).VisitSsoConnectionCallbackResponse(w)
			}
			if err != nil {
				t.Fatal(err)
			}
			var found bool
			for _, cookie := range w.Result().Cookies() {
				if cookie.Name == name {
					found = true
					if cookie.Value != sess.ID || cookie.Secure != secure || !cookie.HttpOnly || cookie.Path != "/" || cookie.Domain != "" || cookie.SameSite != http.SameSiteLaxMode {
						t.Fatalf("%s unsafe transport cookie %+v", kind, cookie)
					}
				}
			}
			if !found {
				t.Fatalf("%s omitted selected session cookie", kind)
			}
		}
		w := httptest.NewRecorder()
		_ = (logoutResponse{secure: secure, cookieName: name}).VisitLogoutResponse(w)
		for _, cookie := range w.Result().Cookies() {
			if cookie.MaxAge != -1 {
				t.Fatal("logout did not expire cookie")
			}
			if !secure && cookie.Name == "__Host-tunnex_session" {
				t.Fatal("HTTP logout overwrote HTTPS session")
			}
		}
	}
}

func TestOIDCBindingCookiesCannotCrossTransport(t *testing.T) {
	transport, _ := newRequestTransport([]string{"192.0.2.1"})
	for _, secure := range []bool{false, true} {
		proto := "http"
		if secure {
			proto = "https"
		}
		ctx := requestTransportTestContext(secure)
		name := connectionFlowCookieName(ctx)
		r := httptest.NewRequest("GET", "http://console.example/api/v1/auth/sso-connections/callback", nil)
		r.RemoteAddr = "192.0.2.1:80"
		r.Header.Set("X-Forwarded-Proto", proto)
		r.AddCookie(&http.Cookie{Name: "tnx_oidc_flow", Value: "legacy-injected"})
		other := connectionFlowCookieName(requestTransportTestContext(!secure))
		r.AddCookie(&http.Cookie{Name: other, Value: "other-scheme"})
		h := transport.middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			legacy := "legacy-injected"
			if got := connectionFlowBinding(r.Context(), &legacy); got != "" {
				t.Fatal("cross-scheme OIDC binding accepted")
			}
			resp := connectionStartResponse{binding: "selected", secure: secure, flowCookieName: name}
			if err := resp.VisitStartSsoConnectionResponse(w); err != nil {
				t.Fatal(err)
			}
		}))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		cookies := w.Result().Cookies()
		if len(cookies) != 1 {
			t.Fatal("missing flow cookie")
		}
		c := cookies[0]
		if c.Name != name || c.Secure != secure || !c.HttpOnly || (secure && (c.Path != "/" || c.Domain != "")) {
			t.Fatalf("unsafe flow cookie %+v", c)
		}
	}
}

func TestSSOCallbackTransportKeepsHTTPSBindingAndLegacyBehavior(t *testing.T) {
	if err := requireSSOCallbackTransport(requestTransportTestContext(false), "https://console.example"); err == nil {
		t.Fatal("HTTP flow would lose its binding at HTTPS callback")
	}
	if err := requireSSOCallbackTransport(requestTransportTestContext(true), "https://console.example"); err != nil {
		t.Fatal(err)
	}
	if err := requireSSOCallbackTransport(requestTransportTestContext(false), "http://console.example"); err != nil {
		t.Fatal(err)
	}
	if err := requireSSOCallbackTransport(context.Background(), "https://console.example"); err != nil {
		t.Fatal("legacy SSO transport changed", err)
	}
}
