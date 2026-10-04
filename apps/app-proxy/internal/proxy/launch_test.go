package proxy

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/packages/apptransport/authoritywire"
	"github.com/tunnexio/tunnex/packages/apptransport"
)

// This fixture injects publication and single-use redemption authority. It
// qualifies proxy behavior; real SQL/Redis issuance belongs to the API tests.
type launchAuthority struct {
	deniedAuthority
	route         Route
	mu            sync.Mutex
	hash, code    string
	used          bool
	result        RedeemResult
	sessionError  error
	redeems       int
	metadata      Request
	pendingError  error
	pendingExpiry time.Time
	pendingInput  PendingInput
}

func launchBinding() Binding {
	return Binding{OrgID: "11111111-1111-1111-1111-111111111111", GatewayID: "22222222-2222-2222-2222-222222222222", AppID: "33333333-3333-3333-3333-333333333333", Generation: "44444444-4444-4444-4444-444444444444", Digest: strings.Repeat("a", 64), Revision: 1, AuthorityVersion: 1, Hostname: "app.apps.example.net", Purpose: "browser_proxy"}
}
func newLaunchAuthority() *launchAuthority {
	b := launchBinding()
	return &launchAuthority{route: Route{Binding: authoritywire.AppProxyRouteBinding(b)}, code: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), result: RedeemResult{AppSessionToken: base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("s", 32))), RelativeTarget: "/forms?tab=details", ExpiresAt: time.Now().Add(time.Hour)}}
}
func (a *launchAuthority) Lookup(_ context.Context, host string) (Route, error) {
	if host != a.route.Binding.Hostname {
		return Route{}, ErrDenied
	}
	return a.route, nil
}
func (a *launchAuthority) Authorize(_ context.Context, _ Binding, _ string, r Request) (Decision, error) {
	a.metadata = r
	return Decision{}, a.sessionError
}
func (a *launchAuthority) Redeem(_ context.Context, input RedeemInput) (RedeemResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.redeems++
	hash := sha256.Sum256([]byte(input.Nonce))
	if a.used || input.Code != a.code || input.Hostname != a.route.Binding.Hostname || hex.EncodeToString(hash[:]) != a.hash {
		return RedeemResult{}, ErrDenied
	}
	a.used = true
	return a.result, nil
}
func launchHandler(t *testing.T, a *launchAuthority) *Handler {
	t.Helper()
	h := NewHandler("apps.example.net", a, nil)
	u, e := ConsoleURL("https://console.example.com", "apps.example.net")
	if e != nil {
		t.Fatal(e)
	}
	h.Console = u
	return h
}
func appRequest(method, path, cookie string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	r.Host = "app.apps.example.net"
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
	r.Header.Set("Cookie", cookie)
	return r
}
func TestStartNonceBoundToServerRoute(t *testing.T) {
	a := newLaunchAuthority()
	h := launchHandler(t, a)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, appRequest("GET", StartPath+"?target=%2Fforms%3Ftab%3Ddetails", ""))
	if w.Code != 303 {
		t.Fatal(w.Code)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatal("nonce cookie count")
	}
	nonce := cookies[0]
	if nonce.Name != apptransport.AppNonceCookie || !secret32(nonce.Value) || nonce.Domain != "" || nonce.Path != "/" || !nonce.Secure || !nonce.HttpOnly || nonce.SameSite != http.SameSiteLaxMode || nonce.MaxAge < 598 || nonce.MaxAge > 600 {
		t.Fatal("nonce attributes")
	}
	destination, e := url.Parse(w.Header().Get("Location"))
	if e != nil || destination.Host != "console.example.com" || destination.Path != "/app-access/launch" {
		t.Fatal(destination, e)
	}
	hash := sha256.Sum256([]byte(nonce.Value))
	query := destination.Query()
	if a.pendingInput.NonceHash != hex.EncodeToString(hash[:]) || a.pendingInput.RelativeTarget != "/forms?tab=details" || query.Get("nonce_hash") != hex.EncodeToString(hash[:]) || query.Get("orgId") != a.route.Binding.OrgID || query.Get("appId") != a.route.Binding.AppID || query.Get("target") != "/forms?tab=details" || strings.Contains(destination.String(), nonce.Value) {
		t.Fatal("launch metadata")
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("secret response caching")
	}
}
func TestReservedPathsAndMalformedTargetsNeverIssueCookie(t *testing.T) {
	h := launchHandler(t, newLaunchAuthority())
	for _, path := range []string{StartPath + "?target=%2F__tunnex_app%2Fstart", StartPath + "?target=https%3A%2F%2Fevil.example", StartPath + "?target=%2F%2Fevil.example", StartPath + "?target=%2F%255cfoo", StartPath + "?target=%2Fok&orgId=spoof", StartPath + "?target=%2Fa&target=%2Fb", "/__tunnex_app/unknown", RedeemPath + "?code=bad", RedeemPath + "?code=bad&code=other"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, appRequest("GET", path, ""))
		if w.Code != 403 || len(w.Header().Values("Set-Cookie")) != 0 {
			t.Fatal(path, w.Code)
		}
	}
}
func TestRedeemFailureReplayAndSafeReturn(t *testing.T) {
	for _, kind := range []string{"wrong_nonce", "missing_nonce", "duplicate_nonce", "wrong_host", "external_return", "expired", "invalid_token"} {
		a := newLaunchAuthority()
		h := launchHandler(t, a)
		nonce := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("n", 32)))
		hash := sha256.Sum256([]byte(nonce))
		a.hash = hex.EncodeToString(hash[:])
		cookie := apptransport.AppNonceCookie + "=" + nonce
		r := appRequest("GET", RedeemPath+"?code="+a.code, cookie)
		switch kind {
		case "wrong_nonce":
			r.Header.Set("Cookie", apptransport.AppNonceCookie+"="+a.code)
		case "missing_nonce":
			r.Header.Del("Cookie")
		case "duplicate_nonce":
			r.Header.Add("Cookie", cookie)
		case "wrong_host":
			r.Host = "other.apps.example.net"
		case "external_return":
			a.result.RelativeTarget = "https://evil.example"
		case "expired":
			a.result.ExpiresAt = time.Now().Add(-time.Second)
		case "invalid_token":
			a.result.AppSessionToken = strings.Repeat("\n", 40)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 403 || len(w.Header().Values("Set-Cookie")) != 0 {
			t.Fatal(kind, w.Code)
		}
	}
	a := newLaunchAuthority()
	h := launchHandler(t, a)
	nonce := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("n", 32)))
	hash := sha256.Sum256([]byte(nonce))
	a.hash = hex.EncodeToString(hash[:])
	r := appRequest("GET", RedeemPath+"?code="+a.code, apptransport.AppNonceCookie+"="+nonce)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 303 || w.Header().Get("Location") != a.result.RelativeTarget || strings.Contains(w.Header().Get("Location"), a.code) {
		t.Fatal("unclean redirect")
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 2 || cookies[0].Name != apptransport.AppSessionCookie || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].Domain != "" || cookies[0].Path != "/" || cookies[1].Name != apptransport.AppNonceCookie || cookies[1].MaxAge >= 0 {
		t.Fatal("session/nonce cookie isolation")
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 || len(w.Header().Values("Set-Cookie")) != 0 {
		t.Fatal("replay issued cookie")
	}
}
func TestRestartOnlySafeMissingOrExpiredSession(t *testing.T) {
	for _, method := range []string{"GET", "HEAD", "POST", "PUT"} {
		for _, kind := range []string{"missing", "expired", "revoked"} {
			a := newLaunchAuthority()
			a.sessionError = ErrDenied
			cookie := ""
			if kind != "missing" {
				cookie = apptransport.AppSessionCookie + "=existing"
			}
			if kind == "expired" {
				a.sessionError = ErrAppSession
			}
			h := launchHandler(t, a)
			r := appRequest(method, "/forms?tab=details", cookie)
			r.Header.Set("Origin", "https://app.apps.example.net")
			r.Header.Set("Sec-Fetch-Mode", "navigate")
			r.Header.Set("Sec-Fetch-Dest", "document")
			r.Header.Set("Sec-Fetch-User", "?1")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			want := 403
			if (method == "GET" || method == "HEAD") && kind != "revoked" {
				want = 303
			}
			if w.Code != want || len(w.Header().Values("Set-Cookie")) != 0 {
				t.Fatal(method, kind, w.Code)
			}
			if cookie != "" && (a.metadata.RelativePath != "/forms?tab=details" || a.metadata.FetchMode == nil || *a.metadata.FetchMode != "navigate") {
				t.Fatal("fetch metadata")
			}
		}
	}
	a := newLaunchAuthority()
	h := launchHandler(t, a)
	r := appRequest("GET", "/ws", "")
	r.Header.Set("Origin", "https://app.apps.example.net")
	r.Header.Set("Upgrade", "websocket")
	r.Header.Set("Connection", "Upgrade")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 || w.Header().Get("Location") != "" {
		t.Fatal("WebSocket login replay")
	}
}
func TestHTTPSBrowserCookieJarLaunchAndCleanup(t *testing.T) {
	a := newLaunchAuthority()
	h := launchHandler(t, a)
	leaf, caPEM := browserCertificates(t)
	certPEM, keyPEM := leaf(7, true)
	cert, _ := tls.X509KeyPair(certPEM, keyPEM)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	server := httptest.NewUnstartedServer(h)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}
	server.StartTLS()
	defer server.Close()
	jar, _ := cookiejar.New(nil)
	console, _ := url.Parse("https://console.example.com")
	jar.SetCookies(console, []*http.Cookie{{Name: "tunnex_session", Value: "console-only", Secure: true, Path: "/"}})
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}, DialContext: func(ctx context.Context, n, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, n, server.Listener.Addr().String())
	}}}
	response, e := client.Get("https://app.apps.example.net" + StartPath)
	if e != nil {
		t.Fatal(e)
	}
	response.Body.Close()
	destination, _ := url.Parse(response.Header.Get("Location"))
	a.hash = destination.Query().Get("nonce_hash")
	response, e = client.Get("https://app.apps.example.net" + RedeemPath + "?code=" + a.code)
	if e != nil {
		t.Fatal(e)
	}
	response.Body.Close()
	if response.StatusCode != 303 || response.Header.Get("Location") != a.result.RelativeTarget {
		t.Fatal("redemption failed")
	}
	app, _ := url.Parse("https://app.apps.example.net")
	cookies := jar.Cookies(app)
	if len(cookies) != 1 || cookies[0].Name != apptransport.AppSessionCookie {
		t.Fatal("app cookie jar audience")
	}
	cookies = jar.Cookies(console)
	if len(cookies) != 1 || cookies[0].Name != "tunnex_session" {
		t.Fatal("console cookie jar audience")
	}
}

func (a *launchAuthority) Pending(_ context.Context, in PendingInput) (PendingResult, error) {
	a.pendingInput = in
	if a.pendingError != nil {
		return PendingResult{}, a.pendingError
	}
	if !a.pendingExpiry.IsZero() {
		return PendingResult{ExpiresAt: a.pendingExpiry}, nil
	}
	if in.Binding != a.route.Binding || len(in.NonceHash) != 64 {
		return PendingResult{}, ErrDenied
	}
	return PendingResult{ExpiresAt: time.Now().Add(10 * time.Minute)}, nil
}

func TestPendingFailureIssuesNoCookieOrRedirect(t *testing.T) {
	for _, expiry := range []time.Time{time.Time{}, time.Now().Add(-time.Second), time.Now().Add(time.Hour)} {
		a := newLaunchAuthority()
		if expiry.IsZero() {
			a.pendingError = ErrDenied
		} else {
			a.pendingExpiry = expiry
		}
		w := httptest.NewRecorder()
		launchHandler(t, a).ServeHTTP(w, appRequest("GET", StartPath, ""))
		if w.Code != 403 || len(w.Result().Cookies()) != 0 || w.Header().Get("Location") != "" {
			t.Fatal("failed pending registration escaped")
		}
	}
}
func TestParallelStartsPreserveNewNonceOnOldCodeFailure(t *testing.T) {
	a := newLaunchAuthority()
	h := launchHandler(t, a)
	first := httptest.NewRecorder()
	h.ServeHTTP(first, appRequest("GET", StartPath, ""))
	oldNonce := first.Result().Cookies()[0].Value
	hash := sha256.Sum256([]byte(oldNonce))
	a.hash = hex.EncodeToString(hash[:])
	second := httptest.NewRecorder()
	h.ServeHTTP(second, appRequest("GET", StartPath, ""))
	newNonce := second.Result().Cookies()[0].Value
	if oldNonce == newNonce {
		t.Fatal("nonce reused")
	}
	failed := httptest.NewRecorder()
	h.ServeHTTP(failed, appRequest("GET", RedeemPath+"?code="+a.code, apptransport.AppNonceCookie+"="+newNonce))
	if failed.Code != 403 || len(failed.Result().Cookies()) != 0 {
		t.Fatal("old code cleared newer browser transaction")
	}
}
func TestDecisionAllowsLatencyButRejectsUnboundedExpiry(t *testing.T) {
	start := time.Now().Add(-100 * time.Millisecond)
	if !validDecision(Decision{StreamID: "s", ExpiresAt: time.Now().Add(4 * time.Second)}, start) {
		t.Fatal("server-start lease refused due RPC latency")
	}
	if validDecision(Decision{StreamID: "s", ExpiresAt: time.Now().Add(5 * time.Second)}, start) {
		t.Fatal("unbounded lease accepted")
	}
}
