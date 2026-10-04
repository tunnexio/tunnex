package http

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/appaccess"
	"github.com/tunnexio/tunnex/apps/api/internal/appdomains"
)

type denyProxyAuthority struct{ authCalls int }

type domainProxyAuthority struct {
	denyProxyAuthority
	err         error
	domainCalls int
}

func (s *domainProxyAuthority) ProxyDomains(context.Context, appaccess.AuthenticatedProxy) (appdomains.Config, error) {
	s.domainCalls++
	return appdomains.Config{PortalURL: "https://internal.example.com", AppBaseDomain: "internal.example.com"}, s.err
}
func TestAppProxyDomainsRequiresPrivateAuthority(t *testing.T) {
	for _, tc := range []struct {
		name, body, auth string
		tls              bool
		want             int
	}{
		{"authorized", `{}`, "AppProxy " + appaccess.ProxyTokenPrefix + strings.Repeat("a", 43), true, 200},
		{"missing authentication", `{}`, "", true, 401},
		{"wrong credential class", `{}`, "Bearer human", true, 401},
		{"no TLS", `{}`, "AppProxy " + appaccess.ProxyTokenPrefix + strings.Repeat("a", 43), false, 401},
		{"caller override", `{"portal_url":"https://attacker.example"}`, "AppProxy " + appaccess.ProxyTokenPrefix + strings.Repeat("a", 43), true, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &domainProxyAuthority{}
			r := httptest.NewRequest("POST", "https://authority/internal/app-access/domains", strings.NewReader(tc.body))
			r.TLS = nil
			if tc.tls {
				r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
			}
			r.Header.Set("Authorization", tc.auth)
			w := httptest.NewRecorder()
			NewAppProxyAuthorityHandler(s, nil).ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			if tc.want == 200 {
				var body map[string]string
				if json.Unmarshal(w.Body.Bytes(), &body) != nil || body["portal_url"] != "https://internal.example.com" || body["app_base_domain"] != "internal.example.com" {
					t.Fatal("domain projection changed")
				}
			} else if s.domainCalls != 0 {
				t.Fatal("invalid request reached settings")
			}
		})
	}
}

func (s *denyProxyAuthority) AuthenticateProxy(context.Context, string) (appaccess.AuthenticatedProxy, error) {
	s.authCalls++
	return appaccess.AuthenticatedProxy{CredentialID: uuid.New(), CredentialVersion: 1}, nil
}
func (*denyProxyAuthority) LookupRoute(context.Context, appaccess.AuthenticatedProxy, string, bool) (appaccess.Route, error) {
	return appaccess.Route{}, apierr.New(404, "route_unavailable", "unavailable")
}
func (*denyProxyAuthority) AuthorizeRequest(context.Context, appaccess.AuthenticatedProxy, appaccess.RequestInput, bool) (appaccess.Decision, error) {
	return appaccess.Decision{Allowed: false}, nil
}
func (*denyProxyAuthority) RenewLease(context.Context, appaccess.AuthenticatedProxy, appaccess.LeaseInput, bool) (appaccess.Decision, error) {
	return appaccess.Decision{Allowed: false}, nil
}
func (*denyProxyAuthority) ChannelAuthorize(context.Context, appaccess.AuthenticatedProxy, appaccess.RouteBinding, string, bool) (time.Time, error) {
	return time.Time{}, apierr.Forbidden("browser_authority_unavailable", "unavailable")
}
func TestAppProxyAuthorityAdmission(t *testing.T) {
	token := appaccess.ProxyTokenPrefix + strings.Repeat("a", 43)
	for _, tc := range []struct {
		name, auth string
		version    uint16
		duplicate  bool
	}{
		{"plain", "AppProxy " + token, 0, false}, {"downgrade", "AppProxy " + token, tls.VersionTLS12, false}, {"browser cookie", "", tls.VersionTLS13, false}, {"bearer", "Bearer " + token, tls.VersionTLS13, false}, {"gateway", "", tls.VersionTLS13, false}, {"duplicate", "AppProxy " + token, tls.VersionTLS13, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &denyProxyAuthority{}
			r := httptest.NewRequest("POST", "https://authority/internal/app-access/route-lookup", strings.NewReader(`{"hostname":"unknown.apps.test"}`))
			if tc.version != 0 {
				r.TLS = &tls.ConnectionState{Version: tc.version}
			} else {
				r.TLS = nil
			}
			r.Header.Set("Authorization", tc.auth)
			r.Header.Set("Cookie", "__Host-tunnex-session=human")
			r.Header.Set("X-Forwarded-Proto", "https")
			if tc.duplicate {
				r.Header.Add("Authorization", tc.auth)
			}
			w := httptest.NewRecorder()
			NewAppProxyAuthorityHandler(s, nil).ServeHTTP(w, r)
			if w.Code != 401 || s.authCalls != 0 {
				t.Fatalf("code %d auth calls %d", w.Code, s.authCalls)
			}
			if strings.Contains(w.Body.String(), token) {
				t.Fatal("credential echoed")
			}
		})
	}
}
func TestAppProxyAuthorityClosedPorts(t *testing.T) {
	b := appProxyBindingWire{OrgID: uuid.New(), AppID: uuid.New(), GatewayID: uuid.New(), Generation: uuid.New(), Revision: 1, AuthorityVersion: 1, Digest: strings.Repeat("a", 64), Hostname: "app.apps.test", Purpose: "browser_proxy"}
	binding, _ := json.Marshal(b)
	tests := []struct {
		path, body string
		status     int
	}{
		{"route-lookup", `{"hostname":"unknown.apps.test"}`, 404},
		{"route-lookup", `{"hostname":"app.apps.test","org_id":"forged"}`, 400},
		{"route-lookup", `{"hostname":"app.apps.test"} {}`, 400},
		{"route-lookup", `{"hostname":"` + strings.Repeat("a", 65537) + `"}`, 413},
		{"authorize", `{"binding":` + string(binding) + `,"app_session_token":"opaque","request":{"method":"GET","relative_path":"/","origin":"","referer":""}}`, 403},
		{"leases/renew", `{"binding":` + string(binding) + `,"stream_id":"` + uuid.NewString() + `"}`, 403},
		{"channel-authorize", `{"binding":` + string(binding) + `,"certificate_serial":"abcd"}`, 403},
	}
	for _, tc := range tests {
		t.Run(tc.path+"_"+http.StatusText(tc.status), func(t *testing.T) {
			r := httptest.NewRequest("POST", "https://authority/internal/app-access/"+tc.path, strings.NewReader(tc.body))
			r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
			r.Header.Set("Authorization", "AppProxy "+appaccess.ProxyTokenPrefix+strings.Repeat("a", 43))
			w := httptest.NewRecorder()
			NewAppProxyAuthorityHandler(&denyProxyAuthority{}, func() bool { return true }).ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("got %d %s", w.Code, w.Body.String())
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("missing no-store")
			}
		})
	}
}

type sessionProxyAuthority struct {
	denyProxyAuthority
	decision    appaccess.Decision
	err         error
	pendingHash string
	metadata    appaccess.RequestInput
}

func (s *sessionProxyAuthority) AuthorizeRequest(_ context.Context, _ appaccess.AuthenticatedProxy, in appaccess.RequestInput, _ bool) (appaccess.Decision, error) {
	s.metadata = in
	return s.decision, s.err
}
func (s *sessionProxyAuthority) RenewLease(context.Context, appaccess.AuthenticatedProxy, appaccess.LeaseInput, bool) (appaccess.Decision, error) {
	return s.decision, s.err
}
func (s *sessionProxyAuthority) RedeemApp(context.Context, appaccess.AuthenticatedProxy, string, string, string, bool) (appaccess.RedeemResult, error) {
	return appaccess.RedeemResult{AppSessionToken: "tnxas_" + strings.Repeat("a", 43), RelativeTarget: "/work?view=1", ExpiresAt: time.Now().Add(time.Minute)}, s.err
}
func (s *sessionProxyAuthority) RegisterPendingLaunch(_ context.Context, _ appaccess.AuthenticatedProxy, _ appaccess.RouteBinding, hash, _ string, _ bool) (time.Time, error) {
	s.pendingHash = hash
	return time.Now().Add(9 * time.Minute), s.err
}
func TestAppProxySessionDecisionAndPendingPorts(t *testing.T) {
	b := appProxyBindingWire{OrgID: uuid.New(), AppID: uuid.New(), GatewayID: uuid.New(), Generation: uuid.New(), Revision: 1, AuthorityVersion: 1, Digest: strings.Repeat("a", 64), Hostname: "app.apps.test", Purpose: "browser_proxy"}
	binding, _ := json.Marshal(b)
	call := func(s *sessionProxyAuthority, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest("POST", "https://authority/internal/app-access/"+path, strings.NewReader(body))
		r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
		r.Header.Set("Authorization", "AppProxy "+appaccess.ProxyTokenPrefix+strings.Repeat("a", 43))
		w := httptest.NewRecorder()
		NewAppProxyAuthorityHandler(s, func() bool { return true }).ServeHTTP(w, r)
		return w
	}
	body := `{"binding":` + string(binding) + `,"app_session_token":"opaque","request":{"method":"GET","relative_path":"/","origin":"","referer":"","fetch_mode":"navigate","fetch_dest":"document","fetch_user":"?1"}}`
	for _, tc := range []struct {
		name     string
		stream   uuid.UUID
		duration time.Duration
		allowed  bool
		err      error
		status   int
	}{{"persisted", uuid.New(), 3 * time.Second, true, nil, 200}, {"missing stream", uuid.Nil, 3 * time.Second, true, nil, 403}, {"too long", uuid.New(), 5 * time.Second, true, nil, 403}, {"expired", uuid.New(), -time.Second, true, nil, 403}, {"explicit denial", uuid.New(), 3 * time.Second, false, nil, 403}, {"infra", uuid.Nil, 0, false, apierr.New(503, "app_authority_unavailable", "unavailable"), 503}, {"missing session", uuid.Nil, 0, false, apierr.Forbidden("app_session_invalid", "unavailable"), 403}} {
		t.Run(tc.name, func(t *testing.T) {
			until := time.Now().Add(tc.duration)
			s := &sessionProxyAuthority{decision: appaccess.Decision{StreamID: tc.stream, Allowed: tc.allowed, LeaseUntil: &until}, err: tc.err}
			w := call(s, "authorize", body)
			if w.Code != tc.status {
				t.Fatalf("got%d %s", w.Code, w.Body.String())
			}
			if s.metadata.FetchMode != "navigate" || s.metadata.FetchUser != "?1" {
				t.Fatal("qualified metadata lost")
			}
			if tc.err != nil && tc.name == "missing session" && !strings.Contains(w.Body.String(), "app_session_invalid") {
				t.Fatal("restart sentinel lost")
			}
		})
	}
	s := &sessionProxyAuthority{}
	hash := strings.Repeat("b", 64)
	w := call(s, "pending-launch", `{"binding":`+string(binding)+`,"nonce_hash":"`+hash+`","relative_target":"/work"}`)
	if w.Code != 200 || s.pendingHash != hash {
		t.Fatalf("pending port %d", w.Code)
	}
	w = call(s, "redeem", `{"code":"`+strings.Repeat("a", 43)+`","nonce":"`+strings.Repeat("b", 43)+`","hostname":"app.apps.test"}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "app_session_token") {
		t.Fatalf("redeem %d %s", w.Code, w.Body.String())
	}
}

type channelProxyAuthority struct {
	denyProxyAuthority
	until   time.Time
	err     error
	binding appaccess.RouteBinding
	serial  string
}

func (s *channelProxyAuthority) ChannelAuthorize(_ context.Context, _ appaccess.AuthenticatedProxy, b appaccess.RouteBinding, serial string, _ bool) (time.Time, error) {
	s.binding = b
	s.serial = serial
	return s.until, s.err
}
func TestAppProxyChannelLeasePositiveAndFailClosed(t *testing.T) {
	b := appProxyBindingWire{OrgID: uuid.New(), AppID: uuid.New(), GatewayID: uuid.New(), Generation: uuid.New(), Revision: 1, AuthorityVersion: 1, Digest: strings.Repeat("a", 64), Hostname: "app.apps.test", Purpose: "browser_proxy"}
	raw, _ := json.Marshal(appProxyChannelWire{Binding: b, Serial: "abcd"})
	for _, tc := range []struct {
		name     string
		duration time.Duration
		err      error
		want     int
	}{{"current", 3 * time.Second, nil, 200}, {"expired", -time.Second, nil, 403}, {"oversized", 5 * time.Second, nil, 403}, {"denied", 3 * time.Second, apierr.Forbidden("browser_authority_unavailable", "unavailable"), 403}, {"infrastructure", 0, apierr.New(503, "app_authority_unavailable", "unavailable"), 503}} {
		t.Run(tc.name, func(t *testing.T) {
			s := &channelProxyAuthority{until: time.Now().Add(tc.duration), err: tc.err}
			r := httptest.NewRequest("POST", "https://authority/internal/app-access/channel-authorize", strings.NewReader(string(raw)))
			r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
			r.Header.Set("Authorization", "AppProxy "+appaccess.ProxyTokenPrefix+strings.Repeat("a", 43))
			w := httptest.NewRecorder()
			NewAppProxyAuthorityHandler(s, func() bool { return true }).ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("status %d want %d", w.Code, tc.want)
			}
			if s.binding != b.domain() || s.serial != "abcd" {
				t.Fatal("exact channel tuple lost")
			}
			if tc.want == 200 {
				var lease appProxyExpiryWire
				if json.Unmarshal(w.Body.Bytes(), &lease) != nil || !lease.ExpiresAt.After(time.Now()) || lease.ExpiresAt.After(time.Now().Add(4*time.Second)) {
					t.Fatal("invalid channel lease")
				}
			}
		})
	}
}
