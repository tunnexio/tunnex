package http

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/publicurl"
	"github.com/tunnexio/tunnex/apps/api/internal/session"
	"github.com/tunnexio/tunnex/apps/api/internal/sso"
)

type portalLandingSSOStub struct {
	ssoPort
	result sso.LoginResult
	err    error
}

func (s portalLandingSSOStub) StartLoginWithReturn(context.Context, string, string, string) (string, error) {
	panic("not used in callback test")
}

func (s portalLandingSSOStub) HandleCallbackWithAuthority(context.Context, string, string, string) (sso.LoginResult, error) {
	return s.result, s.err
}

// Changing the configured domain during the IdP round trip must not send the
// completed login to a host that cannot receive its host-only session cookie.
func TestSSOCallbackLandingUsesVerifiedFlowPortal(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	sessions := session.NewWithClient(rdb, time.Hour, 8*time.Hour)
	const original = "https://old.example.test"
	const current = "https://new.example.test"
	const next = "/app-access/launch?target=%2Fwork"
	actor := uuid.New()
	for _, kind := range []string{"provider", "connection"} {
		for _, pinned := range []string{original, ""} {
			for _, rejected := range []bool{false, true} {
				t.Run(kind+"/pinned="+pinned+"/rejected="+map[bool]string{false: "false", true: "true"}[rejected], func(t *testing.T) {
					portal := pinned
					if portal == "" {
						portal = current // Legacy flows and test adapters.
					}
					ctx := publicurl.With(requestTransportTestContext(true), current)
					var callbackErr error
					if rejected {
						callbackErr = apierr.BadRequest("sso_verification_failed", "private detail")
					}
					server := apiServer{sessions: sessions, appBaseURL: "https://environment.example.test"}
					w := httptest.NewRecorder()
					if kind == "provider" {
						server.sso = portalLandingSSOStub{result: sso.LoginResult{UserID: actor, AppAuthEpoch: 7, Next: next, PortalURL: pinned}, err: callbackErr}
						response, err := server.SsoCallback(ctx, api.SsoCallbackRequestObject{Provider: "google"})
						if err != nil {
							t.Fatal(err)
						}
						if err = response.VisitSsoCallbackResponse(w); err != nil {
							t.Fatal(err)
						}
					} else {
						response, err := server.completeSSOConnectionResponse(ctx, sso.ConnectionResult{UserID: actor, AppAuthEpoch: 7, Next: next, PortalURL: pinned}, callbackErr)
						if err != nil {
							t.Fatal(err)
						}
						if err = response.VisitSsoConnectionCallbackResponse(w); err != nil {
							t.Fatal(err)
						}
					}
					if publicurl.From(ctx, "") != current {
						t.Fatal("callback replaced the request context's current configuration")
					}
					location, err := url.Parse(w.Header().Get("Location"))
					if err != nil || w.Code != http.StatusFound || location.Scheme+"://"+location.Host != portal {
						t.Fatalf("callback left its trusted portal: %d %s", w.Code, w.Header().Get("Location"))
					}
					var loginCookie *http.Cookie
					for _, cookie := range w.Result().Cookies() {
						if cookie.Name == "__Host-tunnex_session" {
							loginCookie = cookie
						}
					}
					if rejected {
						if loginCookie != nil || location.Path != "/login" || location.Query().Get("next") != next || strings.Contains(location.String(), "private detail") {
							t.Fatal("failed callback lost safe return or minted a session")
						}
						return
					}
					if location.String() != portal+next || loginCookie == nil || !loginCookie.Secure || !loginCookie.HttpOnly || loginCookie.Domain != "" || loginCookie.Path != "/" {
						t.Fatal("successful callback did not preserve host-only cookie and landing")
					}
					stored, _, err := sessions.GetNoTouch(ctx, loginCookie.Value)
					if err != nil || stored.UserID != actor || stored.AppAuthEpoch != 7 {
						t.Fatal("callback did not retain verified session authority")
					}
					jar, _ := cookiejar.New(nil)
					callback, _ := url.Parse(portal + "/api/v1/auth/callback")
					jar.SetCookies(callback, []*http.Cookie{loginCookie})
					if len(jar.Cookies(location)) != 1 {
						t.Fatal("browser cannot send callback session to final landing")
					}
					if pinned != "" {
						newPortal, _ := url.Parse(current)
						if len(jar.Cookies(newPortal)) != 0 {
							t.Fatal("session cookie leaked to the replacement portal")
						}
					}
				})
			}
		}
	}
}

func TestSSOConnectionSettingsLandingUsesVerifiedFlowPortal(t *testing.T) {
	for _, link := range []bool{false, true} {
		ctx := publicurl.With(requestTransportTestContext(true), "https://new.example.test")
		server := apiServer{appBaseURL: "https://environment.example.test"}
		response, err := server.completeSSOConnectionResponse(ctx, sso.ConnectionResult{Test: !link, Link: link, PortalURL: "https://old.example.test"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		if err = response.VisitSsoConnectionCallbackResponse(w); err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(w.Header().Get("Location"), "https://old.example.test/settings?") {
			t.Fatal("admin callback lost its existing host-bound session")
		}
	}
}

// The callback transports verified proof without converting an old IdP
// authentication event into a fresh verification at Tunnex session creation.
func TestSSOCallbacksPreserveMFAAuthority(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	sessions := session.NewWithClient(rdb, time.Hour, 8*time.Hour)
	actor := uuid.New()
	for _, kind := range []string{"provider", "connection"} {
		for _, tc := range []struct {
			name     string
			verified time.Time
		}{
			{"missing", time.Time{}},
			{"fresh", time.Now().Add(-time.Minute).Truncate(time.Second)},
			{"stale", time.Now().Add(-time.Hour).Truncate(time.Second)},
		} {
			t.Run(kind+"/"+tc.name, func(t *testing.T) {
				ctx := publicurl.With(requestTransportTestContext(true), "https://portal.example.test")
				server := apiServer{sessions: sessions, appBaseURL: "https://portal.example.test"}
				w := httptest.NewRecorder()
				if kind == "provider" {
					server.sso = portalLandingSSOStub{result: sso.LoginResult{UserID: actor, AppAuthEpoch: 7, MFAVerifiedAt: tc.verified}}
					result, err := server.SsoCallback(ctx, api.SsoCallbackRequestObject{Provider: "google"})
					if err != nil {
						t.Fatal(err)
					}
					if err = result.VisitSsoCallbackResponse(w); err != nil {
						t.Fatal(err)
					}
				} else {
					result, err := server.completeSSOConnectionResponse(ctx, sso.ConnectionResult{UserID: actor, AppAuthEpoch: 7, MFAVerifiedAt: tc.verified}, nil)
					if err != nil {
						t.Fatal(err)
					}
					if err = result.VisitSsoConnectionCallbackResponse(w); err != nil {
						t.Fatal(err)
					}
				}
				var cookie *http.Cookie
				for _, c := range w.Result().Cookies() {
					if c.Name == "__Host-tunnex_session" {
						cookie = c
					}
				}
				if cookie == nil {
					t.Fatal("callback did not create expected parent")
				}
				parent, _, err := sessions.GetNoTouch(ctx, cookie.Value)
				if err != nil {
					t.Fatal(err)
				}
				if parent.AppAuthEpoch != 7 || parent.AuthMethod != "sso" || !parent.MFAVerifiedAt.Equal(tc.verified) {
					t.Fatal("callback changed verified MFA authority")
				}
				expected := ""
				if !tc.verified.IsZero() {
					expected = "sso_mfa"
				}
				if parent.MFAAssuranceSource != expected {
					t.Fatal("callback promoted unproven MFA")
				}
			})
		}
	}
}
