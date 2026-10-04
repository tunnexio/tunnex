package apptransport

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestAppResponseCannotClearPortalCookiesOrRelaxOriginClustering(t *testing.T) {
	origin, err := url.Parse("https://private.internal:8080")
	if err != nil {
		t.Fatal(err)
	}
	for _, clear := range []string{`"cookies"`, `"*"`, `"cache", "storage"`} {
		t.Run(clear, func(t *testing.T) {
			body := io.NopCloser(strings.NewReader("private application"))
			response := &http.Response{Header: http.Header{
				"Clear-Site-Data":         {clear, `"cookies"`},
				"Origin-Agent-Cluster":    {"?0", "?0"},
				"Permissions-Policy":      {"camera=(), microphone=()"},
				"Content-Security-Policy": {"default-src 'self'"},
				"Location":                {"https://private.internal:8080/login"},
				"Set-Cookie":              {"application_session=origin-token; Domain=private.internal; Path=/; HttpOnly"},
			}, Body: body}
			if err := RewriteResponse(response, origin, "test.internal.tunnex.app"); err != nil {
				t.Fatal(err)
			}
			if values := response.Header.Values("Clear-Site-Data"); len(values) != 0 {
				t.Fatalf("app can clear shared-site browser data: %v", values)
			}
			if values := response.Header.Values("Origin-Agent-Cluster"); len(values) != 1 || values[0] != "?1" {
				t.Fatalf("app can override origin clustering: %v", values)
			}
			if response.Header.Get("Permissions-Policy") != "camera=(), microphone=()" || response.Header.Get("Content-Security-Policy") != "default-src 'self'" || response.Body != body {
				t.Fatal("unrelated app policy or body changed")
			}
			if response.Header.Get("Location") != "https://test.internal.tunnex.app/login" {
				t.Fatal("application redirect did not remain on its published host")
			}
			cookies := response.Cookies()
			if len(cookies) != 1 || cookies[0].Domain != "" || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].Value != "origin-token" {
				t.Fatalf("application cookie policy changed: %v", cookies)
			}
		})
	}
}

func TestApplicationAuthPreserved(t *testing.T) {
	h := http.Header{"Authorization": {"Bearer application-secret"}, "X-Auth-Token": {"application-token"}, "X-App-Csrf": {"csrf"}, "X-App-Id": {"forged"}, "X-Tunnex-User": {"forged"}, "X-Auth-User": {"forged"}, "X-Forwarded-For": {"spoof"}, "Cookie": {"ordinary=value; __Host-tunnex_app_session=secret; tunnex_session=control"}}
	StripCredentials(h)
	for _, k := range []string{"Authorization", "X-Auth-Token", "X-App-Csrf"} {
		if h.Get(k) == "" {
			t.Fatal(k)
		}
	}
	for _, k := range []string{"X-App-Id", "X-Tunnex-User", "X-Auth-User", "X-Forwarded-For"} {
		if h.Get(k) != "" {
			t.Fatal(k)
		}
	}
	if h.Get("Cookie") != "ordinary=value" {
		t.Fatal(h)
	}
}
func TestDuplicateSessionCookie(t *testing.T) {
	r := &http.Request{Header: http.Header{"Cookie": {"__Host-tunnex_app_session=a; __Host-tunnex_app_session=b"}}}
	if _, e := AppToken(r); e == nil {
		t.Fatal("accepted")
	}
}
func TestHostAndRelativeRefusal(t *testing.T) {
	for _, h := range []string{"apps.test", "app.apps.test:443", "app.apps.test.", "app.evil.test", "a..apps.test", "127.0.0.1"} {
		if _, e := ExactHost(h, "apps.test"); e == nil {
			t.Fatal(h)
		}
	}
	for _, raw := range []string{"//evil.test/path", `/\evil.test/path`, "///evil.test/path", "/%2f/evil", "/%2Fevil.test/path", "/%5cpath", "/%5Cevil.test/path", "/%2f%5cevil.test/path", "/%09/evil.test/path", "/%00path", "https://evil.test/path"} {
		u, _ := url.Parse(raw)
		if _, e := RelativeTarget(u); e == nil {
			t.Fatal(raw)
		}
	}
}

func TestPurposePoolsRemainSeparate(t *testing.T) {
	browser := NewBrowserBroker(nil)
	check := NewBroker(nil)
	defer browser.Close()
	defer check.Close()
	for _, tc := range []struct {
		broker        *Broker
		path, purpose string
	}{{browser, "/app-access/channel", "origin_check"}, {browser, "/agent/app-access/channel", "browser_proxy"}, {check, "/agent/app-access/channel", "browser_proxy"}, {check, "/app-access/channel", "origin_check"}} {
		request := &http.Request{Method: "CONNECT", URL: &url.URL{Path: tc.path}, ProtoMajor: 1}
		writer := httptest.NewRecorder()
		if tc.broker.Accept(writer, request, Binding{Purpose: tc.purpose}, "verified-serial") == nil || writer.Code != 403 {
			t.Fatal("cross-purpose channel admitted", writer.Code)
		}
	}
}
