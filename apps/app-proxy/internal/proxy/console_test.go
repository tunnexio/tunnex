package proxy

import (
	"net/http/httptest"
	"testing"
)

func TestProxyGeneratedResponsesKeepOriginKeying(t *testing.T) {
	for _, write := range []struct {
		name  string
		write func(*httptest.ResponseRecorder)
	}{
		{"denial", func(w *httptest.ResponseRecorder) { deny(w) }},
		{"launch", func(w *httptest.ResponseRecorder) { redirectHeaders(w) }},
	} {
		t.Run(write.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			write.write(w)
			if w.Header().Get("Origin-Agent-Cluster") != "?1" {
				t.Fatal("generated response can initialize a different origin-clustering policy")
			}
		})
	}
}

func TestTrustedConsoleIndependentDomain(t *testing.T) {
	for _, raw := range []string{"http://console.example.com", "https://console.example.net", "https://console.example.com/path", "https://user@console.example.com", "https://console.example.com?", "https://console.example.com#", "https://localhost", "https://console.unknown", "https://console.example.com:", "https://[console.example.com]", "https://console.example.com:0", "https://console.example.com:65536"} {
		if _, e := ConsoleURL(raw, "apps.example.net"); e == nil {
			t.Fatal(raw)
		}
	}
	for _, raw := range []string{"https://console.example.com", "https://console.example.com/", "https://console.example.com:8443"} {
		u, e := ConsoleURL(raw, "apps.example.net")
		if e != nil || u.Path != "" {
			t.Fatal(raw, u, e)
		}
	}
}

func TestTrustedHTTPSIPConsoleStillRequiresDNSApplications(t *testing.T) {
	for _, raw := range []string{"https://16.192.177.77", "https://16.192.177.77:9443", "https://127.0.0.1", "https://[2001:db8::1]", "https://[2001:db8::1]:9443"} {
		if u, err := ConsoleURL(raw, "apps.example.net"); err != nil || u.String() != raw {
			t.Fatalf("configured HTTPS IP portal %q: %v, %v", raw, u, err)
		}
	}
	for _, raw := range []string{"http://16.192.177.77", "https://16.192.177.77/path", "https://16.192.177.77:", "https://16.192.177.77:0443", "https://[fe80::1%25eth0]", "https://[2001:db8::1]:0"} {
		if _, err := ConsoleURL(raw, "apps.example.net"); err == nil {
			t.Fatalf("invalid IP portal accepted: %q", raw)
		}
	}
	for _, base := range []string{"16.192.177.77", "[2001:db8::1]", "localhost", "*.example.net", "apps.example.net:443"} {
		if _, err := ConsoleURL("https://16.192.177.77", base); err == nil {
			t.Fatalf("invalid application base accepted: %q", base)
		}
	}
}

func TestTrustedConsoleParentDomain(t *testing.T) {
	for _, raw := range []string{"https://internal.tunnex.app", "https://internal.tunnex.app/", "https://internal.tunnex.app:9443"} {
		u, err := ConsoleURL(raw, "internal.tunnex.app")
		if err != nil || u.Path != "" || u.Hostname() != "internal.tunnex.app" {
			t.Fatalf("parent portal %q: %v, %v", raw, u, err)
		}
	}
	for _, tc := range []struct{ console, base string }{
		{"https://console.tunnex.app", "internal.tunnex.app"},
		{"https://test.internal.tunnex.app", "internal.tunnex.app"},
		{"https://tunnex.app", "internal.tunnex.app"},
		{"https://internal.tunnex.app", "tunnex.app"},
		{"http://internal.tunnex.app", "internal.tunnex.app"},
		{"https://Internal.tunnex.app", "internal.tunnex.app"},
		{"https://internal.tunnex.app.", "internal.tunnex.app"},
		{"https://internal.tunnex.app/path", "internal.tunnex.app"},
		{"https://internal.tunnex.app?next=evil", "internal.tunnex.app"},
		{"https://internal.tunnex.app#", "internal.tunnex.app"},
		{"https://user@internal.tunnex.app", "internal.tunnex.app"},
		{"https://internal.tunnex.app:", "internal.tunnex.app"},
		{"https://internal.tunnex.app:0", "internal.tunnex.app"},
		{"https://internal.tunnex.app:65536", "internal.tunnex.app"},
		{"https://127.0.0.1", "127.0.0.1"},
		{"https://[::1]", "::1"},
		{"https://localhost", "localhost"},
		{"https://internal.unknown", "internal.unknown"},
		{"https://co.uk", "co.uk"},
	} {
		if _, err := ConsoleURL(tc.console, tc.base); err == nil {
			t.Errorf("accepted invalid parent boundary: %q, %q", tc.console, tc.base)
		}
	}
}
