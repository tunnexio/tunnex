package aivpn

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const peer = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func TestPeerKeyRefusals(t *testing.T) {
	for _, tc := range []struct {
		name, table, source string
		ok                  bool
	}{
		{"individual", peer + "\t10.99.0.2/32", "10.99.0.2", true},
		{"unknown", peer + "\t10.99.0.2/32", "10.99.0.3", false},
		{"site", peer + "\t10.99.0.0/24", "10.99.0.2", false},
		{"routed", peer + "\t10.99.0.2/32,10.20.0.0/16", "10.99.0.2", false},
		{"ambiguous", peer + "\t10.99.0.2/32\n" + peer + "\t10.99.0.2/32", "10.99.0.2", false},
		{"bad-key", "invalid\t10.99.0.2/32", "10.99.0.2", false},
		{"mapped-ipv6", peer + "\t10.99.0.2/32", "::ffff:10.99.0.2", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, err := PeerKey(tc.table, tc.source)
			if (err == nil) != tc.ok || (tc.ok && key != peer) {
				t.Fatalf("key=%q err=%v", key, err)
			}
		})
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestRelayStripsForgedIdentity(t *testing.T) {
	target, _ := url.Parse("https://control:8443")
	calls := 0
	tr := roundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Path != "/agent/ai/organizations/org/v1/chat/completions" {
			t.Fatal(r.URL.Path)
		}
		if r.Header.Get("X-Tunnex-VPN-IP") != "10.99.0.2" || r.Header.Get("X-Tunnex-VPN-Key") != peer {
			t.Fatal("wrong evidence")
		}
		for _, h := range []string{"Authorization", "Cookie", "Forwarded", "X-Forwarded-For", "X-Api-Key", "X-Tunnex-User"} {
			if r.Header.Get(h) != "" {
				t.Fatalf("header escaped: %s", h)
			}
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"ok":true}`))}, nil
	})
	web := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "ordinary web", 418) })
	handler := Handler("internal.test", target, tr, func(context.Context) (string, error) { return peer + "\t10.99.0.2/32", nil }, web)
	for _, src := range []string{"10.99.0.2:1234", "203.0.113.1:1234"} {
		req := httptest.NewRequest("POST", "https://internal.test/api/v1/organizations/org/ai-gateway/inference/v1/chat/completions", strings.NewReader(`{}`))
		req.RemoteAddr = src
		for _, h := range []string{"Authorization", "Cookie", "Forwarded", "X-Forwarded-For", "X-Api-Key", "X-Tunnex-User", "X-Tunnex-VPN-IP", "X-Tunnex-VPN-Key"} {
			req.Header.Set(h, "forged")
		}
		req.Header.Set("Content-Type", "application/json")
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		want := 200
		if strings.HasPrefix(src, "203.") {
			want = 401
		}
		if res.Code != want {
			t.Fatalf("status=%d want=%d", res.Code, want)
		}
	}
	if calls != 1 {
		t.Fatalf("upstream calls=%d", calls)
	}
	req := httptest.NewRequest("GET", "https://internal.test/", nil)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != 418 {
		t.Fatal("web path changed")
	}
}
