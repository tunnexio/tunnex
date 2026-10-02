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

func TestAliasUsesVerifiedPeerAndDedicatedControlRoute(t *testing.T) {
	target, _ := url.Parse("https://control:8443")
	calls := 0
	tr := roundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Path != "/agent/ai/v1/chat/completions" || r.Header.Get("Authorization") != "" || r.Header.Get("X-Tunnex-VPN-Key") != peer {
			t.Fatal("alias lost its trusted routing boundary")
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	})
	h := Handler("internal.test", target, tr, func(context.Context) (string, error) { return peer + "\t10.99.0.2/32", nil }, http.NotFoundHandler())
	for _, source := range []string{"10.99.0.2:1234", "203.0.113.1:1234"} {
		r := httptest.NewRequest("POST", "https://internal.test/ai/v1/chat/completions", strings.NewReader(`{}`))
		r.RemoteAddr = source
		r.Header.Set("Authorization", "Bearer unused")
		r.Header.Set("X-Tunnex-VPN-Key", "forged")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if source == "10.99.0.2:1234" && w.Code != 200 || source != "10.99.0.2:1234" && w.Code != 401 {
			t.Fatalf("source %s status %d", source, w.Code)
		}
	}
	if calls != 1 {
		t.Fatalf("upstream calls %d", calls)
	}
}

func TestPeerKeyAcceptsOneDualStackDeviceButNeverRoutes(t *testing.T) {
	for _, tc := range []struct {
		name, allowed string
		ok            bool
	}{
		{"dual stack", "10.99.0.2/32,fd99::2/128", true},
		{"dual stack spaced", "fd99::2/128, 10.99.0.2/32", true},
		{"native WireGuard whitespace", "10.99.0.2/32 fd99::2/128", true},
		{"native routed peer", "10.99.0.2/32 fd99::/64", false},
		{"IPv6 subnet", "10.99.0.2/32,fd99::/64", false},
		{"second IPv4", "10.99.0.2/32,10.99.0.3/32", false},
		{"duplicate IPv4", "10.99.0.2/32,10.99.0.2/32", false},
		{"second IPv6", "10.99.0.2/32,fd99::2/128,fd99::3/128", false},
		{"mapped IPv6", "10.99.0.2/32,::ffff:10.99.0.2/128", false},
		{"malformed extra route", "10.99.0.2/32,invalid", false},
		{"trailing delimiter", "10.99.0.2/32,", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, err := PeerKey(peer+"\t"+tc.allowed, "10.99.0.2")
			if (err == nil) != tc.ok || (tc.ok && key != peer) {
				t.Fatalf("key=%q err=%v", key, err)
			}
		})
	}
}

func TestHTTPRelayUsesOnlyCurrentKernelIdentityAndDedicatedRoute(t *testing.T) {
	target, _ := url.Parse("https://control.test:8443")
	readback := peer + "\t10.99.0.2/32,fd99::2/128"
	calls := 0
	tr := roundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Scheme != "https" || r.URL.Host != "control.test:8443" || r.Host != "control.test:8443" {
			t.Fatal("request escaped authenticated control target")
		}
		if r.URL.Path != "/agent/ai-http/v1/chat/completions" && r.URL.Path != "/agent/ai-http/organizations/org/v1/chat/completions" {
			t.Fatal("request lost the fixed HTTP transport route")
		}
		if r.Header.Get("X-Tunnex-VPN-IP") != "10.99.0.2" || r.Header.Get("X-Tunnex-VPN-Key") != peer {
			t.Fatal("forged identity escaped")
		}
		for _, h := range []string{"Authorization", "Cookie", "Forwarded", "X-Forwarded-For", "X-Forwarded-Proto", "X-Tunnex-VPN-Transport", "X-Tunnex-VPN-Scheme", "X-Tunnex-User", "X-Api-Key"} {
			if r.Header.Get(h) != "" {
				t.Fatalf("untrusted header escaped: %s", h)
			}
		}
		// A policy refusal from the CP must pass through, without local bypass.
		return &http.Response{StatusCode: 403, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"error":"http_disabled"}`))}, nil
	})
	h := HTTPHandler("10.99.0.1", target, tr, func(context.Context) (string, error) { return readback, nil })
	for _, path := range []string{"/ai/v1/chat/completions", "/api/v1/organizations/org/ai-gateway/inference/v1/chat/completions"} {
		r := httptest.NewRequest("POST", "http://10.99.0.1:8083"+path, strings.NewReader(`{}`))
		r.RemoteAddr = "10.99.0.2:1234"
		for _, header := range []string{"Authorization", "Cookie", "Forwarded", "X-Forwarded-For", "X-Forwarded-Proto", "X-Tunnex-VPN-IP", "X-Tunnex-VPN-Key", "X-Tunnex-VPN-Transport", "X-Tunnex-VPN-Scheme", "X-Tunnex-User", "X-Api-Key"} {
			r.Header.Set(header, "forged")
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatalf("control-plane refusal was bypassed: %d", w.Code)
		}
	}
	readback = "" // revoked peer; the next request must read the kernel again.
	r := httptest.NewRequest("POST", "http://10.99.0.1:8083/ai/v1/chat/completions", strings.NewReader(`{}`))
	r.RemoteAddr = "10.99.0.2:1234"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 || calls != 2 {
		t.Fatalf("revoked peer reached upstream: status=%d calls=%d", w.Code, calls)
	}
}

func TestHTTPRelayHasNoWebPublicIdentityOrOperationFallback(t *testing.T) {
	target, _ := url.Parse("https://control.test:8443")
	tr := roundTrip(func(*http.Request) (*http.Response, error) {
		t.Fatal("denied request reached control plane")
		return nil, nil
	})
	h := HTTPHandler("10.99.0.1", target, tr, func(context.Context) (string, error) { return peer + "\t10.99.0.2/32", nil })
	for _, tc := range []struct {
		method, path, host, source string
		want                       int
	}{
		{"GET", "/", "10.99.0.1:8083", "10.99.0.2:1234", 404},
		{"GET", "/api/v1/auth/me", "10.99.0.1:8083", "10.99.0.2:1234", 404},
		{"POST", "/ai/v1/embeddings", "10.99.0.1:8083", "10.99.0.2:1234", 404},
		{"GET", "/ai/v1/chat/completions", "10.99.0.1:8083", "10.99.0.2:1234", 400},
		{"POST", "/ai/v1/chat/completions?override=https", "10.99.0.1:8083", "10.99.0.2:1234", 400},
		{"POST", "/ai/v1/chat/completions", "public.example:8083", "10.99.0.2:1234", 421},
		{"POST", "/ai/v1/chat/completions", "10.99.0.1:8083", "203.0.113.5:1234", 401},
		{"POST", "/ai/v1/chat/completions", "10.99.0.1:8083", "malformed", 401},
	} {
		t.Run(tc.path+tc.host+tc.source+tc.method, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, "http://"+tc.host+tc.path, nil)
			r.RemoteAddr = tc.source
			r.Header.Set("X-Tunnex-VPN-IP", "10.99.0.2")
			r.Header.Set("X-Tunnex-VPN-Key", peer)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("status=%d want=%d", w.Code, tc.want)
			}
		})
	}
}
