package http

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/tunnexio/tunnex/apps/api/internal/aigateway"
)

const testStaticKey = "tnx_sk_0123456789abcdefghijABCDEFGHIJ0123456789abcdeXXXXXX"

func TestStaticCredentialHeaders(t *testing.T) {
	cases := []struct {
		name          string
		path          string
		auth, apiKeys []string
		claimed, ok   bool
	}{
		{"bearer", "/ai/v1/chat/completions", []string{"Bearer " + testStaticKey}, nil, true, true},
		{"not static", "/ai/v1/chat/completions", []string{"Bearer tnx_wai_abc"}, nil, false, false},
		{"workload token with unrelated api key", "/ai/v1/chat/completions", []string{"Bearer tnx_wai_abc"}, []string{"other"}, false, false},
		{"two authorization headers", "/ai/v1/chat/completions", []string{"Bearer " + testStaticKey, "Bearer x"}, nil, true, false},
		{"bearer plus api key", "/ai/anthropic/v1/messages", []string{"Bearer " + testStaticKey}, []string{testStaticKey}, true, false},
		{"api key on messages", "/ai/anthropic/v1/messages", nil, []string{testStaticKey}, true, true},
		{"api key elsewhere", "/ai/v1/chat/completions", nil, []string{testStaticKey}, true, false},
		{"api key plus workload bearer", "/ai/anthropic/v1/messages", []string{"Bearer tnx_wai_abc"}, []string{testStaticKey}, true, false},
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodPost, c.path, nil)
		for _, v := range c.auth {
			r.Header.Add("Authorization", v)
		}
		for _, v := range c.apiKeys {
			r.Header.Add("X-Api-Key", v)
		}
		raw, claimed, ok := staticCredential(r, "/ai/anthropic/v1/messages")
		if claimed != c.claimed || ok != c.ok || (ok && raw != testStaticKey) {
			t.Errorf("%s: claimed=%v ok=%v raw=%q", c.name, claimed, ok, raw)
		}
	}
}

func staticKeyRequest(path string, secure *bool) *http.Request {
	r := httptest.NewRequest(http.MethodPost, path, nil)
	r.Header.Set("Authorization", "Bearer "+testStaticKey)
	if secure != nil {
		r = r.WithContext(context.WithValue(r.Context(), requestTransportKey{}, requestTransportState{secure: *secure}))
	}
	return r
}

func TestStaticKeyMiddlewareRefusesBeforeLookup(t *testing.T) {
	adapter, err := aigateway.NewAdapter("http://127.0.0.1:1", func(context.Context, string, string) (aigateway.Grant, error) {
		t.Fatal("default closure must not be reached")
		return aigateway.Grant{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	keys := aigateway.NewStaticKeys(nil, nil)
	reached := false
	h := staticKeyMiddleware(keys, adapter)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
	yes, no := true, false
	for _, c := range []struct {
		name   string
		r      *http.Request
		status int
	}{
		{"plain http refused whatever Allow HTTP says", staticKeyRequest("/ai/v1/chat/completions", &no), 403},
		{"unknown transport refused", staticKeyRequest("/ai/v1/chat/completions", nil), 403},
		{"videos not served", staticKeyRequest("/ai/v1/videos", &yes), 404},
		{"models over http refused", staticKeyRequest("/ai/v1/models", &no), 403},
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, c.r)
		if w.Code != c.status || reached {
			t.Errorf("%s: status=%d reached=%v", c.name, w.Code, reached)
		}
	}
	// Static keys on HTTPS reach the static key service, never the next handler.
	w := httptest.NewRecorder()
	h.ServeHTTP(w, staticKeyRequest("/ai/v1/chat/completions", &yes))
	if reached || w.Code == http.StatusOK {
		t.Fatalf("static key passed through: %d", w.Code)
	}
	// Other credentials are untouched.
	r := httptest.NewRequest(http.MethodPost, "/ai/v1/chat/completions", nil)
	r.Header.Set("Authorization", "Bearer tnx_wai_abc")
	h.ServeHTTP(httptest.NewRecorder(), r)
	if !reached {
		t.Fatal("non-static request did not pass through")
	}
}

func TestRequestClientAddrUsesTrustedChainOnly(t *testing.T) {
	capture := func(peers []string, remote string, tlsOn bool, headers map[string][]string) (netip.Addr, bool) {
		transport, err := newRequestTransport(peers)
		if err != nil {
			t.Fatal(err)
		}
		var got netip.Addr
		var ok bool
		h := transport.middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			got, ok = requestClientAddr(r.Context())
		}))
		r := httptest.NewRequest(http.MethodGet, "/ai/v1/models", nil)
		r.RemoteAddr = remote
		if tlsOn {
			r.TLS = &tls.ConnectionState{}
		}
		for k, values := range headers {
			for _, v := range values {
				r.Header.Add(k, v)
			}
		}
		h.ServeHTTP(httptest.NewRecorder(), r)
		return got, ok
	}
	proto := []string{"https"}
	if got, ok := capture([]string{"10.0.0.1"}, "10.0.0.1:443", false, map[string][]string{"X-Real-Ip": {"8.8.8.8"}, "X-Forwarded-Proto": proto}); !ok || got.String() != "8.8.8.8" {
		t.Fatalf("trusted proxy X-Real-IP: %v %v", got, ok)
	}
	if _, ok := capture([]string{"10.0.0.1"}, "10.0.0.1:443", false, map[string][]string{"X-Real-Ip": {"8.8.8.8", "1.1.1.1"}, "X-Forwarded-Proto": proto}); ok {
		t.Fatal("two X-Real-IP values accepted")
	}
	if _, ok := capture([]string{"10.0.0.1"}, "10.0.0.1:443", false, map[string][]string{"X-Real-Ip": {"not-an-ip"}, "X-Forwarded-Proto": proto}); ok {
		t.Fatal("invalid X-Real-IP accepted")
	}
	if _, ok := capture([]string{"10.0.0.1"}, "203.0.113.9:443", true, map[string][]string{"X-Real-Ip": {"8.8.8.8"}, "X-Forwarded-For": {"8.8.8.8"}}); ok {
		t.Fatal("spoofed X-Real-IP from an untrusted peer accepted")
	}
	if got, ok := capture(nil, "198.51.100.4:5000", true, map[string][]string{"X-Real-Ip": {"8.8.8.8"}, "X-Forwarded-For": {"8.8.8.8"}}); !ok || got.String() != "198.51.100.4" {
		t.Fatalf("no trusted proxy must record the raw peer: %v %v", got, ok)
	}
}
