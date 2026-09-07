package ai0

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func fixture(_ context.Context, token, model string) (Grant, error) {
	if token != "fixture-agent-a" || model != "openrouter/allowed" {
		return Grant{}, errors.New("denied")
	}
	return Grant{Tenant: "tenant-a", Agent: "agent-a", VirtualKey: "fixture-internal-a", Expires: time.Now().Add(time.Minute)}, nil
}

func TestDeniedRequestsNeverArrive(t *testing.T) {
	var arrivals atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { arrivals.Add(1) }))
	defer up.Close()
	a, err := NewAdapter(up.URL, fixture)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, path, token, body string
		status                  int
	}{
		{"missing identity", "/v1/chat/completions", "", `{"model":"openrouter/allowed"}`, 401},
		{"other tenant", "/v1/chat/completions", "fixture-agent-b", `{"model":"openrouter/allowed"}`, 403},
		{"denied model", "/v1/chat/completions", "fixture-agent-a", `{"model":"openrouter/denied"}`, 403},
		{"admin", "/api/virtual-keys", "fixture-agent-a", `{}`, 404},
		{"query injection", "/v1/chat/completions?api_key=evil", "fixture-agent-a", `{"model":"openrouter/allowed"}`, 400},
		{"duplicate model", "/v1/chat/completions", "fixture-agent-a", `{"model":"openrouter/allowed","model":"openrouter/denied"}`, 400},
		{"invalid json", "/v1/chat/completions", "fixture-agent-a", `{`, 400},
		{"oversized", "/v1/chat/completions", "fixture-agent-a", strings.Repeat("x", MaxBodyBytes+1), 413},
		{"provider override", "/v1/chat/completions", "fixture-agent-a", `{"model":"openrouter/allowed","fallbacks":["openrouter/denied"]}`, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", tc.path, strings.NewReader(tc.body))
			if tc.token != "" {
				r.Header.Set("Authorization", "Bearer "+tc.token)
			}
			w := httptest.NewRecorder()
			a.ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("status %d, want %d", w.Code, tc.status)
			}
		})
	}
	if arrivals.Load() != 0 {
		t.Fatalf("denied requests arrived: %d", arrivals.Load())
	}
}

func TestTrustedHeadersAndSSE(t *testing.T) {
	for _, path := range []string{"/v1/chat/completions", "/anthropic/v1/messages"} {
		t.Run(path, func(t *testing.T) {
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != path {
					t.Errorf("path %q", r.URL.Path)
				}
				if r.Header.Get("X-Bf-Vk") != "fixture-internal-a" {
					t.Error("missing scoped virtual key")
				}
				for _, h := range []string{"Authorization", "Cookie", "X-Api-Key", "X-Goog-Api-Key", "X-Tunnex-Tenant", "X-Bf-Provider", "X-Bf-Api-Key", "Forwarded", "X-Forwarded-For"} {
					if r.Header.Get(h) != "" {
						t.Errorf("forwarded untrusted %s", h)
					}
				}
				w.Header().Set("Content-Type", "text/event-stream")
				w.Header().Set("Set-Cookie", "secret=must-not-leak")
				w.Header().Set("X-Bf-Vk", "must-not-leak")
				io.WriteString(w, "data: first\n\n")
				w.(http.Flusher).Flush()
				io.WriteString(w, "data: [DONE]\n\n")
			}))
			defer up.Close()
			a, err := NewAdapter(up.URL, fixture)
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest("POST", path, strings.NewReader(`{"model":"openrouter/allowed","messages":[],"stream":true}`))
			r.Header.Set("Authorization", "Bearer fixture-agent-a")
			for _, h := range []string{"Cookie", "X-Api-Key", "X-Goog-Api-Key", "X-Tunnex-Tenant", "X-Bf-Vk", "X-Bf-Provider", "X-Bf-Api-Key", "Forwarded", "X-Forwarded-For"} {
				r.Header.Set(h, "evil")
			}
			w := httptest.NewRecorder()
			a.ServeHTTP(w, r)
			if w.Code != 200 || !strings.Contains(w.Body.String(), "[DONE]") || !w.Flushed {
				t.Fatalf("stream failed: %d %q", w.Code, w.Body.String())
			}
			if w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-Bf-Vk") != "" {
				t.Fatal("upstream auth metadata leaked")
			}
		})
	}
}

func TestInvalidGrantNeverArrives(t *testing.T) {
	var arrivals atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { arrivals.Add(1) }))
	defer up.Close()
	for _, g := range []Grant{{}, {Tenant: "a", Agent: "b", VirtualKey: "key", Expires: time.Now().Add(-time.Second)}, {Tenant: "a", Agent: "b", VirtualKey: "\r\nkey", Expires: time.Now().Add(time.Minute)}} {
		a, _ := NewAdapter(up.URL, func(context.Context, string, string) (Grant, error) { return g, nil })
		r := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"model":"openrouter/allowed"}`))
		r.Header.Set("Authorization", "Bearer fixture-agent-a")
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatalf("status %d", w.Code)
		}
	}
	if arrivals.Load() != 0 {
		t.Fatal("invalid grant reached upstream")
	}
}

func TestRedirectIsNotFollowed(t *testing.T) {
	var arrivals atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { arrivals.Add(1) }))
	defer target.Close()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 307) }))
	defer up.Close()
	a, _ := NewAdapter(up.URL, fixture)
	r := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"model":"openrouter/allowed"}`))
	r.Header.Set("Authorization", "Bearer fixture-agent-a")
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != 502 || arrivals.Load() != 0 || w.Header().Get("Location") != "" {
		t.Fatal("redirect boundary failed")
	}
}

func TestCancellationReachesUpstream(t *testing.T) {
	started, cancelled := make(chan struct{}), make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		close(started)
		<-r.Context().Done()
		close(cancelled)
	}))
	defer up.Close()
	a, _ := NewAdapter(up.URL, fixture)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"model":"openrouter/allowed"}`)).WithContext(ctx)
	r.Header.Set("Authorization", "Bearer fixture-agent-a")
	done := make(chan struct{})
	go func() { a.ServeHTTP(httptest.NewRecorder(), r); close(done) }()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("upstream not reached")
	}
	cancel()
	select {
	case <-cancelled:
	case <-time.After(3 * time.Second):
		t.Fatal("upstream not cancelled")
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("adapter did not stop")
	}
}
