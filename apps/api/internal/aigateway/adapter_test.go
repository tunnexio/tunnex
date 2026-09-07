package aigateway

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

// Only for immediate in-memory tests. Real deadline behavior is tested below
// with actual socket connections, not this recorder's no-op methods.
type deadlineRecorder struct{ *httptest.ResponseRecorder }

func newDeadlineRecorder() *deadlineRecorder               { return &deadlineRecorder{httptest.NewRecorder()} }
func (*deadlineRecorder) SetReadDeadline(time.Time) error  { return nil }
func (*deadlineRecorder) SetWriteDeadline(time.Time) error { return nil }

func TestAdapterRejectsUnsupportedDeadlineWriter(t *testing.T) {
	a, _ := NewAdapter("http://127.0.0.1:1", fixture)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, httptest.NewRequest("POST", "/v1/chat/completions", nil))
	if w.Code != 500 {
		t.Fatal("unsupported writer did not fail closed")
	}
}

func TestFirstEventArrivesBeforeCompletion(t *testing.T) {
	release := make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer up.Close()
	a, _ := NewAdapter(up.URL, fixture)
	server := httptest.NewServer(a)
	defer server.Close()
	defer close(release)
	r, _ := http.NewRequest("POST", server.URL+"/v1/chat/completions", strings.NewReader(`{"model":"openrouter/allowed","messages":[{"role":"user","content":"OK"}],"stream":true}`))
	r.Header.Set("Authorization", "Bearer fixture-agent-a")
	client := &http.Client{Timeout: 2 * time.Second}
	res, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	line, err := bufio.NewReader(res.Body).ReadString('\n')
	if err != nil || line != "data: first\n" {
		t.Fatal("first event was not delivered before completion release")
	}
}

func TestSlowUploadAndDownloadStopAtDeadline(t *testing.T) {
	for _, upload := range []bool{true, false} {
		t.Run(fmt.Sprint("upload=", upload), func(t *testing.T) {
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				payload := strings.Repeat("x", 64<<10)
				for {
					if _, err := io.WriteString(w, payload); err != nil {
						return
					}
					if r.Context().Err() != nil {
						return
					}
				}
			}))
			defer up.Close()
			a, _ := NewAdapter(up.URL, fixture)
			a.requestTimeout = 150 * time.Millisecond
			done := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { defer close(done); a.ServeHTTP(w, r) }))
			defer server.Close()
			conn, err := net.Dial("tcp", strings.TrimPrefix(server.URL, "http://"))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.(*net.TCPConn).SetReadBuffer(1024)
			body := `{"model":"openrouter/allowed","messages":[{"role":"user","content":"OK"}],"stream":true}`
			length := len(body)
			if upload {
				length = 100
			}
			fmt.Fprintf(conn, "POST /v1/chat/completions HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer fixture-agent-a\r\nContent-Length: %d\r\n\r\n", length)
			if !upload {
				io.WriteString(conn, body)
			}
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("slow connection outlived adapter deadline")
			}
		})
	}
}

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
		{"missing identity", "/v1/chat/completions", "", `{"model":"openrouter/allowed","messages":[{"role":"user","content":"OK"}]}`, 401},
		{"other tenant", "/v1/chat/completions", "fixture-agent-b", `{"model":"openrouter/allowed","messages":[{"role":"user","content":"OK"}]}`, 403},
		{"denied model", "/v1/chat/completions", "fixture-agent-a", `{"model":"openrouter/denied","messages":[{"role":"user","content":"OK"}]}`, 403},
		{"admin", "/api/virtual-keys", "fixture-agent-a", `{}`, 404},
		{"query injection", "/v1/chat/completions?api_key=evil", "fixture-agent-a", `{"model":"openrouter/allowed","messages":[{"role":"user","content":"OK"}]}`, 400},
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
			w := newDeadlineRecorder()
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
			r := httptest.NewRequest("POST", path, strings.NewReader(`{"model":"openrouter/allowed","messages":[{"role":"user","content":"OK"}],"stream":true}`))
			r.Header.Set("Authorization", "Bearer fixture-agent-a")
			for _, h := range []string{"Cookie", "X-Api-Key", "X-Goog-Api-Key", "X-Tunnex-Tenant", "X-Bf-Vk", "X-Bf-Provider", "X-Bf-Api-Key", "Forwarded", "X-Forwarded-For"} {
				r.Header.Set(h, "evil")
			}
			w := newDeadlineRecorder()
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
		r := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"model":"openrouter/allowed","messages":[{"role":"user","content":"OK"}]}`))
		r.Header.Set("Authorization", "Bearer fixture-agent-a")
		w := newDeadlineRecorder()
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
	r := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"model":"openrouter/allowed","messages":[{"role":"user","content":"OK"}]}`))
	r.Header.Set("Authorization", "Bearer fixture-agent-a")
	w := newDeadlineRecorder()
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
	r := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"model":"openrouter/allowed","messages":[{"role":"user","content":"OK"}]}`)).WithContext(ctx)
	r.Header.Set("Authorization", "Bearer fixture-agent-a")
	done := make(chan struct{})
	go func() { a.ServeHTTP(newDeadlineRecorder(), r); close(done) }()
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

// An active authorization lease can end before the adapter's request timeout.
// Exercise both blocked upstream reads and downstream socket writes: cancelling
// the upstream context alone does not unblock a blocked ResponseWriter.Write.
func TestActiveGrantExpiryStopsStream(t *testing.T) {
	for _, blockedDownstream := range []bool{false, true} {
		t.Run(fmt.Sprint("blocked_downstream=", blockedDownstream), func(t *testing.T) {
			started, cancelled := make(chan struct{}), make(chan struct{})
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer close(cancelled)
				io.Copy(io.Discard, r.Body)
				w.Header().Set("Content-Type", "text/event-stream")
				io.WriteString(w, "data: first\n\n")
				w.(http.Flusher).Flush()
				close(started)
				if !blockedDownstream {
					<-r.Context().Done()
					return
				}
				payload := strings.Repeat("x", 64<<10)
				for {
					if _, err := io.WriteString(w, payload); err != nil {
						return
					}
					if r.Context().Err() != nil {
						return
					}
				}
			}))
			defer up.Close()
			a, err := NewAdapter(up.URL, func(ctx context.Context, token, model string) (Grant, error) {
				grant, err := fixture(ctx, token, model)
				grant.Expires = time.Now().Add(300 * time.Millisecond)
				return grant, err
			})
			if err != nil {
				t.Fatal(err)
			}
			a.requestTimeout = 5 * time.Second
			done := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer close(done)
				a.ServeHTTP(w, r)
			}))
			defer server.Close()
			conn, err := net.Dial("tcp", strings.TrimPrefix(server.URL, "http://"))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err := conn.(*net.TCPConn).SetReadBuffer(1024); err != nil {
				t.Fatal(err)
			}
			body := `{"model":"openrouter/allowed","messages":[{"role":"user","content":"OK"}],"stream":true}`
			if _, err := fmt.Fprintf(conn, "POST /v1/chat/completions HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer fixture-agent-a\r\nContent-Length: %d\r\n\r\n%s", len(body), body); err != nil {
				t.Fatal(err)
			}
			// Deliberately leave the response unread. A large stream must stop
			// even when the downstream receive window is full.
			limit := time.NewTimer(2 * time.Second)
			defer limit.Stop()
			for _, event := range []struct {
				name string
				ch   <-chan struct{}
			}{{"upstream start", started}, {"adapter termination", done}, {"upstream cancellation", cancelled}} {
				select {
				case <-event.ch:
				case <-limit.C:
					t.Fatalf("grant expiry did not cause %s before global request deadline", event.name)
				}
			}
		})
	}
}

func TestAdapterPrivateDestinationContract(t *testing.T) {
	for _, upstream := range []string{"http://bifrost:8080", "http://127.0.0.1:8080", "http://[::1]:8080", "https://private.example.com"} {
		a, err := NewAdapter(upstream, fixture)
		if err != nil {
			t.Fatalf("approved private destination refused: %v", err)
		}
		if a.client.Transport.(*http.Transport).Proxy != nil {
			t.Fatal("environment proxy enabled")
		}
	}
	for _, upstream := range []string{"http://bifrost.example.com", "http://bifrost.", "http://localhost:8080", "http://10.1.2.3:8080", "http://example.com", "https://user:password@private.example.com"} {
		if _, err := NewAdapter(upstream, fixture); err == nil {
			t.Fatalf("unapproved destination accepted: %s", upstream)
		}
	}
}

func TestAdapterResolverErrorsHaveSafeStatus(t *testing.T) {
	var arrivals atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { arrivals.Add(1) }))
	defer upstream.Close()
	for _, tc := range []struct {
		name    string
		err     error
		status  int
		message string
	}{
		{"unauthorized", apierr.New(401, "private-code", "private-message"), 401, "authentication required"},
		{"wrapped unauthorized", fmt.Errorf("private cause: %w", apierr.New(401, "private-code", "private-message")), 401, "authentication required"},
		{"unavailable", apierr.New(503, "private-code", "private-message"), 503, "AI gateway is unavailable"},
		{"policy", apierr.New(403, "private-code", "private-message"), 403, "AI access is not available under the current policy"},
		{"unsupported status", apierr.New(418, "private-code", "private-message"), 403, "AI access is not available under the current policy"},
		{"untyped denied", errors.New("private-message"), 403, "AI access is not available under the current policy"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _ := NewAdapter(upstream.URL, func(context.Context, string, string) (Grant, error) { return Grant{}, tc.err })
			r := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"model":"openrouter/allowed","messages":[{"role":"user","content":"OK"}]}`))
			r.Header.Set("Authorization", "Bearer fixture-agent-a")
			w := newDeadlineRecorder()
			a.ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("unsafe resolver response: status=%d body=%q", w.Code, w.Body.String())
			}
			public := assertAdapterJSONError(t, w.Result(), tc.status)
			if public != tc.message {
				t.Fatalf("wrong public message %q", public)
			}
		})
	}
	if arrivals.Load() != 0 {
		t.Fatal("resolver error reached engine")
	}
}

func TestAdapterOutputBoundsOnWire(t *testing.T) {
	var arrivals atomic.Int32
	limits := make(chan int, 4)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arrivals.Add(1)
		var payload struct {
			MaxTokens int `json:"max_tokens"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
		}
		limits <- payload.MaxTokens
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"ok":true}`)
	}))
	defer upstream.Close()
	a, _ := NewAdapter(upstream.URL, fixture)
	server := httptest.NewServer(a)
	defer server.Close()
	client := &http.Client{Timeout: 2 * time.Second}
	for _, tc := range []struct {
		field  string
		want   int
		status int
	}{{"", 1024, 200}, {`,"max_tokens":1`, 1, 200}, {`,"max_tokens":4096`, 4096, 200}, {`,"max_tokens":4097`, 0, 400}, {`,"max_tokens":0`, 0, 400}, {`,"max_tokens":-1`, 0, 400}, {`,"max_tokens":null`, 0, 400}, {`,"max_tokens":1.5`, 0, 400}, {`,"max_tokens":"1024"`, 0, 400}} {
		before := arrivals.Load()
		body := `{"model":"openrouter/allowed","messages":[{"role":"user","content":"OK"}]` + tc.field + `}`
		r, _ := http.NewRequest("POST", server.URL+"/v1/chat/completions", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer fixture-agent-a")
		res, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
		if res.StatusCode != tc.status {
			t.Fatalf("output bound %q status=%d", tc.field, res.StatusCode)
		}
		if tc.status == 200 {
			select {
			case got := <-limits:
				if got != tc.want {
					t.Fatalf("upstream limit=%d want=%d", got, tc.want)
				}
			case <-time.After(time.Second):
				t.Fatal("successful request never arrived")
			}
		} else if arrivals.Load() != before {
			t.Fatal("invalid limit reached engine")
		}
	}
}

// Open streams occupy real downstream and upstream sockets. Saturation and
// recovery are asserted through HTTP/provider arrivals, not synthetic counters.
func TestAdapterAdmissionBoundsAndCancellationRecovery(t *testing.T) {
	for _, global := range []bool{false, true} {
		t.Run(fmt.Sprint("global=", global), func(t *testing.T) {
			var arrivals atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				io.Copy(io.Discard, r.Body)
				arrivals.Add(1)
				w.Header().Set("Content-Type", "text/event-stream")
				io.WriteString(w, "data: active\n\n")
				w.(http.Flusher).Flush()
				select {
				case <-r.Context().Done():
				case <-time.After(10 * time.Second):
				}
			}))
			defer upstream.Close()
			a, err := NewAdapter(upstream.URL, func(_ context.Context, token, model string) (Grant, error) {
				return Grant{Tenant: "tenant-a", Agent: token, VirtualKey: "fixture-internal", Expires: time.Now().Add(10 * time.Second)}, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(a)
			defer server.Close()
			client := &http.Client{Timeout: 5 * time.Second}
			var cancels []context.CancelFunc
			var bodies []io.ReadCloser
			defer func() {
				for _, cancel := range cancels {
					cancel()
				}
				for _, body := range bodies {
					body.Close()
				}
			}()
			open := func(agent string) (int, io.ReadCloser, context.CancelFunc) {
				t.Helper()
				ctx, cancel := context.WithCancel(context.Background())
				r, _ := http.NewRequestWithContext(ctx, "POST", server.URL+"/v1/chat/completions", strings.NewReader(`{"model":"openrouter/allowed","messages":[{"role":"user","content":"OK"}],"stream":true}`))
				r.Header.Set("Authorization", "Bearer "+agent)
				res, err := client.Do(r)
				if err != nil {
					cancel()
					t.Fatal(err)
				}
				if res.StatusCode == 429 && (res.Header.Get("Content-Type") != "application/json" || res.Header.Get("Cache-Control") != "no-store") {
					res.Body.Close()
					cancel()
					t.Fatal("overflow response is not uncached JSON")
				}
				return res.StatusCode, res.Body, cancel
			}
			count := 4
			if global {
				count = 64
			}
			for i := 0; i < count; i++ {
				agent := "agent-a"
				if global {
					agent = fmt.Sprintf("agent-%d", i/4)
				}
				status, body, cancel := open(agent)
				cancels = append(cancels, cancel)
				bodies = append(bodies, body)
				if status != 200 {
					t.Fatalf("admission %d/%d status=%d", i, count, status)
				}
			}
			if arrivals.Load() != int32(count) {
				t.Fatalf("active upstream requests=%d want=%d", arrivals.Load(), count)
			}
			extraAgent := "agent-a"
			if global {
				extraAgent = "agent-overflow"
			}
			status, body, cancel := open(extraAgent)
			// The socket response is represented by its body/status here;
			// decode it to ensure 429 is a standard envelope, not plaintext.
			var overflow struct {
				Error struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if json.NewDecoder(body).Decode(&overflow) != nil || overflow.Error.Code != "ai_request_limit" || overflow.Error.Message != "AI request limit reached" {
				t.Fatal("overflow is not the sanitized JSON envelope")
			}
			io.Copy(io.Discard, body)
			body.Close()
			cancel()
			if status != 429 || arrivals.Load() != int32(count) {
				t.Fatalf("overflow status=%d arrivals=%d", status, arrivals.Load())
			}
			// Cancel one stream and require a new request to acquire its released slot.
			cancels[0]()
			bodies[0].Close()
			end := time.Now().Add(2 * time.Second)
			for {
				status, body, cancel = open(extraAgent)
				if status == 200 {
					cancels = append(cancels, cancel)
					bodies = append(bodies, body)
					break
				}
				io.Copy(io.Discard, body)
				body.Close()
				cancel()
				if status != 429 || time.Now().After(end) {
					t.Fatalf("cancelled slot was not released: status=%d", status)
				}
				time.Sleep(5 * time.Millisecond)
			}
			if arrivals.Load() != int32(count+1) {
				t.Fatalf("recovery arrivals=%d want=%d", arrivals.Load(), count+1)
			}
		})
	}
}

func TestAdapterCompletedRequestsReleaseAdmission(t *testing.T) {
	var arrivals atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		arrivals.Add(1)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"ok":true}`)
	}))
	defer upstream.Close()
	a, _ := NewAdapter(upstream.URL, fixture)
	server := httptest.NewServer(a)
	defer server.Close()
	client := &http.Client{Timeout: 2 * time.Second}
	// Exceed both lifetime totals sequentially: neither counter may retain
	// completed requests as if they were still active.
	for i := 0; i < 68; i++ {
		r, _ := http.NewRequest("POST", server.URL+"/v1/chat/completions", strings.NewReader(`{"model":"openrouter/allowed","messages":[{"role":"user","content":"OK"}]}`))
		r.Header.Set("Authorization", "Bearer fixture-agent-a")
		res, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.Copy(io.Discard, res.Body)
		res.Body.Close()
		if err != nil || res.StatusCode != 200 {
			t.Fatalf("completed request %d did not release admission: status=%d err=%v", i, res.StatusCode, err)
		}
	}
	if arrivals.Load() != 68 {
		t.Fatalf("normal completions arrivals=%d", arrivals.Load())
	}
}

func assertAdapterJSONError(t *testing.T, res *http.Response, status int) string {
	t.Helper()
	if res.StatusCode != status || res.Header.Get("Content-Type") != "application/json" || res.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("incorrect error envelope metadata: status=%d content-type=%q", res.StatusCode, res.Header.Get("Content-Type"))
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
			Details []any  `json:"details"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &envelope) != nil || envelope.Error.Code == "" || envelope.Error.Message == "" || len(envelope.Error.Details) != 0 {
		t.Fatalf("invalid standard error envelope: %s", body)
	}
	for _, secret := range []string{"private-message", "private-code", "private cause", "fixture-internal", "fixture-agent-a"} {
		if strings.Contains(string(body), secret) {
			t.Fatalf("private data leaked in JSON error")
		}
	}
	return envelope.Error.Message
}

func TestAdapterGatewayFailureJSONEnvelope(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "private-message fixture-internal", 500) }))
	defer upstream.Close()
	a, _ := NewAdapter(upstream.URL, fixture)
	server := httptest.NewServer(a)
	defer server.Close()
	req, _ := http.NewRequest("POST", server.URL+"/v1/chat/completions", strings.NewReader(`{"model":"openrouter/allowed","messages":[{"role":"user","content":"OK"}]}`))
	req.Header.Set("Authorization", "Bearer fixture-agent-a")
	res, err := (&http.Client{Timeout: 2 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if message := assertAdapterJSONError(t, res, 502); message != "AI engine is unavailable" {
		t.Fatalf("wrong public message %q", message)
	}
}
