package sandboxrunner

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func request(b *Broker, path string, body []byte, auth bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", path, bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if auth {
		u, _ := url.Parse(b.RunnerURI)
		r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, VerifiedChains: [][]*x509.Certificate{{{URIs: []*url.URL{u}}}}}
	}
	w := httptest.NewRecorder()
	b.ServeHTTP(w, r)
	return w
}
func TestRoundtripBoundAndRedelivery(t *testing.T) {
	b, _ := NewBroker("spiffe://tunnex/runner/one")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		p, e := b.Call(ctx, json.RawMessage(`{}`))
		if e == nil && string(p) != `{"ok":true}` {
			e = ErrInvalid
		}
		done <- e
	}()
	for i := 0; i < 100; i++ {
		b.mu.Lock()
		ready := b.pending != nil
		b.mu.Unlock()
		if ready {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if _, e := b.Call(ctx, json.RawMessage(`{}`)); e != ErrUnavailable {
		t.Fatal(e)
	}
	if w := request(b, "/internal/sandbox-runners/v1/poll", nil, false); w.Code != 403 {
		t.Fatal(w.Code)
	}
	var a, c Command
	json.Unmarshal(request(b, "/internal/sandbox-runners/v1/poll", nil, true).Body.Bytes(), &a)
	json.Unmarshal(request(b, "/internal/sandbox-runners/v1/poll", nil, true).Body.Bytes(), &c)
	if a.ID != c.ID {
		t.Fatal("unstable ID")
	}
	raw, _ := json.Marshal(Reply{a.ID, json.RawMessage(`{"ok":true}`)})
	if w := request(b, "/internal/sandbox-runners/v1/reply", raw, true); w.Code != 204 {
		t.Fatal(w.Code)
	}
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	if w := request(b, "/internal/sandbox-runners/v1/reply", raw, true); w.Code != 409 {
		t.Fatal(w.Code)
	}
}
func TestCancel(t *testing.T) {
	b, _ := NewBroker("spiffe://tunnex/runner/one")
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if _, e := b.Call(ctx, json.RawMessage(`{}`)); e != ErrUnavailable {
		t.Fatal(e)
	}
	if w := request(b, "/internal/sandbox-runners/v1/poll", nil, true); w.Code != 204 {
		t.Fatal(w.Code)
	}
}

func TestPeerIdentityAndVersion(t *testing.T) {
	b, _ := NewBroker("spiffe://tunnex/runner/one")
	for _, identity := range []string{"spiffe://tunnex/runner/two", ""} {
		r := httptest.NewRequest("POST", "/internal/sandbox-runners/v1/poll", nil)
		r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
		if identity != "" {
			u, _ := url.Parse(identity)
			r.TLS.VerifiedChains = [][]*x509.Certificate{{{URIs: []*url.URL{u}}}}
		}
		w := httptest.NewRecorder()
		b.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal("foreign/unverified peer accepted")
		}
	}
	r := httptest.NewRequest("POST", "/internal/sandbox-runners/v1/poll", nil)
	u, _ := url.Parse(b.RunnerURI)
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS12, VerifiedChains: [][]*x509.Certificate{{{URIs: []*url.URL{u}}}}}
	w := httptest.NewRecorder()
	b.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("old TLS accepted")
	}
}
