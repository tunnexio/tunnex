package sandboxrunner

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func enrolledRequest(b *Broker, path string, body []byte, key string, expires time.Time) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", path, bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	u, _ := url.Parse(b.RunnerURI)
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, VerifiedChains: [][]*x509.Certificate{{{URIs: []*url.URL{u}, RawSubjectPublicKeyInfo: []byte(key), NotBefore: time.Now().Add(-time.Minute), NotAfter: expires}}}}
	w := httptest.NewRecorder()
	b.ServeHTTP(w, r)
	return w
}

func TestEnrolledQualificationUploadIsActiveOnlyBoundedAndNotReady(t *testing.T) {
	b, _ := NewBroker("spiffe://tunnex/runner/one")
	var cleanup atomic.Bool
	b.Authorize = func(_ context.Context, leaf *x509.Certificate) (bool, error) {
		if string(leaf.RawSubjectPublicKeyInfo) != "current" {
			return false, ErrUnavailable
		}
		return cleanup.Load(), nil
	}
	var uploads atomic.Int32
	b.SubmitQualification = func(_ context.Context, _ *x509.Certificate, raw json.RawMessage) error {
		if string(raw) != `{"version":1,"checks":[]}` {
			return ErrInvalid
		}
		uploads.Add(1)
		return nil
	}
	path := "/internal/sandbox-runners/v1/qualification"
	expires := time.Now().Add(time.Hour)
	valid := []byte(`{"version":1,"checks":[]}`)
	if got := enrolledRequest(b, path, valid, "current", expires).Code; got != 204 {
		t.Fatal("public report was not stored", got)
	}
	if uploads.Load() != 1 || b.health != nil {
		t.Fatal("report upload implied health or readiness")
	}
	for _, key := range []string{"former", "unrelated"} {
		if got := enrolledRequest(b, path, valid, key, expires).Code; got != 403 {
			t.Fatal("wrong current credential submitted report", got)
		}
	}
	cleanup.Store(true)
	if got := enrolledRequest(b, path, valid, "current", expires).Code; got != 403 {
		t.Fatal("cleanup credential submitted report", got)
	}
	cleanup.Store(false)
	for _, raw := range [][]byte{[]byte(`{"version":2}`), []byte(`{} {}`), []byte(`{"large":"` + strings.Repeat("x", QualificationReportLimit) + `"}`)} {
		if got := enrolledRequest(b, path, raw, "current", expires).Code; got != 400 {
			t.Fatal("invalid or oversized report accepted", got)
		}
	}
	if got := enrolledRequest(b, path+"?token=forbidden", valid, "current", expires).Code; got != 400 {
		t.Fatal("query transport accepted", got)
	}
	if uploads.Load() != 1 {
		t.Fatal("refused report reached service")
	}
}

func awaitPending(t *testing.T, b *Broker) Command {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		b.mu.Lock()
		p := b.pending
		if p != nil {
			command := p.command
			b.mu.Unlock()
			return command
		}
		b.mu.Unlock()
		time.Sleep(time.Millisecond)
	}
	t.Fatal("command was not queued")
	return Command{}
}

func TestEnrolledBrokerRejectsFormerKeyAndExpiredKeepAlive(t *testing.T) {
	b, _ := NewBroker("spiffe://tunnex/runner/one")
	var calls atomic.Int32
	b.Authorize = func(_ context.Context, leaf *x509.Certificate) (bool, error) {
		calls.Add(1)
		if string(leaf.RawSubjectPublicKeyInfo) != "current" {
			return false, ErrUnavailable
		}
		return false, nil
	}
	expires := time.Now().Add(time.Hour)
	for _, path := range []string{"poll", "reply", "health/poll", "health/reply", "renew"} {
		if got := enrolledRequest(b, "/internal/sandbox-runners/v1/"+path, nil, "former", expires).Code; got != 403 {
			t.Fatalf("former certificate admitted on %s: %d", path, got)
		}
	}
	if calls.Load() != 5 {
		t.Fatal("certificate authority was not refreshed on every request")
	}
	if got := enrolledRequest(b, "/internal/sandbox-runners/v1/poll", nil, "current", time.Now().Add(-time.Second)).Code; got != 403 {
		t.Fatal("expired established connection admitted", got)
	}
	if calls.Load() != 5 {
		t.Fatal("expired certificate reached durable authority callback")
	}
	if got := enrolledRequest(b, "/internal/sandbox-runners/v1/poll", nil, "current", expires).Code; got != 204 {
		t.Fatal("current idle runner denied", got)
	}
}

func TestEnrolledBrokerCleanupOnlyCannotStartRenewOrSignalHealth(t *testing.T) {
	b, _ := NewBroker("spiffe://tunnex/runner/one")
	b.Authorize = func(context.Context, *x509.Certificate) (bool, error) { return true, nil }
	b.AuthorizeCommand = func(_ context.Context, _ *x509.Certificate, raw json.RawMessage) error {
		if string(raw) != `{"Operation":"delete","ID":"retained"}` {
			return ErrUnavailable
		}
		return nil
	}
	renewed := false
	b.RenewAuthorized = func(context.Context, *x509.Certificate) ([]byte, error) {
		renewed = true
		return []byte("unexpected"), nil
	}
	expires := time.Now().Add(time.Hour)
	for _, path := range []string{"health/poll", "health/reply", "renew"} {
		if got := enrolledRequest(b, "/internal/sandbox-runners/v1/"+path, nil, "current", expires).Code; got != 403 {
			t.Fatal("cleanup runner reached live lane", path, got)
		}
	}
	if renewed {
		t.Fatal("cleanup authority reached renewal issuer")
	}
	for _, payload := range []string{`{"Operation":"start","ID":"retained"}`, `{"Operation":"delete","ID":"retained"}`} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		done := make(chan error, 1)
		go func() { _, err := b.Call(ctx, json.RawMessage(payload)); done <- err }()
		command := awaitPending(t, b)
		poll := enrolledRequest(b, "/internal/sandbox-runners/v1/poll", nil, "current", expires)
		if payload == `{"Operation":"start","ID":"retained"}` {
			if poll.Code != 403 {
				t.Fatal("revoked runner received start", poll.Code)
			}
			cancel()
			<-done
			continue
		}
		if poll.Code != 200 {
			t.Fatal("exact cleanup was not delivered", poll.Code)
		}
		reply, _ := json.Marshal(Reply{command.ID, json.RawMessage(`{"ok":true}`)})
		if got := enrolledRequest(b, "/internal/sandbox-runners/v1/reply", reply, "current", expires).Code; got != 204 {
			t.Fatal("cleanup receipt rejected", got)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		cancel()
	}
}

func TestEnrolledBrokerRechecksCommandWhenLateReplyArrives(t *testing.T) {
	b, _ := NewBroker("spiffe://tunnex/runner/one")
	b.Authorize = func(context.Context, *x509.Certificate) (bool, error) { return false, nil }
	var allowed atomic.Bool
	allowed.Store(true)
	b.AuthorizeCommand = func(context.Context, *x509.Certificate, json.RawMessage) error {
		if !allowed.Load() {
			return ErrUnavailable
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := b.Call(ctx, json.RawMessage(`{"Operation":"start"}`)); done <- err }()
	command := awaitPending(t, b)
	expires := time.Now().Add(time.Hour)
	if got := enrolledRequest(b, "/internal/sandbox-runners/v1/poll", nil, "current", expires).Code; got != 200 {
		t.Fatal(got)
	}
	allowed.Store(false)
	reply, _ := json.Marshal(Reply{command.ID, json.RawMessage(`{"ok":true}`)})
	if got := enrolledRequest(b, "/internal/sandbox-runners/v1/reply", reply, "current", expires).Code; got != 403 {
		t.Fatal("withdrawn effect receipt accepted", got)
	}
	select {
	case <-done:
		t.Fatal("rejected receipt falsely completed effect")
	default:
	}
	cancel()
	<-done
}
