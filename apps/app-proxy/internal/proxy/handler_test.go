package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/packages/apptransport"
)

type deniedAuthority struct{ calls atomic.Int32 }

func (a *deniedAuthority) Lookup(context.Context, string) (Route, error) {
	a.calls.Add(1)
	return Route{}, ErrDenied
}
func (a *deniedAuthority) Authorize(context.Context, Binding, string, Request) (Decision, error) {
	a.calls.Add(1)
	return Decision{}, ErrDenied
}
func (a *deniedAuthority) Renew(context.Context, Binding, string) (Decision, error) {
	return Decision{}, ErrDenied
}
func (a *deniedAuthority) Channel(context.Context, Binding, string) (time.Time, error) {
	return time.Time{}, ErrDenied
}
func TestPublicGuardsBeforeAuthority(t *testing.T) {
	a := &deniedAuthority{}
	broker := apptransport.NewBrowserBroker(nil)
	defer broker.Close()
	h := NewHandler("apps.test", a, broker)
	for _, tc := range []struct{ host, method, path, upgrade, cookie string }{{"foreign.test", "GET", "/", "", ""}, {"a.apps.test:443", "GET", "/", "", ""}, {"a.apps.test", "CONNECT", "/", "", ""}, {"a.apps.test", "POST", "/", "", ""}, {"a.apps.test", "GET", "//evil.test", "", ""}, {"a.apps.test", "GET", "/", "h2c", ""}, {"a.apps.test", "GET", "/", "", "__Host-tunnex_app_session=a; __Host-tunnex_app_session=b"}} {
		r := httptest.NewRequest(tc.method, tc.path, nil)
		r.Host = tc.host
		r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
		r.Header.Set("Upgrade", tc.upgrade)
		r.Header.Set("Cookie", tc.cookie)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal(tc, w.Code)
		}
	}
	if a.calls.Load() != 0 {
		t.Fatal("authority queried for malformed request")
	}
}
func TestStreamExpiryUnblocksOrdinaryDownload(t *testing.T) {
	done := make(chan struct{})
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		writer := newStreamWriter(w, r)
		timer := time.AfterFunc(200*time.Millisecond, writer.close)
		defer timer.Stop()
		w.Header().Set("Content-Length", "67108864")
		chunk := make([]byte, 64<<10)
		for i := 0; i < 1024; i++ {
			if _, e := writer.Write(chunk); e != nil {
				return
			}
		}
	}))
	server.Config.ConnContext = ConnectionContext
	server.StartTLS()
	defer server.Close()
	config := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	conn, e := tls.Dial("tcp", server.Listener.Addr().String(), config)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	_, e = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: a.apps.test\r\n\r\n")
	if e != nil {
		t.Fatal(e)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("lease failed to interrupt blocked ordinary download")
	}
}
func TestStreamExpiryUnblocksUpload(t *testing.T) {
	done := make(chan struct{})
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		writer := newStreamWriter(w, r)
		timer := time.AfterFunc(200*time.Millisecond, writer.close)
		defer timer.Stop()
		_, e := io.Copy(io.Discard, r.Body)
		if e == nil {
			t.Error("incomplete upload completed")
		}
	}))
	server.Config.ConnContext = ConnectionContext
	server.StartTLS()
	defer server.Close()
	config := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	conn, e := tls.Dial("tcp", server.Listener.Addr().String(), config)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	io.WriteString(conn, "POST / HTTP/1.1\r\nHost: a.apps.test\r\nContent-Length: 1000000\r\n\r\nx")
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("lease failed to interrupt stalled upload")
	}
}
func TestExpiryBeforeHijackClosesSocket(t *testing.T) {
	done := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writer := &streamWriter{ResponseWriter: w}
		writer.close()
		conn, _, e := writer.Hijack()
		if e == nil {
			_ = conn.Close()
		}
		close(done)
	}))
	defer server.Close()
	config := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	conn, e := tls.Dial("tcp", server.Listener.Addr().String(), config)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	io.WriteString(conn, "GET / HTTP/1.1\r\nHost: a.apps.test\r\n\r\n")
	conn.SetReadDeadline(time.Now().Add(time.Second))
	_, e = bufio.NewReader(conn).ReadByte()
	if e == nil {
		t.Fatal("expired socket readable")
	}
	<-done
}
func TestTLSParserRefusesAmbiguousRequests(t *testing.T) {
	a := &deniedAuthority{}
	b := apptransport.NewBrowserBroker(nil)
	defer b.Close()
	server := httptest.NewTLSServer(NewHandler("apps.test", a, b))
	defer server.Close()
	config := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	for _, headers := range []string{"Host: a.apps.test\r\nHost: b.apps.test\r\n", "Host: a.apps.test\r\nContent-Length: 1\r\nContent-Length: 2\r\n", "Host: a.apps.test\r\nUpgrade: h2c\r\n", "Host: a.apps.test\r\nAuthorization: Bearer application-token\r\nAuthorization: AppProxy tnxap_secret\r\n", "Host: a.apps.test\r\nProxy-Authorization: Basic app\r\nProxy-Authorization: AppProxy tnxap_secret\r\n", "Host: a.apps.test\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n"} {
		conn, e := tls.Dial("tcp", server.Listener.Addr().String(), config)
		if e != nil {
			t.Fatal(e)
		}
		payload := "GET / HTTP/1.1\r\n" + headers + "\r\n"
		if strings.Contains(headers, "Transfer-Encoding") {
			payload += "0\r\n\r\n"
		}
		io.WriteString(conn, payload)
		conn.SetReadDeadline(time.Now().Add(time.Second))
		line, e := bufio.NewReader(conn).ReadString('\n')
		conn.Close()
		if e != nil || (!strings.Contains(line, "400") && !strings.Contains(line, "403")) {
			t.Fatal(line, e)
		}
	}
	if a.calls.Load() != 0 {
		t.Fatal("ambiguous requests reached authority")
	}
}

var _ net.Conn

func TestConcurrencyReservationsBoundAndReleased(t *testing.T) {
	h := NewHandler("apps.test", &deniedAuthority{}, nil)
	b := Binding{OrgID: "org", AppID: "app", GatewayID: "gw"}
	releases := []func(){}
	for i := 0; i < 16; i++ {
		release := h.reserve(b, "same-session")
		if release == nil {
			t.Fatal(i)
		}
		releases = append(releases, release)
	}
	if h.reserve(b, "same-session") != nil {
		t.Fatal("session bound exceeded")
	}
	for i := 0; i < 16; i++ {
		release := h.reserve(b, "other-session")
		if release == nil {
			t.Fatal(i)
		}
		releases = append(releases, release)
	}
	if h.reserve(b, "third-session") != nil {
		t.Fatal("app bound exceeded")
	}
	for _, release := range releases {
		release()
	}
	if len(h.counts) != 0 {
		t.Fatal("reservation leak", h.counts)
	}
}
func TestIgnoredRenewDoesNotExtendLease(t *testing.T) {
	a := &stalledRenewAuthority{entered: make(chan struct{}), release: make(chan struct{})}
	h := NewHandler("apps.test", a, nil)
	writer := &streamWriter{ResponseWriter: httptest.NewRecorder()}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	deadline := time.Now().Add(2200 * time.Millisecond)
	closedDone := make(chan struct{})
	timer := time.AfterFunc(time.Until(deadline), func() { cancel(); writer.close(); close(closedDone) })
	defer timer.Stop()
	renewDone := make(chan struct{})
	go func() {
		defer close(renewDone)
		h.renew(ctx, cancel, writer, timer, Binding{}, Decision{StreamID: "stream", ExpiresAt: deadline})
	}()
	<-a.entered
	select {
	case <-ctx.Done():
	case <-time.After(500 * time.Millisecond):
		t.Fatal("ignored renew extended lease")
	}
	<-closedDone
	writer.mu.Lock()
	closed := writer.closed
	writer.mu.Unlock()
	if !closed {
		t.Fatal("stream remained open")
	}
	close(a.release)
	<-renewDone
	if _, e := writer.Write([]byte("late")); e == nil {
		t.Fatal("late renewal reopened stream")
	}
}

type stalledRenewAuthority struct {
	deniedAuthority
	entered, release chan struct{}
}

func (a *stalledRenewAuthority) Renew(context.Context, Binding, string) (Decision, error) {
	close(a.entered)
	<-a.release
	return Decision{StreamID: "stream", ExpiresAt: time.Now().Add(4 * time.Second)}, nil
}

func TestGlobalGatewayAndCallbackBounds(t *testing.T) {
	h := NewHandler("apps.test", &deniedAuthority{}, nil)
	releases := []func(){}
	for i := 0; i < 256; i++ {
		gateway := "first"
		if i >= 128 {
			gateway = "second"
		}
		r := h.reserve(Binding{OrgID: "org", AppID: fmt.Sprint(i), GatewayID: gateway}, fmt.Sprint(i))
		if r == nil {
			t.Fatal(i)
		}
		releases = append(releases, r)
		if i == 127 && h.reserve(Binding{OrgID: "org", AppID: "extra", GatewayID: "first"}, "extra") != nil {
			t.Fatal("gateway bound")
		}
	}
	if h.reserve(Binding{OrgID: "org", AppID: "extra", GatewayID: "third"}, "extra") != nil {
		t.Fatal("global bound")
	}
	for _, r := range releases {
		r()
	}
	if len(h.counts) != 0 {
		t.Fatal("count leak")
	}
	for i := 0; i < 128; i++ {
		h.callbacks <- struct{}{}
	}
	request := httptest.NewRequest("GET", "/", nil)
	request.Host = "a.apps.test"
	request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
	request.Header.Set("Cookie", apptransport.AppSessionCookie+"=test")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request)
	if w.Code != 403 || h.Authority.(*deniedAuthority).calls.Load() != 0 {
		t.Fatal("saturated callbacks invoked authority")
	}
	<-h.callbacks
	w = httptest.NewRecorder()
	h.ServeHTTP(w, request)
	if h.Authority.(*deniedAuthority).calls.Load() != 1 || len(h.callbacks) != 127 {
		t.Fatal("callback slot leak")
	}
}

// A retired callback must not change deadlines on a keep-alive connection
// after its response completed and the server moved to another request.
func TestRetiredStreamDoesNotTouchNextRequest(t *testing.T) {
	recorder := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	conn := &expiryRecordingConn{}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r = r.WithContext(ConnectionContext(r.Context(), tls.Server(conn, &tls.Config{})))
	w := newStreamWriter(recorder, r)
	w.finish()
	w.close()
	if recorder.deadlines != 0 || w.closed || conn.closes != 0 {
		t.Fatal("retired stream changed reused connection")
	}
}

func TestStreamExpiryClosesUnderlyingTLSTransport(t *testing.T) {
	recorder := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	conn := &expiryRecordingConn{}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r = r.WithContext(ConnectionContext(r.Context(), tls.Server(conn, &tls.Config{})))
	w := newStreamWriter(recorder, r)
	if w.transport != conn {
		t.Fatal("expiry retained TLS close-notify instead of the underlying transport")
	}
	w.close()
	if conn.closes != 1 || recorder.deadlines != 2 {
		t.Fatalf("expiry did not close transport and deadlines: closes=%d deadlines=%d", conn.closes, recorder.deadlines)
	}
	if _, err := w.Write([]byte("late data")); err != net.ErrClosed || recorder.Body.Len() != 0 {
		t.Fatal("expired stream accepted a later write")
	}
}

type expiryRecordingConn struct {
	net.Conn
	closes int
}

func (c *expiryRecordingConn) Close() error { c.closes++; return nil }

type deadlineRecorder struct {
	*httptest.ResponseRecorder
	deadlines int
}

func (w *deadlineRecorder) SetWriteDeadline(time.Time) error { w.deadlines++; return nil }
func (w *deadlineRecorder) SetReadDeadline(time.Time) error  { w.deadlines++; return nil }

func (a *deniedAuthority) Redeem(context.Context, RedeemInput) (RedeemResult, error) {
	return RedeemResult{}, ErrDenied
}

func TestUnauthenticatedStalledBodyDrainBounded(t *testing.T) {
	a := &deniedAuthority{}
	h := NewHandler("apps.test", a, nil)
	done := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { defer close(done); h.ServeHTTP(w, r) }))
	defer server.Close()
	config := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	conn, e := tls.Dial("tcp", server.Listener.Addr().String(), config)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	io.WriteString(conn, "POST / HTTP/1.1\r\nHost: a.apps.test\r\nOrigin: https://a.apps.test\r\nContent-Length: 1000\r\n\r\nx")
	conn.SetReadDeadline(time.Now().Add(12 * time.Second))
	line, e := bufio.NewReader(conn).ReadString('\n')
	if e != nil || !strings.Contains(line, "403") {
		t.Fatal("stalled denial not bounded", line, e)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("body drain retained handler")
	}
}

func (a *deniedAuthority) Pending(context.Context, PendingInput) (PendingResult, error) {
	return PendingResult{}, ErrDenied
}
