package apptransport

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

func gateway(t *testing.T, server string, b Binding) (net.Conn, int) {
	t.Helper()
	u, _ := url.Parse(server)
	conn, e := net.Dial("tcp", u.Host)
	if e != nil {
		t.Fatal(e)
	}
	req := &http.Request{Method: "CONNECT", URL: &url.URL{Opaque: "/agent/app-access/channel"}, Host: u.Host, Header: make(http.Header)}
	BindingHeaders(req.Header, b)
	if e = req.Write(conn); e != nil {
		t.Fatal(e)
	}
	response, e := http.ReadResponse(bufio.NewReader(conn), req)
	if e != nil {
		t.Fatal(e)
	}
	return conn, response.StatusCode
}
func waitConnections(t *testing.T, b *Broker, want int) {
	t.Helper()
	timeout := time.NewTimer(time.Second)
	defer timeout.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		b.mu.Lock()
		n := len(b.connections)
		b.mu.Unlock()
		if n == want {
			return
		}
		select {
		case <-timeout.C:
			t.Fatalf("connections %d want%d", n, want)
		case <-tick.C:
		}
	}
}
func TestBrokerCapacityAndIdleEOFReclaimed(t *testing.T) {
	binding := Binding{OrgID: "org", GatewayID: "gw", AppID: "app", Generation: "gen", Revision: 1, Digest: "digest", Purpose: "origin_check"}
	b := NewBroker(func(context.Context, Binding, string) (time.Time, error) { return time.Now().Add(4 * time.Second), nil })
	defer b.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _ = b.Accept(w, r, binding, "serial") }))
	defer server.Close()
	first, status := gateway(t, server.URL, binding)
	if status != 200 {
		t.Fatal(status)
	}
	defer first.Close()
	second, status := gateway(t, server.URL, binding)
	if status != 200 {
		t.Fatal(status)
	}
	defer second.Close()
	third, status := gateway(t, server.URL, binding)
	third.Close()
	if status != 503 {
		t.Fatal(status)
	}
	first.Close()
	waitConnections(t, b, 1)
	third, status = gateway(t, server.URL, binding)
	defer third.Close()
	if status != 200 {
		t.Fatal("expired slot not reclaimed", status)
	}
	waitConnections(t, b, 2)
	b.Close()
	waitConnections(t, b, 0)
}
func TestBrokerExpiredAuthorityAndBadRoute(t *testing.T) {
	binding := Binding{Purpose: "origin_check"}
	b := NewBroker(func(context.Context, Binding, string) (time.Time, error) {
		return time.Now().Add(60 * time.Millisecond), nil
	})
	defer b.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _ = b.Accept(w, r, binding, "serial") }))
	defer server.Close()
	conn, status := gateway(t, server.URL, binding)
	defer conn.Close()
	if status != 200 {
		t.Fatal(status)
	}
	waitConnections(t, b, 0)
	response, e := http.Get(server.URL + "/browser")
	if e != nil {
		t.Fatal(e)
	}
	defer response.Body.Close()
	if response.StatusCode != 403 {
		t.Fatal("browser route accepted")
	}
}
func TestBindingRefusesAmbiguousHeaders(t *testing.T) {
	b := Binding{AppID: "a", Revision: 1, Digest: "d", Generation: "g", Purpose: "origin_check"}
	h := make(http.Header)
	BindingHeaders(h, b)
	if b.ValidateHeaders(h) != nil {
		t.Fatal("correct headers refused")
	}
	h.Add("X-App-ID", "a")
	if b.ValidateHeaders(h) == nil {
		t.Fatal("duplicate identity accepted")
	}
}

func TestLeaseExpiryClosesActiveChannelWhileRenewalIgnoresContext(t *testing.T) {
	binding := Binding{Purpose: "origin_check"}
	deadline := time.Now().Add(2600 * time.Millisecond)
	blocked := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	var calls atomic.Int32
	broker := NewBroker(func(context.Context, Binding, string) (time.Time, error) {
		if calls.Add(1) > 1 {
			close(blocked)
			<-release
			return time.Now().Add(4 * time.Second), nil
		}
		return deadline, nil
	})
	defer broker.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _ = broker.Accept(w, r, binding, "serial") }))
	defer server.Close()
	peer, status := gateway(t, server.URL, binding)
	defer peer.Close()
	if status != 200 {
		t.Fatal(status)
	}
	conn, e := broker.Dial(t.Context(), binding)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	select {
	case <-blocked:
	case <-time.After(2300 * time.Millisecond):
		t.Fatal("renewal did not start")
	}
	_ = peer.SetReadDeadline(deadline.Add(250 * time.Millisecond))
	var one [1]byte
	_, e = peer.Read(one[:])
	var timeout net.Error
	if e == nil || (errors.As(e, &timeout) && timeout.Timeout()) {
		t.Fatal("stalled renewal kept active channel open", e)
	}
	waitConnections(t, broker, 0)
	if len(broker.authoritySlots) != 1 {
		t.Fatal("stalled callback released admission bound before returning")
	}
}
func TestExpiredAdmissionResultCannotEstablishChannel(t *testing.T) {
	binding := Binding{Purpose: "origin_check"}
	broker := NewBroker(func(ctx context.Context, _ Binding, _ string) (time.Time, error) {
		<-ctx.Done()
		return time.Now().Add(4 * time.Second), nil
	})
	defer broker.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _ = broker.Accept(w, r, binding, "serial") }))
	defer server.Close()
	peer, status := gateway(t, server.URL, binding)
	defer peer.Close()
	if status != 403 {
		t.Fatal("expired admission established tunnel", status)
	}
	waitConnections(t, broker, 0)
}
func TestPendingAdmissionsCountBeforeAuthorizerRuns(t *testing.T) {
	binding := Binding{Purpose: "origin_check"}
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	broker := NewBroker(func(context.Context, Binding, string) (time.Time, error) {
		entered <- struct{}{}
		<-release
		return time.Now().Add(4 * time.Second), nil
	})
	defer broker.Close()
	request := func() *http.Request {
		r := &http.Request{Method: "CONNECT", URL: &url.URL{Path: "/agent/app-access/channel"}, ProtoMajor: 1, Header: make(http.Header)}
		return r
	}
	finished := make(chan struct{}, 2)
	for i := 0; i < 2; i++ {
		go func() {
			_ = broker.Accept(httptest.NewRecorder(), request(), binding, "serial")
			finished <- struct{}{}
		}()
	}
	for i := 0; i < 2; i++ {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("admission not reserved")
		}
	}
	recorder := httptest.NewRecorder()
	_ = broker.Accept(recorder, request(), binding, "serial")
	if recorder.Code != 503 {
		t.Fatal("third authorization work admitted", recorder.Code)
	}
	broker.mu.Lock()
	pending := broker.pendingCount
	broker.mu.Unlock()
	if pending != 2 {
		t.Fatal(pending)
	}
	close(release)
	for i := 0; i < 2; i++ {
		select {
		case <-finished:
		case <-time.After(time.Second):
			t.Fatal("admission callback leaked")
		}
	}
	broker.mu.Lock()
	pending = broker.pendingCount
	broker.mu.Unlock()
	if pending != 0 || len(broker.authoritySlots) != 0 {
		t.Fatal("admission slots not released", pending)
	}
}
