package apptransport

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

func beamCapacityPeer(t *testing.T, server string, binding Binding) (net.Conn, int) {
	t.Helper()
	u, _ := url.Parse(server)
	conn, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatal(err)
	}
	request := &http.Request{Method: "CONNECT", URL: &url.URL{Opaque: "/beam/channel"}, Host: u.Host, Header: make(http.Header)}
	BindingHeaders(request.Header, binding)
	if err = request.Write(conn); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), request)
	if err != nil {
		t.Fatal(err)
	}
	return conn, response.StatusCode
}

func TestBeamChannelCapacityLeavesRoomForAnotherOrganization(t *testing.T) {
	b := NewBeamBroker(func(context.Context, Binding, string) (time.Time, error) { return time.Now().Add(4 * time.Second), nil })
	defer b.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		binding := Binding{OrgID: r.Header.Get("X-App-Org-ID"), AppID: r.Header.Get("X-App-ID"), GatewayID: r.Header.Get("X-App-Gateway-ID"), Generation: r.Header.Get("X-App-Generation"), Revision: 1, Digest: r.Header.Get("X-App-Digest"), Hostname: r.Header.Get("X-App-Hostname"), AuthorityVersion: 1, Purpose: "beam_proxy"}
		_ = b.Accept(w, r, binding, "serial")
	}))
	defer server.Close()
	first := Binding{OrgID: "org-a", AppID: "share-a", GatewayID: "connector-a", Generation: "generation", Revision: 1, Digest: "digest", Hostname: "a.beam.test", AuthorityVersion: 1, Purpose: "beam_proxy"}
	var peers, claimed []net.Conn
	defer func() {
		for _, conn := range peers {
			_ = conn.Close()
		}
		for _, conn := range claimed {
			_ = conn.Close()
		}
	}()
	open := func(binding Binding) {
		t.Helper()
		peer, status := beamCapacityPeer(t, server.URL, binding)
		peers = append(peers, peer)
		if status != 200 {
			t.Fatalf("admission status=%d", status)
		}
		conn, err := b.Dial(t.Context(), binding)
		if err != nil {
			t.Fatal(err)
		}
		claimed = append(claimed, conn)
	}
	for i := 0; i < 34; i++ {
		open(first)
	}
	peer, status := beamCapacityPeer(t, server.URL, first)
	_ = peer.Close()
	if status != 503 {
		t.Fatal("share reservation limit not enforced", status)
	}
	second := first
	second.AppID = "share-b"
	second.GatewayID = "connector-b"
	second.Hostname = "b.beam.test"
	for i := 0; i < 30; i++ {
		open(second)
	}
	third := first
	third.AppID = "share-c"
	third.GatewayID = "connector-c"
	third.Hostname = "c.beam.test"
	peer, status = beamCapacityPeer(t, server.URL, third)
	_ = peer.Close()
	if status != 503 {
		t.Fatal("organization exhausted shared pool", status)
	}
	other := third
	other.OrgID = "org-b"
	open(other)
	if b.Capacity().Connections != 65 {
		t.Fatal("unrelated organization lost capacity")
	}
	_ = claimed[0].Close()
	open(third)
	if b.Capacity().Connections != 65 {
		t.Fatal("released reservation was not reclaimed")
	}
}

func TestBeamPendingAdmissionsCountTowardOrganizationCapacity(t *testing.T) {
	started := make(chan struct{}, 65)
	release := make(chan struct{})
	b := NewBeamBroker(func(ctx context.Context, _ Binding, _ string) (time.Time, error) {
		started <- struct{}{}
		select {
		case <-release:
			return time.Time{}, fmt.Errorf("fixture refused")
		case <-ctx.Done():
			return time.Time{}, ctx.Err()
		}
	})
	defer b.Close()
	var running sync.WaitGroup
	for i := 0; i < 64; i++ {
		binding := Binding{OrgID: "org-a", AppID: fmt.Sprint(i), Purpose: "beam_proxy"}
		running.Add(1)
		go func() {
			defer running.Done()
			_ = b.Accept(httptest.NewRecorder(), httptest.NewRequest("CONNECT", "/beam/channel", nil), binding, "serial")
		}()
	}
	for i := 0; i < 64; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			close(release)
			running.Wait()
			t.Fatal("admissions were not reserved")
		}
	}
	w := httptest.NewRecorder()
	_ = b.Accept(w, httptest.NewRequest("CONNECT", "/beam/channel", nil), Binding{OrgID: "org-a", AppID: "extra", Purpose: "beam_proxy"}, "serial")
	if w.Code != 503 {
		t.Fatal("pending organization quota not enforced", w.Code)
	}
	running.Add(1)
	go func() {
		defer running.Done()
		_ = b.Accept(httptest.NewRecorder(), httptest.NewRequest("CONNECT", "/beam/channel", nil), Binding{OrgID: "org-b", AppID: "other", Purpose: "beam_proxy"}, "serial")
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		close(release)
		running.Wait()
		t.Fatal("another organization could not reserve authority")
	}
	close(release)
	running.Wait()
	if capacity := b.Capacity(); capacity.PendingAdmissions != 0 || capacity.AuthorityCallbacks != 0 {
		t.Fatal("failed admission leaked reservations", capacity)
	}
}
