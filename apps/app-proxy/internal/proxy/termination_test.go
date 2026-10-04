package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"github.com/tunnexio/tunnex/packages/apptransport/authoritywire"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type terminationFixture struct {
	launchAuthority
	entered  chan authoritywire.AppProxyStreamTerminatedInput
	release  chan struct{}
	returned chan struct{}
}

func (a *terminationFixture) Terminated(ctx context.Context, in authoritywire.AppProxyStreamTerminatedInput) error {
	a.entered <- in
	<-a.release // Deliberately ignores deadline; callback slot must remain held.
	close(a.returned)
	return nil
}
func TestTerminationNotificationBoundedAndRedacted(t *testing.T) {
	a := &terminationFixture{entered: make(chan authoritywire.AppProxyStreamTerminatedInput, 1), release: make(chan struct{}), returned: make(chan struct{})}
	h := NewHandler("apps.example.net", a, nil)
	h.terminationCallbacks = make(chan struct{}, 1)
	h.notifyTerminated(Binding{AppID: "immutable-app"}, "stream-id", true)
	select {
	case in := <-a.entered:
		if in.StreamID != "stream-id" || in.Binding.AppID != "immutable-app" || in.Reason != authoritywire.AppProxyLeaseExpired {
			t.Fatal("incorrect exact termination tuple")
		}
	case <-time.After(time.Second):
		t.Fatal("notification not dispatched")
	}
	// A callback ignoring cancellation cannot leak another goroutine per stream.
	h.notifyTerminated(Binding{}, "discarded", false)
	if len(h.terminationCallbacks) != 1 {
		t.Fatal("outstanding callback reservation lost")
	}
	close(a.release)
	select {
	case <-a.returned:
	case <-time.After(time.Second):
		t.Fatal("fixture callback stuck")
	}
	deadline := time.Now().Add(time.Second)
	for len(h.terminationCallbacks) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(h.terminationCallbacks) != 0 {
		t.Fatal("callback slot not released")
	}
	if h.metrics.terminationAccepted.Load() != 1 || h.metrics.terminationDropped.Load() != 1 {
		t.Fatal("accepted/drop notification observations incorrect")
	}
	select {
	case <-a.entered:
		t.Fatal("saturated event not dropped")
	default:
	}
}

func TestTypedTerminationClientAccepts204(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/app-access/stream-terminated" || r.Header.Get("Authorization") != "AppProxy tnxap_fixture" {
			t.Error("wrong private consumer request")
		}
		var in authoritywire.AppProxyStreamTerminatedInput
		if json.NewDecoder(r.Body).Decode(&in) != nil || in.StreamID != "exact-stream" || in.Reason != authoritywire.AppProxyConnectionClosed {
			t.Error("wrong typed termination payload")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	client, err := NewClient(server.URL, "tnxap_fixture", &tls.Config{RootCAs: roots, ServerName: "example.com", MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	if err = client.Terminated(context.Background(), authoritywire.AppProxyStreamTerminatedInput{StreamID: "exact-stream", Reason: authoritywire.AppProxyConnectionClosed}); err != nil {
		t.Fatal(err)
	}
}
