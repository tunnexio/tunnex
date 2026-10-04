package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/packages/apptransport"
	"github.com/tunnexio/tunnex/packages/apptransport/authoritywire"
)

type domainChannelFixture struct {
	domainFixture
	binding      Binding
	channelCalls atomic.Int32
}

func (a *domainChannelFixture) Channel(_ context.Context, binding Binding, serial string) (time.Time, error) {
	a.channelCalls.Add(1)
	if binding != a.binding || serial != "2" {
		return time.Time{}, ErrDenied
	}
	return time.Now().Add(3 * time.Second), nil
}

func TestDynamicGatewayRetainsExactCertificateAndPublishedBinding(t *testing.T) {
	authority := &domainChannelFixture{binding: launchBinding()}
	broker, handler := NewGateway("new.internal.tunnex.app", authority)
	defer broker.Close()
	leaf, ca := browserCertificates(t)
	serverPEM, serverKey := leaf(4, true)
	serverCert, err := tls.X509KeyPair(serverPEM, serverKey)
	if err != nil {
		t.Fatal(err)
	}
	clientPEM, clientKey := leaf(2, false)
	clientCert, err := tls.X509KeyPair(clientPEM, clientKey)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("fixture roots")
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	server.StartTLS()
	defer server.Close()
	u, _ := url.Parse(server.URL)
	for _, tc := range []struct {
		hostname string
		status   int
	}{{authority.binding.Hostname, http.StatusOK}, {"unknown.internal.tunnex.app", http.StatusForbidden}, {"127.0.0.1", http.StatusForbidden}} {
		t.Run(tc.hostname, func(t *testing.T) {
			conn, err := tls.Dial("tcp", u.Host, &tls.Config{MinVersion: tls.VersionTLS13, ServerName: "tunnex-app-proxy", RootCAs: roots, Certificates: []tls.Certificate{clientCert}})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			binding := authority.binding.Transport()
			binding.Hostname = tc.hostname
			request := &http.Request{Method: "CONNECT", URL: &url.URL{Opaque: "/app-access/channel"}, Host: u.Host, Header: make(http.Header)}
			apptransport.BindingHeaders(request.Header, binding)
			if err := request.Write(conn); err != nil {
				t.Fatal(err)
			}
			response, err := http.ReadResponse(bufio.NewReader(conn), request)
			if err != nil || response.StatusCode != tc.status {
				t.Fatalf("channel %q: %v %v", tc.hostname, response, err)
			}
		})
	}
	if authority.channelCalls.Load() != 2 {
		t.Fatal("canonical DNS host did not reach exact channel authority, or IP bypassed the syntax guard")
	}
}

type domainReadinessFixture struct{ domainFixture }

func (a *domainReadinessFixture) ClaimReadiness(_ context.Context, input authoritywire.AppProxyReadinessClaimInput) (authoritywire.AppProxyReadinessClaimResult, error) {
	work := authoritywire.AppProxyReadinessWork{OperationID: "77777777-7777-7777-7777-777777777777", ReadinessRequestID: "88888888-8888-8888-8888-888888888888", Version: 1, Route: domainRoute("test.internal.tunnex.app"), Deadline: time.Now().Add(30 * time.Second)}
	work.ChallengeToken = challengeToken(input.InstanceToken, work.ReadinessRequestID)
	bad := work
	bad.ReadinessRequestID = "99999999-9999-9999-9999-999999999999"
	bad.ChallengeToken = challengeToken(input.InstanceToken, bad.ReadinessRequestID)
	bad.Route = domainRoute("127.0.0.1")
	return authoritywire.AppProxyReadinessClaimResult{Items: []authoritywire.AppProxyReadinessWork{bad, work}}, nil
}
func (*domainReadinessFixture) ReportReadiness(context.Context, authoritywire.AppProxyReadinessReportInput) (authoritywire.AppProxyReadinessReportResult, error) {
	return authoritywire.AppProxyReadinessReportResult{}, nil
}

func TestDynamicReadinessUsesExactClaimedHostAfterBaseChange(t *testing.T) {
	broker := apptransport.NewBrowserBroker(nil)
	defer broker.Close()
	worker, err := NewReadinessWorker("old.example.net", &domainReadinessFixture{}, broker)
	if err != nil {
		t.Fatal(err)
	}
	probed := make(chan string, 2)
	worker.PublicProbe = func(_ context.Context, host, _, _, _ string) (string, string, string) {
		probed <- host
		return "failed", "pending", "fixture_probe"
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); worker.Run(ctx) }()
	select {
	case host := <-probed:
		if host != "test.internal.tunnex.app" {
			t.Fatalf("malformed claimed hostname reached probe: %s", host)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("new domain blocked by stale base-domain suffix")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("readiness did not stop with its context")
	}
	select {
	case host := <-probed:
		t.Fatalf("unexpected probe: %s", host)
	default:
	}
}
