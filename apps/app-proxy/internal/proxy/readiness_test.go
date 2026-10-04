package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/packages/apptransport"
	"github.com/tunnexio/tunnex/packages/apptransport/authoritywire"
	"github.com/tunnexio/tunnex/packages/apptransport/originpolicy"
)

type readinessFixture struct {
	deniedAuthority
	binding Binding
	work    authoritywire.AppProxyReadinessWork
	reports chan authoritywire.AppProxyReadinessReportInput
}

func (a *readinessFixture) Channel(_ context.Context, b Binding, serial string) (time.Time, error) {
	if b != a.binding || serial != "2" {
		return time.Time{}, ErrDenied
	}
	return time.Now().Add(3 * time.Second), nil
}
func (a *readinessFixture) ClaimReadiness(context.Context, authoritywire.AppProxyReadinessClaimInput) (authoritywire.AppProxyReadinessClaimResult, error) {
	return authoritywire.AppProxyReadinessClaimResult{}, nil
}
func (a *readinessFixture) ReportReadiness(_ context.Context, input authoritywire.AppProxyReadinessReportInput) (authoritywire.AppProxyReadinessReportResult, error) {
	a.reports <- input
	return authoritywire.AppProxyReadinessReportResult{}, nil
}

func TestReadinessActualPendingChannelAndSameInstancePublicTLS(t *testing.T) {
	leaf, caPEM := browserCertificates(t)
	serverPEM, key := leaf(4, true)
	serverCert, _ := tls.X509KeyPair(serverPEM, key)
	clientPEM, clientKey := leaf(2, false)
	clientCert, _ := tls.X509KeyPair(clientPEM, clientKey)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	b := launchBinding()
	a := &readinessFixture{binding: b, reports: make(chan authoritywire.AppProxyReadinessReportInput, 1)}
	broker, gatewayHandler := NewGateway("apps.example.net", a)
	defer broker.Close()
	gateway := httptest.NewUnstartedServer(gatewayHandler)
	gateway.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	gateway.StartTLS()
	defer gateway.Close()
	worker, err := NewReadinessWorker("apps.example.net", a, broker)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler("apps.example.net", a, broker)
	handler.Readiness = worker
	public := httptest.NewUnstartedServer(handler)
	public.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert}}
	public.StartTLS()
	defer public.Close()
	work := authoritywire.AppProxyReadinessWork{OperationID: "77777777-7777-7777-7777-777777777777", ReadinessRequestID: "88888888-8888-8888-8888-888888888888", Version: 1, Route: Route{Binding: authoritywire.AppProxyRouteBinding(b)}, Deadline: time.Now().Add(time.Minute)}
	work.ChallengeToken = challengeToken(worker.instance, work.ReadinessRequestID)
	// Explicit fixture-only loopback physical dial and owned CA; shipping probe
	// still rejects loopback and trusts system roots only.
	worker.PublicProbe = func(ctx context.Context, host, id, challenge, hash string) (string, string, string) {
		return probePublicAddresses(ctx, host, id, challenge, hash, []netip.Addr{netip.MustParseAddr("93.184.216.34")}, &tls.Config{MinVersion: tls.VersionTLS13, ServerName: host, RootCAs: roots}, func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", public.Listener.Addr().String())
		})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	u, _ := url.Parse(gateway.URL)
	conn, err := tls.Dial("tcp", u.Host, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "tunnex-app-proxy", Certificates: []tls.Certificate{clientCert}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	request := &http.Request{Method: "CONNECT", URL: &url.URL{Opaque: "/app-access/channel"}, Host: u.Host, Header: make(http.Header)}
	apptransport.BindingHeaders(request.Header, b.Transport())
	if err = request.Write(conn); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, request)
	if err != nil || response.StatusCode != 200 {
		t.Fatal(response, err)
	}
	tracked := &fixtureConn{Conn: conn, reader: reader, done: make(chan struct{})}
	listener := &fixtureListener{conn: tracked}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" || r.Header.Get("Cookie") != "" {
			t.Error("readiness reached app data")
		}
		w.WriteHeader(401)
	}))
	defer origin.Close()
	policy, _ := originpolicy.Normalize([]string{"10.1.2.0/24"}, "")
	checker := originpolicy.Checker{Lookup: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("10.1.2.3")}, nil
	}, Dial: func(ctx context.Context, _, address string) (net.Conn, error) {
		if address != "10.1.2.3:80" {
			t.Error(address)
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", origin.Listener.Addr().String())
	}}
	server := &http.Server{Handler: apptransport.BrowserReadiness(b.Transport(), work.OperationID, work.ReadinessRequestID, work.Deadline, func(ctx context.Context) originpolicy.Result {
		return checker.Check(ctx, "http://origin.example.com", policy)
	}, make(chan struct{}, 8))}
	var wait sync.WaitGroup
	wait.Add(1)
	go func() { defer wait.Done(); _ = server.Serve(listener) }()
	defer func() { server.Close(); tracked.Close(); wait.Wait() }()
	worker.round(ctx, work)
	select {
	case report := <-a.reports:
		if report.CertificateSerial != "2" || report.Binding != work.Route.Binding || report.PublicDNSStatus != "passed" || report.PublicTLSStatus != "passed" || report.DNSStatus != "passed" || report.ConnectStatus != "passed" || report.TLSStatus != "skipped" || report.ErrorCode != "" || report.InstanceToken != worker.instance {
			t.Fatalf("incorrect proof: %+v", report)
		}
	case <-ctx.Done():
		t.Fatal("no readiness report")
	}
	// Pending authority remains absent from public route lookup.
	denied := httptest.NewRecorder()
	handler.ServeHTTP(denied, appRequest("GET", "/", ""))
	if denied.Code != 403 {
		t.Fatal("pending route exposed")
	}
	challenge := httptest.NewRecorder()
	handler.ServeHTTP(challenge, appRequest("GET", PublicReadinessPath+"?request_id="+work.ReadinessRequestID, ""))
	if challenge.Code != 403 {
		t.Fatal("completed challenge retained")
	}
}
func TestStrictPublicReadinessRejectsLoopback(t *testing.T) {
	dns, tlsStatus, code := StrictPublicProbe(context.Background(), "127.0.0.1", "id", "challenge", "hash")
	if dns != "failed" || tlsStatus != "pending" || code != "public_dns_failed" {
		t.Fatal(dns, tlsStatus, code)
	}
}

func TestPublicReadinessChallengeTrustAndBoundedResponse(t *testing.T) {
	leaf, caPEM := browserCertificates(t)
	pem, key := leaf(4, true)
	cert, _ := tls.X509KeyPair(pem, key)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	for _, mode := range []string{"valid", "wrong_request", "wrong_challenge", "wrong_instance", "redirect", "oversized", "unknown_ca"} {
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" || r.Host != "app.apps.example.net" {
				t.Error("challenge leaked credentials or lost registered hostname")
			}
			if mode == "redirect" {
				w.Header().Set("Location", "https://external.example.com")
				w.WriteHeader(302)
				return
			}
			if mode == "oversized" {
				w.Write([]byte(strings.Repeat(" ", 4097)))
				return
			}
			id, challenge, hash := "id", "challenge", "hash"
			if mode == "wrong_request" {
				id = "other"
			}
			if mode == "wrong_challenge" {
				challenge = "other"
			}
			if mode == "wrong_instance" {
				hash = "other"
			}
			json.NewEncoder(w).Encode(map[string]string{"request_id": id, "challenge_token": challenge, "instance_hash": hash})
		}))
		server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}
		server.StartTLS()
		config := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: "app.apps.example.net", RootCAs: roots}
		if mode == "unknown_ca" {
			config.RootCAs = x509.NewCertPool()
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		dns, tlsStatus, code := probePublicAddresses(ctx, "app.apps.example.net", "id", "challenge", "hash", []netip.Addr{netip.MustParseAddr("93.184.216.34")}, config, func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
		})
		cancel()
		server.Close()
		if dns != "passed" {
			t.Fatal(mode, dns)
		}
		if mode == "valid" {
			if tlsStatus != "passed" || code != "" {
				t.Fatal(mode, tlsStatus, code)
			}
		} else if mode == "unknown_ca" {
			if tlsStatus != "failed" || code != "public_tls_failed" {
				t.Fatal(mode, tlsStatus, code)
			}
		} else if code != "public_challenge_failed" {
			t.Fatal(mode, code)
		}
	}
}

func TestPublicReadinessRejectsHeaderPresenceAndHiddenDuplicates(t *testing.T) {
	a := &readinessFixture{binding: launchBinding()}
	worker, err := NewReadinessWorker("apps.example.net", a, nil)
	if err != nil {
		t.Fatal(err)
	}
	work := authoritywire.AppProxyReadinessWork{Route: Route{Binding: authoritywire.AppProxyRouteBinding(a.binding)}, ReadinessRequestID: "request", ChallengeToken: "challenge"}
	worker.challenges["request"] = readinessChallenge{work: work, expires: time.Now().Add(time.Minute)}
	for _, name := range []string{"Cookie", "Authorization", "Upgrade"} {
		for _, duplicate := range []bool{false, true} {
			request := appRequest("GET", PublicReadinessPath+"?request_id=request", "")
			request.Header.Del("Cookie")
			request.Header.Add(name, "")
			if duplicate {
				request.Header.Add(name, "secret")
			}
			response := httptest.NewRecorder()
			worker.Challenge(response, request, a.binding.Hostname)
			if response.Code != 403 {
				t.Fatal(name, duplicate, "header presence accepted")
			}
		}
	}
}
