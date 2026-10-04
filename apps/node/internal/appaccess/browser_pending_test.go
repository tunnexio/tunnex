package appaccess

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/packages/apptransport"
	"github.com/tunnexio/tunnex/packages/apptransport/originpolicy"
)

func TestBrowserPoolPendingActualOriginDiagnosticOnly(t *testing.T) {
	leaf, caPEM := browserCertificates(t)
	serverPEM, key := leaf(4, true)
	serverCert, _ := tls.X509KeyPair(serverPEM, key)
	clientPEM, clientKey := leaf(2, false)
	clientCert, _ := tls.X509KeyPair(clientPEM, clientKey)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	b := apptransport.Binding{OrgID: "11111111-1111-1111-1111-111111111111", GatewayID: "22222222-2222-2222-2222-222222222222", AppID: "33333333-3333-3333-3333-333333333333", Generation: "44444444-4444-4444-4444-444444444444", Revision: 2, AuthorityVersion: 2, Digest: strings.Repeat("b", 64), Hostname: "app.apps.example.net", Purpose: "browser_proxy"}
	broker := apptransport.NewBrowserBroker(func(_ context.Context, binding apptransport.Binding, serial string) (time.Time, error) {
		if binding != b || serial != "2" {
			return time.Time{}, apptransport.ErrUnavailable
		}
		return time.Now().Add(3 * time.Second), nil
	})
	defer broker.Close()
	gateway := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { broker.Accept(w, r, b, "2") }))
	gateway.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	gateway.StartTLS()
	defer gateway.Close()
	var hits atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != "/" || r.Header.Get("Cookie") != "" {
			t.Error("probe forwarded arbitrary content")
		}
		w.WriteHeader(401)
	}))
	defer origin.Close()
	checker := originpolicy.Checker{Lookup: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("10.1.2.3")}, nil
	}, Dial: func(ctx context.Context, _, address string) (net.Conn, error) {
		if address != "10.1.2.3:80" {
			t.Error(address)
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", origin.Listener.Addr().String())
	}}
	pool, err := NewBrowserPool(gateway.URL, &tls.Config{RootCAs: roots, GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &clientCert, nil }}, checker)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	defer pool.Close()
	policy, _ := originpolicy.Normalize([]string{"10.1.2.0/24"}, "")
	assignment := BrowserAssignment{Binding: b, OriginURL: "http://origin.example.com", Policy: policy, Stage: "pending", OperationID: "77777777-7777-7777-7777-777777777777", ReadinessRequestID: "88888888-8888-8888-8888-888888888888", Deadline: time.Now().Add(time.Minute)}
	pool.Sync(ctx, []BrowserAssignment{assignment})
	send := func(path string, diagnostic bool) *http.Response {
		t.Helper()
		conn, serial, err := broker.DialAuthenticated(ctx, b)
		if err != nil || serial != "2" {
			t.Fatal(serial, err)
		}
		tr := &http.Transport{DisableKeepAlives: true, DialContext: func(context.Context, string, string) (net.Conn, error) { return conn, nil }}
		request, _ := http.NewRequestWithContext(ctx, "GET", "http://connector.internal"+path, nil)
		request.Host = b.Hostname
		apptransport.BindingHeaders(request.Header, b)
		if diagnostic {
			request.Header.Set("X-App-Operation-ID", assignment.OperationID)
			request.Header.Set("X-App-Readiness-ID", assignment.ReadinessRequestID)
		} else {
			request.Header.Set("X-App-Stream-ID", "browser-stream")
		}
		response, err := tr.RoundTrip(request)
		if err != nil {
			conn.Close()
			t.Fatal(err)
		}
		return response
	}
	refused := send("/private-data", false)
	if refused.StatusCode != 403 {
		t.Fatal("pending origin forwarded browser traffic")
	}
	refused.Body.Close()
	if hits.Load() != 0 {
		t.Fatal("pending reached origin")
	}
	response := send(apptransport.BrowserReadinessPath, true)
	defer response.Body.Close()
	var result originpolicy.Result
	if response.StatusCode != 200 || json.NewDecoder(response.Body).Decode(&result) != nil || result.Status != "ready" || result.HTTPStatus != 401 || hits.Load() != 1 {
		t.Fatal("missing actual origin readiness", response.StatusCode, result, hits.Load())
	}
}
