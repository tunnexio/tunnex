package control

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestAIVPNTransportUsesCurrentCertificateAfterRenewAndRecovery(t *testing.T) {
	ca := newTestCA(t)
	var mu sync.Mutex
	var seen []string
	mux := http.NewServeMux()
	mux.HandleFunc("/agent/ai-http/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) != 1 {
			t.Error("missing authenticated node identity")
			w.WriteHeader(401)
			return
		}
		mu.Lock()
		seen = append(seen, r.TLS.PeerCertificates[0].SerialNumber.String())
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/agent/renew", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		block, _ := pem.Decode(body)
		if block == nil {
			t.Error("bad CSR")
			w.WriteHeader(500)
			return
		}
		cert, _ := ca.sign(t, block.Bytes, x509.ExtKeyUsageClientAuth)
		_, _ = w.Write([]byte(cert))
	})
	srvKey, srvCSR, err := GenerateKeyAndCSR("tunnex-control")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(srvCSR)
	srvCertPEM, _ := ca.sign(t, block.Bytes, x509.ExtKeyUsageServerAuth)
	srvCert, err := tls.X509KeyPair([]byte(srvCertPEM), srvKey)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.pem)
	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{srvCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	srv.StartTLS()
	defer srv.Close()
	cert, key := ca.clientCert(t, "gateway-one")
	client, err := NewClient(srv.URL, "tunnex-control", "gateway-one", cert, key, ca.pem)
	if err != nil {
		t.Fatal(err)
	}
	target, transport, err := client.AIVPNTransport()
	if err != nil {
		t.Fatal(err)
	}
	defer transport.(*http.Transport).CloseIdleConnections()
	request := func() {
		t.Helper()
		r, err := http.NewRequestWithContext(t.Context(), http.MethodPost, target.String()+"/agent/ai-http/v1/chat/completions", nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := transport.RoundTrip(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != 204 {
			t.Fatalf("status=%d", response.StatusCode)
		}
	}
	request()
	if _, _, err := client.Renew(t.Context(), "test"); err != nil {
		t.Fatal(err)
	}
	request()
	recoveredCert, recoveredKey := ca.clientCert(t, "gateway-one")
	if err := client.AdoptCredentials(recoveredCert, recoveredKey); err != nil {
		t.Fatal(err)
	}
	request()
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 3 || seen[0] == seen[1] || seen[1] == seen[2] || seen[0] == seen[2] {
		t.Fatalf("inference retained an old TLS identity: %v", seen)
	}
}

func TestAIVPNTransportRefusesUntrustedControlConfiguration(t *testing.T) {
	ca := newTestCA(t)
	cert, key := ca.clientCert(t, "gateway-one")
	for _, base := range []string{"http://control:8443", "https://user:password@control:8443", "https://control:8443/path", "https://control:8443?override=true", "https://control:8443#fragment"} {
		t.Run(base, func(t *testing.T) {
			client, err := NewClient(base, "tunnex-control", "gateway-one", cert, key, ca.pem)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err = client.AIVPNTransport(); err == nil {
				t.Fatal("invalid control origin accepted")
			}
		})
	}
	client, err := NewClient("https://control:8443", "tunnex-control", "gateway-one", cert, key, ca.pem)
	if err != nil {
		t.Fatal(err)
	}
	client.http.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = true
	if _, _, err := client.AIVPNTransport(); err == nil {
		t.Fatal("disabled TLS verification accepted")
	}
}

func TestReportInfoCarriesDedicatedAIVPNReadiness(t *testing.T) {
	var gotReady bool
	var gotAddress string
	client := &Client{base: "http://unused.test", http: &http.Client{Transport: reportCaptureTransport{capture: func(ready bool, address string) { gotReady = ready; gotAddress = address }}}}
	for _, tc := range []PolicyStatus{{AIVPNHTTPReady: true, AIVPNHTTPAddress: "10.77.0.9"}, {}} {
		if err := client.ReportInfo(t.Context(), "public-key", "endpoint.test:51820", true, false, tc); err != nil {
			t.Fatal(err)
		}
		if gotReady != tc.AIVPNHTTPReady || gotAddress != tc.AIVPNHTTPAddress {
			t.Fatalf("readiness=%v address=%q", gotReady, gotAddress)
		}
	}
}

type reportCaptureTransport struct{ capture func(bool, string) }

func (tr reportCaptureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	var payload struct {
		Ready   bool   `json:"ai_vpn_http_ready"`
		Address string `json:"ai_vpn_http_address"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		return nil, err
	}
	tr.capture(payload.Ready, payload.Address)
	return &http.Response{StatusCode: http.StatusNoContent, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
}
