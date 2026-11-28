package control

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// mtlsControl starts an mTLS control plane serving mux and returns a client with a rotating node identity.
func mtlsControl(t *testing.T, mux http.Handler) *Client {
	t.Helper()
	ca := newTestCA(t)
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
	t.Cleanup(srv.Close)
	cert, key := ca.clientCert(t, "gateway-one")
	client, err := NewClient(srv.URL, "tunnex-control", "gateway-one", cert, key, ca.pem)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

const desiredJSON = `{"version":1,"endpoint":{"id":"0b6f7c1e-3a52-4c1d-9e8f-2a7b5c4d3e21","revision":3,"listen_addresses":["10.123.0.1","192.168.10.5"],"port":9443,"dns_name":"ai.internal.example","source_cidrs":["10.20.0.0/16"],"tls_mode":"tunnex_ca"}}`

func TestAIInternalDesiredStateReadsTheDocumentOverMTLS(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /agent/ai-internal/desired-state", func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) != 1 || r.TLS.PeerCertificates[0].Subject.CommonName != "gateway-one" {
			w.WriteHeader(401)
			return
		}
		_, _ = io.WriteString(w, desiredJSON)
	})
	got, err := mtlsControl(t, mux).AIInternalDesiredState(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	ep := got.Endpoint
	if got.Version != 1 || ep == nil || ep.ID != "0b6f7c1e-3a52-4c1d-9e8f-2a7b5c4d3e21" || ep.Revision != 3 || ep.Port != 9443 ||
		ep.DNSName != "ai.internal.example" || ep.TLSMode != "tunnex_ca" || len(ep.ListenAddresses) != 2 || len(ep.SourceCIDRs) != 1 {
		t.Fatalf("document: %+v %+v", got, ep)
	}
}

func TestAIInternalDesiredStateSeparatesOffFromTransient(t *testing.T) {
	for name, tc := range map[string]struct {
		handler func(http.ResponseWriter, *http.Request)
		off     bool
	}{
		"404 from an older control plane": {func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(404) }, true},
		"403 refused node":                {func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(403) }, true},
		"redirect not followed": {func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://elsewhere.test/agent/ai-internal/desired-state", http.StatusFound)
		}, true},
		"unreadable document": {func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "{not json") }, true},
		"oversized document": {func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, `{"version":1,"pad":"`+strings.Repeat("a", 70<<10)+`"}`)
		}, true},
		"503": {func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) }, false},
	} {
		t.Run(name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/agent/ai-internal/desired-state", tc.handler)
			_, err := mtlsControl(t, mux).AIInternalDesiredState(t.Context())
			if err == nil || errors.Is(err, ErrAIInternalOff) != tc.off {
				t.Fatalf("err=%v off=%v", err, errors.Is(err, ErrAIInternalOff))
			}
		})
	}
}

func TestAIInternalRefusesAPlainOrUnauthenticatedChannel(t *testing.T) {
	ca := newTestCA(t)
	cert, key := ca.clientCert(t, "gateway-one")
	client, err := NewClient("http://control:8443", "tunnex-control", "gateway-one", cert, key, ca.pem)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.AIInternalDesiredState(t.Context()); !errors.Is(err, ErrAIInternalOff) {
		t.Fatalf("plain HTTP control: %v", err)
	}
	if _, err := client.AIInternalSign(t.Context(), "csr"); err == nil {
		t.Fatal("a CSR was sent over plain HTTP")
	}
	if _, _, err := client.AIInternalTransport(); err == nil {
		t.Fatal("a relay transport over plain HTTP")
	}
}

func TestAIInternalSignPostsTheCSRAndReadsTheLeaf(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /agent/ai-internal/certificate", func(w http.ResponseWriter, r *http.Request) {
		var in map[string]string
		if r.Header.Get("Content-Type") != "application/json" || json.NewDecoder(r.Body).Decode(&in) != nil || len(in) != 1 || in["csr_pem"] != "CSR-PEM" {
			w.WriteHeader(400)
			return
		}
		_, _ = io.WriteString(w, `{"certificate_pem":"LEAF","chain_pem":"CA","not_after":"2026-12-28T00:00:00Z"}`)
	})
	client := mtlsControl(t, mux)
	got, err := client.AIInternalSign(t.Context(), "CSR-PEM")
	if err != nil || got.CertificatePEM != "LEAF" || got.ChainPEM != "CA" || got.NotAfter != "2026-12-28T00:00:00Z" {
		t.Fatalf("got=%+v err=%v", got, err)
	}
	conflict := http.NewServeMux()
	conflict.HandleFunc("POST /agent/ai-internal/certificate", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(409)
		_, _ = io.WriteString(w, `{"error":"secret detail"}`)
	})
	_, err = mtlsControl(t, conflict).AIInternalSign(t.Context(), "CSR-PEM")
	if err == nil || strings.Contains(err.Error(), "secret detail") {
		t.Fatalf("409: %v", err)
	}
}

func TestReportInfoCarriesTheInternalAIEndpoint(t *testing.T) {
	var payload map[string]any
	client := &Client{base: "http://unused.test", http: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		payload = nil
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: http.StatusNoContent, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
	})}}
	ps := PolicyStatus{AIInternalEndpointVersion: 1, AIInternalEndpointReady: true, AIInternalEndpointAddresses: []string{"10.123.0.1", "192.168.10.5"},
		AIInternalEndpointPort: 9443, AIInternalEndpointRevision: 3, AIInternalEndpointError: strings.Repeat("e", 300),
		AIInternalEndpointCertNotAfter: "2026-12-28T00:00:00Z", AIInternalEndpointCertSHA256: strings.Repeat("ab", 32)}
	if err := client.ReportInfo(t.Context(), "public-key", "endpoint.test:51820", true, false, ps); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"ai_internal_endpoint_version": float64(1), "ai_internal_endpoint_ready": true,
		"ai_internal_endpoint_port": float64(9443), "ai_internal_endpoint_revision": float64(3),
		"ai_internal_endpoint_cert_not_after": "2026-12-28T00:00:00Z", "ai_internal_endpoint_cert_sha256": strings.Repeat("ab", 32)}
	for k, v := range want {
		if payload[k] != v {
			t.Fatalf("%s=%v want %v", k, payload[k], v)
		}
	}
	if addrs, ok := payload["ai_internal_endpoint_addresses"].([]any); !ok || len(addrs) != 2 || addrs[0] != "10.123.0.1" {
		t.Fatalf("addresses=%v", payload["ai_internal_endpoint_addresses"])
	}
	if e, _ := payload["ai_internal_endpoint_error"].(string); len(e) != 256 {
		t.Fatalf("the error is not bounded: %d", len(e))
	}
	if err := client.ReportInfo(t.Context(), "public-key", "endpoint.test:51820", true, false, PolicyStatus{}); err != nil {
		t.Fatal(err)
	}
	if addrs, ok := payload["ai_internal_endpoint_addresses"].([]any); !ok || len(addrs) != 0 {
		t.Fatalf("an absent listener reports addresses=%#v, want []", payload["ai_internal_endpoint_addresses"])
	}
	if payload["ai_internal_endpoint_version"] != float64(0) || payload["ai_internal_endpoint_ready"] != false {
		t.Fatalf("an absent listener: %v %v", payload["ai_internal_endpoint_version"], payload["ai_internal_endpoint_ready"])
	}
}
