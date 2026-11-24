package control

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// AA-EN-1 E5: the endpoint is read over the mTLS agent channel; an older
// control plane (404) maps to ErrProxyEndpointUnsupported so the gateway keeps
// its current behaviour.
func TestAppProxyEndpointOverAgentChannel(t *testing.T) {
	ca := newTestCA(t)
	status := http.StatusNotFound
	mux := http.NewServeMux()
	mux.HandleFunc("/agent/app-access/proxy-endpoint", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.TLS == nil || len(r.TLS.PeerCertificates) != 1 {
			t.Error("endpoint must be a GET on the mTLS agent channel")
		}
		w.WriteHeader(status)
		if status == http.StatusOK {
			_, _ = w.Write([]byte(`{"enabled":true,"port":8444,"host":"10.70.0.2"}`))
		}
	})
	srvKeyPEM, srvCSR, _ := GenerateKeyAndCSR("tunnex-control")
	blk, _ := pem.Decode(srvCSR)
	srvCertPEM, _ := ca.sign(t, blk.Bytes, x509.ExtKeyUsageServerAuth)
	srvCert, _ := tls.X509KeyPair([]byte(srvCertPEM), srvKeyPEM)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.pem)
	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{srvCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	srv.StartTLS()
	defer srv.Close()
	certPEM, keyPEM := ca.clientCert(t, "gw-1")
	client, err := NewClient(srv.URL, "tunnex-control", "gw-1", certPEM, keyPEM, ca.pem)
	if err != nil {
		t.Fatal(err)
	}
	if client.AgentHost() != "127.0.0.1" {
		t.Fatalf("agent host = %q", client.AgentHost())
	}
	if _, err := client.AppProxyEndpoint(t.Context()); !errors.Is(err, ErrProxyEndpointUnsupported) {
		t.Fatalf("old control plane = %v", err)
	}
	status = http.StatusServiceUnavailable
	if _, err := client.AppProxyEndpoint(t.Context()); err == nil || errors.Is(err, ErrProxyEndpointUnsupported) {
		t.Fatalf("503 = %v, want a plain error (keep state)", err)
	}
	status = http.StatusOK
	got, err := client.AppProxyEndpoint(t.Context())
	if err != nil || got != (AppProxyEndpoint{Enabled: true, Port: 8444, Host: "10.70.0.2"}) {
		t.Fatalf("delivered = %+v, %v", got, err)
	}
}
