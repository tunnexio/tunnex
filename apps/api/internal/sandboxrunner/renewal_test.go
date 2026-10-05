package sandboxrunner

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestAuthenticatedRenewalPersistsAcrossRestart(t *testing.T) {
	controllerURI := "spiffe://tunnex/controller/renewal"
	runnerURI := "spiffe://tunnex/runner/renewal"
	enrollment, e := Enroll("localhost", controllerURI, runnerURI, time.Now().Add(-13*time.Hour))
	if e != nil {
		t.Fatal(e)
	}
	controller, e := tls.X509KeyPair(enrollment.ControllerCertificate, enrollment.ControllerKey)
	if e != nil {
		t.Fatal(e)
	}
	runner, e := tls.X509KeyPair(enrollment.RunnerCertificate, enrollment.RunnerKey)
	if e != nil {
		t.Fatal(e)
	}
	issuer, e := NewIssuer(enrollment.CA, enrollment.ControllerCAKey, controller, runnerURI)
	if e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(enrollment.CA)
	broker, _ := NewBroker(runnerURI)
	broker.Renew = issuer.RenewRunner
	server := httptest.NewUnstartedServer(broker)
	server.TLS, e = TLSConfig(controller, roots)
	if e != nil {
		t.Fatal(e)
	}
	server.TLS.Certificates = nil
	server.TLS.GetCertificate = issuer.GetCertificate
	server.StartTLS()
	defer server.Close()
	root, e := os.OpenRoot(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	client, e := NewClient(server.URL, "localhost", controllerURI, runner, roots, root)
	if e != nil {
		t.Fatal(e)
	}
	before := client.certificate.Leaf.SerialNumber.String()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if e = client.renewIfDue(ctx); e != nil {
		t.Fatal(e)
	}
	if client.certificate.Leaf.SerialNumber.String() == before || time.Until(client.certificate.Leaf.NotAfter) < 23*time.Hour {
		t.Fatal("certificate did not renew")
	}
	restarted, e := NewClient(server.URL, "localhost", controllerURI, runner, roots, root)
	if e != nil {
		t.Fatal(e)
	}
	if restarted.certificate.Leaf.SerialNumber.Cmp(client.certificate.Leaf.SerialNumber) != 0 {
		t.Fatal("renewal lost at restart")
	}
}
func TestRevokedBrokerDeniesControlAndRenewal(t *testing.T) {
	broker, _ := NewBroker("spiffe://tunnex/runner/revoked")
	broker.Revoked = true
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, e := broker.Call(ctx, json.RawMessage(`{}`)); e != ErrUnavailable {
		t.Fatal("revoked admitted", e)
	}
	for _, path := range []string{"poll", "renew"} {
		if w := request(broker, "/internal/sandbox-runners/v1/"+path, nil, true); w.Code != 403 {
			t.Fatal("revoked peer admitted", path, w.Code)
		}
	}
}
