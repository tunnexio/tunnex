package sandboxes

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxrunner"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxruntime"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestRemoteOfflineFenceExactExpiredIdentity(t *testing.T) {
	b := persistentTestBinding()
	server, client, provider := persistentRPCFixture(t, b)
	now := time.Now().UTC()
	a := RuntimeAuthorization{SandboxID: uuid.New(), OrgID: b.OrgID, CreatorID: b.CreatorID, GatewayID: b.GatewayID, TerminalDeviceID: b.TerminalDeviceID, TemplateID: b.Profiles[0].TemplateID, Profile: b.Profiles[0], Generation: 1, Desired: "stopped", CreatedAt: now.Add(-901 * time.Second), ExpiresAt: now.Add(-time.Second)}
	if e := client.AuthorizeRuntime(context.Background(), a); e != nil {
		t.Fatal(e)
	}
	hash, _ := sandboxruntime.Fingerprint(a.spec())
	provider.status = sandboxruntime.Status{Exists: true, Running: true, RuntimeID: strings.Repeat("a", 64), ImageDigest: a.Profile.ConfigDigest, SpecHash: hash}
	lease := sandboxrunner.Lease{SandboxID: a.SandboxID, Generation: a.Generation, CreatedAt: a.CreatedAt, ExpiresAt: a.ExpiresAt}
	wrong := lease
	wrong.SandboxID = uuid.New()
	if server.FenceExpiredRuntime(context.Background(), wrong) == nil {
		t.Fatal("foreign workload fenced")
	}
	if !provider.status.Running {
		t.Fatal("foreign call stopped workload")
	}
	if e := server.FenceExpiredRuntime(context.Background(), lease); e != nil {
		t.Fatal(e)
	}
	if provider.status.Running {
		t.Fatal("expiry did not stop")
	}
	if e := server.FenceExpiredRuntime(context.Background(), lease); e != nil {
		t.Fatal("retry not idempotent", e)
	}
	if server.active.Desired != "stopped" || server.active.Generation != 1 {
		t.Fatal("offline fence changed canonical intent")
	}
}

func TestRemoteRuntimeActualTLSRPC(t *testing.T) {
	b := persistentTestBinding()
	worker, _, _ := persistentRPCFixture(t, b)
	enrollment, e := sandboxrunner.Enroll("localhost", "spiffe://tunnex/controller/fixture", "spiffe://tunnex/runner/fixture", time.Now().UTC())
	if e != nil {
		t.Fatal(e)
	}
	controller, e := tls.X509KeyPair(enrollment.ControllerCertificate, enrollment.ControllerKey)
	if e != nil {
		t.Fatal(e)
	}
	runnerCert, e := tls.X509KeyPair(enrollment.RunnerCertificate, enrollment.RunnerKey)
	if e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(enrollment.CA) {
		t.Fatal("CA")
	}
	broker, _ := sandboxrunner.NewBroker("spiffe://tunnex/runner/fixture")
	server := httptest.NewUnstartedServer(broker)
	server.TLS, e = sandboxrunner.TLSConfig(controller, roots)
	if e != nil {
		t.Fatal(e)
	}
	server.StartTLS()
	defer server.Close()
	root, e := os.OpenRoot(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	runner, e := sandboxrunner.NewClient(server.URL, "localhost", "spiffe://tunnex/controller/fixture", runnerCert, roots, root)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- worker.RunRemoteWorker(ctx, runner, sandboxrunner.LeaseStore{Root: root}) }()
	apiClient := &WorkerRPCClient{client: &http.Client{Transport: brokerTransport{broker}, Timeout: 5 * time.Second}, probe: worker.Identity.PublicKey()}
	if e = apiClient.CheckBinding(ctx, b); e != nil {
		t.Fatal("remote binding", e)
	}
	now := time.Now().UTC()
	a := RuntimeAuthorization{SandboxID: uuid.New(), OrgID: b.OrgID, CreatorID: b.CreatorID, GatewayID: b.GatewayID, TerminalDeviceID: b.TerminalDeviceID, TemplateID: b.Profiles[0].TemplateID, Profile: b.Profiles[0], Generation: 1, Desired: "started", CreatedAt: now, ExpiresAt: now.Add(300 * time.Second)}
	if e = apiClient.AuthorizeRuntime(ctx, a); e != nil {
		t.Fatal("remote authorize", e)
	}
	if _, e = root.Stat(a.SandboxID.String() + ".lease.json"); e != nil {
		t.Fatal("no durable offline lease", e)
	}
	if worker.active == nil || worker.active.SandboxID != a.SandboxID {
		t.Fatal("runtime binding not pinned")
	}
	cancel()
	<-done
}
