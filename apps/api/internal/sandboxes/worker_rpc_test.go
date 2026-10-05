package sandboxes

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxruntime"
	"github.com/tunnexio/tunnex/apps/api/internal/wgkey"
	"golang.org/x/crypto/ssh"
)

// Portable protocol fixture only. Production context is set solely from Unix
// SO_PEERCRED; this transport intentionally exercises no live runtime/authority.
type rpcProviderFixture struct{ runningProvider }

func (p *rpcProviderFixture) Delete(context.Context, uuid.UUID) error {
	p.status = sandboxruntime.Status{}
	return nil
}

type rpcTestTransport struct{ handler *WorkerRPCServer }

func (t rpcTestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	recorder := httptest.NewRecorder()
	t.handler.ServeHTTP(recorder, req.WithContext(context.WithValue(req.Context(), workerPeerContext{}, true)))
	return recorder.Result(), nil
}
func TestWorkerRPCRejectsUnauthenticatedHeadersAndMalformedInput(t *testing.T) {
	server := &WorkerRPCServer{}
	request := httptest.NewRequest(http.MethodPost, "/v1/control", strings.NewReader(`{"Version":1,"Operation":"ping"}`))
	request.Header.Set("X-User-ID", "10001")
	request.Header.Set("Content-Type", "application/json")
	out := httptest.NewRecorder()
	server.ServeHTTP(out, request)
	if out.Code != http.StatusForbidden {
		t.Fatal("HTTP headers authorized peer")
	}
	for _, body := range []string{`{"Version":1,"Operation":"ping","Command":"sh"}`, `{"Version":1} {}`, strings.Repeat("x", workerRPCLimit+1)} {
		req := httptest.NewRequest(http.MethodPost, "/v1/control", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(context.WithValue(req.Context(), workerPeerContext{}, true))
		out = httptest.NewRecorder()
		server.ServeHTTP(out, req)
		if out.Code != http.StatusBadRequest {
			t.Fatal("malformed/oversized RPC accepted")
		}
	}
}
func TestWorkerRPCErrorBoundaryAndPublicSigner(t *testing.T) {
	const privateDetail = "private-key-credential-content"
	if workerErrorCode(errors.New(privateDetail)) != "unavailable" {
		t.Fatal("private detail crossed RPC")
	}
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	identity, _ := ssh.NewSignerFromKey(private)
	public := PublicProbeIdentity{identity.PublicKey()}
	if !bytes.Equal(public.PublicKey().Marshal(), identity.PublicKey().Marshal()) {
		t.Fatal("public identity changed")
	}
	if _, err := public.Sign(rand.Reader, []byte("test")); !errors.Is(err, ErrDisabled) {
		t.Fatal("API public identity signed")
	}
}
func TestAPIOrchestratorPostgresRPCInitialReadyAndCleanup(t *testing.T) {
	f := newFixture(t)
	binding := boundedTestBinding()
	binding.OrgID, binding.CreatorID, binding.GatewayID = f.org, f.user, f.node
	seedBoundedTerminalDevice(t, f, binding)
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO sandbox_templates(id,org_id,name,image_digest,maximum_scope,memory_mib,max_ttl_seconds,enabled) VALUES($1,$2,'native RPC',$3,'[]',128,3600,true)`, binding.TemplateID, binding.OrgID, binding.ImageDigest); err != nil {
		t.Fatal(err)
	}
	_, gatewayKey, _ := wgkey.Generate()
	if _, err := f.pool.Exec(f.ctx, `UPDATE nodes SET endpoint='127.0.0.1:51820',wg_public_key=$2,status='active',policy_reported_at=now() WHERE id=$1`, f.node, gatewayKey); err != nil {
		t.Fatal(err)
	}
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	identity, _ := ssh.NewSignerFromKey(private)
	assetsRoot, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer assetsRoot.Close()
	controlRoot, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer controlRoot.Close()
	assets, _ := sandboxruntime.NewFilesystemAssets(assetsRoot)
	invoker := &enrollmentInvokerFixture{f: f, uncertain: true}
	files, err := NewFileBootstrapTransport(controlRoot, "https://fixture.example", invoker)
	if err != nil {
		t.Fatal(err)
	}
	provider := &rpcProviderFixture{}
	network := &composedNetworkFixture{f: f, pendingProbe: true}
	server := &WorkerRPCServer{Binding: binding, AssetsRoot: assetsRoot, ControlRoot: controlRoot, Assets: assets, Provider: provider, Files: files, Network: network, Gateway: network, Probe: network, Identity: identity}
	client := &WorkerRPCClient{client: &http.Client{Transport: rpcTestTransport{server}}, probe: identity.PublicKey()}
	if err = client.CheckBinding(f.ctx, binding); err != nil {
		t.Fatal("worker health binding", err)
	}
	foreign := binding
	foreign.GatewayID = uuid.New()
	if err = client.CheckBinding(f.ctx, foreign); !errors.Is(err, ErrDisabled) {
		t.Fatal("foreign gateway health accepted", err)
	}
	orchestration, err := NewAPIOrchestrator(f.store, binding, client, &readinessPolicyFixture{hash: "canonical-api"}, launchTestSealer(t))
	if err != nil {
		t.Fatal(err)
	}
	input := f.input("api-owned-RPC")
	input.TemplateID = binding.TemplateID
	input.Requested = []Scope{}
	sandbox, _, err := f.store.Create(f.ctx, f.org, f.user, input)
	if err != nil {
		t.Fatal(err)
	}
	reportCount := 0
	var reports []error
	// Two deliberately uncertain gates must remain pending; thereafter readiness
	// is asynchronous and must converge within a bounded window. Production polls
	// rather than assuming its third immediate call necessarily sees fresh status.
	for range 2 {
		if err = orchestration.batch(f.ctx, func(_ uuid.UUID, e error) { reportCount++; reports = append(reports, e) }); err != nil {
			t.Fatal(err)
		}
	}
	if reportCount != 2 || invoker.calls != 1 {
		t.Fatal("uncertain gates did not remain pending", reportCount, invoker.calls)
	}
	var current Sandbox
	deadline := time.Now().Add(2 * time.Second)
	for {
		if err = orchestration.batch(f.ctx, func(_ uuid.UUID, e error) { reportCount++; reports = append(reports, e) }); err != nil {
			t.Fatal(err)
		}
		current, err = f.store.Get(f.ctx, f.org, f.user, sandbox.Identity.ID)
		if err != nil {
			t.Fatal(err)
		}
		if current.State == StateReady {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("RPC readiness did not converge", current.State, reports)
		}
		timer := time.NewTimer(20 * time.Millisecond)
		<-timer.C
	}
	if current.Connection == nil || invoker.calls != 1 {
		t.Fatal("ready recovery changed enrollment identity", invoker.calls)
	}
	if server.sandboxID != sandbox.Identity.ID {
		t.Fatal("worker sandbox not pinned")
	}
	if _, err = client.Inspect(f.ctx, uuid.New()); !errors.Is(err, ErrForbidden) {
		t.Fatal("foreign sandbox inspected", err)
	}
	badSpec := sandboxruntime.Spec{ID: sandbox.Identity.ID, ImageDigest: binding.ImageDigest, MemoryMiB: 256, CPUs: 1, PIDs: 128}
	if err = client.Create(f.ctx, badSpec); !errors.Is(err, ErrForbidden) {
		t.Fatal("resource expansion admitted", err)
	}
	// No worker root exists in the API adapter; terminal verification returned a
	// public key, and the API's public signer is incapable of private signing.
	if _, ok := orchestration.initial.ProbeIdentity.(PublicProbeIdentity); !ok {
		t.Fatal("API received private probe signer")
	}
	current, err = f.store.SetDesired(f.ctx, f.org, f.user, sandbox.Identity.ID, current.Revision, "deleted")
	if err != nil {
		t.Fatal(err)
	}
	if err = orchestration.batch(f.ctx, func(_ uuid.UUID, err error) { t.Errorf("cleanup reconciliation: %v", err) }); err != nil {
		t.Fatal(err)
	}
	current, err = f.store.Get(f.ctx, f.org, f.user, sandbox.Identity.ID)
	if err != nil || current.State != StateDeleted || network.removals != 1 || network.absences != 1 {
		t.Fatal("RPC cleanup incomplete", current.State, network.removals, network.absences, err)
	}
	if err = orchestration.batch(f.ctx, func(_ uuid.UUID, err error) { t.Errorf("retirement: %v", err) }); err != nil {
		t.Fatal(err)
	}
	if _, err = assetsRoot.Lstat(sandbox.Identity.ID.String()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("retired workload data retained", err)
	}
	if _, err = controlRoot.Lstat(sandbox.Identity.ID.String()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("retired enrollment data retained", err)
	}
	if !server.retired || !orchestration.retired {
		t.Fatal("retirement not acknowledged")
	}
	var marked bool
	if err = f.pool.QueryRow(f.ctx, `SELECT worker_retired_at IS NOT NULL FROM sandbox_runtime_bindings WHERE sandbox_id=$1`, sandbox.Identity.ID).Scan(&marked); err != nil || !marked {
		t.Fatal("API retirement receipt absent", err)
	}
	if err = client.CheckBinding(f.ctx, binding); !errors.Is(err, ErrDisabled) {
		t.Fatal("retired worker still available", err)
	}
	if err = client.Start(f.ctx, sandbox.Identity.ID); !errors.Is(err, ErrDisabled) {
		t.Fatal("retired worker started workload", err)
	}
	restarted := WorkerRPCServer{Binding: binding, ControlRoot: controlRoot}
	if retired, err := restarted.CheckRetirement(); err != nil || !retired {
		t.Fatal("worker restart restored authority", err)
	}
	// Tombstone and immutable worker pin deny a replacement despite freed quota.
	input.IdempotencyKey = "another"
	if _, _, err = f.store.Create(f.ctx, f.org, f.user, input); !errors.Is(err, ErrQuota) {
		t.Fatal("second main launch admitted", err)
	}
}

func TestWorkerPingDoesNotBlockEnrollmentAndClosesAfterRetirement(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	identity, _ := ssh.NewSignerFromKey(private)
	binding := BoundedRuntimeBinding{OrgID: uuid.New(), CreatorID: uuid.New(), GatewayID: uuid.New(), TemplateID: uuid.New(), TerminalDeviceID: uuid.New(), ImageDigest: "sha256:" + strings.Repeat("a", 64), MemoryMiB: 128, CPUs: 1, PIDs: 128, MaxTTLSeconds: 3600, ExpiresAt: time.Now().Add(time.Hour)}
	server := &WorkerRPCServer{Binding: binding, ControlRoot: root, Identity: identity}
	server.mu.Lock()
	defer server.mu.Unlock()
	done := make(chan error, 1)
	go func() {
		_, err := server.dispatch(context.Background(), workerRequest{Version: workerRPCVersion, Operation: "ping"})
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("ping deadlocked on enrollment effect mutex")
	}
	marker, err := root.OpenFile("api-retired.json", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	marker.Close()
	if _, err = server.dispatch(context.Background(), workerRequest{Version: workerRPCVersion, Operation: "ping"}); !errors.Is(err, ErrDisabled) {
		t.Fatal("retired worker ping reopened")
	}
}
