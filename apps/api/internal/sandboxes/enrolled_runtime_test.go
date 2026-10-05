package sandboxes

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxrunner"
	"golang.org/x/crypto/ssh"
)

// The authority is synthetic; these fixtures exercise transport composition,
// not production enrollment or native runner qualification.
type enrolledAuthorityFixture struct {
	mu                   sync.Mutex
	probe                ssh.PublicKey
	credential           RunnerCredential
	qualified            bool
	healthCalls          int
	sweepErr             error
	qualificationReports []RunnerQualificationReport
}

func (a *enrolledAuthorityFixture) AuthorizeCertificate(context.Context, *x509.Certificate) (RunnerCredential, error) {
	return a.CurrentCredential(context.Background())
}
func (a *enrolledAuthorityFixture) AuthorizeCommand(context.Context, RunnerCredential, json.RawMessage) error {
	return nil
}
func (a *enrolledAuthorityFixture) CurrentCredential(context.Context) (RunnerCredential, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.credential, nil
}
func (a *enrolledAuthorityFixture) CurrentProbe(context.Context) (ssh.PublicKey, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.probe == nil {
		return nil, ErrDisabled
	}
	return a.probe, nil
}
func (a *enrolledAuthorityFixture) RecordHealth(context.Context, RunnerCredential, BoundedRuntimeBinding) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.healthCalls++
	return nil
}
func (a *enrolledAuthorityFixture) RuntimeReady(context.Context) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.qualified
}
func (a *enrolledAuthorityFixture) RenewCertificate(context.Context, *x509.Certificate) ([]byte, error) {
	return nil, ErrDisabled
}
func (a *enrolledAuthorityFixture) Sweep(context.Context) error { return a.sweepErr }
func (a *enrolledAuthorityFixture) SubmitQualification(_ context.Context, _ *x509.Certificate, report RunnerQualificationReport) (RunnerQualificationRecord, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.qualificationReports = append(a.qualificationReports, report)
	return RunnerQualificationRecord{}, nil
}

func TestEnrolledAPIConfigRequiresExplicitOrganizationRemoteMode(t *testing.T) {
	base := APIWorkerConfig{Binding: organizationTestBinding(), Remote: &RemoteWorkerConfig{Listen: "10.0.0.1:9443", RunnerURI: "spiffe://tunnex/runner/org"}, Enrollment: &RunnerEnrollmentConfig{RunnerURI: "spiffe://tunnex/runner/org"}}
	path := filepath.Join(t.TempDir(), "public-worker.json")
	write := func(cfg APIWorkerConfig) {
		t.Helper()
		raw, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(base)
	loaded, err := LoadAPIWorkerConfig(path)
	if err != nil || loaded.Enrollment == nil || loaded.ProbePublicKey != "" {
		t.Fatal("explicit disconnected enrollment rejected", err)
	}
	if _, err := loaded.Client(); !errors.Is(err, ErrDisabled) {
		t.Fatal("enrollment bypassed durable authority", err)
	}
	if _, err := loaded.EnrollmentClient(nil); !errors.Is(err, ErrInvalid) {
		t.Fatal("nil authority accepted", err)
	}
	for _, mutate := range []func(*APIWorkerConfig){
		func(c *APIWorkerConfig) { c.Enrollment = nil },
		func(c *APIWorkerConfig) { c.Remote = nil },
		func(c *APIWorkerConfig) { c.Binding = persistentTestBinding() },
		func(c *APIWorkerConfig) { c.ProbePublicKey = publicTerminalKey(t) },
		func(c *APIWorkerConfig) { c.InitialCreate = &CreateInput{} },
		func(c *APIWorkerConfig) {
			c.Enrollment = &RunnerEnrollmentConfig{RunnerURI: "spiffe://tunnex/runner/another"}
		},
	} {
		cfg := base
		mutate(&cfg)
		write(cfg)
		if _, err := LoadAPIWorkerConfig(path); err == nil {
			t.Fatal("ambiguous or legacy enrollment mode accepted")
		}
	}
}

func TestEnrolledRuntimeHealthRequiresCurrentProbeAndTrustedQualification(t *testing.T) {
	b := organizationTestBinding()
	server, client, _ := persistentRPCFixture(t, b)
	authority := &enrolledAuthorityFixture{probe: server.Identity.PublicKey(), credential: RunnerCredential{EnrollmentID: uuid.New(), ProbePublicKey: string(ssh.MarshalAuthorizedKey(server.Identity.PublicKey()))}}
	client.enrollment = authority
	client.probe = nil
	ctx := context.Background()
	if err := client.CheckBinding(ctx, b); !errors.Is(err, ErrDisabled) {
		t.Fatal("unqualified responding host became ready", err)
	}
	if authority.healthCalls != 1 {
		t.Fatal("matching real worker health did not reach trusted authority")
	}
	authority.qualified = true
	if err := client.CheckBinding(ctx, b); err != nil {
		t.Fatal("qualified exact binding refused", err)
	}
	foreign := b
	foreign.GatewayID = uuid.New()
	if err := client.CheckBinding(ctx, foreign); !errors.Is(err, ErrDisabled) {
		t.Fatal("foreign gateway health admitted", err)
	}
	if authority.healthCalls != 2 {
		t.Fatal("mismatching binding reached readiness authority")
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(publicTerminalKey(t)))
	if err != nil {
		t.Fatal(err)
	}
	authority.probe = key
	authority.credential.ProbePublicKey = string(ssh.MarshalAuthorizedKey(key))
	if err := client.CheckBinding(ctx, b); !errors.Is(err, ErrDisabled) {
		t.Fatal("previous runner key remained ready after replacement", err)
	}
	if string(ssh.MarshalAuthorizedKey(client.ProbePublicKey())) != authority.credential.ProbePublicKey {
		t.Fatal("cached construction-time probe retained")
	}
	authority.probe = nil
	if err := client.CheckBinding(ctx, b); !errors.Is(err, ErrDisabled) || client.ProbePublicKey() != nil {
		t.Fatal("withdrawn public probe retained", err)
	}
}

func TestEnrolledProbeSnapshotsAreSynchronizedAndNilSafe(t *testing.T) {
	b := organizationTestBinding()
	server, client, _ := persistentRPCFixture(t, b)
	authority := &enrolledAuthorityFixture{probe: server.Identity.PublicKey()}
	client.enrollment = authority
	var wait sync.WaitGroup
	for range 16 {
		wait.Go(func() {
			for range 50 {
				_, _ = client.resolveProbe(context.Background())
				_ = client.ProbePublicKey()
			}
		})
	}
	for range 100 {
		authority.mu.Lock()
		authority.probe = nil
		authority.mu.Unlock()
		if _, err := client.ProbePrivateTerminal(context.Background(), PrivateNetworkTarget{}, server.Identity.PublicKey(), PublicProbeIdentity{}); !errors.Is(err, ErrInvalid) {
			t.Fatal("absent identity admitted", err)
		}
		authority.mu.Lock()
		authority.probe = server.Identity.PublicKey()
		authority.mu.Unlock()
	}
	wait.Wait()
}

func TestEnrolledOrchestratorOnlyTypedClientMayAwaitProbe(t *testing.T) {
	b := organizationTestBinding()
	store := &Store{pool: &pgxpool.Pool{}}
	policies := &readinessPolicyFixture{}
	sealer := launchTestSealer(t)
	if _, err := NewAPIOrchestrator(store, b, &WorkerRPCClient{}, policies, sealer); !errors.Is(err, ErrDisabled) {
		t.Fatal("static missing probe admitted", err)
	}
	client := &WorkerRPCClient{enrollment: &enrolledAuthorityFixture{}}
	o, err := NewAPIOrchestrator(store, b, client, policies, sealer)
	if err != nil || o.initial.ProbeIdentity.PublicKey() != nil {
		t.Fatal("explicit enrollment cannot await public identity", err)
	}
	if _, err := NewAPIOrchestrator(store, persistentTestBinding(), client, policies, sealer); !errors.Is(err, ErrDisabled) {
		t.Fatal("legacy binding used dynamic enrollment", err)
	}
	authority := client.enrollment.(*enrolledAuthorityFixture)
	authority.sweepErr = ErrForbidden
	if err := o.batch(context.Background(), nil); !errors.Is(err, ErrForbidden) {
		t.Fatal("dispatch proceeded before enrollment sweep", err)
	}
}

func TestEnrolledOrchestratorRefreshesIdleHealthWithoutAdmittingRevokedRunner(t *testing.T) {
	b := organizationTestBinding()
	server, client, _ := persistentRPCFixture(t, b)
	authority := &enrolledAuthorityFixture{probe: server.Identity.PublicKey(), qualified: true, credential: RunnerCredential{EnrollmentID: uuid.New(), ProbePublicKey: string(ssh.MarshalAuthorizedKey(server.Identity.PublicKey()))}}
	client.enrollment = authority
	o := &APIOrchestrator{worker: client, binding: b}
	o.refreshEnrollmentHealth(context.Background())
	if authority.healthCalls != 1 {
		t.Fatal("idle worker's actual health reply not recorded")
	}
	o.refreshEnrollmentHealth(context.Background())
	if authority.healthCalls != 1 {
		t.Fatal("health exceeded bounded cadence")
	}
	authority.credential.CleanupOnly = true
	o.lastEnrollmentProbe = time.Now().Add(-6 * time.Second)
	o.refreshEnrollmentHealth(context.Background())
	if authority.healthCalls != 1 {
		t.Fatal("revoked cleanup credential received health authority")
	}
	authority.credential.CleanupOnly = false
	authority.qualified = false
	o.lastEnrollmentProbe = time.Now().Add(-6 * time.Second)
	o.refreshEnrollmentHealth(context.Background())
	if authority.healthCalls != 2 || authority.RuntimeReady(context.Background()) {
		t.Fatal("unqualified connectivity was omitted or marked ready")
	}
}

func TestEnrolledQualificationAdapterStrictlyDecodesPublicReport(t *testing.T) {
	authority := &enrolledAuthorityFixture{}
	id := uuid.New()
	raw, err := json.Marshal(RunnerQualificationReport{Version: 1, EnrollmentID: id})
	if err != nil {
		t.Fatal(err)
	}
	if err := submitRunnerQualification(context.Background(), authority, &x509.Certificate{}, raw); err != nil {
		t.Fatal("typed public report refused", err)
	}
	if len(authority.qualificationReports) != 1 || authority.qualificationReports[0].EnrollmentID != id {
		t.Fatal("report not passed to durable scoped service")
	}
	for _, raw := range []string{`{"version":1,"secret_payload":"not permitted"}`, `{"version":2}`, `null`, `{"version":1} {"version":1}`} {
		if err := submitRunnerQualification(context.Background(), authority, &x509.Certificate{}, json.RawMessage(raw)); !errors.Is(err, sandboxrunner.ErrInvalid) {
			t.Fatal("unrecognized report authority accepted", err)
		}
	}
	if len(authority.qualificationReports) != 1 {
		t.Fatal("invalid report reached service")
	}
}
