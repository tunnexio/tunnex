package sandboxes

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/google/uuid"
)

// Synthetic provider/SSH adapters exercise the real control-plane lifecycle and
// current certificate/command service, not native host qualification.
type trialAuthorityTransport struct {
	server  *WorkerRPCServer
	service *RunnerQualificationService
	leaf    *x509.Certificate
}

func (t trialAuthorityTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	r.Body.Close()
	c, err := t.service.AuthorizeCertificate(r.Context(), t.leaf)
	if err != nil {
		return nil, err
	}
	if err = t.service.AuthorizeCommand(r.Context(), c, raw); err != nil {
		return nil, err
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	return (rpcTestTransport{t.server}).RoundTrip(r)
}
func TestRunnerTrialPostgresCanonicalStartStopResumeReceiptsAndCancelRetirement(t *testing.T) {
	f, b, ctx, s, leaf, in, enrollmentID := runnerTrialFixture(t)
	server, client, provider := persistentRPCFixture(t, b)
	probe, err := s.CurrentProbe(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	server.Identity = PublicProbeIdentity{probe}
	client.probe = probe
	client.enrollment = s
	client.client.Transport = trialAuthorityTransport{server, s, leaf}
	invoker := &enrollmentInvokerFixture{f: f}
	files, err := NewFileBootstrapTransport(server.ControlRoot, "https://fixture.example", invoker)
	if err != nil {
		t.Fatal(err)
	}
	network := &composedNetworkFixture{f: f}
	server.Files, server.Network, server.Gateway, server.Probe = files, network, network, network
	orchestrator, err := NewAPIOrchestrator(f.store, b, client, &readinessPolicyFixture{hash: "canonical-api"}, launchTestSealer(t))
	if err != nil {
		t.Fatal(err)
	}
	s.WithWake(orchestrator.Wake)
	trial, _, err := s.BeginQualification(ctx, f.org, f.user, enrollmentID, in)
	if err != nil {
		t.Fatal(err)
	}
	batch := func() {
		t.Helper()
		var failures []error
		if err := orchestrator.batch(f.ctx, func(_ uuid.UUID, e error) { failures = append(failures, e) }); err != nil {
			t.Fatal("canonical trial batch", err)
		}
		for _, e := range failures {
			var stage *LaunchStageError
			if !errors.As(e, &stage) || (stage.Stage != "readiness-policy-after" && stage.Stage != "readiness-policy-before") {
				t.Fatal("canonical trial batch", failures)
			}
		}
	}
	for range 7 {
		devExec(t, f, `UPDATE nodes SET policy_reported_at=clock_timestamp() WHERE id=$1`, f.node)
		batch()
	}
	trial, err = s.StatusQualification(ctx, f.org, f.user, enrollmentID, trial.ID)
	if err != nil || trial.Phase != "awaiting_expiry" || trial.Generation != 3 || trial.ObservedState != StateReady || trial.Connection == nil {
		t.Fatal("canonical resume proof", trial, err)
	}
	if invoker.calls != 1 || !provider.status.Running {
		t.Fatal("re-enrolled or never started", invoker.calls)
	}
	view, err := s.QualificationMachineView(f.ctx, leaf, trial.ID)
	if err != nil || view.InitialReadyAt == nil || view.StoppedAt == nil || view.ResumeReadyAt == nil || view.ProofSHA256 != "" {
		t.Fatal("premature qualification", view, err)
	}
	for _, code := range []string{"initial_ready", "resume_ready"} {
		var raw []byte
		if err = f.pool.QueryRow(f.ctx, `SELECT evidence FROM sandbox_runner_qualification_events WHERE trial_id=$1 AND code=$2`, trial.ID, code).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var receipt map[string]json.RawMessage
		if json.Unmarshal(raw, &receipt) != nil || !bytes.Contains(receipt["terminal_probe"], []byte(`"UID": 1001`)) || !bytes.Contains(receipt["ssh_origin"], []byte("runner")) || !bytes.Contains(receipt["policy_before"], []byte("canonical-api")) {
			t.Fatal("missing actual gate facts", string(raw))
		}
	}
	if err = s.VerifyRunnerQualification(f.ctx, enrollmentID, RunnerQualificationReport{EnrollmentID: enrollmentID, ProfileID: s.config.Profile.ID, BindingSHA256: view.BindingSHA256, SourceSHA: view.SourceSHA}); !errors.Is(err, ErrDisabled) {
		t.Fatal("incomplete trial became native proof", err)
	}
	if _, err = f.store.SetDesired(ctx, f.org, f.user, trial.SandboxID, trial.Generation, "deleted"); err != nil {
		t.Fatal(err)
	}
	batch()
	batch()
	batch()
	trial, err = s.StatusQualification(ctx, f.org, f.user, enrollmentID, trial.ID)
	if err != nil || trial.ObservedState != StateDeleted || trial.RetiredAt == nil || trial.Phase != "failed" {
		t.Fatal("cancel must retire without passing", trial, err)
	}
	if provider.status.RuntimeID != "" {
		t.Fatal("database marked deletion before provider absence")
	}
}
