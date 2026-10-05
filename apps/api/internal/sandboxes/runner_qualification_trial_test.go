package sandboxes

import (
	"context"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

func runnerTrialFixture(t *testing.T) (fixture, BoundedRuntimeBinding, context.Context, *RunnerQualificationService, *x509.Certificate, RunnerQualificationTrialInput, uuid.UUID) {
	t.Helper()
	f, b, devices, ctx, enrollment := runnerEnrollmentFixture(t)
	issue, _, leaf := issueRunner(t, f, ctx, enrollment)
	credential, err := enrollment.AuthorizeCertificate(f.ctx, leaf)
	if err != nil {
		t.Fatal(err)
	}
	if err = enrollment.RecordHealth(f.ctx, credential, b); err != nil {
		t.Fatal(err)
	}
	s, err := NewRunnerQualificationService(f.store, enrollment, b)
	if err != nil {
		t.Fatal(err)
	}
	enrollment.WithQualificationTrialValidator(s).WithNativeProofVerifier(s)
	f.store.WithRunnerAvailability(s.RuntimeReady).WithRunnerAdmission(s.BindSandboxAdmission)
	devExec(t, f, `UPDATE organizations SET sandboxes_enabled=false WHERE id=$1`, f.org)
	devExec(t, f, `UPDATE sandbox_templates SET enabled=false WHERE id=$1`, b.Profiles[0].TemplateID)
	return f, b, ctx, s, leaf, RunnerQualificationTrialInput{TerminalDeviceID: devices[f.user], SSHPublicKeys: []string{f.sshPublicKey}, IdempotencyKey: uuid.New()}, issue.Enrollment.ID
}
func TestRunnerTrialPostgresBoundedAdmissionFlagsAndReplay(t *testing.T) {
	f, b, ctx, s, _, in, enrollmentID := runnerTrialFixture(t)
	trial, replay, err := s.BeginQualification(ctx, f.org, f.user, enrollmentID, in)
	if err != nil || replay {
		t.Fatal("trial admission", err, replay)
	}
	if trial.Generation != 1 || trial.DesiredState != "started" || trial.ExpiresAt.Sub(trial.CreatedAt) != 900*time.Second || !strings.Contains(trial.QualificationCommand, enrollmentID.String()) {
		t.Fatal("wrong trial bounds", trial)
	}
	again, replay, err := s.BeginQualification(ctx, f.org, f.user, enrollmentID, in)
	if err != nil || !replay || again.ID != trial.ID || again.SandboxID != trial.SandboxID {
		t.Fatal("replay", err, replay)
	}
	var orgEnabled, templateEnabled, valid bool
	if err = f.pool.QueryRow(f.ctx, `SELECT o.sandboxes_enabled,t.enabled,sandbox_qualification_trial_valid($3) FROM organizations o JOIN sandbox_templates t ON t.org_id=o.id WHERE o.id=$1 AND t.id=$2`, f.org, b.Profiles[0].TemplateID, trial.SandboxID).Scan(&orgEnabled, &templateEnabled, &valid); err != nil || orgEnabled || templateEnabled || !valid {
		t.Fatal("trial broadened ordinary provisioning", err)
	}
	if _, _, err = f.store.Create(f.ctx, f.org, f.user, organizationInput(f, b, in.TerminalDeviceID, "ordinary")); !errors.Is(err, ErrDisabled) {
		t.Fatal("ordinary disabled creation", err)
	}
	changed := in
	changed.SSHPublicKeys = []string{publicTerminalKey(t)}
	if _, _, err = s.BeginQualification(ctx, f.org, f.user, enrollmentID, changed); !errors.Is(err, ErrConflict) {
		t.Fatal("changed replay", err)
	}
	another := in
	another.IdempotencyKey = uuid.New()
	if _, _, err = s.BeginQualification(ctx, f.org, f.user, enrollmentID, another); !errors.Is(err, ErrQuota) {
		t.Fatal("retained trial quota", err)
	}
}
func TestRunnerTrialPostgresCurrentHumanTerminalAndEnrollmentAuthority(t *testing.T) {
	f, b, ctx, s, _, in, enrollmentID := runnerTrialFixture(t)
	member := authctx.WithPrincipal(f.ctx, &authctx.Principal{UserID: f.other, Roles: map[uuid.UUID]string{f.org: rbac.RoleOwner}, EmailVerified: true})
	if _, _, err := s.BeginQualification(member, f.org, f.other, enrollmentID, in); !errors.Is(err, ErrForbidden) {
		t.Fatal("forged current role", err)
	}
	machine := authctx.WithPrincipal(f.ctx, authctx.NewMachinePrincipal(f.user, uuid.New(), f.org, "fixture", rbac.RoleOwner, ""))
	if _, _, err := s.BeginQualification(machine, f.org, f.user, enrollmentID, in); !errors.Is(err, ErrForbidden) {
		t.Fatal("machine trial", err)
	}
	wrong := in
	wrong.TerminalDeviceID = uuid.New()
	if _, _, err := s.BeginQualification(ctx, f.org, f.user, enrollmentID, wrong); !errors.Is(err, ErrForbidden) {
		t.Fatal("unowned terminal", err)
	}
	trial, _, err := s.BeginQualification(ctx, f.org, f.user, enrollmentID, in)
	if err != nil {
		t.Fatal(err)
	}
	a := RuntimeAuthorization{SandboxID: trial.SandboxID, OrgID: f.org, CreatorID: f.user, GatewayID: b.GatewayID, TerminalDeviceID: in.TerminalDeviceID, TemplateID: b.Profiles[0].TemplateID, Profile: b.Profiles[0], Generation: trial.Generation, Desired: trial.DesiredState, CreatedAt: trial.CreatedAt, ExpiresAt: trial.ExpiresAt}
	if err = s.VerifyRunnerQualificationTrial(f.ctx, enrollmentID, a); err != nil {
		t.Fatal("valid exact trial", err)
	}
	forged := a
	forged.Generation++
	if err = s.VerifyRunnerQualificationTrial(f.ctx, enrollmentID, forged); !errors.Is(err, ErrForbidden) {
		t.Fatal("stale generation", err)
	}
	devExec(t, f, `UPDATE organizations SET sandboxes_enabled=true WHERE id=$1`, f.org)
	devExec(t, f, `UPDATE sandbox_templates SET enabled=true WHERE id=$1`, a.TemplateID)
	devExec(t, f, `UPDATE sandbox_runner_enrollments SET revoked_at=clock_timestamp(),revoke_reason='fixture' WHERE id=$1`, enrollmentID)
	if err = s.VerifyRunnerQualificationTrial(f.ctx, enrollmentID, a); !errors.Is(err, ErrForbidden) {
		t.Fatal("revoked trial authority", err)
	}
	if err = s.PumpQualificationTrials(f.ctx); err != nil {
		t.Fatal(err)
	}
	var desired string
	var gen int64
	var eligible bool
	if err = f.pool.QueryRow(f.ctx, `SELECT desired_state,generation,sandbox_qualification_trial_authority(id) FROM sandboxes WHERE id=$1`, a.SandboxID).Scan(&desired, &gen, &eligible); err != nil || desired != "deleted" || gen != 2 || eligible {
		t.Fatal("fallback authority after grant withdrawal", desired, gen, eligible, err)
	}
}

func TestRunnerTrialPostgresUnavailableRunnerCannotConsumeOrdinarySlotOrStart(t *testing.T) {
	f, b, ctx, s, _, in, enrollmentID := runnerTrialFixture(t)
	devExec(t, f, `UPDATE organizations SET sandboxes_enabled=true WHERE id=$1`, f.org)
	devExec(t, f, `UPDATE sandbox_templates SET enabled=true WHERE id=$1`, b.Profiles[0].TemplateID)
	if s.RuntimeReady(f.ctx) {
		t.Fatal("unqualified runner unexpectedly available")
	}
	if _, _, err := f.store.Create(f.ctx, f.org, f.user, organizationInput(f, b, in.TerminalDeviceID, "stale-enabled-flags")); !errors.Is(err, ErrDisabled) {
		t.Fatal("unqualified public admission", err)
	}
	var count int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM sandboxes WHERE org_id=$1`, f.org).Scan(&count); err != nil || count != 0 {
		t.Fatal("failed availability consumed retained slot", count, err)
	}
	trial, _, err := s.BeginQualification(ctx, f.org, f.user, enrollmentID, in)
	if err != nil {
		t.Fatal("typed trial unavailable bypass", err)
	}
	if _, err = f.store.SetDesired(ctx, f.org, f.user, trial.SandboxID, trial.Generation, "started"); !errors.Is(err, ErrDisabled) {
		t.Fatal("unavailable public start", err)
	}
	stopped, err := f.store.SetDesired(ctx, f.org, f.user, trial.SandboxID, trial.Generation, "stopped")
	if err != nil {
		t.Fatal("stop blocked by availability", err)
	}
	if _, err = f.store.SetDesired(ctx, f.org, f.user, trial.SandboxID, stopped.Revision, "deleted"); err != nil {
		t.Fatal("delete blocked by availability", err)
	}
}

func TestRunnerTrialPostgresImmutableGrantAndReceipts(t *testing.T) {
	f, _, ctx, s, _, in, enrollmentID := runnerTrialFixture(t)
	trial, _, err := s.BeginQualification(ctx, f.org, f.user, enrollmentID, in)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{`UPDATE sandbox_runner_qualification_trials SET expires_at=expires_at+interval '1 second' WHERE id=$1`, `UPDATE sandbox_runner_qualification_trials SET creator_id=gen_random_uuid() WHERE id=$1`, `UPDATE sandbox_runner_qualification_trials SET spki_hash=decode(repeat('00',32),'hex') WHERE id=$1`} {
		if _, err = f.pool.Exec(f.ctx, q, trial.ID); err == nil {
			t.Fatal("immutable trial grant changed")
		}
	}
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = recordRunnerTrialEvent(f.ctx, tx, trial.SandboxID, "initial_ready", 1, map[string]any{"source_fixture": true}); err != nil {
		tx.Rollback(f.ctx)
		t.Fatal(err)
	}
	if err = tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{`UPDATE sandbox_runner_qualification_events SET evidence='{"fake":true}' WHERE trial_id=$1`, `DELETE FROM sandbox_runner_qualification_events WHERE trial_id=$1`} {
		if _, err = f.pool.Exec(f.ctx, q, trial.ID); err == nil {
			t.Fatal("canonical receipt changed")
		}
	}
	if err = s.PumpQualificationTrials(f.ctx); err != nil {
		t.Fatal(err)
	}
	status, err := s.StatusQualification(ctx, f.org, f.user, enrollmentID, trial.ID)
	if err != nil || status.Generation != 1 || status.ObservedState != StateCreating || status.Phase != "initial_ready" {
		t.Fatal("receipt alone selected Ready", status, err)
	}
}
