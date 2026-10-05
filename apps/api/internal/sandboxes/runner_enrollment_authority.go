package sandboxes

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"reflect"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/ssh"
)

func (s *RunnerEnrollmentService) credential(ctx context.Context, q reservationReader, r runnerEnrollmentRecord) (RunnerCredential, error) {
	if r.consumed == nil || r.probe == nil || r.view.CertificateExpiresAt == nil || !time.Now().Before(*r.view.CertificateExpiresAt) {
		return RunnerCredential{}, ErrForbidden
	}
	valid, err := s.standing(ctx, q, r)
	if err != nil {
		return RunnerCredential{}, err
	}
	retained, err := s.retained(ctx, q, r.view.ID)
	if err != nil {
		return RunnerCredential{}, err
	}
	cleanup := r.revoked != nil || !valid || s.config.ModuleState != "enabled"
	if cleanup && retained == nil {
		return RunnerCredential{}, ErrForbidden
	}
	return RunnerCredential{EnrollmentID: r.view.ID, ProbePublicKey: *r.probe, CleanupOnly: cleanup, RetainedSandboxID: retained}, nil
}
func (s *RunnerEnrollmentService) certificateRecord(ctx context.Context, q reservationReader, leaf *x509.Certificate) (runnerEnrollmentRecord, error) {
	if leaf == nil || len(leaf.URIs) != 1 || leaf.URIs[0].String() != s.config.RunnerURI || time.Now().Before(leaf.NotBefore) || !time.Now().Before(leaf.NotAfter) || leaf.NotAfter.Sub(leaf.NotBefore) > 24*time.Hour+2*time.Minute {
		return runnerEnrollmentRecord{}, ErrForbidden
	}
	root, err := runnerCA(s.config.RunnerCA)
	if err != nil || leaf.CheckSignatureFrom(root) != nil {
		return runnerEnrollmentRecord{}, ErrForbidden
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		return runnerEnrollmentRecord{}, ErrForbidden
	}
	r, err := scanRunnerEnrollment(q.QueryRow(ctx, `SELECT `+runnerEnrollmentColumns+` FROM sandbox_runner_enrollments e WHERE e.org_id=$1 AND e.spki_hash=$2 ORDER BY e.created_at DESC,e.id LIMIT 1`, s.binding.OrgID, runnerKeyHash(leaf)))
	if err != nil {
		return r, ErrForbidden
	}
	if r.view.CertificateExpiresAt == nil || leaf.NotAfter.After(r.view.CertificateExpiresAt.Add(time.Second)) {
		return r, ErrForbidden
	}
	return r, nil
}
func (s *RunnerEnrollmentService) AuthorizeCertificate(ctx context.Context, leaf *x509.Certificate) (RunnerCredential, error) {
	r, err := s.certificateRecord(ctx, s.store.pool, leaf)
	if err != nil {
		return RunnerCredential{}, err
	}
	return s.credential(ctx, s.store.pool, r)
}
func (s *RunnerEnrollmentService) CurrentCredential(ctx context.Context) (RunnerCredential, error) {
	r, err := scanRunnerEnrollment(s.store.pool.QueryRow(ctx, `SELECT `+runnerEnrollmentColumns+` FROM sandbox_runner_enrollments e WHERE e.org_id=$1 AND e.consumed_at IS NOT NULL ORDER BY e.created_at DESC,e.id LIMIT 1`, s.binding.OrgID))
	if err != nil {
		return RunnerCredential{}, ErrDisabled
	}
	return s.credential(ctx, s.store.pool, r)
}
func (s *RunnerEnrollmentService) CurrentProbe(ctx context.Context) (ssh.PublicKey, error) {
	c, err := s.CurrentCredential(ctx)
	if err != nil {
		return nil, err
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(c.ProbePublicKey))
	return key, err
}
func (s *RunnerEnrollmentService) RecordHealth(ctx context.Context, c RunnerCredential, b BoundedRuntimeBinding) error {
	if !bindingEqual(b, s.binding) {
		return ErrForbidden
	}
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = s.orgLock(ctx, tx); err != nil {
		return err
	}
	r, err := s.read(ctx, tx, c.EnrollmentID, true)
	if err != nil {
		return err
	}
	current, err := s.credential(ctx, tx, r)
	if err != nil || current.CleanupOnly || current.ProbePublicKey != c.ProbePublicKey {
		return ErrForbidden
	}
	qualified, err := s.isQualified(ctx, tx, r)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE sandbox_runner_enrollments SET last_seen_at=clock_timestamp(),ready_at=CASE WHEN $2 THEN clock_timestamp() ELSE NULL END WHERE id=$1`, c.EnrollmentID, qualified); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func (s *RunnerEnrollmentService) RuntimeReady(ctx context.Context) bool {
	c, err := s.CurrentCredential(ctx)
	if err != nil || c.CleanupOnly {
		return false
	}
	r, err := s.read(ctx, s.store.pool, c.EnrollmentID, false)
	if err != nil {
		return false
	}
	qualified, err := s.isQualified(ctx, s.store.pool, r)
	return err == nil && r.view.LastSeenAt != nil && time.Since(*r.view.LastSeenAt) <= RunnerHealthFreshness && qualified
}
func (s *RunnerEnrollmentService) RenewCertificate(ctx context.Context, leaf *x509.Certificate) ([]byte, error) {
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if _, err = s.orgLock(ctx, tx); err != nil {
		return nil, err
	}
	r, err := s.certificateRecord(ctx, tx, leaf)
	if err != nil {
		return nil, err
	}
	r, err = s.read(ctx, tx, r.view.ID, true)
	if err != nil {
		return nil, err
	}
	c, err := s.credential(ctx, tx, r)
	if err != nil || c.CleanupOnly {
		return nil, ErrForbidden
	}
	raw, err := s.signer.RenewRunner(leaf)
	if err != nil {
		return nil, ErrDisabled
	}
	block, rest := pem.Decode(raw)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrDisabled
	}
	next, err := x509.ParseCertificate(block.Bytes)
	root, _ := runnerCA(s.config.RunnerCA)
	if err != nil || next.CheckSignatureFrom(root) != nil || len(next.URIs) != 1 || next.URIs[0].String() != s.config.RunnerURI || !bytes.Equal(next.RawSubjectPublicKeyInfo, leaf.RawSubjectPublicKeyInfo) || time.Until(next.NotAfter) > 24*time.Hour+time.Minute {
		return nil, ErrDisabled
	}
	if _, err = tx.Exec(ctx, `UPDATE sandbox_runner_enrollments SET certificate_expires_at=$2 WHERE id=$1 AND revoked_at IS NULL`, r.view.ID, next.NotAfter); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return raw, nil
}

func (s *RunnerEnrollmentService) commandAuthorization(ctx context.Context, q reservationReader, sb Sandbox) (RuntimeAuthorization, error) {
	var device uuid.UUID
	if err := q.QueryRow(ctx, `SELECT terminal_device_id FROM sandboxes WHERE id=$1 AND org_id=$2`, sb.Identity.ID, s.binding.OrgID).Scan(&device); err != nil {
		return RuntimeAuthorization{}, ErrForbidden
	}
	p, ok := s.binding.profile(sb.TemplateVersionID)
	if !ok {
		return RuntimeAuthorization{}, ErrForbidden
	}
	a := RuntimeAuthorization{SandboxID: sb.Identity.ID, OrgID: sb.Identity.OrgID, CreatorID: sb.Identity.CreatorID, GatewayID: s.binding.GatewayID, TerminalDeviceID: device, TemplateID: sb.TemplateVersionID, Profile: p, Generation: sb.Revision, Desired: sb.DesiredState, CreatedAt: sb.CreatedAt, ExpiresAt: sb.ExpiresAt}
	if !a.valid(s.binding) {
		return a, ErrForbidden
	}
	return a, nil
}

// BindSandboxAdmission runs inside ordinary Create's existing organization
// transaction and lock. It performs only durable authority reads/writes: no new
// lock, provider call, or qualification-trial bypass. Mapping before commit lets
// a concurrent runner withdrawal retire every accepted workload, including one
// whose first runtime command has not yet been dispatched.
func (s *RunnerEnrollmentService) BindSandboxAdmission(ctx context.Context, tx pgx.Tx, sb Sandbox) error {
	if s == nil || tx == nil || s.config.ModuleState != "enabled" {
		return ErrDisabled
	}
	if sb.Identity.ID == uuid.Nil || sb.Identity.OrgID != s.binding.OrgID || sb.DesiredState != "started" {
		return ErrForbidden
	}
	r, err := scanRunnerEnrollment(tx.QueryRow(ctx, `SELECT `+runnerEnrollmentColumns+` FROM sandbox_runner_enrollments e
 WHERE e.org_id=$1 AND e.consumed_at IS NOT NULL ORDER BY e.created_at DESC,e.id LIMIT 1 FOR UPDATE OF e`, s.binding.OrgID))
	if err != nil {
		return ErrDisabled
	}
	credential, err := s.credential(ctx, tx, r)
	if err != nil || credential.CleanupOnly || r.view.LastSeenAt == nil || time.Since(*r.view.LastSeenAt) > RunnerHealthFreshness {
		return ErrDisabled
	}
	scope, args := s.binding.eligibilityScope()
	args = append([]any{sb.Identity.ID}, args...)
	canonical, err := scanSandbox(tx.QueryRow(ctx, `SELECT `+sandboxColumns+` FROM sandboxes s WHERE s.id=$1 AND `+scope+` FOR UPDATE OF s`, args...))
	if err != nil {
		return ErrForbidden
	}
	a, err := s.commandAuthorization(ctx, tx, canonical)
	if err != nil {
		return err
	}
	requested, err := s.commandAuthorization(ctx, tx, sb)
	if err != nil || !sameWorkload(a, requested) || a.Generation != requested.Generation || a.Desired != requested.Desired || !time.Now().Before(a.ExpiresAt) {
		return ErrForbidden
	}
	eligible, err := sandboxEligible(ctx, tx, a.SandboxID)
	if err != nil {
		return err
	}
	qualified, err := s.isQualified(ctx, tx, r)
	if err != nil {
		return err
	}
	if !eligible || !qualified {
		return ErrDisabled
	}
	if _, err = tx.Exec(ctx, `INSERT INTO sandbox_runner_workloads(sandbox_id,org_id,enrollment_id) VALUES($1,$2,$3) ON CONFLICT(sandbox_id) DO NOTHING`, a.SandboxID, a.OrgID, r.view.ID); err != nil {
		return err
	}
	var mapped uuid.UUID
	if err = tx.QueryRow(ctx, `SELECT enrollment_id FROM sandbox_runner_workloads WHERE sandbox_id=$1 AND org_id=$2`, a.SandboxID, a.OrgID).Scan(&mapped); err != nil {
		return err
	}
	if mapped != r.view.ID {
		return ErrForbidden
	}
	return nil
}

func (s *RunnerEnrollmentService) executionAllowed(ctx context.Context, q reservationReader, r runnerEnrollmentRecord, a RuntimeAuthorization) (bool, error) {
	if !time.Now().Before(a.ExpiresAt) || r.view.LastSeenAt == nil || time.Since(*r.view.LastSeenAt) > RunnerHealthFreshness {
		return false, nil
	}
	eligible, err := sandboxEligible(ctx, q, a.SandboxID)
	if err != nil {
		return false, err
	}
	qualified, err := s.isQualified(ctx, q, r)
	if err != nil {
		return false, err
	}
	if eligible && qualified {
		return true, nil
	}
	// The separately implemented trial validates its own current human grant,
	// exact terminal/profile/TTL and slot. There is no generic unqualified path.
	return s.trial != nil && s.trial.VerifyRunnerQualificationTrial(ctx, r.view.ID, a) == nil, nil
}
func (s *RunnerEnrollmentService) AuthorizeCommand(ctx context.Context, c RunnerCredential, raw json.RawMessage) error {
	if len(raw) > workerRPCLimit {
		return ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var in workerRequest
	if decoder.Decode(&in) != nil || decoder.Decode(new(any)) != io.EOF || in.Version != workerRPCVersion {
		return ErrInvalid
	}
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = s.orgLock(ctx, tx); err != nil {
		return err
	}
	r, err := s.read(ctx, tx, c.EnrollmentID, true)
	if err != nil {
		return err
	}
	current, err := s.credential(ctx, tx, r)
	if err != nil || current.ProbePublicKey != c.ProbePublicKey {
		return ErrForbidden
	}
	if reflect.DeepEqual(in, workerRequest{Version: workerRPCVersion, Operation: "ping"}) && !current.CleanupOnly {
		return tx.Commit(ctx)
	}
	if in.ID == uuid.Nil || in.Generation <= 0 {
		return ErrInvalid
	}
	scope, args := s.binding.eligibilityScope()
	args = append([]any{in.ID}, args...)
	sb, err := scanSandbox(tx.QueryRow(ctx, `SELECT `+sandboxColumns+` FROM sandboxes s WHERE s.id=$1 AND `+scope+` FOR UPDATE OF s`, args...))
	if err != nil {
		return ErrForbidden
	}
	if sb.Revision != in.Generation {
		return ErrConflict
	}
	canonical, err := s.commandAuthorization(ctx, tx, sb)
	if err != nil {
		return err
	}
	var mapped uuid.UUID
	err = tx.QueryRow(ctx, `SELECT enrollment_id FROM sandbox_runner_workloads WHERE sandbox_id=$1 AND org_id=$2`, in.ID, s.binding.OrgID).Scan(&mapped)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if err == nil && mapped != c.EnrollmentID {
		return ErrForbidden
	}
	if in.Operation == "authorize" {
		a := in.Authorization
		if a == nil || !a.valid(s.binding) || !sameWorkload(*a, canonical) || a.Generation != canonical.Generation || a.Desired != canonical.Desired {
			return ErrForbidden
		}
		if current.CleanupOnly && (mapped != c.EnrollmentID || a.Desired != "deleted") {
			return ErrForbidden
		}
		if a.Desired == "started" {
			allowed, e := s.executionAllowed(ctx, tx, r, canonical)
			if e != nil {
				return e
			}
			if !allowed {
				return ErrForbidden
			}
		}
		if mapped == uuid.Nil {
			if current.CleanupOnly {
				return ErrForbidden
			}
			if _, err = tx.Exec(ctx, `INSERT INTO sandbox_runner_workloads(sandbox_id,org_id,enrollment_id) VALUES($1,$2,$3)`, in.ID, s.binding.OrgID, c.EnrollmentID); err != nil {
				return err
			}
		}
		return tx.Commit(ctx)
	}
	if mapped != c.EnrollmentID {
		return ErrForbidden
	}
	if current.CleanupOnly || sb.DesiredState == "deleted" {
		if sb.DesiredState != "deleted" {
			return ErrForbidden
		}
		switch in.Operation {
		case "inspect", "stop", "delete", "check-config", "remove-network", "gateway-absence", "retire":
		default:
			return ErrForbidden
		}
	} else {
		eligible, e := s.executionAllowed(ctx, tx, r, canonical)
		if e != nil {
			return e
		}
		if !eligible {
			return ErrForbidden
		}
	}
	return tx.Commit(ctx)
}
