package sandboxes

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"golang.org/x/crypto/ssh"
)

type runnerEnrollmentRecord struct {
	view                                         RunnerEnrollment
	org, issuer                                  uuid.UUID
	requestHash, bindingHash, tokenHash, keyHash []byte
	uri                                          string
	consumed, revoked, ready                     *time.Time
	certificate, probe, reason                   *string
}

const runnerEnrollmentColumns = `e.id,e.org_id,e.issuer_id,e.profile_id,e.name,e.created_at,e.expires_at,e.request_hash,e.binding_hash,e.token_hash,e.runner_uri,e.consumed_at,e.spki_hash,e.probe_public_key,e.certificate,e.certificate_expires_at,e.revoked_at,e.revoke_reason,e.last_seen_at,e.ready_at`

func scanRunnerEnrollment(row pgx.Row) (runnerEnrollmentRecord, error) {
	var r runnerEnrollmentRecord
	err := row.Scan(&r.view.ID, &r.org, &r.issuer, &r.view.ProfileID, &r.view.Name, &r.view.CreatedAt, &r.view.ExpiresAt, &r.requestHash, &r.bindingHash, &r.tokenHash, &r.uri, &r.consumed, &r.keyHash, &r.probe, &r.certificate, &r.view.CertificateExpiresAt, &r.revoked, &r.reason, &r.view.LastSeenAt, &r.ready)
	if errors.Is(err, pgx.ErrNoRows) {
		return r, ErrNotFound
	}
	return r, err
}
func (s *RunnerEnrollmentService) read(ctx context.Context, q reservationReader, id uuid.UUID, lock bool) (runnerEnrollmentRecord, error) {
	suffix := ""
	if lock {
		suffix = " FOR UPDATE OF e"
	}
	return scanRunnerEnrollment(q.QueryRow(ctx, `SELECT `+runnerEnrollmentColumns+` FROM sandbox_runner_enrollments e WHERE e.id=$1 AND e.org_id=$2`+suffix, id, s.binding.OrgID))
}
func (s *RunnerEnrollmentService) orgLock(ctx context.Context, tx pgx.Tx) (string, error) {
	var mode string
	err := tx.QueryRow(ctx, `SELECT zero_trust_mode FROM organizations WHERE id=$1 AND deleted_at IS NULL FOR UPDATE`, s.binding.OrgID).Scan(&mode)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrForbidden
	}
	return mode, err
}
func (s *RunnerEnrollmentService) human(ctx context.Context, tx pgx.Tx, org, actor uuid.UUID) error {
	if org != s.binding.OrgID {
		return ErrForbidden
	}
	if err := delegationHuman(ctx, actor); err != nil {
		return err
	}
	_, err := authorize(ctx, tx, org, actor, rbac.PermSandboxRunnerManage)
	return err
}
func (s *RunnerEnrollmentService) standing(ctx context.Context, q reservationReader, r runnerEnrollmentRecord) (bool, error) {
	var roles []string
	var valid bool
	err := q.QueryRow(ctx, `SELECT COALESCE(m.roles,ARRAY[m.role]),u.email_verified_at IS NOT NULL AND NOT u.must_change_password FROM memberships m JOIN users u ON u.id=m.user_id JOIN organizations o ON o.id=m.org_id WHERE m.org_id=$1 AND m.user_id=$2 AND m.access_revoked_at IS NULL AND u.status='active' AND u.deleted_at IS NULL AND o.deleted_at IS NULL AND o.zero_trust_mode='enforcing'`, r.org, r.issuer).Scan(&roles, &valid)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return valid && rbac.CanAny(roles, rbac.PermSandboxRunnerManage) && equalHash(r.bindingHash, s.bindingHash) && r.uri == s.config.RunnerURI && r.view.ProfileID == s.config.Profile.ID, nil
}

const runnerRetained = `(s.observed_state<>'deleted' OR NOT EXISTS(SELECT 1 FROM sandbox_runtime_bindings b WHERE b.sandbox_id=s.id AND b.worker_retired_at IS NOT NULL))`

func (s *RunnerEnrollmentService) retained(ctx context.Context, q reservationReader, id uuid.UUID) (*uuid.UUID, error) {
	var out uuid.UUID
	err := q.QueryRow(ctx, `SELECT s.id FROM sandbox_runner_workloads w JOIN sandboxes s ON s.id=w.sandbox_id AND s.org_id=w.org_id WHERE w.org_id=$1 AND w.enrollment_id=$2 AND `+runnerRetained+` ORDER BY s.id LIMIT 1`, s.binding.OrgID, id).Scan(&out)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &out, nil
}
func (s *RunnerEnrollmentService) view(ctx context.Context, q reservationReader, r runnerEnrollmentRecord) (RunnerEnrollment, error) {
	v := r.view
	v.BlockedReasons = []string{}
	v.InstallCommand = s.installCommand(v.ID.String())
	now := time.Now()
	retained, err := s.retained(ctx, q, v.ID)
	if err != nil {
		return v, err
	}
	valid, err := s.standing(ctx, q, r)
	if err != nil {
		return v, err
	}
	qualification, err := s.qualification(ctx, q, r.view.ID)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return v, err
	}
	if err == nil {
		v.Qualification = &qualification
	}
	qualified, err := s.isQualified(ctx, q, r)
	if err != nil {
		return v, err
	}
	switch {
	case r.revoked != nil || !valid || s.config.ModuleState != "enabled":
		v.State = "revoked"
		v.BlockedReasons = append(v.BlockedReasons, "enrollment_revoked")
		if r.reason != nil && (*r.reason == "bootstrap_expired" || *r.reason == "credential_expired") {
			v.State = "expired"
			v.BlockedReasons = []string{*r.reason}
		}
		if retained != nil {
			v.State = "pending_cleanup"
			v.BlockedReasons = append(v.BlockedReasons, "cleanup_pending")
		}
	case r.consumed == nil && !now.Before(v.ExpiresAt):
		v.State = "expired"
		v.BlockedReasons = append(v.BlockedReasons, "bootstrap_expired")
	case r.consumed == nil:
		v.State = "awaiting_install"
	case v.CertificateExpiresAt == nil || !now.Before(*v.CertificateExpiresAt):
		v.State = "expired"
		v.BlockedReasons = append(v.BlockedReasons, "credential_expired")
	case v.LastSeenAt == nil:
		v.State = "awaiting_connection"
	case now.Sub(*v.LastSeenAt) > RunnerHealthFreshness:
		v.State = "offline"
		v.BlockedReasons = append(v.BlockedReasons, "runner_offline")
	case !qualified:
		v.State = "awaiting_connection"
		v.BlockedReasons = append(v.BlockedReasons, "native_qualification_required")
	default:
		v.State = "ready"
	}
	return v, nil
}
func runnerAudit(ctx context.Context, tx pgx.Tx, org, actor, id uuid.UUID, action string, metadata any) error {
	raw, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	if actor == uuid.Nil {
		_, err = tx.Exec(ctx, `INSERT INTO audit_logs(org_id,actor_system,action,target_type,target_id,metadata) VALUES($1,'sandbox-runner-controller',$2,'sandbox_runner',$3,$4)`, org, action, id.String(), raw)
	} else {
		_, err = tx.Exec(ctx, `INSERT INTO audit_logs(org_id,actor_user_id,action,target_type,target_id,metadata) VALUES($1,$2,$3,'sandbox_runner',$4,$5)`, org, actor, action, id.String(), raw)
	}
	return err
}
func (s *RunnerEnrollmentService) List(ctx context.Context, org, actor uuid.UUID) (RunnerEnrollmentList, error) {
	out := RunnerEnrollmentList{Profiles: []RunnerEnrollmentProfile{}, Enrollments: []RunnerEnrollment{}, BlockedReasons: []string{}}
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer tx.Rollback(ctx)
	if err = s.human(ctx, tx, org, actor); err != nil {
		return out, err
	}
	var mode string
	if err = tx.QueryRow(ctx, `SELECT zero_trust_mode FROM organizations WHERE id=$1`, org).Scan(&mode); err != nil {
		return out, err
	}
	if s.config.ModuleState != "enabled" {
		out.BlockedReasons = append(out.BlockedReasons, "module_"+s.config.ModuleState)
	}
	if mode != "enforcing" {
		out.BlockedReasons = append(out.BlockedReasons, "policy_not_enforcing")
	}
	p := s.config.Profile
	p.BlockedReasons = append([]string{}, out.BlockedReasons...)
	p.Prerequisites = append([]string{}, p.Prerequisites...)
	out.Profiles = append(out.Profiles, p)
	// Keep current install/runner and retained cleanup controls visible ahead of
	// bounded recent history. Closed attempts remain in the DB and audit log;
	// accumulating them must never disable inventory or hide active retirement.
	rows, err := tx.Query(ctx, `SELECT `+runnerEnrollmentColumns+` FROM sandbox_runner_enrollments e WHERE e.org_id=$1
 ORDER BY ((e.revoked_at IS NULL AND ((e.consumed_at IS NULL AND e.expires_at>now())
 OR (e.consumed_at IS NOT NULL AND e.certificate_expires_at>now())))
 OR EXISTS(SELECT 1 FROM sandbox_runner_workloads w JOIN sandboxes s ON s.id=w.sandbox_id AND s.org_id=w.org_id
 WHERE w.enrollment_id=e.id AND w.org_id=e.org_id AND `+runnerRetained+`)) DESC,e.created_at DESC,e.id LIMIT 20`, org)
	if err != nil {
		return out, err
	}
	var records []runnerEnrollmentRecord
	for rows.Next() {
		r, e := scanRunnerEnrollment(rows)
		if e != nil {
			rows.Close()
			return out, e
		}
		records = append(records, r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	for _, r := range records {
		v, e := s.view(ctx, tx, r)
		if e != nil {
			return out, e
		}
		out.Enrollments = append(out.Enrollments, v)
	}
	return out, tx.Commit(ctx)
}
func (s *RunnerEnrollmentService) Get(ctx context.Context, org, actor, id uuid.UUID) (RunnerEnrollment, error) {
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return RunnerEnrollment{}, err
	}
	defer tx.Rollback(ctx)
	if err = s.human(ctx, tx, org, actor); err != nil {
		return RunnerEnrollment{}, err
	}
	r, err := s.read(ctx, tx, id, false)
	if err != nil {
		return RunnerEnrollment{}, err
	}
	out, err := s.view(ctx, tx, r)
	if err != nil {
		return out, err
	}
	return out, tx.Commit(ctx)
}
func (s *RunnerEnrollmentService) Issue(ctx context.Context, org, actor uuid.UUID, in RunnerEnrollmentCreate) (RunnerEnrollmentIssue, error) {
	in.Name = strings.TrimSpace(in.Name)
	if in.ProfileID != s.config.Profile.ID || in.IdempotencyKey == uuid.Nil || len(in.Name) == 0 || len(in.Name) > 80 {
		return RunnerEnrollmentIssue{}, ErrInvalid
	}
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return RunnerEnrollmentIssue{}, err
	}
	defer tx.Rollback(ctx)
	mode, err := s.orgLock(ctx, tx)
	if err != nil {
		return RunnerEnrollmentIssue{}, err
	}
	if err = s.human(ctx, tx, org, actor); err != nil {
		return RunnerEnrollmentIssue{}, err
	}
	if s.config.ModuleState != "enabled" || mode != "enforcing" {
		return RunnerEnrollmentIssue{}, ErrDisabled
	}
	raw, _ := json.Marshal(in)
	intent := sha256.Sum256(raw)
	r, err := scanRunnerEnrollment(tx.QueryRow(ctx, `SELECT `+runnerEnrollmentColumns+` FROM sandbox_runner_enrollments e WHERE e.org_id=$1 AND e.issuer_id=$2 AND e.idempotency_key=$3 FOR UPDATE OF e`, org, actor, in.IdempotencyKey))
	if err == nil {
		if !equalHash(r.requestHash, intent[:]) {
			return RunnerEnrollmentIssue{}, ErrConflict
		}
		v, e := s.view(ctx, tx, r)
		if e != nil {
			return RunnerEnrollmentIssue{}, e
		}
		return RunnerEnrollmentIssue{Enrollment: v}, tx.Commit(ctx)
	}
	if !errors.Is(err, ErrNotFound) {
		return RunnerEnrollmentIssue{}, err
	}
	if err = s.sweepTx(ctx, tx); err != nil {
		return RunnerEnrollmentIssue{}, err
	}
	var active, retained bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM sandbox_runner_enrollments WHERE org_id=$1 AND revoked_at IS NULL AND (consumed_at IS NOT NULL OR expires_at>clock_timestamp()))`, org).Scan(&active); err != nil {
		return RunnerEnrollmentIssue{}, err
	}
	// Replacement cannot strand a retained workload from an older configured
	// profile/gateway or one awaiting its first authorization binding.
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM sandboxes s WHERE s.org_id=$1 AND `+runnerRetained+`)`, org).Scan(&retained); err != nil {
		return RunnerEnrollmentIssue{}, err
	}
	if active || retained {
		return RunnerEnrollmentIssue{}, ErrConflict
	}
	var secret [32]byte
	if _, err = rand.Read(secret[:]); err != nil {
		return RunnerEnrollmentIssue{}, err
	}
	token := base64.RawURLEncoding.EncodeToString(secret[:])
	hash := sha256.Sum256([]byte(token))
	// A single database clock establishes the immutable bounded challenge.
	id := uuid.New()
	_, err = tx.Exec(ctx, `INSERT INTO sandbox_runner_enrollments(id,org_id,issuer_id,profile_id,name,idempotency_key,request_hash,binding_hash,token_hash,runner_uri,created_at,expires_at) SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,t,t+interval '10 minutes' FROM (SELECT clock_timestamp() t) q`, id, org, actor, in.ProfileID, in.Name, in.IdempotencyKey, intent[:], s.bindingHash, hash[:], s.config.RunnerURI)
	if err != nil {
		return RunnerEnrollmentIssue{}, err
	}
	if err = runnerAudit(ctx, tx, org, actor, id, "sandbox.runner_enrollment_issue", map[string]any{"profile_id": in.ProfileID, "name": in.Name}); err != nil {
		return RunnerEnrollmentIssue{}, err
	}
	r, err = s.read(ctx, tx, id, false)
	if err != nil {
		return RunnerEnrollmentIssue{}, err
	}
	v, err := s.view(ctx, tx, r)
	if err != nil {
		return RunnerEnrollmentIssue{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return RunnerEnrollmentIssue{}, err
	}
	return RunnerEnrollmentIssue{Enrollment: v, BootstrapToken: token}, nil
}
func parseRunnerCSR(raw string) (*x509.CertificateRequest, error) {
	if len(raw) > 4096 {
		return nil, ErrInvalid
	}
	block, rest := pem.Decode([]byte(raw))
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrInvalid
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil || csr.PublicKeyAlgorithm != x509.Ed25519 || len(csr.Extensions) != 0 {
		return nil, ErrInvalid
	}
	if _, ok := csr.PublicKey.(ed25519.PublicKey); !ok {
		return nil, ErrInvalid
	}
	return csr, nil
}
func parseRunnerProbe(raw string) (string, error) {
	if len(raw) > 1024 {
		return "", ErrInvalid
	}
	key, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(raw))
	if err != nil || key.Type() != ssh.KeyAlgoED25519 || len(options) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return "", ErrInvalid
	}
	return string(ssh.MarshalAuthorizedKey(key)), nil
}
func (s *RunnerEnrollmentService) Redeem(ctx context.Context, id uuid.UUID, token string, in RunnerRedeemInput) (RunnerEnrollmentBundle, error) {
	if id == uuid.Nil || len(token) != 43 {
		return RunnerEnrollmentBundle{}, ErrForbidden
	}
	csr, err := parseRunnerCSR(in.CertificateRequest)
	if err != nil {
		return RunnerEnrollmentBundle{}, err
	}
	probe, err := parseRunnerProbe(in.ProbePublicKey)
	if err != nil {
		return RunnerEnrollmentBundle{}, err
	}
	spki, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return RunnerEnrollmentBundle{}, ErrInvalid
	}
	keyHash := sha256.Sum256(spki)
	tokenHash := sha256.Sum256([]byte(token))
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return RunnerEnrollmentBundle{}, err
	}
	defer tx.Rollback(ctx)
	mode, err := s.orgLock(ctx, tx)
	if err != nil {
		return RunnerEnrollmentBundle{}, ErrForbidden
	}
	r, err := s.read(ctx, tx, id, true)
	if err != nil {
		return RunnerEnrollmentBundle{}, ErrForbidden
	}
	standing, err := s.standing(ctx, tx, r)
	if err != nil {
		return RunnerEnrollmentBundle{}, err
	}
	if !standing || s.config.ModuleState != "enabled" || mode != "enforcing" || r.revoked != nil || !time.Now().Before(r.view.ExpiresAt) || !equalHash(r.tokenHash, tokenHash[:]) {
		return RunnerEnrollmentBundle{}, ErrForbidden
	}
	var certificate string
	if r.consumed != nil {
		// Recovery returns the same public certificate for the same machine keys.
		// It cannot mint a replacement, renew the challenge, or recover secrets.
		if !equalHash(r.keyHash, keyHash[:]) || r.probe == nil || *r.probe != probe {
			return RunnerEnrollmentBundle{}, ErrConflict
		}
		certificate = *r.certificate
	} else {
		raw, e := s.signer.SignRunnerCSR([]byte(in.CertificateRequest))
		if e != nil {
			return RunnerEnrollmentBundle{}, ErrDisabled
		}
		block, rest := pem.Decode(raw)
		if block == nil || len(bytes.TrimSpace(rest)) != 0 {
			return RunnerEnrollmentBundle{}, ErrDisabled
		}
		leaf, e := x509.ParseCertificate(block.Bytes)
		root, _ := runnerCA(s.config.RunnerCA)
		if e != nil || leaf.CheckSignatureFrom(root) != nil || len(leaf.URIs) != 1 || leaf.URIs[0].String() != s.config.RunnerURI || !bytes.Equal(leaf.RawSubjectPublicKeyInfo, spki) || !leaf.NotAfter.After(time.Now()) || time.Until(leaf.NotAfter) > 24*time.Hour+time.Minute {
			return RunnerEnrollmentBundle{}, ErrDisabled
		}
		certificate = string(raw)
		if _, err = tx.Exec(ctx, `UPDATE sandbox_runner_enrollments SET consumed_at=clock_timestamp(),spki_hash=$2,probe_public_key=$3,certificate=$4,certificate_expires_at=$5 WHERE id=$1 AND consumed_at IS NULL`, id, keyHash[:], probe, certificate, leaf.NotAfter); err != nil {
			return RunnerEnrollmentBundle{}, err
		}
		if err = runnerAudit(ctx, tx, r.org, uuid.Nil, id, "sandbox.runner_enrollment_redeem", map[string]any{"profile_id": r.view.ProfileID}); err != nil {
			return RunnerEnrollmentBundle{}, err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return RunnerEnrollmentBundle{}, err
	}
	return RunnerEnrollmentBundle{EnrollmentID: id, ProfileID: s.config.Profile.ID, BindingSHA256: hex.EncodeToString(s.bindingHash), Certificate: certificate, RunnerCA: s.config.RunnerCA, APICA: s.config.APICA, Install: s.config.Profile.Install}, nil
}
func (s *RunnerEnrollmentService) withdrawTx(ctx context.Context, tx pgx.Tx, id, actor uuid.UUID, reason string) error {
	if _, err := tx.Exec(ctx, `UPDATE sandbox_runner_enrollments SET revoked_at=COALESCE(revoked_at,clock_timestamp()),revoke_reason=COALESCE(revoke_reason,$2),ready_at=NULL WHERE id=$1`, id, reason); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `UPDATE sandboxes s SET desired_state='deleted',generation=generation+1 FROM sandbox_runner_workloads w WHERE w.enrollment_id=$1 AND w.sandbox_id=s.id AND w.org_id=s.org_id AND s.org_id=$2 AND s.desired_state<>'deleted' AND `+runnerRetained+` RETURNING s.id,s.generation`, id, s.binding.OrgID)
	if err != nil {
		return err
	}
	var changed []struct {
		id         uuid.UUID
		generation int64
	}
	for rows.Next() {
		var r struct {
			id         uuid.UUID
			generation int64
		}
		if err = rows.Scan(&r.id, &r.generation); err != nil {
			rows.Close()
			return err
		}
		changed = append(changed, r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE sandbox_runtime_credentials c SET revoked_at=COALESCE(c.revoked_at,clock_timestamp()) FROM sandbox_runner_workloads w WHERE w.enrollment_id=$1 AND w.sandbox_id=c.sandbox_id AND w.org_id=c.org_id`, id); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE devices d SET health_blocked=true FROM sandboxes s JOIN sandbox_runner_workloads w ON w.sandbox_id=s.id AND w.org_id=s.org_id WHERE w.enrollment_id=$1 AND d.id=s.peer_id AND d.org_id=s.org_id AND d.kind='sandbox'`, id); err != nil {
		return err
	}
	for _, r := range changed {
		if err = runnerAudit(ctx, tx, s.binding.OrgID, actor, r.id, "sandbox.runner_withdraw", map[string]any{"enrollment_id": id, "generation": r.generation, "cleanup_pending": true, "cause": reason}); err != nil {
			return err
		}
	}
	return nil
}
func (s *RunnerEnrollmentService) Revoke(ctx context.Context, org, actor, id uuid.UUID) (RunnerEnrollment, error) {
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return RunnerEnrollment{}, err
	}
	defer tx.Rollback(ctx)
	if _, err = s.orgLock(ctx, tx); err != nil {
		return RunnerEnrollment{}, err
	}
	if err = s.human(ctx, tx, org, actor); err != nil {
		return RunnerEnrollment{}, err
	}
	r, err := s.read(ctx, tx, id, true)
	if err != nil {
		return RunnerEnrollment{}, err
	}
	if r.revoked == nil {
		if err = s.withdrawTx(ctx, tx, id, actor, "admin_revoke"); err != nil {
			return RunnerEnrollment{}, err
		}
		if err = runnerAudit(ctx, tx, org, actor, id, "sandbox.runner_enrollment_revoke", map[string]any{"cleanup_pending": true}); err != nil {
			return RunnerEnrollment{}, err
		}
	}
	r, err = s.read(ctx, tx, id, false)
	if err != nil {
		return RunnerEnrollment{}, err
	}
	v, err := s.view(ctx, tx, r)
	if err != nil {
		return v, err
	}
	if err = tx.Commit(ctx); err != nil {
		return v, err
	}
	s.store.notifyPolicy(ctx, org)
	return v, nil
}
func (s *RunnerEnrollmentService) sweepTx(ctx context.Context, tx pgx.Tx) error {
	rows, err := tx.Query(ctx, `SELECT `+runnerEnrollmentColumns+` FROM sandbox_runner_enrollments e WHERE e.org_id=$1 AND e.revoked_at IS NULL ORDER BY e.created_at,e.id LIMIT 20 FOR UPDATE OF e`, s.binding.OrgID)
	if err != nil {
		return err
	}
	var records []runnerEnrollmentRecord
	for rows.Next() {
		r, e := scanRunnerEnrollment(rows)
		if e != nil {
			rows.Close()
			return e
		}
		records = append(records, r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, r := range records {
		valid, e := s.standing(ctx, tx, r)
		if e != nil {
			return e
		}
		if !valid || s.config.ModuleState != "enabled" || r.consumed == nil && !time.Now().Before(r.view.ExpiresAt) || r.consumed != nil && (r.view.CertificateExpiresAt == nil || !time.Now().Before(*r.view.CertificateExpiresAt)) {
			reason := "authority_unavailable"
			if r.consumed == nil && !time.Now().Before(r.view.ExpiresAt) {
				reason = "bootstrap_expired"
			}
			if r.consumed != nil && (r.view.CertificateExpiresAt == nil || !time.Now().Before(*r.view.CertificateExpiresAt)) {
				reason = "credential_expired"
			}
			if err = s.withdrawTx(ctx, tx, r.view.ID, uuid.Nil, reason); err != nil {
				return err
			}
		}
	}
	return nil
}
func (s *RunnerEnrollmentService) Sweep(ctx context.Context) error {
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = s.orgLock(ctx, tx); err != nil {
		return err
	}
	if err = s.sweepTx(ctx, tx); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err == nil {
		s.store.notifyPolicy(ctx, s.binding.OrgID)
	}
	return err
}
