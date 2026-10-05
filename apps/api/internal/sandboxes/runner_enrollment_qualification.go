package sandboxes

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var runnerQualificationChecks = []string{"host-capabilities", "approved-image-load", "bounded-provider-start-stop", "offline-expiry-fence", "private-network-connectivity"}

type RunnerQualificationPlatform struct {
	OS           string `json:"os"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
}
type RunnerQualificationCheck struct {
	Code     string `json:"code"`
	Result   string `json:"result"`
	Evidence string `json:"evidence"`
}
type RunnerQualificationReport struct {
	Version            int                         `json:"version"`
	EnrollmentID       uuid.UUID                   `json:"enrollment_id"`
	ProfileID          uuid.UUID                   `json:"profile_id"`
	BindingSHA256      string                      `json:"binding_sha256"`
	SourceSHA          string                      `json:"source_sha"`
	Platform           RunnerQualificationPlatform `json:"platform"`
	Checks             []RunnerQualificationCheck  `json:"checks"`
	ImageConfigDigests []string                    `json:"image_config_digests"`
	StartedAt          time.Time                   `json:"started_at"`
	FinishedAt         time.Time                   `json:"finished_at"`
}
type RunnerQualificationRecord struct {
	ReportSHA256     string                    `json:"report_sha256"`
	Report           RunnerQualificationReport `json:"report"`
	Decision         string                    `json:"decision"`
	ReviewedBy       *uuid.UUID                `json:"reviewed_by,omitempty"`
	ReviewedAt       *time.Time                `json:"reviewed_at,omitempty"`
	ReviewNote       *string                   `json:"review_note,omitempty"`
	SubmittedAt      time.Time                 `json:"submitted_at"`
	RunnerSPKISHA256 string                    `json:"runner_spki_sha256"`
	Approvable       bool                      `json:"approvable"`
	BlockedReasons   []string                  `json:"blocked_reasons"`
}
type RunnerQualificationReview struct {
	ExpectedReportSHA256 string `json:"expected_report_sha256"`
	Decision             string `json:"decision"`
	ReviewNote           string `json:"review_note"`
}

func (s *RunnerEnrollmentService) validateReport(r RunnerQualificationReport) error {
	raw, _ := json.Marshal(r)
	if len(raw) > 16384 || r.Version != 1 || r.EnrollmentID == uuid.Nil || r.ProfileID != s.config.Profile.ID || r.BindingSHA256 != hex.EncodeToString(s.bindingHash) || r.SourceSHA != s.config.Profile.Install.SourceSHA || len(r.Checks) > 16 || len(r.ImageConfigDigests) != len(s.binding.Profiles) || r.StartedAt.IsZero() || !r.FinishedAt.After(r.StartedAt) || r.FinishedAt.Sub(r.StartedAt) > time.Hour || r.FinishedAt.After(time.Now().Add(time.Minute)) {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, check := range r.Checks {
		if seen[check.Code] || len(check.Evidence) > 1024 || (check.Result != "passed" && check.Result != "failed" && check.Result != "unrun") || strings.Contains(strings.ToUpper(check.Evidence), "PRIVATE KEY") || strings.Contains(strings.ToLower(check.Evidence), "authorization:") {
			return ErrInvalid
		}
		known := false
		for _, code := range runnerQualificationChecks {
			known = known || code == check.Code
		}
		if !known {
			return ErrInvalid
		}
		seen[check.Code] = true
	}
	seen = map[string]bool{}
	for _, digest := range r.ImageConfigDigests {
		if seen[digest] {
			return ErrInvalid
		}
		seen[digest] = true
		known := false
		for _, p := range s.binding.Profiles {
			known = known || p.ConfigDigest == digest
		}
		if !known {
			return ErrInvalid
		}
	}
	return nil
}
func (s *RunnerEnrollmentService) reportPassed(r RunnerQualificationReport) bool {
	if s.validateReport(r) != nil || r.Platform.OS != s.config.Profile.HostOS || r.Platform.Version != s.config.Profile.HostVersion || r.Platform.Architecture != s.config.Profile.Architecture || len(r.Checks) != len(runnerQualificationChecks) {
		return false
	}
	for _, check := range r.Checks {
		if check.Result != "passed" || strings.TrimSpace(check.Evidence) == "" {
			return false
		}
	}
	return true
}
func (s *RunnerEnrollmentService) qualification(ctx context.Context, q reservationReader, id uuid.UUID) (RunnerQualificationRecord, error) {
	var out RunnerQualificationRecord
	var raw, hash, key []byte
	err := q.QueryRow(ctx, `SELECT report_hash,report,decision,reviewed_by,reviewed_at,review_note,created_at,spki_hash FROM sandbox_runner_qualification_reports WHERE org_id=$1 AND enrollment_id=$2 ORDER BY created_at DESC,id DESC LIMIT 1`, s.binding.OrgID, id).Scan(&hash, &raw, &out.Decision, &out.ReviewedBy, &out.ReviewedAt, &out.ReviewNote, &out.SubmittedAt, &key)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNotFound
	}
	if err != nil {
		return out, err
	}
	out.ReportSHA256 = hex.EncodeToString(hash)
	out.RunnerSPKISHA256 = hex.EncodeToString(key)
	if json.Unmarshal(raw, &out.Report) != nil {
		return out, ErrInvalid
	}
	out.BlockedReasons = []string{}
	if !s.reportPassed(out.Report) {
		out.BlockedReasons = append(out.BlockedReasons, "qualification_checks_incomplete")
	}
	if s.nativeProof == nil || s.nativeProof.VerifyRunnerQualification(ctx, id, out.Report) != nil {
		out.BlockedReasons = append(out.BlockedReasons, "native_proof_required")
	}
	out.Approvable = out.Decision == "pending" && len(out.BlockedReasons) == 0
	return out, nil
}
func (s *RunnerEnrollmentService) isQualified(ctx context.Context, q reservationReader, r runnerEnrollmentRecord) (bool, error) {
	var raw, key, binding []byte
	var decision string
	err := q.QueryRow(ctx, `SELECT report,spki_hash,binding_hash,decision FROM sandbox_runner_qualification_reports WHERE org_id=$1 AND enrollment_id=$2 ORDER BY created_at DESC,id DESC LIMIT 1`, s.binding.OrgID, r.view.ID).Scan(&raw, &key, &binding, &decision)
	if errors.Is(err, pgx.ErrNoRows) {
		return s.qualified(r.keyHash), nil
	}
	if err != nil {
		return false, err
	}
	var report RunnerQualificationReport
	if json.Unmarshal(raw, &report) != nil {
		return false, ErrInvalid
	}
	bound := equalHash(key, r.keyHash) && equalHash(binding, s.bindingHash) && report.EnrollmentID == r.view.ID && s.reportPassed(report)
	return bound && (s.qualified(r.keyHash) || decision == "approved" && s.nativeProof != nil && s.nativeProof.VerifyRunnerQualification(ctx, r.view.ID, report) == nil), nil
}
func (s *RunnerEnrollmentService) SubmitQualification(ctx context.Context, leaf *x509.Certificate, report RunnerQualificationReport) (RunnerQualificationRecord, error) {
	if err := s.validateReport(report); err != nil {
		return RunnerQualificationRecord{}, err
	}
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return RunnerQualificationRecord{}, err
	}
	defer tx.Rollback(ctx)
	if _, err = s.orgLock(ctx, tx); err != nil {
		return RunnerQualificationRecord{}, err
	}
	r, err := s.certificateRecord(ctx, tx, leaf)
	if err != nil {
		return RunnerQualificationRecord{}, err
	}
	r, err = s.read(ctx, tx, r.view.ID, true)
	if err != nil {
		return RunnerQualificationRecord{}, err
	}
	c, err := s.credential(ctx, tx, r)
	if err != nil || c.CleanupOnly || report.EnrollmentID != r.view.ID {
		return RunnerQualificationRecord{}, ErrForbidden
	}
	raw, _ := json.Marshal(report)
	hash := sha256.Sum256(raw)
	if _, err = tx.Exec(ctx, `INSERT INTO sandbox_runner_qualification_reports(org_id,enrollment_id,spki_hash,binding_hash,report_hash,report) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(org_id,enrollment_id,report_hash) DO NOTHING`, r.org, r.view.ID, r.keyHash, s.bindingHash, hash[:], raw); err != nil {
		return RunnerQualificationRecord{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE sandbox_runner_enrollments SET ready_at=NULL WHERE id=$1`, r.view.ID); err != nil {
		return RunnerQualificationRecord{}, err
	}
	out, err := s.qualification(ctx, tx, r.view.ID)
	if err != nil {
		return out, err
	}
	if err = runnerAudit(ctx, tx, r.org, uuid.Nil, r.view.ID, "sandbox.runner_qualification_report", map[string]any{"report_sha256": hex.EncodeToString(hash[:]), "passed": s.reportPassed(report)}); err != nil {
		return out, err
	}
	return out, tx.Commit(ctx)
}
func (s *RunnerEnrollmentService) ReviewQualification(ctx context.Context, org, actor, id uuid.UUID, in RunnerQualificationReview) (RunnerQualificationRecord, error) {
	if !runnerHash.MatchString(in.ExpectedReportSHA256) || (in.Decision != "approve" && in.Decision != "reject") || len(strings.TrimSpace(in.ReviewNote)) == 0 || len(in.ReviewNote) > 512 {
		return RunnerQualificationRecord{}, ErrInvalid
	}
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return RunnerQualificationRecord{}, err
	}
	defer tx.Rollback(ctx)
	if _, err = s.orgLock(ctx, tx); err != nil {
		return RunnerQualificationRecord{}, err
	}
	if err = s.human(ctx, tx, org, actor); err != nil {
		return RunnerQualificationRecord{}, err
	}
	r, err := s.read(ctx, tx, id, true)
	if err != nil {
		return RunnerQualificationRecord{}, err
	}
	c, err := s.credential(ctx, tx, r)
	if err != nil || c.CleanupOnly {
		return RunnerQualificationRecord{}, ErrForbidden
	}
	out, err := s.qualification(ctx, tx, id)
	if err != nil {
		return out, err
	}
	if out.ReportSHA256 != in.ExpectedReportSHA256 {
		return out, ErrConflict
	}
	if in.Decision == "approve" && !s.reportPassed(out.Report) {
		return out, ErrInvalid
	}
	if in.Decision == "approve" && (s.nativeProof == nil || s.nativeProof.VerifyRunnerQualification(ctx, id, out.Report) != nil) {
		return out, ErrDisabled
	}
	decision := "approved"
	if in.Decision == "reject" {
		decision = "rejected"
	}
	if out.Decision != "pending" {
		if out.Decision == decision && out.ReviewNote != nil && *out.ReviewNote == in.ReviewNote {
			return out, tx.Commit(ctx)
		}
		return out, ErrConflict
	}
	hash, _ := hex.DecodeString(out.ReportSHA256)
	tag, err := tx.Exec(ctx, `UPDATE sandbox_runner_qualification_reports SET decision=$4,reviewed_by=$5,reviewed_at=clock_timestamp(),review_note=$6 WHERE org_id=$1 AND enrollment_id=$2 AND report_hash=$3 AND spki_hash=$7 AND binding_hash=$8 AND decision='pending'`, org, id, hash, decision, actor, in.ReviewNote, r.keyHash, s.bindingHash)
	if err != nil {
		return out, err
	}
	if tag.RowsAffected() != 1 {
		return out, ErrConflict
	}
	if err = runnerAudit(ctx, tx, org, actor, id, "sandbox.runner_qualification_review", map[string]any{"report_sha256": out.ReportSHA256, "decision": decision}); err != nil {
		return out, err
	}
	out, err = s.qualification(ctx, tx, id)
	if err != nil {
		return out, err
	}
	return out, tx.Commit(ctx)
}

// Public reports are normalized before hashing. They remain evidence supplied
// by the authenticated machine and explicitly reviewed by a human, not a claim
// that report parsing independently measured the native host.
