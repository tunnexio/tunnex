package sandboxes

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (s *RunnerQualificationService) machineTrial(ctx context.Context, tx pgx.Tx, leaf *x509.Certificate, id uuid.UUID, lock bool) (runnerTrialRecord, error) {
	r, err := s.readTrial(ctx, tx, id, lock)
	if err != nil {
		return r, err
	}
	enrollment, err := s.certificateRecord(ctx, tx, leaf)
	if err != nil {
		return r, err
	}
	credential, err := s.credential(ctx, tx, enrollment)
	if err != nil || credential.CleanupOnly || credential.EnrollmentID != r.view.EnrollmentID || !equalHash(enrollment.keyHash, r.keyHash) || !equalHash(r.bindingHash, s.bindingHash) {
		return r, ErrForbidden
	}
	return r, nil
}
func (s *RunnerQualificationService) QualificationMachineView(ctx context.Context, leaf *x509.Certificate, id uuid.UUID) (RunnerQualificationMachineView, error) {
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return RunnerQualificationMachineView{}, err
	}
	defer tx.Rollback(ctx)
	r, err := s.machineTrial(ctx, tx, leaf, id, false)
	if err != nil {
		return RunnerQualificationMachineView{}, err
	}
	v := RunnerQualificationMachineView{Version: 1, EnrollmentID: r.view.EnrollmentID, ProfileID: r.view.ProfileID, BindingSHA256: hex.EncodeToString(r.bindingHash), SourceSHA: r.sourceSHA, TrialID: r.view.ID, SandboxID: r.view.SandboxID, Generation: r.view.Generation, CreatedAt: r.view.CreatedAt, ExpiresAt: r.view.ExpiresAt, Phase: r.view.Phase, InitialReadyAt: r.initialReady, StoppedAt: r.stopped, ResumeReadyAt: r.resumeReady, RetiredAt: r.view.RetiredAt, OfflineWitnessSHA256: hex.EncodeToString(r.witnessHash)}
	if r.view.RuntimeID != nil {
		v.RuntimeID = *r.view.RuntimeID
	}
	if r.view.Phase == "complete" {
		v.ProofSHA256, err = s.trialProof(ctx, tx, r)
		if err != nil {
			return v, err
		}
	}
	return v, nil
}

// A machine witness is explicitly authenticated evidence of the local guard,
// not an independent host measurement. Controller lifecycle receipts and an
// administrator's separate review are additionally required for readiness.
func (s *RunnerQualificationService) validateOfflineWitness(r runnerTrialRecord, w RunnerQualificationOfflineWitness, now time.Time) error {
	v := r.view
	if w.Version != 1 || w.TrialID != v.ID || w.SandboxID != v.SandboxID || v.RuntimeID == nil || w.RuntimeID != *v.RuntimeID || w.Generation != 3 || w.BindingSHA256 != hex.EncodeToString(r.bindingHash) || w.SourceSHA != r.sourceSHA || !w.CreatedAt.Equal(v.CreatedAt) || !w.ExpiresAt.Equal(v.ExpiresAt) || w.ImageDigest != r.imageDigest || w.ObserverSHA256 != s.config.Profile.BootstrapScript.SHA256 || w.MemoryMaxBytes != 134217728 || w.MemorySwapMaxBytes != 0 || w.PIDsMax != 64 || w.CPUQuotaUS != 100000 || w.CPUPeriodUS != 100000 || w.CgroupPopulated || r.resumeReady == nil || r.initialReady == nil || r.stopped == nil || r.failure != nil {
		return ErrInvalid
	}
	if r.view.Phase != "awaiting_expiry" && r.view.Phase != "cleanup_pending" && r.view.Phase != "complete" {
		return ErrConflict
	}
	// Receipt time is the actor's sampled sweep time written only after confirmed
	// stop. It is not represented as an exact physical-completion timestamp.
	if w.TransportStoppedAt.Before(*r.resumeReady) || !w.TransportStoppedAt.Before(v.ExpiresAt) || w.ActorExpiredAt.Before(v.ExpiresAt) || w.StoppedObservedAt.Before(w.ActorExpiredAt) || w.TransportResumedAt.Before(w.StoppedObservedAt) || w.TransportResumedAt.After(now.Add(time.Minute)) || w.StoppedObservedAt.Sub(v.ExpiresAt) > 2*time.Minute || w.TransportResumedAt.Sub(w.StoppedObservedAt) > time.Minute {
		return ErrInvalid
	}
	return nil
}
func (s *RunnerQualificationService) SubmitQualificationOfflineWitness(ctx context.Context, leaf *x509.Certificate, id uuid.UUID, w RunnerQualificationOfflineWitness) error {
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = s.orgLock(ctx, tx); err != nil {
		return err
	}
	r, err := s.machineTrial(ctx, tx, leaf, id, true)
	if err != nil {
		return err
	}
	if err = s.validateOfflineWitness(r, w, time.Now()); err != nil {
		return err
	}
	raw, err := json.Marshal(w)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(raw)
	if len(r.witnessHash) > 0 {
		if !equalHash(r.witnessHash, hash[:]) {
			return ErrConflict
		}
		return tx.Commit(ctx)
	}
	if _, err = tx.Exec(ctx, `UPDATE sandbox_runner_qualification_trials SET offline_witness=$2,offline_witness_hash=$3 WHERE id=$1 AND offline_witness IS NULL`, id, raw, hash[:]); err != nil {
		return err
	}
	if err = recordRunnerTrialEvent(ctx, tx, r.view.SandboxID, "offline_expiry", 3, map[string]any{"witness_sha256": hex.EncodeToString(hash[:]), "observed_at": w.StoppedObservedAt, "actor_receipt_sampled_at": w.ActorExpiredAt, "ssh_origin": "runner"}); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err == nil && s.wake != nil {
		s.wake()
	}
	return err
}
func (s *RunnerQualificationService) trialProof(ctx context.Context, q reservationReader, r runnerTrialRecord) (string, error) {
	if r.view.Phase != "complete" || r.view.Generation != 4 || r.view.ObservedState != StateDeleted || r.view.DesiredState != "deleted" || r.view.RetiredAt == nil || len(r.witnessHash) != 32 || r.initialReady == nil || r.stopped == nil || r.resumeReady == nil || r.failure != nil {
		return "", ErrDisabled
	}
	if r.initialReady.Before(r.view.CreatedAt) || !r.stopped.After(*r.initialReady) || !r.resumeReady.After(*r.stopped) || !r.resumeReady.Before(r.view.ExpiresAt) || r.view.RetiredAt.Before(r.view.ExpiresAt) {
		return "", ErrDisabled
	}
	var retired bool
	if err := q.QueryRow(ctx, `SELECT worker_retired_at IS NOT NULL AND runtime_id=$2 FROM sandbox_runtime_bindings WHERE sandbox_id=$1`, r.view.SandboxID, r.view.RuntimeID).Scan(&retired); err != nil {
		return "", err
	}
	if !retired {
		return "", ErrDisabled
	}
	var witness RunnerQualificationOfflineWitness
	if json.Unmarshal(r.witness, &witness) != nil {
		return "", ErrInvalid
	}
	if err := s.validateOfflineWitness(r, witness, time.Now()); err != nil {
		return "", err
	}
	hashes := []string{}
	for i, code := range []string{"initial_ready", "stopped", "resume_ready", "offline_expiry", "retired"} {
		var hash []byte
		var gen int64
		err := q.QueryRow(ctx, `SELECT evidence_hash,generation FROM sandbox_runner_qualification_events WHERE trial_id=$1 AND code=$2`, r.view.ID, code).Scan(&hash, &gen)
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrDisabled
		}
		if err != nil {
			return "", err
		}
		expected := []int64{1, 2, 3, 3, 4}[i]
		if gen != expected || len(hash) != 32 {
			return "", ErrDisabled
		}
		hashes = append(hashes, hex.EncodeToString(hash))
	}
	raw, _ := json.Marshal(struct {
		TrialID, EnrollmentID, SandboxID      uuid.UUID
		Binding, SPKI, Source, Image, Witness string
		Events                                []string
	}{r.view.ID, r.view.EnrollmentID, r.view.SandboxID, hex.EncodeToString(r.bindingHash), hex.EncodeToString(r.keyHash), r.sourceSHA, r.imageDigest, hex.EncodeToString(r.witnessHash), hashes})
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:]), nil
}
func (s *RunnerQualificationService) VerifyRunnerQualification(ctx context.Context, enrollmentID uuid.UUID, report RunnerQualificationReport) error {
	if report.EnrollmentID != enrollmentID || report.ProfileID != s.config.Profile.ID || report.BindingSHA256 != hex.EncodeToString(s.bindingHash) || report.SourceSHA != s.config.Profile.Install.SourceSHA {
		return ErrForbidden
	}
	var id uuid.UUID
	err := s.store.pool.QueryRow(ctx, `SELECT q.id FROM sandbox_runner_qualification_trials q JOIN sandbox_runner_enrollments e ON e.id=q.enrollment_id AND e.org_id=q.org_id WHERE q.org_id=$1 AND q.enrollment_id=$2 AND q.phase='complete' AND q.binding_hash=$3 AND q.spki_hash=e.spki_hash AND q.profile_id=$4 AND q.source_sha=$5 ORDER BY q.created_at DESC,q.id DESC LIMIT 1`, s.binding.OrgID, enrollmentID, s.bindingHash, report.ProfileID, report.SourceSHA).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrDisabled
	}
	if err != nil {
		return err
	}
	r, err := s.readTrial(ctx, s.store.pool, id, false)
	if err != nil {
		return err
	}
	proof, err := s.trialProof(ctx, s.store.pool, r)
	if err != nil {
		return err
	}
	if report.FinishedAt.Before(*r.view.RetiredAt) {
		return ErrInvalid
	}
	expected := fmt.Sprintf("trial:%s;proof_sha256:%s;offline_witness_sha256:%s;ssh_origin:runner", id, proof, hex.EncodeToString(r.witnessHash))
	found := 0
	for _, check := range report.Checks {
		if check.Code == "bounded-provider-start-stop" || check.Code == "offline-expiry-fence" || check.Code == "private-network-connectivity" {
			if check.Result != "passed" || strings.TrimSpace(check.Evidence) != expected {
				return ErrDisabled
			}
			found++
		}
	}
	if found != 3 {
		return ErrDisabled
	}
	return nil
}
