package sandboxes

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type runnerTrialRecord struct {
	view                               RunnerQualificationTrial
	creator                            uuid.UUID
	bindingHash, keyHash, witnessHash  []byte
	sourceSHA, imageDigest             string
	initialReady, stopped, resumeReady *time.Time
	witness                            []byte
	failure                            *string
}

const runnerTrialColumns = `q.id,q.enrollment_id,q.profile_id,q.sandbox_id,q.terminal_device_id,q.creator_id,q.phase,s.observed_state,s.desired_state,s.generation,q.created_at,q.expires_at,q.runtime_id,q.retired_at,q.binding_hash,q.spki_hash,q.source_sha,q.image_digest,q.initial_ready_at,q.stopped_at,q.resume_ready_at,q.offline_witness,q.offline_witness_hash,q.failure_code`

func (s *RunnerQualificationService) readTrial(ctx context.Context, q reservationReader, id uuid.UUID, lock bool) (runnerTrialRecord, error) {
	var r runnerTrialRecord
	suffix := ""
	if lock {
		suffix = " FOR UPDATE OF q,s"
	}
	err := q.QueryRow(ctx, `SELECT `+runnerTrialColumns+` FROM sandbox_runner_qualification_trials q JOIN sandboxes s ON s.id=q.sandbox_id AND s.org_id=q.org_id WHERE q.org_id=$1 AND q.id=$2`+suffix, s.binding.OrgID, id).Scan(&r.view.ID, &r.view.EnrollmentID, &r.view.ProfileID, &r.view.SandboxID, &r.view.TerminalDeviceID, &r.creator, &r.view.Phase, &r.view.ObservedState, &r.view.DesiredState, &r.view.Generation, &r.view.CreatedAt, &r.view.ExpiresAt, &r.view.RuntimeID, &r.view.RetiredAt, &r.bindingHash, &r.keyHash, &r.sourceSHA, &r.imageDigest, &r.initialReady, &r.stopped, &r.resumeReady, &r.witness, &r.witnessHash, &r.failure)
	if errors.Is(err, pgx.ErrNoRows) {
		return r, ErrNotFound
	}
	return r, err
}
func (s *RunnerQualificationService) trialView(ctx context.Context, tx pgx.Tx, r runnerTrialRecord) (RunnerQualificationTrial, error) {
	v := r.view
	v.BlockedReasons = []string{}
	v.State = "pending"
	switch v.Phase {
	case "complete":
		v.State = "complete"
	case "failed":
		v.State = "failed"
	case "awaiting_expiry", "cleanup_pending":
		v.State = v.Phase
	}
	if r.failure != nil {
		v.BlockedReasons = append(v.BlockedReasons, *r.failure)
	}
	// This stable installed entry point resolves only its own root-owned config.
	v.QualificationCommand = "sudo /usr/bin/python3 /usr/local/libexec/tunnex-sandbox/enrollments/" + v.EnrollmentID.String() + "/qualify.py --qualification-trial-id " + v.ID.String()
	v.Phases = []RunnerQualificationTrialPhase{}
	for _, code := range []string{"initial_ready", "stopped", "resume_ready", "offline_expiry", "retired"} {
		p := RunnerQualificationTrialPhase{Code: code, State: "pending"}
		var at time.Time
		var hash []byte
		err := tx.QueryRow(ctx, `SELECT observed_at,evidence_hash FROM sandbox_runner_qualification_events WHERE trial_id=$1 AND code=$2`, v.ID, code).Scan(&at, &hash)
		if err == nil {
			p.State = "passed"
			p.ObservedAt = &at
			p.EvidenceSHA256 = hex.EncodeToString(hash)
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return v, err
		}
		if v.Phase == "failed" && p.State == "pending" {
			p.State = "failed"
		}
		v.Phases = append(v.Phases, p)
	}
	if v.ObservedState == StateReady && v.DesiredState == "started" {
		sb, err := scanSandbox(tx.QueryRow(ctx, `SELECT `+sandboxColumns+` FROM sandboxes WHERE id=$1 AND org_id=$2`, v.SandboxID, s.binding.OrgID))
		if err != nil {
			return v, err
		}
		if err = loadConnection(ctx, tx, &sb); err != nil {
			return v, err
		}
		v.Connection = sb.Connection
	}
	return v, nil
}
func (s *RunnerQualificationService) StatusQualification(ctx context.Context, org, actor, enrollmentID, trialID uuid.UUID) (RunnerQualificationTrial, error) {
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return RunnerQualificationTrial{}, err
	}
	defer tx.Rollback(ctx)
	if err = s.authorizeTrialView(ctx, tx, org, actor); err != nil {
		return RunnerQualificationTrial{}, err
	}
	r, err := s.readTrial(ctx, tx, trialID, false)
	if err != nil {
		return RunnerQualificationTrial{}, err
	}
	if r.view.EnrollmentID != enrollmentID {
		return RunnerQualificationTrial{}, ErrNotFound
	}
	return s.trialView(ctx, tx, r)
}
func (s *RunnerQualificationService) LatestQualificationTrial(ctx context.Context, org, actor, enrollmentID uuid.UUID) (RunnerQualificationTrial, error) {
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return RunnerQualificationTrial{}, err
	}
	defer tx.Rollback(ctx)
	if err = s.authorizeTrialView(ctx, tx, org, actor); err != nil {
		return RunnerQualificationTrial{}, err
	}
	var id uuid.UUID
	err = tx.QueryRow(ctx, `SELECT id FROM sandbox_runner_qualification_trials WHERE org_id=$1 AND enrollment_id=$2 ORDER BY created_at DESC,id DESC LIMIT 1`, org, enrollmentID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return RunnerQualificationTrial{}, ErrNotFound
	}
	if err != nil {
		return RunnerQualificationTrial{}, err
	}
	r, err := s.readTrial(ctx, tx, id, false)
	if err != nil {
		return RunnerQualificationTrial{}, err
	}
	return s.trialView(ctx, tx, r)
}

// The callback is invoked while enrollment holds its organization transaction.
// It deliberately takes no advisory/row locks or external action.
func (s *RunnerQualificationService) VerifyRunnerQualificationTrial(ctx context.Context, enrollmentID uuid.UUID, a RuntimeAuthorization) error {
	if s == nil || s.config.ModuleState != "enabled" || !a.valid(s.binding) {
		return ErrForbidden
	}
	var allowed bool
	err := s.store.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM sandbox_runner_qualification_trials q JOIN sandboxes s ON s.id=q.sandbox_id AND s.org_id=q.org_id JOIN sandbox_runner_enrollments e ON e.id=q.enrollment_id AND e.org_id=q.org_id WHERE q.enrollment_id=$1 AND q.sandbox_id=$2 AND q.org_id=$3 AND q.creator_id=$4 AND q.terminal_device_id=$5 AND q.template_id=$6 AND s.generation=$7 AND s.desired_state=$8 AND q.created_at=$9 AND q.expires_at=$10 AND q.binding_hash=$11 AND q.profile_id=$12 AND q.source_sha=$13 AND q.image_digest=$14 AND q.spki_hash=e.spki_hash AND sandbox_qualification_trial_valid(s.id) AND (`+sandboxEligibilitySQL+`))`, enrollmentID, a.SandboxID, a.OrgID, a.CreatorID, a.TerminalDeviceID, a.TemplateID, a.Generation, a.Desired, a.CreatedAt, a.ExpiresAt, s.bindingHash, s.config.Profile.ID, s.config.Profile.Install.SourceSHA, a.Profile.ConfigDigest).Scan(&allowed)
	if err != nil {
		return err
	}
	if !allowed {
		return ErrForbidden
	}
	return nil
}

// A receipt is inserted only in the same transaction that commits a verified
// Ready/Stopped transition. This is control-plane evidence, not a host flag.
func recordRunnerTrialEvent(ctx context.Context, tx pgx.Tx, sandboxID uuid.UUID, code string, generation int64, evidence any) error {
	var id uuid.UUID
	err := tx.QueryRow(ctx, `SELECT id FROM sandbox_runner_qualification_trials WHERE sandbox_id=$1`, sandboxID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	expected := map[string]int64{"initial_ready": 1, "stopped": 2, "resume_ready": 3, "offline_expiry": 3, "retired": 4}[code]
	if (code == "retired" && generation <= 0) || (code != "retired" && (expected == 0 || generation != expected)) {
		return ErrConflict
	}
	raw, err := json.Marshal(evidence)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(raw)
	_, err = tx.Exec(ctx, `INSERT INTO sandbox_runner_qualification_events(trial_id,code,generation,observed_at,evidence,evidence_hash) VALUES($1,$2,$3,clock_timestamp(),$4,$5) ON CONFLICT DO NOTHING`, id, code, generation, raw, hash[:])
	return err
}
func trialEvent(ctx context.Context, tx pgx.Tx, id uuid.UUID, code string, generation int64) (time.Time, error) {
	var at time.Time
	err := tx.QueryRow(ctx, `SELECT observed_at FROM sandbox_runner_qualification_events WHERE trial_id=$1 AND code=$2 AND generation=$3`, id, code, generation).Scan(&at)
	if errors.Is(err, pgx.ErrNoRows) {
		return at, ErrDisabled
	}
	return at, err
}

func (s *RunnerQualificationService) PumpQualificationTrials(ctx context.Context) error {
	rows, err := s.store.pool.Query(ctx, `SELECT id FROM sandbox_runner_qualification_trials WHERE org_id=$1 AND phase NOT IN ('complete','failed') ORDER BY created_at,id LIMIT 2`, s.binding.OrgID)
	if err != nil {
		return err
	}
	ids := []uuid.UUID{}
	for rows.Next() {
		var id uuid.UUID
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err = s.pumpTrial(ctx, id); err != nil {
			return err
		}
	}
	return nil
}
func (s *RunnerQualificationService) pumpTrial(ctx context.Context, id uuid.UUID) error {
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = s.orgLock(ctx, tx); err != nil {
		return err
	}
	r, err := s.readTrial(ctx, tx, id, true)
	if err != nil {
		return err
	}
	v := r.view
	var valid, expired bool
	if err = tx.QueryRow(ctx, `SELECT sandbox_qualification_trial_valid($1),expires_at<=now() FROM sandboxes WHERE id=$1`, v.SandboxID).Scan(&valid, &expired); err != nil {
		return err
	}
	if v.ObservedState == StateDeleted {
		var retired *time.Time
		if err = tx.QueryRow(ctx, `SELECT worker_retired_at FROM sandbox_runtime_bindings WHERE sandbox_id=$1`, v.SandboxID).Scan(&retired); err != nil {
			return err
		}
		if retired != nil {
			if err = recordRunnerTrialEvent(ctx, tx, v.SandboxID, "retired", v.Generation, map[string]any{"sandbox_id": v.SandboxID, "generation": v.Generation, "runtime_id": v.RuntimeID, "worker_retired_at": retired, "confirmed_deleted": true}); err != nil {
				return err
			}
			phase, failure := "cleanup_pending", ""
			if r.initialReady != nil && r.stopped != nil && r.resumeReady != nil && len(r.witnessHash) == 32 && expired && v.Generation == 4 && r.failure == nil {
				phase = "complete"
			} else if r.failure != nil || time.Now().After(v.ExpiresAt.Add(2*time.Minute)) {
				phase, failure = "failed", "qualification_incomplete"
			}
			_, err = tx.Exec(ctx, `UPDATE sandbox_runner_qualification_trials SET phase=$2,retired_at=COALESCE(retired_at,$3),failure_code=NULLIF($4,'') WHERE id=$1`, id, phase, *retired, failure)
			if err != nil {
				return err
			}
			return tx.Commit(ctx)
		}
	}
	if expired || !valid || s.config.ModuleState != "enabled" || v.DesiredState == "deleted" {
		if v.DesiredState != "deleted" {
			if _, err = tx.Exec(ctx, `UPDATE sandboxes SET desired_state='deleted',generation=generation+1 WHERE id=$1 AND desired_state<>'deleted'`, v.SandboxID); err != nil {
				return err
			}
		}
		reason := ""
		if !expired && (!valid || s.config.ModuleState != "enabled") {
			reason = "trial_authority_withdrawn"
		}
		if v.DesiredState == "deleted" && !expired {
			reason = "trial_cancelled"
		}
		_, err = tx.Exec(ctx, `UPDATE sandbox_runner_qualification_trials SET phase='cleanup_pending',failure_code=COALESCE(failure_code,NULLIF($2,'')) WHERE id=$1`, id, reason)
		if err != nil {
			return err
		}
		if err = tx.Commit(ctx); err == nil {
			s.store.notifyPolicy(ctx, s.binding.OrgID)
		}
		return err
	}
	next, desired, code, stamp, expectedGen := "", "", "", "", int64(0)
	switch v.Phase {
	case "initial_ready":
		if v.Generation == 1 && v.DesiredState == "started" && v.ObservedState == StateReady {
			next, desired, code, stamp, expectedGen = "stopped", "stopped", "initial_ready", "initial_ready_at", 1
		}
	case "stopped":
		if v.Generation == 2 && v.DesiredState == "stopped" && v.ObservedState == StateStopped {
			next, desired, code, stamp, expectedGen = "resume_ready", "started", "stopped", "stopped_at", 2
		}
	case "resume_ready":
		if v.Generation == 3 && v.DesiredState == "started" && v.ObservedState == StateReady {
			next, code, stamp, expectedGen = "awaiting_expiry", "resume_ready", "resume_ready_at", 3
		}
	}
	if next == "" {
		return tx.Commit(ctx)
	}
	at, err := trialEvent(ctx, tx, id, code, expectedGen)
	if errors.Is(err, ErrDisabled) {
		return tx.Commit(ctx)
	}
	if err != nil {
		return err
	}
	var runtimeID *string
	if err = tx.QueryRow(ctx, `SELECT runtime_id FROM sandbox_runtime_bindings WHERE sandbox_id=$1`, v.SandboxID).Scan(&runtimeID); err != nil {
		return err
	}
	if runtimeID == nil {
		return ErrConflict
	}
	if r.view.RuntimeID != nil && *r.view.RuntimeID != *runtimeID {
		return ErrConflict
	}
	if desired != "" {
		tag, e := tx.Exec(ctx, `UPDATE sandboxes s SET desired_state=$2,generation=generation+1 WHERE id=$1 AND generation=$3 AND (`+sandboxEligibilitySQL+`)`, v.SandboxID, desired, expectedGen)
		if e != nil {
			return e
		}
		if tag.RowsAffected() != 1 {
			return ErrConflict
		}
	}
	// stamp is selected above from a closed constant allowlist, never user input.
	if _, err = tx.Exec(ctx, `UPDATE sandbox_runner_qualification_trials SET phase=$2,runtime_id=COALESCE(runtime_id,$3),`+stamp+`=COALESCE(`+stamp+`,$4) WHERE id=$1`, id, next, *runtimeID, at); err != nil {
		return err
	}
	if err = runnerAudit(ctx, tx, s.binding.OrgID, r.creator, v.EnrollmentID, "sandbox.runner_qualification_phase", map[string]any{"trial_id": id, "sandbox_id": v.SandboxID, "phase": next, "generation": expectedGen}); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err == nil {
		s.store.notifyPolicy(ctx, s.binding.OrgID)
		if s.wake != nil {
			s.wake()
		}
	}
	return err
}
