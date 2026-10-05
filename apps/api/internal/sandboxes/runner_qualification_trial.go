package sandboxes

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

// Host enrollment authority remains distinct from per-workload creator/device
// authority. Only this optional qualification coordinator owns trial grants.
type RunnerQualificationService struct {
	*RunnerEnrollmentService
	wake func()
}

func NewRunnerQualificationService(store *Store, enrollment *RunnerEnrollmentService, binding BoundedRuntimeBinding) (*RunnerQualificationService, error) {
	if store == nil || store.pool == nil || enrollment == nil || enrollment.store != store || !binding.OrganizationScoped() || !bindingEqual(binding, enrollment.binding) {
		return nil, ErrInvalid
	}
	return &RunnerQualificationService{RunnerEnrollmentService: enrollment}, nil
}

func (s *RunnerQualificationService) WithWake(wake func()) *RunnerQualificationService {
	s.wake = wake
	return s
}

type runnerTrialCreate struct {
	service                          *RunnerQualificationService
	enrollmentID, trialID, sandboxID uuid.UUID
	input                            RunnerQualificationTrialInput
	requestHash                      [32]byte
	profile                          QualifiedRuntimeProfile
	record                           runnerEnrollmentRecord
}

func (t *runnerTrialCreate) prepare(ctx context.Context, tx pgx.Tx, store *Store, org, actor uuid.UUID, in CreateInput) error {
	s := t.service
	if s == nil || store != s.store || store.boundedRuntime == nil || !bindingEqual(*store.boundedRuntime, s.binding) || s.config.ModuleState != "enabled" || org != s.binding.OrgID || len(in.Requested) != 0 || len(in.SelectedSkills) != 0 || len(in.SSHPublicKeys) != 1 || in.TTLSeconds != 900 || in.TemplateID != t.profile.TemplateID || in.TerminalDeviceID == nil || *in.TerminalDeviceID != t.input.TerminalDeviceID || t.profile.PIDs != 64 {
		return ErrForbidden
	}
	if err := s.human(ctx, tx, org, actor); err != nil {
		return err
	}
	r, err := s.read(ctx, tx, t.enrollmentID, true)
	if err != nil {
		return err
	}
	c, err := s.credential(ctx, tx, r)
	if err != nil || c.CleanupOnly || !equalHash(r.bindingHash, s.bindingHash) || r.view.ProfileID != s.config.Profile.ID {
		return ErrForbidden
	}
	if r.view.LastSeenAt == nil || !freshEvidence(time.Now(), *r.view.LastSeenAt, RunnerHealthFreshness) {
		return ErrDisabled
	}
	t.record = r
	var priorID, priorSandbox, priorCreator uuid.UUID
	var priorHash []byte
	err = tx.QueryRow(ctx, `SELECT id,sandbox_id,creator_id,request_hash FROM sandbox_runner_qualification_trials WHERE org_id=$1 AND enrollment_id=$2 AND idempotency_key=$3`, org, t.enrollmentID, t.input.IdempotencyKey).Scan(&priorID, &priorSandbox, &priorCreator, &priorHash)
	if err == nil {
		if priorCreator != actor {
			return ErrForbidden
		}
		if !equalHash(priorHash, t.requestHash[:]) {
			return ErrConflict
		}
		t.trialID, t.sandboxID = priorID, priorSandbox
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	// Publishing a private trusted revision never turns on its catalog flag.
	if _, err = tx.Exec(ctx, `INSERT INTO sandbox_templates(id,org_id,name,image_digest,maximum_scope,memory_mib,max_ttl_seconds,enabled) VALUES($1,$2,'Ubuntu 26 terminal',$3,'[]',128,900,false) ON CONFLICT DO NOTHING`, t.profile.TemplateID, org, t.profile.ConfigDigest); err != nil {
		return err
	}
	var compatible bool
	err = tx.QueryRow(ctx, `SELECT image_digest=$3 AND maximum_scope='[]'::jsonb AND memory_mib=128 AND max_ttl_seconds<=900 FROM sandbox_templates WHERE id=$1 AND org_id=$2 FOR SHARE`, t.profile.TemplateID, org, t.profile.ConfigDigest).Scan(&compatible)
	if err != nil {
		return err
	}
	if !compatible {
		return ErrConflict
	}
	return nil
}

func (t *runnerTrialCreate) insert(ctx context.Context, tx pgx.Tx, org, actor, terminal uuid.UUID) error {
	if terminal != t.input.TerminalDeviceID || t.record.view.ID != t.enrollmentID {
		return ErrForbidden
	}
	_, err := tx.Exec(ctx, `INSERT INTO sandbox_runner_qualification_trials(id,org_id,enrollment_id,sandbox_id,creator_id,terminal_device_id,profile_id,template_id,binding_hash,spki_hash,source_sha,image_digest,idempotency_key,request_hash,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,now()+interval '900 seconds')`, t.trialID, org, t.enrollmentID, t.sandboxID, actor, terminal, t.record.view.ProfileID, t.profile.TemplateID, t.service.bindingHash, t.record.keyHash, t.service.config.Profile.Install.SourceSHA, t.profile.ConfigDigest, t.input.IdempotencyKey, t.requestHash[:])
	return err
}

func (s *RunnerQualificationService) BeginQualification(ctx context.Context, org, actor, enrollmentID uuid.UUID, in RunnerQualificationTrialInput) (RunnerQualificationTrial, bool, error) {
	if s == nil || in.IdempotencyKey == uuid.Nil || in.TerminalDeviceID == uuid.Nil || enrollmentID == uuid.Nil || org != s.binding.OrgID || len(s.binding.Profiles) == 0 {
		return RunnerQualificationTrial{}, false, ErrInvalid
	}
	if s.config.ModuleState != "enabled" {
		return RunnerQualificationTrial{}, false, ErrDisabled
	}
	keys, err := NormalizeSSHPublicKeys(in.SSHPublicKeys, 1)
	if err != nil || len(keys) != 1 {
		return RunnerQualificationTrial{}, false, ErrInvalid
	}
	in.SSHPublicKeys = keys
	profile := s.binding.Profiles[0]
	if profile.PIDs != 64 {
		return RunnerQualificationTrial{}, false, ErrDisabled
	}
	raw, _ := json.Marshal(in)
	intent := &runnerTrialCreate{service: s, enrollmentID: enrollmentID, trialID: uuid.New(), sandboxID: uuid.New(), input: in, requestHash: sha256.Sum256(raw), profile: profile}
	create := CreateInput{TemplateID: profile.TemplateID, TerminalDeviceID: &in.TerminalDeviceID, Name: "Runner qualification", SSHPublicKeys: keys, Requested: []Scope{}, SelectedSkills: []SkillSelection{}, TTLSeconds: 900, IdempotencyKey: fmt.Sprintf("qualification:%s:%s", enrollmentID, in.IdempotencyKey)}
	_, replay, err := s.store.create(ctx, org, actor, create, intent)
	if err != nil {
		return RunnerQualificationTrial{}, false, err
	}
	if s.wake != nil {
		s.wake()
	}
	view, err := s.StatusQualification(ctx, org, actor, enrollmentID, intent.trialID)
	return view, replay, err
}

func (s *RunnerQualificationService) authorizeTrialView(ctx context.Context, tx pgx.Tx, org, actor uuid.UUID) error {
	if err := s.human(ctx, tx, org, actor); err != nil {
		return err
	}
	_, err := authorize(ctx, tx, org, actor, rbac.PermSandboxView)
	return err
}

type RunnerQualificationTrialInput struct {
	TerminalDeviceID uuid.UUID `json:"terminal_device_id"`
	SSHPublicKeys    []string  `json:"ssh_public_keys"`
	IdempotencyKey   uuid.UUID `json:"idempotency_key"`
}

type RunnerQualificationTrialPhase struct {
	Code           string     `json:"code"`
	State          string     `json:"state"`
	ObservedAt     *time.Time `json:"observed_at,omitempty"`
	EvidenceSHA256 string     `json:"evidence_sha256,omitempty"`
}

type RunnerQualificationTrial struct {
	ID                   uuid.UUID                       `json:"id"`
	EnrollmentID         uuid.UUID                       `json:"enrollment_id"`
	ProfileID            uuid.UUID                       `json:"profile_id"`
	SandboxID            uuid.UUID                       `json:"sandbox_id"`
	TerminalDeviceID     uuid.UUID                       `json:"terminal_device_id"`
	State                string                          `json:"state"`
	Phase                string                          `json:"phase"`
	ObservedState        State                           `json:"observed_state"`
	DesiredState         string                          `json:"desired_state"`
	Generation           int64                           `json:"generation"`
	CreatedAt            time.Time                       `json:"created_at"`
	ExpiresAt            time.Time                       `json:"expires_at"`
	RuntimeID            *string                         `json:"runtime_id,omitempty"`
	Connection           *ConnectionInfo                 `json:"connection,omitempty"`
	Phases               []RunnerQualificationTrialPhase `json:"phases"`
	BlockedReasons       []string                        `json:"blocked_reasons"`
	QualificationCommand string                          `json:"qualification_command"`
	RetiredAt            *time.Time                      `json:"retired_at,omitempty"`
}

type RunnerQualificationMachineView struct {
	Version              int        `json:"version"`
	EnrollmentID         uuid.UUID  `json:"enrollment_id"`
	ProfileID            uuid.UUID  `json:"profile_id"`
	BindingSHA256        string     `json:"binding_sha256"`
	SourceSHA            string     `json:"source_sha"`
	TrialID              uuid.UUID  `json:"trial_id"`
	SandboxID            uuid.UUID  `json:"sandbox_id"`
	RuntimeID            string     `json:"runtime_id"`
	Generation           int64      `json:"generation"`
	CreatedAt            time.Time  `json:"created_at"`
	ExpiresAt            time.Time  `json:"expires_at"`
	Phase                string     `json:"phase"`
	InitialReadyAt       *time.Time `json:"initial_ready_at,omitempty"`
	StoppedAt            *time.Time `json:"stopped_at,omitempty"`
	ResumeReadyAt        *time.Time `json:"resume_ready_at,omitempty"`
	RetiredAt            *time.Time `json:"retired_at,omitempty"`
	OfflineWitnessSHA256 string     `json:"offline_witness_sha256,omitempty"`
	ProofSHA256          string     `json:"proof_sha256,omitempty"`
}

type RunnerQualificationOfflineWitness struct {
	Version            int       `json:"version"`
	TrialID            uuid.UUID `json:"trial_id"`
	SandboxID          uuid.UUID `json:"sandbox_id"`
	RuntimeID          string    `json:"runtime_id"`
	Generation         int64     `json:"generation"`
	BindingSHA256      string    `json:"binding_sha256"`
	SourceSHA          string    `json:"source_sha"`
	CreatedAt          time.Time `json:"created_at"`
	ExpiresAt          time.Time `json:"expires_at"`
	TransportStoppedAt time.Time `json:"transport_stopped_at"`
	StoppedObservedAt  time.Time `json:"stopped_observed_at"`
	ActorExpiredAt     time.Time `json:"actor_expired_at"`
	TransportResumedAt time.Time `json:"transport_resumed_at"`
	ImageDigest        string    `json:"image_digest"`
	MemoryMaxBytes     int64     `json:"memory_max_bytes"`
	MemorySwapMaxBytes int64     `json:"memory_swap_max_bytes"`
	PIDsMax            int64     `json:"pids_max"`
	CPUQuotaUS         int64     `json:"cpu_quota_us"`
	CPUPeriodUS        int64     `json:"cpu_period_us"`
	CgroupPopulated    bool      `json:"cgroup_populated"`
	ObserverSHA256     string    `json:"observer_sha256"`
}

// The machine sees only its current enrollment's public trial. Certificate
// authority is rechecked by both the broker and these service methods.
type RunnerQualificationMachineAuthority interface {
	QualificationMachineView(context.Context, *x509.Certificate, uuid.UUID) (RunnerQualificationMachineView, error)
	SubmitQualificationOfflineWitness(context.Context, *x509.Certificate, uuid.UUID, RunnerQualificationOfflineWitness) error
}
