package sandboxes

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

const RunnerEnrollmentLifetime = 10 * time.Minute
const RunnerHealthFreshness = 45 * time.Second

// These are public pins. Paths, private keys and database credentials belong to
// the installing machine or control plane, and never appear in this plan.
type RunnerArtifact struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
}
type RunnerInstallImage struct {
	TemplateID            uuid.UUID `json:"template_id"`
	URL                   string    `json:"url"`
	SHA256                string    `json:"sha256"`
	ConfigDigest          string    `json:"config_digest"`
	Architecture          string    `json:"architecture"`
	QualificationEvidence string    `json:"qualification_evidence"`
}
type RunnerInstallTerminal struct {
	NodeID          uuid.UUID `json:"node_id"`
	Endpoint        string    `json:"endpoint"`
	RuntimeEndpoint string    `json:"runtime_endpoint"`
}
type RunnerInstallGateway struct {
	NodeID      uuid.UUID              `json:"node_id"`
	ContainerID string                 `json:"container_id"`
	ImageDigest string                 `json:"image_digest"`
	Interface   string                 `json:"interface"`
	Terminal    *RunnerInstallTerminal `json:"terminal,omitempty"`
}
type RunnerInstallController struct {
	URL        string `json:"url"`
	ServerName string `json:"server_name"`
	URI        string `json:"uri"`
	APIURL     string `json:"api_url"`
}
type RunnerInstallPlan struct {
	Version    int                     `json:"version"`
	Edition    string                  `json:"edition"`
	SourceSHA  string                  `json:"source_sha"`
	Bundle     RunnerArtifact          `json:"bundle"`
	OrgID      uuid.UUID               `json:"org_id"`
	Gateway    RunnerInstallGateway    `json:"gateway"`
	Controller RunnerInstallController `json:"controller"`
	Images     []RunnerInstallImage    `json:"images"`
}
type RunnerEnrollmentProfile struct {
	ID                uuid.UUID         `json:"id"`
	Name              string            `json:"name"`
	Architecture      string            `json:"architecture"`
	HostOS            string            `json:"host_os"`
	HostVersion       string            `json:"host_version"`
	TerminalGatewayID uuid.UUID         `json:"terminal_gateway_id"`
	Prerequisites     []string          `json:"prerequisites"`
	BlockedReasons    []string          `json:"blocked_reasons"`
	BootstrapScript   RunnerArtifact    `json:"bootstrap_script"`
	Install           RunnerInstallPlan `json:"install"`
}
type RunnerEnrollmentConfig struct {
	RunnerURI                 string
	RunnerCA                  string
	APICA                     string
	Profile                   RunnerEnrollmentProfile
	QualifiedRunnerSPKIHash   string
	HostQualificationEvidence string
	DistributionFile          string
	// Root wiring supplies the current module state. The public config cannot
	// opt the module in or change the immutable runtime binding.
	ModuleState string `json:"-"`
}
type RunnerEnrollment struct {
	ID                   uuid.UUID                  `json:"id"`
	Name                 string                     `json:"name"`
	ProfileID            uuid.UUID                  `json:"profile_id"`
	State                string                     `json:"state"`
	CreatedAt            time.Time                  `json:"created_at"`
	ExpiresAt            time.Time                  `json:"expires_at"`
	CertificateExpiresAt *time.Time                 `json:"certificate_expires_at,omitempty"`
	LastSeenAt           *time.Time                 `json:"last_seen_at,omitempty"`
	BlockedReasons       []string                   `json:"blocked_reasons"`
	InstallCommand       string                     `json:"install_command"`
	Qualification        *RunnerQualificationRecord `json:"qualification,omitempty"`
}
type RunnerEnrollmentCreate struct {
	ProfileID      uuid.UUID `json:"profile_id"`
	Name           string    `json:"name"`
	IdempotencyKey uuid.UUID `json:"idempotency_key"`
}
type RunnerEnrollmentList struct {
	Profiles       []RunnerEnrollmentProfile `json:"profiles"`
	Enrollments    []RunnerEnrollment        `json:"enrollments"`
	BlockedReasons []string                  `json:"blocked_reasons"`
}
type RunnerEnrollmentIssue struct {
	Enrollment     RunnerEnrollment `json:"enrollment"`
	BootstrapToken string           `json:"bootstrap_token,omitempty"`
}
type RunnerRedeemInput struct {
	CertificateRequest string `json:"certificate_request"`
	ProbePublicKey     string `json:"probe_public_key"`
}
type RunnerEnrollmentBundle struct {
	EnrollmentID  uuid.UUID         `json:"enrollment_id"`
	ProfileID     uuid.UUID         `json:"profile_id"`
	BindingSHA256 string            `json:"binding_sha256"`
	Certificate   string            `json:"certificate"`
	RunnerCA      string            `json:"runner_ca"`
	APICA         string            `json:"api_ca"`
	Install       RunnerInstallPlan `json:"install"`
}
type RunnerCredential struct {
	EnrollmentID      uuid.UUID
	ProbePublicKey    string
	CleanupOnly       bool
	RetainedSandboxID *uuid.UUID
}
type RunnerCSRSigner interface {
	SignRunnerCSR([]byte) ([]byte, error)
	RenewRunner(*x509.Certificate) ([]byte, error)
}
type RunnerEnrollmentService struct {
	store       *Store
	config      RunnerEnrollmentConfig
	binding     BoundedRuntimeBinding
	bindingHash []byte
	signer      RunnerCSRSigner
	nativeProof RunnerNativeProofVerifier
	trial       RunnerQualificationTrialValidator
}

// The trial implementation must validate its separate durable admin grant and
// exact workload. A missing validator grants no unqualified execution.
type RunnerQualificationTrialValidator interface {
	VerifyRunnerQualificationTrial(context.Context, uuid.UUID, RuntimeAuthorization) error
}

func (s *RunnerEnrollmentService) WithQualificationTrialValidator(v RunnerQualificationTrialValidator) *RunnerEnrollmentService {
	s.trial = v
	return s
}

// Native proof is produced by the control plane's bounded qualification trial,
// independently of machine-reported capability/check booleans.
type RunnerNativeProofVerifier interface {
	VerifyRunnerQualification(context.Context, uuid.UUID, RunnerQualificationReport) error
}

func (s *RunnerEnrollmentService) WithNativeProofVerifier(v RunnerNativeProofVerifier) *RunnerEnrollmentService {
	s.nativeProof = v
	return s
}

// Interface documents the actual runtime integration. Credentials grant no
// workload effects until AuthorizeCommand validates durable ownership/state.
type RunnerEnrollmentAuthority interface {
	AuthorizeCertificate(context.Context, *x509.Certificate) (RunnerCredential, error)
	AuthorizeCommand(context.Context, RunnerCredential, json.RawMessage) error
	RecordHealth(context.Context, RunnerCredential, BoundedRuntimeBinding) error
}
