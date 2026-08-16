package agentruntime

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

const RuntimeCredentialPrefix = "tnx_runtime_"

var (
	ErrUnauthorized        = errors.New("runtime authentication failed")
	ErrOptedOut            = errors.New("managed runtime is explicitly disabled")
	ErrOptInUnavailable    = errors.New("managed runtime opt-in is not configured")
	ErrInvalidReport       = errors.New("invalid runtime report")
	ErrRuntimeStateMissing = errors.New("runtime state unavailable")
)

type Identity struct {
	OrgID              uuid.UUID
	DeviceID           uuid.UUID
	CredentialRevision int64
	CredentialState    string
}

type identityContextKey struct{}

func WithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, identityContextKey{}, id)
}

func IdentityFromContext(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(identityContextKey{}).(Identity)
	return id, ok
}

type OptInState string

const (
	OptInEnabled     OptInState = "enabled"
	OptInDisabled    OptInState = "disabled"
	OptInUnavailable OptInState = "unavailable"
)

type OptInFunc func(context.Context, uuid.UUID) (OptInState, error)

// OrganizationOptIn is the production opt-in boundary. Both the paid-edition
// unlock and the persisted organization decision must be true; absence or a
// database error fails closed.
func OrganizationOptIn(q *sqlc.Queries, unlocked func() bool) OptInFunc {
	return func(ctx context.Context, orgID uuid.UUID) (OptInState, error) {
		if q == nil || unlocked == nil || !unlocked() {
			return OptInUnavailable, nil
		}
		org, err := q.GetOrganizationByID(ctx, orgID)
		if err != nil {
			return OptInUnavailable, err
		}
		if !org.ManagedAgentRuntimeEnabled {
			return OptInDisabled, nil
		}
		return OptInEnabled, nil
	}
}

type Service struct {
	q        *sqlc.Queries
	optIn    OptInFunc
	notify   Notifier
	now      func() time.Time
	pollTick time.Duration
}

// Notifier wakes the assigned gateway after an agent's applied configuration
// revision advances. The gateway's policy artifact is the source of access-log
// attribution, so waiting for the periodic reconcile would temporarily stamp
// flows with the previous revision.
type Notifier interface{ Notify(nodeID uuid.UUID) }

func New(q *sqlc.Queries, optIn OptInFunc) *Service {
	return &Service{q: q, optIn: optIn, now: time.Now, pollTick: time.Second}
}

func (s *Service) SetNotifier(n Notifier) { s.notify = n }

func (s *Service) Authenticate(ctx context.Context, raw string) (Identity, error) {
	if s == nil || s.q == nil || !strings.HasPrefix(raw, RuntimeCredentialPrefix) {
		return Identity{}, ErrUnauthorized
	}
	h := sha256.Sum256([]byte(raw))
	cred, err := s.q.AuthenticateAgentRuntimeCredential(ctx, h[:])
	if err != nil || cred.RevokedAt.Valid || cred.State != "current" || cred.DeviceID == uuid.Nil || cred.OrgID == uuid.Nil {
		return Identity{}, ErrUnauthorized
	}
	return s.validateCredentialIdentity(ctx, cred.OrgID, cred.DeviceID, cred.Revision, cred.State, cred.RevokedAt.Valid)
}

// AuthenticateCurrent is used only by prepare: a candidate may promote on its
// first poll/report, never by calling the preparation endpoint itself.
func (s *Service) AuthenticateCurrent(ctx context.Context, raw string) (Identity, error) {
	if s == nil || s.q == nil || !strings.HasPrefix(raw, RuntimeCredentialPrefix) {
		return Identity{}, ErrUnauthorized
	}
	h := sha256.Sum256([]byte(raw))
	cred, err := s.q.GetAgentRuntimeCredential(ctx, h[:])
	if err != nil || cred.State != "current" {
		return Identity{}, ErrUnauthorized
	}
	return s.validateCredentialIdentity(ctx, cred.OrgID, cred.DeviceID, cred.Revision, cred.State, cred.RevokedAt.Valid)
}

func (s *Service) validateCredentialIdentity(ctx context.Context, orgID, deviceID uuid.UUID, revision int64, state string, revoked bool) (Identity, error) {
	if revoked || orgID == uuid.Nil || deviceID == uuid.Nil {
		return Identity{}, ErrUnauthorized
	}
	dev, err := s.q.GetDevice(ctx, sqlc.GetDeviceParams{ID: deviceID, OrgID: orgID})
	if err != nil || dev.OrgID != orgID || dev.ID != deviceID || dev.Kind != "agent" || dev.DeletedAt.Valid || (dev.Status != "active" && dev.Status != "pending") {
		return Identity{}, ErrUnauthorized
	}
	return Identity{OrgID: orgID, DeviceID: deviceID, CredentialRevision: revision, CredentialState: state}, nil
}

func (s *Service) requireOptIn(ctx context.Context, orgID uuid.UUID) error {
	if s == nil || s.optIn == nil {
		return ErrOptInUnavailable
	}
	state, err := s.optIn(ctx, orgID)
	if err != nil {
		return ErrOptInUnavailable
	}
	switch state {
	case OptInEnabled:
		return nil
	case OptInDisabled:
		return ErrOptedOut
	default:
		return ErrOptInUnavailable
	}
}

type Config struct {
	Revision                   int64
	DeviceID                   uuid.UUID
	OrgID                      uuid.UUID
	Address                    string
	GatewayEndpoint            string
	GatewayPublicKey           string
	AllowedIPs                 []string
	DNS                        []string
	PersistentKeepalive        int
	CredentialRotationRevision *int64
	WireGuardCurrentRevision   int64
	WireGuardRotationRevision  *int64
	WireGuardRotationState     *string
}

// PrepareCredentialCandidate stores only a locally generated successor hash.
// Repeating the same requested revision/hash is idempotent in PostgreSQL.
func (s *Service) PrepareCredentialCandidate(ctx context.Context, id Identity, revision int64, hashHex string) error {
	if s == nil || s.q == nil || id.CredentialState != "current" || revision != id.CredentialRevision+1 {
		return ErrUnauthorized
	}
	hash, err := hex.DecodeString(hashHex)
	if err != nil || len(hash) != sha256.Size {
		return ErrInvalidReport
	}
	prepared, err := s.q.PrepareAgentRuntimeCredentialCandidate(ctx, sqlc.PrepareAgentRuntimeCredentialCandidateParams{
		OrgID: id.OrgID, DeviceID: id.DeviceID, TokenHash: hash, Revision: revision,
	})
	if err != nil || prepared.Revision != revision || prepared.State != "candidate" {
		return ErrRuntimeStateMissing
	}
	return nil
}

// PrepareWireGuardCandidate stores only the public half generated by the
// runtime. The current private key and successor private key never cross this
// boundary. Same revision/key retries are idempotent in PostgreSQL.
func (s *Service) PrepareWireGuardCandidate(ctx context.Context, id Identity, revision int64, publicKey string) error {
	if s == nil || s.q == nil || id.CredentialState != "current" {
		return ErrUnauthorized
	}
	raw, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil || len(raw) != 32 {
		return ErrInvalidReport
	}
	row, err := s.q.PrepareAgentWireGuardCandidate(ctx, sqlc.PrepareAgentWireGuardCandidateParams{
		OrgID: id.OrgID, DeviceID: id.DeviceID,
		CandidatePublicKey: &publicKey, RequestedRevision: &revision,
	})
	if err != nil || row.RequestedRevision == nil || *row.RequestedRevision != revision || row.State != "prepared" {
		return ErrRuntimeStateMissing
	}
	return nil
}

func (s *Service) Poll(ctx context.Context, id Identity, appliedRevision, wireGuardRevision int64, clientVersion string) (Config, bool, error) {
	if appliedRevision < 0 || wireGuardRevision < 1 || strings.TrimSpace(clientVersion) == "" || len(clientVersion) > 128 {
		return Config{}, false, ErrInvalidReport
	}
	if err := s.requireOptIn(ctx, id.OrgID); err != nil {
		return Config{}, false, err
	}
	if s == nil || s.q == nil {
		return Config{}, false, ErrRuntimeStateMissing
	}
	dev, err := s.q.GetDevice(ctx, sqlc.GetDeviceParams{ID: id.DeviceID, OrgID: id.OrgID})
	if err != nil || dev.Kind != "agent" || dev.DeletedAt.Valid {
		return Config{}, false, ErrRuntimeStateMissing
	}
	// A freshly bootstrapped agent may be awaiting explicit device approval.
	// Its credential proves only this agent identity: return no config until the
	// owner activates it, while revoked/suspended identities remain uniformly
	// unauthorized at Authenticate.
	if dev.Status == "pending" {
		return Config{}, true, nil
	}
	if dev.Status != "active" || dev.AssignedIp == nil {
		return Config{}, false, ErrRuntimeStateMissing
	}
	state, err := s.q.EnsureAgentRuntimeState(ctx, sqlc.EnsureAgentRuntimeStateParams{ID: id.DeviceID, OrgID: id.OrgID})
	if err != nil {
		return Config{}, false, ErrRuntimeStateMissing
	}
	var rotationRevision *int64
	credential, rotationErr := s.q.GetAgentRuntimeCredentialRotation(ctx, sqlc.GetAgentRuntimeCredentialRotationParams{OrgID: id.OrgID, DeviceID: id.DeviceID})
	if rotationErr == nil && credential.RotationRequestedAt.Valid && credential.RotationDeadline.Valid && credential.RotationDeadline.Time.After(s.now()) {
		next := credential.Revision + 1
		rotationRevision = &next
	}
	if err := s.q.ExpireAgentWireGuardRotation(ctx, sqlc.ExpireAgentWireGuardRotationParams{OrgID: id.OrgID, DeviceID: id.DeviceID}); err != nil {
		return Config{}, false, ErrRuntimeStateMissing
	}
	wgCurrentRevision := int64(1)
	var wgRotationRevision *int64
	var wgRotationState *string
	if wg, wgErr := s.q.GetAgentWireGuardRotation(ctx, sqlc.GetAgentWireGuardRotationParams{OrgID: id.OrgID, DeviceID: id.DeviceID}); wgErr == nil {
		wgCurrentRevision = wg.CurrentRevision
		if wg.State != "current" && wg.RequestedRevision != nil && wg.Deadline.Valid && wg.Deadline.Time.After(s.now()) {
			wgRotationRevision = wg.RequestedRevision
			state := wg.State
			wgRotationState = &state
		}
	} else if !errors.Is(wgErr, pgx.ErrNoRows) {
		return Config{}, false, ErrRuntimeStateMissing
	}
	if state.DesiredRevision <= appliedRevision && rotationRevision == nil && wgRotationRevision == nil && wgCurrentRevision == wireGuardRevision {
		return Config{}, true, nil
	}
	node, err := s.q.GetOrgNode(ctx, sqlc.GetOrgNodeParams{ID: dev.NodeID, OrgID: id.OrgID})
	if err != nil || node.Endpoint == "" || node.WgPublicKey == "" {
		return Config{}, false, ErrRuntimeStateMissing
	}
	org, err := s.q.GetOrganizationByID(ctx, id.OrgID)
	if err != nil {
		return Config{}, false, ErrRuntimeStateMissing
	}
	allowed := []string{org.PoolCidr}
	dns := []string(nil)
	if dev.FullTunnel {
		allowed = []string{"0.0.0.0/0"}
		dns = []string{"1.1.1.1"}
	}
	return Config{
		Revision: state.DesiredRevision, DeviceID: id.DeviceID, OrgID: id.OrgID,
		Address: *dev.AssignedIp + "/32", GatewayEndpoint: node.Endpoint,
		GatewayPublicKey: node.WgPublicKey, AllowedIPs: allowed, DNS: dns,
		PersistentKeepalive: 25, CredentialRotationRevision: rotationRevision,
		WireGuardCurrentRevision: wgCurrentRevision, WireGuardRotationRevision: wgRotationRevision,
		WireGuardRotationState: wgRotationState,
	}, false, nil
}

// PollWait performs an immediate read and, only while the caller is current,
// rechecks on a bounded server ticker until the requested hold expires or the
// desired state changes. The ticker is the safety net for changes written by
// any API replica; it deliberately does not rely on an in-process-only signal.
func (s *Service) PollWait(ctx context.Context, id Identity, appliedRevision, wireGuardRevision int64, clientVersion string, wait time.Duration) (Config, bool, error) {
	if wait <= 0 {
		return s.Poll(ctx, id, appliedRevision, wireGuardRevision, clientVersion)
	}
	tick := s.pollTick
	if tick <= 0 {
		tick = time.Second
	}
	return pollUntil(ctx, wait, tick, func() (Config, bool, error) {
		return s.Poll(ctx, id, appliedRevision, wireGuardRevision, clientVersion)
	})
}

func pollUntil(ctx context.Context, wait, tick time.Duration, poll func() (Config, bool, error)) (Config, bool, error) {
	cfg, unchanged, err := poll()
	if err != nil || !unchanged || wait <= 0 {
		return cfg, unchanged, err
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	ticker := time.NewTicker(tick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return Config{}, false, ctx.Err()
		case <-timer.C:
			return cfg, true, nil
		case <-ticker.C:
			cfg, unchanged, err = poll()
			if err != nil || !unchanged {
				return cfg, unchanged, err
			}
		}
	}
}

func (s *Service) Report(ctx context.Context, id Identity, appliedRevision, attemptedRevision int64, clientVersion, errorCode string) error {
	if err := s.requireOptIn(ctx, id.OrgID); err != nil {
		return err
	}
	if appliedRevision < 0 || attemptedRevision < 0 || appliedRevision > attemptedRevision || strings.TrimSpace(clientVersion) == "" || len(clientVersion) > 128 || !validErrorCode(errorCode) {
		return ErrInvalidReport
	}
	if errorCode == "" && appliedRevision != attemptedRevision {
		return ErrInvalidReport
	}
	if s == nil || s.q == nil {
		return ErrRuntimeStateMissing
	}
	state, err := s.q.ReportAgentRuntimeState(ctx, sqlc.ReportAgentRuntimeStateParams{
		DeviceID: id.DeviceID, OrgID: id.OrgID, AppliedRevision: appliedRevision,
		LastAttemptedRevision: attemptedRevision, ClientVersion: clientVersion, ErrorCode: errorCode,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrInvalidReport
		}
		return ErrRuntimeStateMissing
	}
	if state.AppliedRevision < appliedRevision || state.LastAttemptedRevision < attemptedRevision {
		return ErrInvalidReport
	}
	// Best-effort invalidation after the durable report. Duplicate notifications
	// are harmless (the node re-fetches full desired state); same-revision
	// heartbeats do not create needless recompiles.
	if s.notify != nil && state.AppliedChanged {
		s.notify.Notify(state.NodeID)
	}
	return nil
}

func validErrorCode(code string) bool {
	return code == "" || code == "invalid_config" || code == "apply_failed"
}

type Status struct {
	DeviceID              uuid.UUID
	DesiredRevision       int64
	AppliedRevision       int64
	LastAttemptedRevision int64
	ClientVersion         string
	Connectivity          string
	Health                string
	Stale                 bool
	LastSeenAt            *time.Time
	LastErrorCode         *string
	LastErrorRevision     *int64
}

// RouteIntent is the public, secret-free routing portion of the managed
// configuration. It is derived from the same device/org rows as Poll but does
// not mint, consume, report, wake, or update anything.
type RouteIntent struct {
	AllowedIPs []string
}

func (s *Service) RouteIntent(ctx context.Context, orgID, deviceID uuid.UUID) (RouteIntent, error) {
	if err := s.requireOptIn(ctx, orgID); err != nil {
		return RouteIntent{}, err
	}
	if s == nil || s.q == nil {
		return RouteIntent{}, ErrRuntimeStateMissing
	}
	dev, err := s.q.GetDevice(ctx, sqlc.GetDeviceParams{ID: deviceID, OrgID: orgID})
	if err != nil || dev.Kind != "agent" || dev.Status != "active" || dev.AssignedIp == nil {
		return RouteIntent{}, ErrRuntimeStateMissing
	}
	org, err := s.q.GetOrganizationByID(ctx, orgID)
	if err != nil {
		return RouteIntent{}, ErrRuntimeStateMissing
	}
	allowed := []string{org.PoolCidr}
	if dev.FullTunnel {
		allowed = []string{"0.0.0.0/0"}
	}
	return RouteIntent{AllowedIPs: allowed}, nil
}

func (s *Service) Status(ctx context.Context, orgID, deviceID uuid.UUID) (Status, error) {
	if err := s.requireOptIn(ctx, orgID); err != nil {
		return Status{}, err
	}
	if s == nil || s.q == nil {
		return Status{}, ErrRuntimeStateMissing
	}
	dev, err := s.q.GetDevice(ctx, sqlc.GetDeviceParams{ID: deviceID, OrgID: orgID})
	if err != nil || dev.Kind != "agent" {
		return Status{}, ErrRuntimeStateMissing
	}
	state, err := s.q.GetAgentRuntimeState(ctx, sqlc.GetAgentRuntimeStateParams{DeviceID: deviceID, OrgID: orgID})
	if errors.Is(err, pgx.ErrNoRows) {
		return Status{DeviceID: deviceID, DesiredRevision: 1, Connectivity: "unknown", Health: "inconclusive", Stale: true}, nil
	}
	if err != nil {
		return Status{}, ErrRuntimeStateMissing
	}
	var seen *time.Time
	if state.LastSeenAt.Valid {
		v := state.LastSeenAt.Time
		seen = &v
	}
	connectivity, health, stale := deriveRuntimeHealth(s.now(), seen, state.DesiredRevision, state.AppliedRevision, state.LastErrorCode)
	return Status{DeviceID: deviceID, DesiredRevision: state.DesiredRevision, AppliedRevision: state.AppliedRevision,
		LastAttemptedRevision: state.LastAttemptedRevision, ClientVersion: state.ClientVersion,
		Connectivity: connectivity, Health: health, Stale: stale,
		LastSeenAt: seen, LastErrorCode: state.LastErrorCode, LastErrorRevision: state.LastErrorRevision}, nil
}

// RuntimeFreshnessWindow is six default 30-second runtime cycles. It reuses the
// repository's established three-minute liveness window while keeping this
// machine channel's clock owned by its own reports.
const RuntimeFreshnessWindow = 3 * time.Minute

func deriveRuntimeHealth(now time.Time, seen *time.Time, desired, applied int64, lastError *string) (string, string, bool) {
	stale := seen == nil || now.Sub(*seen) > RuntimeFreshnessWindow
	connectivity := "unknown"
	if seen != nil {
		if stale {
			connectivity = "disconnected"
		} else {
			connectivity = "connected"
		}
	}
	health := "inconclusive"
	if applied > 0 {
		health = "last_good"
	}
	if !stale && applied == desired && lastError == nil {
		health = "ready"
	}
	return connectivity, health, stale
}
