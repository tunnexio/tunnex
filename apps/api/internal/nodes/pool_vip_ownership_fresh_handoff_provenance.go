package nodes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/k8s"
)

// The immutable pre-issuance body has the same bounded JSON shape as an
// issued v3 envelope. Keep this local rather than borrowing a handler limit:
// provenance never accepts a transport request.
const poolVIPOwnershipFreshHandoffEnvelopeLimit = 16 << 10

// PoolVIPOwnershipHandoffLeaderSessionProvider is deliberately narrow: the
// read facade obtains the exact advisory-lock session from its unregistered
// caller and verifies it before resolving a fresh plan. It never falls back to
// a general pool connection or an epoch value alone.
type PoolVIPOwnershipHandoffLeaderSessionProvider interface {
	PoolVIPOwnershipHandoffLeaderSession(context.Context) (PoolVIPOwnershipHandoffLeaderSession, error)
}

// PoolVIPOwnershipFreshHandoffCapability is CP-recorded capability evidence.
// ObservedAt is diagnostic source time; ReceiptTime is the CP timestamp used to
// bind the immutable claim. Neither value comes from an issued delivery.
type PoolVIPOwnershipFreshHandoffCapability struct {
	NodeID        uuid.UUID
	WireVersion   int
	DeliveryRowID uuid.UUID
	ReceiptTime   time.Time
	ExpiresAt     time.Time
}

// PoolVIPOwnershipFreshHandoffServiceUID is one live, exact Service
// incarnation from 0084's cluster ledger. It is opaque to P1 and remains
// private to this P2 claim boundary.
type PoolVIPOwnershipFreshHandoffServiceUID struct {
	ActiveNodeID        uuid.UUID
	PromotionGeneration uint64
	Namespace           string
	Service             string
	UID                 string
	ObservationRevision uint64
}

// PoolVIPOwnershipFreshHandoffArtifact keeps raw routes/envelope JSON inside
// P2. The P1 projection is derived only after these artifacts are validated
// and durably claimed.
type PoolVIPOwnershipFreshHandoffArtifact struct {
	Which     k8s.P2HandoffArtifact
	Envelope  PoolVIPOwnershipDeliveryEnvelopeV3
	ExpiresAt time.Time
}

// PoolVIPOwnershipFreshHandoffClaim is the only write input for immutable
// pre-issuance provenance. It is deliberately unregistered; a later P1/P2
// composition layer must supply CP-validated inputs and the exact leader
// session. No agent report, issued delivery, or transient header constructs it.
type PoolVIPOwnershipFreshHandoffClaim struct {
	Intent             HandoffTickIntent
	Plan               k8s.DurableHandoffPlan
	MembershipSnapshot []uuid.UUID
	ServiceUIDs        []PoolVIPOwnershipFreshHandoffServiceUID
	Artifacts          []PoolVIPOwnershipFreshHandoffArtifact
}

var (
	ErrPoolVIPOwnershipFreshHandoffProvenanceConflict = errors.New("pool VIP ownership fresh handoff provenance conflicts with durable state")
	ErrPoolVIPOwnershipFreshHandoffProvenanceRefused  = errors.New("pool VIP ownership fresh handoff provenance is invalid")
)

// PostgresPoolVIPOwnershipFreshHandoffProvenance is both the leader-bound P2
// claim writer and P1's narrow fresh-plan source. Existing 0082 operations are
// still reconstructed only from 0082; this type owns fresh P2 provenance only.
type PostgresPoolVIPOwnershipFreshHandoffProvenance struct {
	pool     *pgxpool.Pool
	sessions PoolVIPOwnershipHandoffLeaderSessionProvider
}

func NewPostgresPoolVIPOwnershipFreshHandoffProvenance(pool *pgxpool.Pool, sessions PoolVIPOwnershipHandoffLeaderSessionProvider) *PostgresPoolVIPOwnershipFreshHandoffProvenance {
	return &PostgresPoolVIPOwnershipFreshHandoffProvenance{pool: pool, sessions: sessions}
}

var _ HandoffFreshPlanProvenanceSource = (*PostgresPoolVIPOwnershipFreshHandoffProvenance)(nil)
var _ PoolVIPOwnershipHandoffEnvelopeProvenance = (*PostgresPoolVIPOwnershipFreshHandoffProvenance)(nil)
var _ PoolVIPOwnershipHandoffLeaderBoundEnvelopeProvenance = (*PostgresPoolVIPOwnershipFreshHandoffProvenance)(nil)
var _ k8s.HandoffOperationProvenanceFence = (*PostgresPoolVIPOwnershipFreshHandoffProvenance)(nil)

// PoolVIPOwnershipHandoffEnvelope is the concrete P2-owned route-bearing
// provenance reader used by the unregistered composition bridge. It projects
// one immutable raw envelope only after matching every non-secret artifact
// identity; it never derives a route set from P1 fields or falls back to an
// issued delivery. The returned envelope stays inside the P2 bridge until the
// existing leader-bound durable issue path accepts it.
func (s *PostgresPoolVIPOwnershipFreshHandoffProvenance) PoolVIPOwnershipHandoffEnvelope(ctx context.Context, artifact PoolVIPOwnershipHandoffArtifact) (PoolVIPOwnershipDeliveryEnvelopeV3, error) {
	if s == nil || s.pool == nil || validPoolVIPOwnershipHandoffArtifact(artifact) != nil {
		return PoolVIPOwnershipDeliveryEnvelopeV3{}, ErrPoolVIPOwnershipFreshHandoffProvenanceRefused
	}
	return loadPoolVIPOwnershipHandoffEnvelope(ctx, sqlc.New(s.pool), artifact)
}

// PoolVIPOwnershipHandoffEnvelopeWithLeadership reads immutable raw envelope
// provenance only through the caller's exact advisory-lock connection. It is
// the bridge-only path: no session provider or general-pool read may race a
// leader handoff between provenance lookup and durable issue.
func (s *PostgresPoolVIPOwnershipFreshHandoffProvenance) PoolVIPOwnershipHandoffEnvelopeWithLeadership(ctx context.Context, artifact PoolVIPOwnershipHandoffArtifact, epoch k8s.HandoffLeadershipEpoch, conn *pgxpool.Conn) (PoolVIPOwnershipDeliveryEnvelopeV3, error) {
	if s == nil || s.pool == nil || conn == nil || validPoolVIPOwnershipHandoffArtifact(artifact) != nil || epoch.BackendPID <= 0 || epoch.LockKey == 0 {
		return PoolVIPOwnershipDeliveryEnvelopeV3{}, ErrPoolVIPOwnershipFreshHandoffProvenanceRefused
	}
	leader := PoolVIPOwnershipHandoffLeadershipEpoch{BackendPID: epoch.BackendPID, AdvisoryLockKey: epoch.LockKey}
	if err := validPoolVIPOwnershipHandoffLeaderSession(ctx, PoolVIPOwnershipHandoffLeaderSession{Epoch: leader, Conn: conn}); err != nil {
		return PoolVIPOwnershipDeliveryEnvelopeV3{}, err
	}
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return PoolVIPOwnershipDeliveryEnvelopeV3{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := validPoolVIPOwnershipHandoffLeaderSessionTx(ctx, tx, leader); err != nil {
		return PoolVIPOwnershipDeliveryEnvelopeV3{}, err
	}
	envelope, err := loadPoolVIPOwnershipHandoffEnvelope(ctx, sqlc.New(tx), artifact)
	if err != nil {
		return PoolVIPOwnershipDeliveryEnvelopeV3{}, err
	}
	if err := validPoolVIPOwnershipHandoffLeaderSessionTx(ctx, tx, leader); err != nil {
		return PoolVIPOwnershipDeliveryEnvelopeV3{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return PoolVIPOwnershipDeliveryEnvelopeV3{}, err
	}
	return envelope, nil
}

func loadPoolVIPOwnershipHandoffEnvelope(ctx context.Context, q *sqlc.Queries, artifact PoolVIPOwnershipHandoffArtifact) (PoolVIPOwnershipDeliveryEnvelopeV3, error) {
	if q == nil || validPoolVIPOwnershipHandoffArtifact(artifact) != nil {
		return PoolVIPOwnershipDeliveryEnvelopeV3{}, ErrPoolVIPOwnershipFreshHandoffProvenanceRefused
	}
	org, err := uuid.Parse(artifact.OrgID)
	if err != nil {
		return PoolVIPOwnershipDeliveryEnvelopeV3{}, ErrPoolVIPOwnershipFreshHandoffProvenanceRefused
	}
	site, err := uuid.Parse(artifact.SiteID)
	if err != nil {
		return PoolVIPOwnershipDeliveryEnvelopeV3{}, ErrPoolVIPOwnershipFreshHandoffProvenanceRefused
	}
	cluster, err := uuid.Parse(artifact.ClusterID)
	if err != nil {
		return PoolVIPOwnershipDeliveryEnvelopeV3{}, ErrPoolVIPOwnershipFreshHandoffProvenanceRefused
	}
	poolID, err := uuid.Parse(artifact.PoolID)
	if err != nil {
		return PoolVIPOwnershipDeliveryEnvelopeV3{}, ErrPoolVIPOwnershipFreshHandoffProvenanceRefused
	}
	operation, err := uuid.Parse(artifact.OperationID)
	if err != nil {
		return PoolVIPOwnershipDeliveryEnvelopeV3{}, ErrPoolVIPOwnershipFreshHandoffProvenanceRefused
	}
	bodies, err := q.GetPoolVIPOwnershipFreshHandoffEnvelopeBodies(ctx, sqlc.GetPoolVIPOwnershipFreshHandoffEnvelopeBodiesParams{OperationID: operation, OrgID: org, SiteID: site, ClusterID: cluster, PoolID: poolID})
	if errors.Is(err, pgx.ErrNoRows) {
		return PoolVIPOwnershipDeliveryEnvelopeV3{}, ErrPoolVIPOwnershipFreshHandoffProvenanceRefused
	}
	if err != nil {
		return PoolVIPOwnershipDeliveryEnvelopeV3{}, err
	}
	raw := [4][]byte{bodies.OldServingEnvelope, bodies.NewPreparedEnvelope, bodies.OldWithdrawalEnvelope, bodies.NewServingEnvelope}
	var matched *PoolVIPOwnershipDeliveryEnvelopeV3
	for _, body := range raw {
		var envelope PoolVIPOwnershipDeliveryEnvelopeV3
		if json.Unmarshal(body, &envelope) != nil || ValidatePoolVIPOwnershipDeliveryEnvelopeV3(envelope) != nil || poolVIPOwnershipHandoffArtifact(envelope) != artifact {
			continue
		}
		if matched != nil {
			return PoolVIPOwnershipDeliveryEnvelopeV3{}, ErrPoolVIPOwnershipFreshHandoffProvenanceRefused
		}
		copy := clonePoolVIPOwnershipDeliveryEnvelopeV3(envelope)
		matched = &copy
	}
	if matched == nil {
		return PoolVIPOwnershipDeliveryEnvelopeV3{}, ErrPoolVIPOwnershipFreshHandoffProvenanceRefused
	}
	return *matched, nil
}

func clonePoolVIPOwnershipDeliveryEnvelopeV3(envelope PoolVIPOwnershipDeliveryEnvelopeV3) PoolVIPOwnershipDeliveryEnvelopeV3 {
	out := envelope
	if envelope.Manifest.WGPeers == nil {
		out.Manifest.WGPeers = nil
	} else {
		out.Manifest.WGPeers = make([]PoolVIPOwnershipWGPeerV3, len(envelope.Manifest.WGPeers))
		copy(out.Manifest.WGPeers, envelope.Manifest.WGPeers)
	}
	for i := range out.Manifest.WGPeers {
		out.Manifest.WGPeers[i].AllowedIPs = append([]string(nil), envelope.Manifest.WGPeers[i].AllowedIPs...)
	}
	out.Manifest.Routes = append([]string(nil), envelope.Manifest.Routes...)
	out.Manifest.Services = append([]PoolVIPOwnershipServiceV3(nil), envelope.Manifest.Services...)
	return out
}

// ValidateHandoffOperationProvenance is called only from P1's exact
// leader-bound operation-create transaction. It rechecks every P2 authority
// row under the same transaction before 0082 becomes durable, so a revocation
// or Service incarnation change cannot land between fresh-plan resolution and
// operation creation.
func (s *PostgresPoolVIPOwnershipFreshHandoffProvenance) ValidateHandoffOperationProvenance(ctx context.Context, tx pgx.Tx, plan k8s.DurableHandoffPlan, epoch k8s.HandoffLeadershipEpoch) error {
	if s == nil || s.pool == nil || tx == nil || k8s.ValidateDurableHandoffPlan(plan) != nil || epoch.BackendPID <= 0 || epoch.LockKey == 0 {
		return ErrPoolVIPOwnershipFreshHandoffProvenanceRefused
	}
	if err := validPoolVIPOwnershipHandoffLeaderSessionTx(ctx, tx, PoolVIPOwnershipHandoffLeadershipEpoch{BackendPID: epoch.BackendPID, AdvisoryLockKey: epoch.LockKey}); err != nil {
		return err
	}
	p := plan.Plan
	var transition, oldLease, targetLease string
	var membership []uuid.UUID
	var old, prepared, withdrawal, serving []byte
	var oldExpiry, preparedExpiry, withdrawalExpiry, servingExpiry time.Time
	err := tx.QueryRow(ctx, `SELECT decision_transition,old_lease_identity,target_lease_identity,membership_snapshot,old_serving_envelope,new_prepared_envelope,old_withdrawal_envelope,new_serving_envelope,old_serving_expires_at,new_prepared_expires_at,old_withdrawal_expires_at,new_serving_expires_at FROM pool_vip_ownership_handoff_provenance WHERE operation_id=$1 AND org_id=$2 AND site_id=$3 AND cluster_id=$4 AND pool_id=$5 AND old_node_id=$6 AND new_node_id=$7 AND expected_generation=$8 AND target_generation=$9 FOR UPDATE`, p.OperationID, p.Scope.OrgID, p.Scope.SiteID, p.Scope.ClusterID, p.Scope.PoolID, p.ExpectedActiveID, p.CandidateID, int64(p.ExpectedGeneration), int64(p.TargetGeneration)).Scan(&transition, &oldLease, &targetLease, &membership, &old, &prepared, &withdrawal, &serving, &oldExpiry, &preparedExpiry, &withdrawalExpiry, &servingExpiry)
	if err != nil {
		return ErrPoolVIPOwnershipFreshHandoffProvenanceRefused
	}
	oldEnvelope, okOld := decodePoolVIPOwnershipFreshHandoffEnvelope(old)
	preparedEnvelope, okPrepared := decodePoolVIPOwnershipFreshHandoffEnvelope(prepared)
	withdrawalEnvelope, okWithdrawal := decodePoolVIPOwnershipFreshHandoffEnvelope(withdrawal)
	servingEnvelope, okServing := decodePoolVIPOwnershipFreshHandoffEnvelope(serving)
	if !okOld || !okPrepared || !okWithdrawal || !okServing {
		return ErrPoolVIPOwnershipFreshHandoffProvenanceRefused
	}
	stored := k8s.DurableHandoffPlan{OldLeaseIdentity: oldLease, TargetLeaseIdentity: targetLease, Plan: k8s.HandoffPlan{OperationID: p.OperationID, Scope: p.Scope, ExpectedActiveID: p.ExpectedActiveID, CandidateID: p.CandidateID, ExpectedGeneration: p.ExpectedGeneration, TargetGeneration: p.TargetGeneration, Decision: p.Decision, OldServing: freshArtifactFromEnvelope(oldEnvelope, oldExpiry, k8s.Serving), NewPrepared: freshArtifactFromEnvelope(preparedEnvelope, preparedExpiry, k8s.PreparedNonServing), OldWithdrawal: freshArtifactFromEnvelope(withdrawalEnvelope, withdrawalExpiry, k8s.PreparedNonServing), NewServing: freshArtifactFromEnvelope(servingEnvelope, servingExpiry, k8s.Serving)}}
	if transition != string(p.Decision.Transition) || !reflect.DeepEqual(stored, plan) {
		return fmt.Errorf("%w: immutable plan mismatch", ErrPoolVIPOwnershipFreshHandoffProvenanceRefused)
	}
	if !validPoolVIPOwnershipFreshHandoffMembershipSnapshot(ctx, tx, p, membership) {
		return fmt.Errorf("%w: membership drift", ErrPoolVIPOwnershipFreshHandoffProvenanceRefused)
	}
	if !validStoredPoolVIPOwnershipFreshHandoffCapabilities(ctx, tx, plan) {
		return fmt.Errorf("%w: capability drift", ErrPoolVIPOwnershipFreshHandoffProvenanceRefused)
	}
	if !validStoredPoolVIPOwnershipFreshHandoffServiceUIDs(ctx, tx, plan) {
		return fmt.Errorf("%w: Service UID drift", ErrPoolVIPOwnershipFreshHandoffProvenanceRefused)
	}
	derived, err := loadPoolVIPOwnershipFreshHandoffServiceUIDs(ctx, tx, p)
	if err != nil || !samePoolVIPOwnershipFreshServiceUIDs(ctx, tx, p.OperationID, p.Scope.OrgID, derived) {
		return ErrPoolVIPOwnershipFreshHandoffProvenanceRefused
	}
	return nil
}

// ClaimPoolVIPOwnershipFreshHandoffProvenance records exactly one immutable
// operation claim using the same leader-session proof as durable v3 delivery
// issue. An exact retry is idempotent; any changed byte/field fails closed.
func (s *PostgresPoolVIPOwnershipFreshHandoffProvenance) ClaimPoolVIPOwnershipFreshHandoffProvenance(ctx context.Context, session PoolVIPOwnershipHandoffLeaderSession, claim PoolVIPOwnershipFreshHandoffClaim) error {
	if s == nil || s.pool == nil {
		return fmt.Errorf("%w: store is not configured", ErrPoolVIPOwnershipFreshHandoffProvenanceRefused)
	}
	if err := validPoolVIPOwnershipHandoffLeaderSession(ctx, session); err != nil {
		return err
	}
	prepared, err := preparePoolVIPOwnershipFreshHandoffClaim(claim)
	if err != nil {
		return err
	}
	tx, err := session.Conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := validPoolVIPOwnershipHandoffLeaderSessionTx(ctx, tx, session.Epoch); err != nil {
		return err
	}
	if err := persistPoolVIPOwnershipFreshHandoffClaim(ctx, tx, prepared); err != nil {
		return err
	}
	if err := validPoolVIPOwnershipHandoffLeaderSessionTx(ctx, tx, session.Epoch); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ResolveFreshHandoffPlan implements P1's read-only source contract. A
// provider is mandatory so the lookup remains tied to an exact verified leader
// session even though it mutates no rows itself.
func (s *PostgresPoolVIPOwnershipFreshHandoffProvenance) ResolveFreshHandoffPlan(ctx context.Context, intent HandoffTickIntent) (k8s.DurableHandoffPlan, bool, error) {
	if s == nil || s.pool == nil || s.sessions == nil || !validHandoffPlanIntent(intent) || intent.Existing {
		return k8s.DurableHandoffPlan{}, false, nil
	}
	session, err := s.sessions.PoolVIPOwnershipHandoffLeaderSession(ctx)
	if err != nil {
		return k8s.DurableHandoffPlan{}, false, err
	}
	return s.ResolveFreshHandoffPlanLeaderBound(ctx, session, intent)
}

func (s *PostgresPoolVIPOwnershipFreshHandoffProvenance) ResolveFreshHandoffPlanLeaderBound(ctx context.Context, session PoolVIPOwnershipHandoffLeaderSession, intent HandoffTickIntent) (k8s.DurableHandoffPlan, bool, error) {
	if s == nil || s.pool == nil || !validHandoffPlanIntent(intent) || intent.Existing {
		return k8s.DurableHandoffPlan{}, false, nil
	}
	if err := validPoolVIPOwnershipHandoffLeaderSession(ctx, session); err != nil {
		return k8s.DurableHandoffPlan{}, false, err
	}
	// This is a read projection, but it takes the same scoped row locks used by
	// claim so member/UID/capability revalidation is one exact leader-bound
	// snapshot rather than a cardinality observation that can race replacement.
	tx, err := session.Conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return k8s.DurableHandoffPlan{}, false, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := validPoolVIPOwnershipHandoffLeaderSessionTx(ctx, tx, session.Epoch); err != nil {
		return k8s.DurableHandoffPlan{}, false, err
	}
	plan, found, err := loadPoolVIPOwnershipFreshHandoffPlan(ctx, tx, intent)
	if err != nil || !found {
		return k8s.DurableHandoffPlan{}, found, err
	}
	if err := validPoolVIPOwnershipHandoffLeaderSessionTx(ctx, tx, session.Epoch); err != nil {
		return k8s.DurableHandoffPlan{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return k8s.DurableHandoffPlan{}, false, err
	}
	return plan, true, nil
}

// ResolveFreshHandoffPlanWithLeadership is the scheduler-only direct-session
// seam. It never asks the session provider for another connection: callers
// must supply the exact advisory-lock socket and epoch that will fence the
// subsequent operation-create path. The fresh plan is still revalidated by
// ValidateHandoffOperationProvenance in CreateOrResume's transaction; this
// read is deliberately not a receipt-only readiness shortcut.
func (s *PostgresPoolVIPOwnershipFreshHandoffProvenance) ResolveFreshHandoffPlanWithLeadership(ctx context.Context, intent HandoffTickIntent, epoch k8s.HandoffLeadershipEpoch, conn *pgxpool.Conn) (k8s.DurableHandoffPlan, bool, error) {
	if s == nil || s.pool == nil || conn == nil || !validHandoffPlanIntent(intent) || intent.Existing || epoch.BackendPID <= 0 || epoch.LockKey == 0 {
		return k8s.DurableHandoffPlan{}, false, ErrPoolVIPOwnershipFreshHandoffProvenanceRefused
	}
	leader := PoolVIPOwnershipHandoffLeadershipEpoch{BackendPID: epoch.BackendPID, AdvisoryLockKey: epoch.LockKey}
	if err := validPoolVIPOwnershipHandoffLeaderSession(ctx, PoolVIPOwnershipHandoffLeaderSession{Epoch: leader, Conn: conn}); err != nil {
		return k8s.DurableHandoffPlan{}, false, err
	}
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return k8s.DurableHandoffPlan{}, false, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := validPoolVIPOwnershipHandoffLeaderSessionTx(ctx, tx, leader); err != nil {
		return k8s.DurableHandoffPlan{}, false, err
	}
	plan, found, err := loadPoolVIPOwnershipFreshHandoffPlan(ctx, tx, intent)
	if err != nil || !found {
		return k8s.DurableHandoffPlan{}, found, err
	}
	if err := validPoolVIPOwnershipHandoffLeaderSessionTx(ctx, tx, leader); err != nil {
		return k8s.DurableHandoffPlan{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return k8s.DurableHandoffPlan{}, false, err
	}
	return plan, true, nil
}

type preparedPoolVIPOwnershipFreshHandoffClaim struct {
	claim        PoolVIPOwnershipFreshHandoffClaim
	artifacts    map[k8s.P2HandoffArtifact]preparedPoolVIPOwnershipFreshHandoffArtifact
	capabilities []PoolVIPOwnershipFreshHandoffCapability
	serviceUIDs  []PoolVIPOwnershipFreshHandoffServiceUID
}

// PoolVIPOwnershipFreshHandoffCreate is the only P1-facing mutation callback
// accepted by the P2 exact-session orchestration seam. The callback receives
// the same transaction that persisted/revalidated 0085; it must create or
// resume 0082 through that transaction and must not acquire another session.
type PoolVIPOwnershipFreshHandoffCreate func(context.Context, pgx.Tx, k8s.DurableHandoffPlan) error

// ClaimResolveFreshHandoffPlanWithLeadership atomically persists an exact
// fresh provenance claim, reconstructs it from durable rows, performs the
// final capability/UID/member fence, and invokes CreateOrResume through the
// same caller-held leader transaction. Any callback error or leadership loss
// rolls back both 0085 and 0082; no partial provenance becomes restartable.
func (s *PostgresPoolVIPOwnershipFreshHandoffProvenance) ClaimResolveFreshHandoffPlanWithLeadership(ctx context.Context, claim PoolVIPOwnershipFreshHandoffClaim, epoch k8s.HandoffLeadershipEpoch, conn *pgxpool.Conn, create PoolVIPOwnershipFreshHandoffCreate) (k8s.DurableHandoffPlan, error) {
	if s == nil || s.pool == nil || conn == nil || create == nil || epoch.BackendPID <= 0 || epoch.LockKey == 0 {
		return k8s.DurableHandoffPlan{}, ErrPoolVIPOwnershipFreshHandoffProvenanceRefused
	}
	prepared, err := preparePoolVIPOwnershipFreshHandoffClaim(claim)
	if err != nil {
		return k8s.DurableHandoffPlan{}, err
	}
	leader := PoolVIPOwnershipHandoffLeadershipEpoch{BackendPID: epoch.BackendPID, AdvisoryLockKey: epoch.LockKey}
	if err := validPoolVIPOwnershipHandoffLeaderSession(ctx, PoolVIPOwnershipHandoffLeaderSession{Epoch: leader, Conn: conn}); err != nil {
		return k8s.DurableHandoffPlan{}, err
	}
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return k8s.DurableHandoffPlan{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := validPoolVIPOwnershipHandoffLeaderSessionTx(ctx, tx, leader); err != nil {
		return k8s.DurableHandoffPlan{}, err
	}
	if err := persistPoolVIPOwnershipFreshHandoffClaim(ctx, tx, prepared); err != nil {
		return k8s.DurableHandoffPlan{}, err
	}
	plan, found, err := loadPoolVIPOwnershipFreshHandoffPlan(ctx, tx, claim.Intent)
	if err != nil || !found || !reflect.DeepEqual(plan, claim.Plan) {
		if err != nil {
			return k8s.DurableHandoffPlan{}, err
		}
		return k8s.DurableHandoffPlan{}, ErrPoolVIPOwnershipFreshHandoffProvenanceRefused
	}
	if err := s.ValidateHandoffOperationProvenance(ctx, tx, plan, epoch); err != nil {
		return k8s.DurableHandoffPlan{}, err
	}
	if err := create(ctx, tx, plan); err != nil {
		return k8s.DurableHandoffPlan{}, err
	}
	if err := validPoolVIPOwnershipHandoffLeaderSessionTx(ctx, tx, leader); err != nil {
		return k8s.DurableHandoffPlan{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return k8s.DurableHandoffPlan{}, err
	}
	return plan, nil
}

type preparedPoolVIPOwnershipFreshHandoffArtifact struct {
	envelopeJSON []byte
	expiresAt    time.Time
	envelope     PoolVIPOwnershipDeliveryEnvelopeV3
}

func preparePoolVIPOwnershipFreshHandoffClaim(claim PoolVIPOwnershipFreshHandoffClaim) (preparedPoolVIPOwnershipFreshHandoffClaim, error) {
	if !validHandoffPlanIntent(claim.Intent) || claim.Intent.Existing || k8s.ValidateDurableHandoffPlan(claim.Plan) != nil || !freshPlanMatchesIntent(claim.Plan, claim.Intent) {
		return preparedPoolVIPOwnershipFreshHandoffClaim{}, ErrPoolVIPOwnershipFreshHandoffProvenanceRefused
	}
	if len(claim.MembershipSnapshot) != len(claim.Intent.OrderedCandidateIDs) || len(claim.MembershipSnapshot) < 2 || len(claim.MembershipSnapshot) > 512 {
		return preparedPoolVIPOwnershipFreshHandoffClaim{}, ErrPoolVIPOwnershipFreshHandoffProvenanceRefused
	}
	seenMembers := make(map[uuid.UUID]struct{}, len(claim.MembershipSnapshot))
	for i, node := range claim.MembershipSnapshot {
		if node == uuid.Nil || node != claim.Intent.OrderedCandidateIDs[i] {
			return preparedPoolVIPOwnershipFreshHandoffClaim{}, ErrPoolVIPOwnershipFreshHandoffProvenanceRefused
		}
		if _, duplicate := seenMembers[node]; duplicate {
			return preparedPoolVIPOwnershipFreshHandoffClaim{}, ErrPoolVIPOwnershipFreshHandoffProvenanceRefused
		}
		seenMembers[node] = struct{}{}
	}
	if _, oldOK := seenMembers[claim.Plan.Plan.ExpectedActiveID]; !oldOK {
		return preparedPoolVIPOwnershipFreshHandoffClaim{}, ErrPoolVIPOwnershipFreshHandoffProvenanceRefused
	}
	if _, newOK := seenMembers[claim.Plan.Plan.CandidateID]; !newOK {
		return preparedPoolVIPOwnershipFreshHandoffClaim{}, ErrPoolVIPOwnershipFreshHandoffProvenanceRefused
	}
	if !validPoolVIPOwnershipFreshHandoffServiceUIDs(claim.ServiceUIDs, claim.Plan) {
		return preparedPoolVIPOwnershipFreshHandoffClaim{}, ErrPoolVIPOwnershipFreshHandoffProvenanceRefused
	}
	prepared := preparedPoolVIPOwnershipFreshHandoffClaim{claim: claim, artifacts: make(map[k8s.P2HandoffArtifact]preparedPoolVIPOwnershipFreshHandoffArtifact, 4)}
	for _, raw := range claim.Artifacts {
		if _, duplicate := prepared.artifacts[raw.Which]; duplicate || raw.ExpiresAt.IsZero() {
			return preparedPoolVIPOwnershipFreshHandoffClaim{}, ErrPoolVIPOwnershipFreshHandoffProvenanceRefused
		}
		want, err := k8s.P2HandoffDeliveryForPlanArtifact(claim.Plan, raw.Which)
		if err != nil || !raw.ExpiresAt.Equal(want.LeaseExpiresAt.UTC()) || !raw.ExpiresAt.Equal(raw.Envelope.ExpiresAt) || ValidatePoolVIPOwnershipDeliveryEnvelopeV3(raw.Envelope) != nil || !poolVIPOwnershipFreshEnvelopeMatchesP2Identity(raw.Envelope, want.Identity) {
			return preparedPoolVIPOwnershipFreshHandoffClaim{}, ErrPoolVIPOwnershipFreshHandoffProvenanceRefused
		}
		body, err := json.Marshal(raw.Envelope)
		if err != nil || len(body) > poolVIPOwnershipFreshHandoffEnvelopeLimit {
			return preparedPoolVIPOwnershipFreshHandoffClaim{}, ErrPoolVIPOwnershipFreshHandoffProvenanceRefused
		}
		prepared.artifacts[raw.Which] = preparedPoolVIPOwnershipFreshHandoffArtifact{envelopeJSON: body, expiresAt: raw.ExpiresAt.UTC(), envelope: raw.Envelope}
	}
	for _, which := range []k8s.P2HandoffArtifact{k8s.P2OldServingArtifact, k8s.P2NewPreparedArtifact, k8s.P2OldWithdrawalArtifact, k8s.P2NewServingArtifact} {
		if _, ok := prepared.artifacts[which]; !ok {
			return preparedPoolVIPOwnershipFreshHandoffClaim{}, ErrPoolVIPOwnershipFreshHandoffProvenanceRefused
		}
	}
	if !validPoolVIPOwnershipFreshHandoffLeaseAndDigestTopology(prepared.artifacts) {
		return preparedPoolVIPOwnershipFreshHandoffClaim{}, ErrPoolVIPOwnershipFreshHandoffProvenanceRefused
	}
	return prepared, nil
}

// validPoolVIPOwnershipFreshHandoffLeaseAndDigestTopology is deliberately
// checked after every raw body has passed the v3 parser. Lease identities are
// CP-issued durable-plan values, never envelope/agent input; the envelopes
// only prove that their epochs and expiries match the one old/target lease
// partition.  The two serving artifacts must describe the exact same P2
// route/VIP snapshot before P1 can reach its CAS boundary.
func validPoolVIPOwnershipFreshHandoffLeaseAndDigestTopology(artifacts map[k8s.P2HandoffArtifact]preparedPoolVIPOwnershipFreshHandoffArtifact) bool {
	old, oldOK := artifacts[k8s.P2OldServingArtifact]
	prepared, preparedOK := artifacts[k8s.P2NewPreparedArtifact]
	withdrawal, withdrawalOK := artifacts[k8s.P2OldWithdrawalArtifact]
	serving, servingOK := artifacts[k8s.P2NewServingArtifact]
	if !oldOK || !preparedOK || !withdrawalOK || !servingOK {
		return false
	}
	if old.envelope.ExpectedRouteDigest != serving.envelope.ExpectedRouteDigest || old.envelope.ExpectedVIPMapDigest != serving.envelope.ExpectedVIPMapDigest ||
		old.envelope.LeaseEpoch >= prepared.envelope.LeaseEpoch || prepared.envelope.LeaseEpoch != withdrawal.envelope.LeaseEpoch || prepared.envelope.LeaseEpoch != serving.envelope.LeaseEpoch ||
		!prepared.expiresAt.Equal(withdrawal.expiresAt) || !prepared.expiresAt.Equal(serving.expiresAt) || withdrawal.envelope.PriorLeaseEpoch != old.envelope.LeaseEpoch {
		return false
	}
	oldManifest, servingManifest := old.envelope.Manifest, serving.envelope.Manifest
	if oldManifest.DNSZone != servingManifest.DNSZone || oldManifest.DNSVIP != servingManifest.DNSVIP ||
		!reflect.DeepEqual(oldManifest.WGPeers, servingManifest.WGPeers) || !reflect.DeepEqual(oldManifest.Routes, servingManifest.Routes) ||
		!reflect.DeepEqual(oldManifest.Services, servingManifest.Services) {
		return false
	}
	for _, nonServing := range []PoolVIPOwnershipManifestV3{prepared.envelope.Manifest, withdrawal.envelope.Manifest} {
		if nonServing.DNSZone != oldManifest.DNSZone || nonServing.DNSVIP != oldManifest.DNSVIP || len(nonServing.WGPeers) != 0 || len(nonServing.Routes) != 0 || len(nonServing.Services) != 0 {
			return false
		}
	}
	return prepared.envelope.ExpectedRouteDigest == k8s.P2HandoffCanonicalEmptyRouteDigest && prepared.envelope.ExpectedVIPMapDigest == "" &&
		withdrawal.envelope.ExpectedRouteDigest == k8s.P2HandoffCanonicalEmptyRouteDigest && withdrawal.envelope.ExpectedVIPMapDigest == ""
}

func freshPlanMatchesIntent(plan k8s.DurableHandoffPlan, intent HandoffTickIntent) bool {
	p := plan.Plan
	return p.OperationID == intent.OperationID && p.Scope == intent.Scope && p.ExpectedActiveID == intent.ExpectedActiveID && p.CandidateID == intent.CandidateID &&
		p.ExpectedGeneration == intent.ExpectedGeneration && p.TargetGeneration == intent.TargetGeneration &&
		p.Decision.Transition == intent.Decision.Transition && p.Decision.FromID == intent.Decision.FromID && p.Decision.ToID == intent.Decision.ToID &&
		p.Decision.Pool.ActiveID == intent.Decision.Pool.ActiveID && p.Decision.Pool.Generation == intent.Decision.Pool.Generation
}

func validPoolVIPOwnershipFreshHandoffCapabilities(values []PoolVIPOwnershipFreshHandoffCapability, plan k8s.DurableHandoffPlan) bool {
	if len(values) != 2 {
		return false
	}
	want := map[uuid.UUID]struct{}{plan.Plan.ExpectedActiveID: {}, plan.Plan.CandidateID: {}}
	for _, value := range values {
		if value.NodeID == uuid.Nil || value.WireVersion != PoolVIPOwnershipDeliveryHandoffVersion || value.DeliveryRowID == uuid.Nil || value.ReceiptTime.IsZero() || value.ExpiresAt.IsZero() || !value.ExpiresAt.After(value.ReceiptTime) {
			return false
		}
		if _, ok := want[value.NodeID]; !ok {
			return false
		}
		delete(want, value.NodeID)
	}
	return len(want) == 0
}

func validPoolVIPOwnershipFreshHandoffServiceUIDs(values []PoolVIPOwnershipFreshHandoffServiceUID, plan k8s.DurableHandoffPlan) bool {
	if len(values) == 0 || len(values) > 512 {
		return false
	}
	seen := map[string]struct{}{}
	for _, value := range values {
		if value.ActiveNodeID == uuid.Nil || !freshHandoffBigint(value.ObservationRevision) || !freshHandoffBigint(value.PromotionGeneration) || !validK8sServiceUIDDNSLabel(value.Namespace) || !validK8sServiceUIDDNSLabel(value.Service) || len(value.UID) == 0 || len(value.UID) > maxK8sServiceUIDBytes || value.PromotionGeneration != plan.Plan.ExpectedGeneration {
			return false
		}
		if value.ActiveNodeID != plan.Plan.ExpectedActiveID {
			return false
		}
		key := fmt.Sprintf("%d\x00%s\x00%s", value.PromotionGeneration, value.Namespace, value.Service)
		if _, duplicate := seen[key]; duplicate {
			return false
		}
		seen[key] = struct{}{}
	}
	return true
}

func poolVIPOwnershipFreshEnvelopeMatchesP2Identity(envelope PoolVIPOwnershipDeliveryEnvelopeV3, identity k8s.P2HandoffDeliveryIdentity) bool {
	return envelope.Version == identity.Version && envelope.OrgID == identity.OrgID.String() && envelope.SiteID == identity.SiteID.String() && envelope.ClusterID == identity.ClusterID.String() && envelope.PoolID == identity.PoolID.String() &&
		envelope.ConnectorNodeID == identity.ConnectorNodeID.String() && envelope.TargetNodeID == identity.TargetNodeID.String() && envelope.OperationID == identity.OperationID.String() && envelope.ManifestIdentity == identity.ManifestIdentity &&
		envelope.Role == string(identity.Role) && envelope.PromotionGeneration == identity.PromotionGeneration && envelope.ManifestRevision == identity.ManifestRevision && envelope.LeaseEpoch == identity.LeaseEpoch &&
		envelope.PriorLeaseEpoch == identity.PriorLeaseEpoch && envelope.DeliveryPhase == identity.DeliveryPhase && envelope.DeliveryID == identity.DeliveryID.String() &&
		envelope.ExpectedRouteDigest == identity.ExpectedRouteDigest && envelope.ExpectedVIPMapDigest == identity.ExpectedVIPMapDigest
}

func persistPoolVIPOwnershipFreshHandoffClaim(ctx context.Context, tx pgx.Tx, prepared preparedPoolVIPOwnershipFreshHandoffClaim) error {
	claim, p := prepared.claim, prepared.claim.Plan.Plan
	if !lockPoolVIPOwnershipFreshHandoffSnapshot(ctx, tx, p, claim.MembershipSnapshot) {
		return fmt.Errorf("persist snapshot fence: %w", ErrPoolVIPOwnershipFreshHandoffProvenanceRefused)
	}
	serviceUIDs, err := loadPoolVIPOwnershipFreshHandoffServiceUIDs(ctx, tx, p)
	if err != nil {
		return fmt.Errorf("persist service UID load: %w", err)
	}
	// Service-UID authority is derived from the locked CP exposure set and the
	// cluster ledger. The caller may carry a copy for an exact retry, but can
	// never omit a live Service or select a different incarnation.
	if !reflect.DeepEqual(canonicalPoolVIPOwnershipFreshServiceUIDs(claim.ServiceUIDs), serviceUIDs) {
		return fmt.Errorf("persist service UID comparison: %w", ErrPoolVIPOwnershipFreshHandoffProvenanceRefused)
	}
	prepared.serviceUIDs = serviceUIDs
	capabilities, err := loadPoolVIPOwnershipFreshHandoffCapabilities(ctx, tx, p)
	if err != nil {
		return fmt.Errorf("persist capability load: %w", err)
	}
	prepared.capabilities = capabilities
	for _, capability := range prepared.capabilities {
		if _, err := tx.Exec(ctx, `INSERT INTO k8s_pool_ownership_v2_capabilities (org_id, site_id, cluster_id, pool_id, node_id, wire_version, delivery_row_id, receipt_time, expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT (org_id,pool_id,node_id) DO UPDATE SET wire_version=EXCLUDED.wire_version, delivery_row_id=EXCLUDED.delivery_row_id, receipt_time=EXCLUDED.receipt_time, expires_at=EXCLUDED.expires_at`, p.Scope.OrgID, p.Scope.SiteID, p.Scope.ClusterID, p.Scope.PoolID, capability.NodeID, capability.WireVersion, capability.DeliveryRowID, capability.ReceiptTime.UTC(), capability.ExpiresAt.UTC()); err != nil {
			return err
		}
	}
	for _, service := range prepared.serviceUIDs {
		if _, err := tx.Exec(ctx, `INSERT INTO k8s_pool_service_uid_provenance (org_id, site_id, cluster_id, pool_id, active_node_id, promotion_generation, ledger_id, namespace, service, service_uid, observation_revision) SELECT $1,$2,$3,$4,$5,$6,l.id,$7,$8,$9,$10 FROM k8s_service_uid_observation_ledgers l WHERE l.org_id=$1 AND l.site_id=$2 AND l.cluster_id=$3 ON CONFLICT (org_id,pool_id,promotion_generation,namespace,service) DO UPDATE SET active_node_id=EXCLUDED.active_node_id, ledger_id=EXCLUDED.ledger_id, service_uid=EXCLUDED.service_uid, observation_revision=EXCLUDED.observation_revision`, p.Scope.OrgID, p.Scope.SiteID, p.Scope.ClusterID, p.Scope.PoolID, service.ActiveNodeID, int64(service.PromotionGeneration), service.Namespace, service.Service, service.UID, int64(service.ObservationRevision)); err != nil {
			return err
		}
	}
	old, preparedArtifact, withdrawal, serving := prepared.artifacts[k8s.P2OldServingArtifact], prepared.artifacts[k8s.P2NewPreparedArtifact], prepared.artifacts[k8s.P2OldWithdrawalArtifact], prepared.artifacts[k8s.P2NewServingArtifact]
	command, err := tx.Exec(ctx, `INSERT INTO pool_vip_ownership_handoff_provenance (operation_id,org_id,site_id,cluster_id,pool_id,old_node_id,new_node_id,expected_generation,target_generation,decision_transition,old_lease_identity,target_lease_identity,membership_snapshot,old_serving_envelope,new_prepared_envelope,old_withdrawal_envelope,new_serving_envelope,old_serving_expires_at,new_prepared_expires_at,old_withdrawal_expires_at,new_serving_expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14::jsonb,$15::jsonb,$16::jsonb,$17::jsonb,$18,$19,$20,$21) ON CONFLICT (operation_id) DO NOTHING`, p.OperationID, p.Scope.OrgID, p.Scope.SiteID, p.Scope.ClusterID, p.Scope.PoolID, p.ExpectedActiveID, p.CandidateID, int64(p.ExpectedGeneration), int64(p.TargetGeneration), string(p.Decision.Transition), claim.Plan.OldLeaseIdentity, claim.Plan.TargetLeaseIdentity, claim.MembershipSnapshot, old.envelopeJSON, preparedArtifact.envelopeJSON, withdrawal.envelopeJSON, serving.envelopeJSON, old.expiresAt, preparedArtifact.expiresAt, withdrawal.expiresAt, serving.expiresAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return ErrPoolVIPOwnershipFreshHandoffProvenanceConflict
		}
		return err
	}
	if command.RowsAffected() == 0 {
		if err := comparePoolVIPOwnershipFreshHandoffClaim(ctx, tx, prepared); err != nil {
			return err
		}
		if validStoredPoolVIPOwnershipFreshHandoffCapabilities(ctx, tx, claim.Plan) {
			return nil
		}
		return refreshPoolVIPOwnershipFreshHandoffCapabilities(ctx, tx, prepared)
	}
	for _, capability := range canonicalPoolVIPOwnershipFreshCapabilities(prepared.capabilities) {
		if _, err := tx.Exec(ctx, `INSERT INTO pool_vip_ownership_handoff_provenance_capabilities (operation_id,org_id,site_id,cluster_id,pool_id,node_id,wire_version,delivery_row_id,receipt_time,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, p.OperationID, p.Scope.OrgID, p.Scope.SiteID, p.Scope.ClusterID, p.Scope.PoolID, capability.NodeID, capability.WireVersion, capability.DeliveryRowID, capability.ReceiptTime.UTC(), capability.ExpiresAt.UTC()); err != nil {
			return err
		}
	}
	for _, service := range prepared.serviceUIDs {
		if _, err := tx.Exec(ctx, `INSERT INTO pool_vip_ownership_handoff_provenance_service_uids (operation_id,org_id,site_id,cluster_id,pool_id,active_node_id,promotion_generation,namespace,service,service_uid,observation_revision) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, p.OperationID, p.Scope.OrgID, p.Scope.SiteID, p.Scope.ClusterID, p.Scope.PoolID, service.ActiveNodeID, int64(service.PromotionGeneration), service.Namespace, service.Service, service.UID, int64(service.ObservationRevision)); err != nil {
			return err
		}
	}
	return nil
}

// Lock the exact pool row and every member before deriving capability/UID
// evidence. The unique generation index is the final concurrent fence; this
// lock makes both the evidence read and that collision deterministic.
func lockPoolVIPOwnershipFreshHandoffSnapshot(ctx context.Context, tx pgx.Tx, plan k8s.HandoffPlan, want []uuid.UUID) bool {
	var active uuid.UUID
	var generation int64
	if err := tx.QueryRow(ctx, `SELECT active_node_id,generation FROM k8s_connector_pools WHERE id=$1 AND org_id=$2 AND site_id=$3 AND cluster_id=$4 FOR UPDATE`, plan.Scope.PoolID, plan.Scope.OrgID, plan.Scope.SiteID, plan.Scope.ClusterID).Scan(&active, &generation); err != nil || active != plan.ExpectedActiveID || generation != int64(plan.ExpectedGeneration) {
		return false
	}
	rows, err := tx.Query(ctx, `SELECT node_id FROM k8s_connector_pool_members WHERE pool_id=$1 AND org_id=$2 AND site_id=$3 ORDER BY admin_priority DESC,node_id FOR SHARE`, plan.Scope.PoolID, plan.Scope.OrgID, plan.Scope.SiteID)
	if err != nil {
		return false
	}
	defer rows.Close()
	var got []uuid.UUID
	for rows.Next() {
		var node uuid.UUID
		if err := rows.Scan(&node); err != nil {
			return false
		}
		got = append(got, node)
	}
	if rows.Err() != nil || len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// loadPoolVIPOwnershipFreshHandoffServiceUIDs derives the whole currently
// exposed Service set from CP state while the pool and every exposure child are
// locked. A caller-provided subset must never become an authority boundary.
func loadPoolVIPOwnershipFreshHandoffServiceUIDs(ctx context.Context, tx pgx.Tx, plan k8s.HandoffPlan) ([]PoolVIPOwnershipFreshHandoffServiceUID, error) {
	// Every exposure insert takes an FK key-share lock on its cluster. FOR UPDATE
	// is therefore the cluster-wide insert fence: locking only the rows that
	// existed when this transaction started would miss a concurrent new Service.
	var cluster uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM k8s_clusters WHERE id=$1 AND org_id=$2 AND site_id=$3 FOR UPDATE`, plan.Scope.ClusterID, plan.Scope.OrgID, plan.Scope.SiteID).Scan(&cluster); err != nil || cluster != plan.Scope.ClusterID {
		return nil, ErrPoolVIPOwnershipFreshHandoffProvenanceRefused
	}
	rows, err := tx.Query(ctx, `SELECT id,namespace,name FROM k8s_services WHERE org_id=$1 AND cluster_id=$2 AND deleted_at IS NULL ORDER BY namespace,name,id FOR SHARE`, plan.Scope.OrgID, plan.Scope.ClusterID)
	if err != nil {
		return nil, err
	}
	services := make(map[string]struct{})
	for rows.Next() {
		var id uuid.UUID
		var namespace, service string
		if err := rows.Scan(&id, &namespace, &service); err != nil {
			rows.Close()
			return nil, err
		}
		services[namespace+"\x00"+service] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	if len(services) == 0 || len(services) > 512 {
		return nil, ErrPoolVIPOwnershipFreshHandoffProvenanceRefused
	}
	keys := make([]string, 0, len(services))
	for key := range services {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	values := make([]PoolVIPOwnershipFreshHandoffServiceUID, 0, len(keys))
	for _, key := range keys {
		parts := strings.SplitN(key, "\x00", 2)
		var value PoolVIPOwnershipFreshHandoffServiceUID
		var generation, revision int64
		err := tx.QueryRow(ctx, `SELECT p.active_node_id,p.generation,c.uid,c.replay_sequence FROM k8s_connector_pools p JOIN k8s_service_uid_observation_ledgers l ON l.org_id=p.org_id AND l.site_id=p.site_id AND l.cluster_id=p.cluster_id JOIN k8s_service_uid_observation_current c ON c.ledger_id=l.id AND c.org_id=l.org_id JOIN k8s_service_uid_observation_current_attributions a ON a.ledger_id=c.ledger_id AND a.org_id=c.org_id AND a.namespace=c.namespace AND a.service=c.service AND a.replay_sequence=c.replay_sequence JOIN k8s_service_uid_observation_replay_states r ON r.id=a.replay_state_id AND r.org_id=a.org_id AND r.site_id=l.site_id AND r.cluster_id=l.cluster_id WHERE p.id=$1 AND p.org_id=$2 AND p.site_id=$3 AND p.cluster_id=$4 AND p.active_node_id=$5 AND p.generation=$6 AND r.connector_node_id=p.active_node_id AND c.namespace=$7 AND c.service=$8 AND c.state='live' FOR SHARE OF p,l,c,a,r`, plan.Scope.PoolID, plan.Scope.OrgID, plan.Scope.SiteID, plan.Scope.ClusterID, plan.ExpectedActiveID, int64(plan.ExpectedGeneration), parts[0], parts[1]).Scan(&value.ActiveNodeID, &generation, &value.UID, &revision)
		if err != nil || generation <= 0 || revision <= 0 {
			return nil, ErrPoolVIPOwnershipFreshHandoffProvenanceRefused
		}
		value.PromotionGeneration, value.Namespace, value.Service, value.ObservationRevision = uint64(generation), parts[0], parts[1], uint64(revision)
		values = append(values, value)
	}
	if !validPoolVIPOwnershipFreshHandoffServiceUIDs(values, k8s.DurableHandoffPlan{Plan: plan}) {
		return nil, ErrPoolVIPOwnershipFreshHandoffProvenanceRefused
	}
	return canonicalPoolVIPOwnershipFreshServiceUIDs(values), nil
}

// loadPoolVIPOwnershipFreshHandoffCapabilities derives capability only from
// authenticated, durable v3 applied-manifest receipts. A transient agent header
// is deliberately not an input to this path. The receipt and expiry window is
// checked again by the 0085 trigger and during leader-bound resolve.
func loadPoolVIPOwnershipFreshHandoffCapabilities(ctx context.Context, tx pgx.Tx, plan k8s.HandoffPlan) ([]PoolVIPOwnershipFreshHandoffCapability, error) {
	values := make([]PoolVIPOwnershipFreshHandoffCapability, 0, 2)
	for _, node := range []uuid.UUID{plan.ExpectedActiveID, plan.CandidateID} {
		expectedRole := string(k8s.PreparedNonServing)
		if node == plan.ExpectedActiveID {
			expectedRole = string(k8s.Serving)
		}
		// Hold the exact node row so revocation/replacement cannot interleave
		// after this authority read but before the enclosing transaction commits.
		var active bool
		if err := tx.QueryRow(ctx, `SELECT status='active' AND revoked_at IS NULL FROM nodes WHERE id=$1 AND org_id=$2 AND site_id=$3 FOR UPDATE`, node, plan.Scope.OrgID, plan.Scope.SiteID).Scan(&active); err != nil || !active {
			return nil, ErrPoolVIPOwnershipFreshHandoffProvenanceRefused
		}
		var value PoolVIPOwnershipFreshHandoffCapability
		err := tx.QueryRow(ctx, `SELECT d.target_node_id,d.wire_version,d.id,a.receipt_time,d.expires_at FROM pool_vip_ownership_deliveries d JOIN pool_vip_ownership_delivery_ack_receipts a ON a.delivery_row_id=d.id AND a.org_id=d.org_id WHERE d.org_id=$1 AND d.site_id=$2 AND d.cluster_id=$3 AND d.pool_id=$4 AND d.target_node_id=$5 AND d.connector_node_id=$5 AND d.wire_version=$6 AND d.promotion_generation=$7 AND d.role=$8 AND d.expires_at > now() AND a.receipt_time >= now()-interval '5 minutes' AND a.receipt_time <= now()+interval '5 seconds' AND a.applied_role=d.role AND a.applied_manifest_identity=d.manifest_identity AND a.applied_promotion_generation=d.promotion_generation AND a.applied_manifest_revision=d.manifest_revision AND a.owned_route_digest=d.expected_route_digest AND a.applied_lease_epoch=CASE WHEN d.role='withdrawal' THEN d.prior_lease_epoch ELSE d.lease_epoch END AND ((d.role='serving' AND a.vip_map_digest=d.expected_vip_map_digest) OR (d.role IN ('prepared_non_serving','withdrawal') AND a.vip_map_digest='')) AND a.applied_manifest=d.ownership_manifest AND a.applied_manifest IS NOT NULL AND d.ownership_manifest<>'{}'::jsonb ORDER BY a.receipt_time DESC,d.id DESC LIMIT 1 FOR UPDATE OF d,a`, plan.Scope.OrgID, plan.Scope.SiteID, plan.Scope.ClusterID, plan.Scope.PoolID, node, PoolVIPOwnershipDeliveryHandoffVersion, int64(plan.ExpectedGeneration), expectedRole).Scan(&value.NodeID, &value.WireVersion, &value.DeliveryRowID, &value.ReceiptTime, &value.ExpiresAt)
		if err != nil {
			return nil, ErrPoolVIPOwnershipFreshHandoffProvenanceRefused
		}
		value.ReceiptTime, value.ExpiresAt = value.ReceiptTime.UTC(), value.ExpiresAt.UTC()
		values = append(values, value)
	}
	if !validPoolVIPOwnershipFreshHandoffCapabilities(values, k8s.DurableHandoffPlan{Plan: plan}) {
		return nil, ErrPoolVIPOwnershipFreshHandoffProvenanceRefused
	}
	return canonicalPoolVIPOwnershipFreshCapabilities(values), nil
}

func comparePoolVIPOwnershipFreshHandoffClaim(ctx context.Context, tx pgx.Tx, prepared preparedPoolVIPOwnershipFreshHandoffClaim) error {
	claim, p := prepared.claim, prepared.claim.Plan.Plan
	var old, nextPrepared, withdrawal, serving []byte
	var oldExpiry, preparedExpiry, withdrawalExpiry, servingExpiry time.Time
	var oldLease, targetLease, transition string
	var membership []uuid.UUID
	err := tx.QueryRow(ctx, `SELECT decision_transition,old_lease_identity,target_lease_identity,membership_snapshot,old_serving_envelope,new_prepared_envelope,old_withdrawal_envelope,new_serving_envelope,old_serving_expires_at,new_prepared_expires_at,old_withdrawal_expires_at,new_serving_expires_at FROM pool_vip_ownership_handoff_provenance WHERE operation_id=$1 AND org_id=$2 AND site_id=$3 AND cluster_id=$4 AND pool_id=$5 AND old_node_id=$6 AND new_node_id=$7 AND expected_generation=$8 AND target_generation=$9 FOR UPDATE`, p.OperationID, p.Scope.OrgID, p.Scope.SiteID, p.Scope.ClusterID, p.Scope.PoolID, p.ExpectedActiveID, p.CandidateID, int64(p.ExpectedGeneration), int64(p.TargetGeneration)).Scan(&transition, &oldLease, &targetLease, &membership, &old, &nextPrepared, &withdrawal, &serving, &oldExpiry, &preparedExpiry, &withdrawalExpiry, &servingExpiry)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrPoolVIPOwnershipFreshHandoffProvenanceConflict
		}
		return err
	}
	values := []struct {
		got, want             []byte
		gotExpiry, wantExpiry time.Time
	}{{old, prepared.artifacts[k8s.P2OldServingArtifact].envelopeJSON, oldExpiry, prepared.artifacts[k8s.P2OldServingArtifact].expiresAt}, {nextPrepared, prepared.artifacts[k8s.P2NewPreparedArtifact].envelopeJSON, preparedExpiry, prepared.artifacts[k8s.P2NewPreparedArtifact].expiresAt}, {withdrawal, prepared.artifacts[k8s.P2OldWithdrawalArtifact].envelopeJSON, withdrawalExpiry, prepared.artifacts[k8s.P2OldWithdrawalArtifact].expiresAt}, {serving, prepared.artifacts[k8s.P2NewServingArtifact].envelopeJSON, servingExpiry, prepared.artifacts[k8s.P2NewServingArtifact].expiresAt}}
	if transition != string(p.Decision.Transition) || oldLease != claim.Plan.OldLeaseIdentity || targetLease != claim.Plan.TargetLeaseIdentity || !reflect.DeepEqual(membership, claim.MembershipSnapshot) {
		return ErrPoolVIPOwnershipFreshHandoffProvenanceConflict
	}
	for _, value := range values {
		if !jsonEqual(value.got, value.want) || !value.gotExpiry.Equal(value.wantExpiry) {
			return ErrPoolVIPOwnershipFreshHandoffProvenanceConflict
		}
	}
	// Capability input is never caller-supplied. Exact retries revalidate the
	// immutable stored applied-state rows during resolve rather than demanding
	// that a newer unrelated capability receipt byte-match the original claim.
	if !samePoolVIPOwnershipFreshServiceUIDs(ctx, tx, p.OperationID, p.Scope.OrgID, prepared.serviceUIDs) {
		return ErrPoolVIPOwnershipFreshHandoffProvenanceConflict
	}
	return nil
}

func samePoolVIPOwnershipFreshCapabilities(ctx context.Context, tx pgx.Tx, operationID, orgID uuid.UUID, want []PoolVIPOwnershipFreshHandoffCapability) bool {
	rows, err := tx.Query(ctx, `SELECT node_id,wire_version,delivery_row_id,receipt_time,expires_at FROM pool_vip_ownership_handoff_provenance_capabilities WHERE operation_id=$1 AND org_id=$2 ORDER BY node_id`, operationID, orgID)
	if err != nil {
		return false
	}
	defer rows.Close()
	var got []PoolVIPOwnershipFreshHandoffCapability
	for rows.Next() {
		var value PoolVIPOwnershipFreshHandoffCapability
		if err := rows.Scan(&value.NodeID, &value.WireVersion, &value.DeliveryRowID, &value.ReceiptTime, &value.ExpiresAt); err != nil {
			return false
		}
		value.ReceiptTime = value.ReceiptTime.UTC()
		value.ExpiresAt = value.ExpiresAt.UTC()
		got = append(got, value)
	}
	return rows.Err() == nil && reflect.DeepEqual(got, canonicalPoolVIPOwnershipFreshCapabilities(want))
}

// refreshPoolVIPOwnershipFreshHandoffCapabilities is the one narrow exception
// to child immutability. It can only refresh authenticated v3 receipts for an
// exact pre-operation retry, under the already verified leader session and
// locked pool snapshot. Once 0082 owns the operation, no provenance input may
// change.
func refreshPoolVIPOwnershipFreshHandoffCapabilities(ctx context.Context, tx pgx.Tx, prepared preparedPoolVIPOwnershipFreshHandoffClaim) error {
	p := prepared.claim.Plan.Plan
	var operationExists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM k8s_connector_handoff_operations WHERE id=$1 AND org_id=$2 AND site_id=$3 AND pool_id=$4 AND cluster_id=$5)`, p.OperationID, p.Scope.OrgID, p.Scope.SiteID, p.Scope.PoolID, p.Scope.ClusterID).Scan(&operationExists); err != nil || operationExists {
		return ErrPoolVIPOwnershipFreshHandoffProvenanceRefused
	}
	if _, err := tx.Exec(ctx, `SET LOCAL tunnex.pool_vip_ownership_capability_reclaim = '1'`); err != nil {
		return err
	}
	for _, capability := range canonicalPoolVIPOwnershipFreshCapabilities(prepared.capabilities) {
		command, err := tx.Exec(ctx, `UPDATE pool_vip_ownership_handoff_provenance_capabilities SET delivery_row_id=$1,receipt_time=$2,expires_at=$3 WHERE operation_id=$4 AND org_id=$5 AND site_id=$6 AND cluster_id=$7 AND pool_id=$8 AND node_id=$9 AND wire_version=$10`, capability.DeliveryRowID, capability.ReceiptTime.UTC(), capability.ExpiresAt.UTC(), p.OperationID, p.Scope.OrgID, p.Scope.SiteID, p.Scope.ClusterID, p.Scope.PoolID, capability.NodeID, PoolVIPOwnershipDeliveryHandoffVersion)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrPoolVIPOwnershipFreshHandoffProvenanceRefused
		}
	}
	if !validStoredPoolVIPOwnershipFreshHandoffCapabilities(ctx, tx, prepared.claim.Plan) {
		return ErrPoolVIPOwnershipFreshHandoffProvenanceRefused
	}
	return nil
}

func samePoolVIPOwnershipFreshServiceUIDs(ctx context.Context, tx pgx.Tx, operationID, orgID uuid.UUID, want []PoolVIPOwnershipFreshHandoffServiceUID) bool {
	rows, err := tx.Query(ctx, `SELECT active_node_id,promotion_generation,namespace,service,service_uid,observation_revision FROM pool_vip_ownership_handoff_provenance_service_uids WHERE operation_id=$1 AND org_id=$2 ORDER BY promotion_generation,namespace,service`, operationID, orgID)
	if err != nil {
		return false
	}
	defer rows.Close()
	var got []PoolVIPOwnershipFreshHandoffServiceUID
	for rows.Next() {
		var generation, revision int64
		var value PoolVIPOwnershipFreshHandoffServiceUID
		if err := rows.Scan(&value.ActiveNodeID, &generation, &value.Namespace, &value.Service, &value.UID, &revision); err != nil || generation <= 0 || revision <= 0 {
			return false
		}
		value.PromotionGeneration = uint64(generation)
		value.ObservationRevision = uint64(revision)
		got = append(got, value)
	}
	return rows.Err() == nil && reflect.DeepEqual(got, canonicalPoolVIPOwnershipFreshServiceUIDs(want))
}

func jsonEqual(a, b []byte) bool {
	var av, bv any
	return json.Unmarshal(a, &av) == nil && json.Unmarshal(b, &bv) == nil && reflect.DeepEqual(av, bv)
}

func canonicalPoolVIPOwnershipFreshCapabilities(values []PoolVIPOwnershipFreshHandoffCapability) []PoolVIPOwnershipFreshHandoffCapability {
	out := append([]PoolVIPOwnershipFreshHandoffCapability(nil), values...)
	sort.Slice(out, func(i, j int) bool { return out[i].NodeID.String() < out[j].NodeID.String() })
	return out
}
func canonicalPoolVIPOwnershipFreshServiceUIDs(values []PoolVIPOwnershipFreshHandoffServiceUID) []PoolVIPOwnershipFreshHandoffServiceUID {
	out := append([]PoolVIPOwnershipFreshHandoffServiceUID(nil), values...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].PromotionGeneration != out[j].PromotionGeneration {
			return out[i].PromotionGeneration < out[j].PromotionGeneration
		}
		if out[i].Namespace != out[j].Namespace {
			return out[i].Namespace < out[j].Namespace
		}
		return out[i].Service < out[j].Service
	})
	return out
}

func loadPoolVIPOwnershipFreshHandoffPlan(ctx context.Context, tx pgx.Tx, intent HandoffTickIntent) (k8s.DurableHandoffPlan, bool, error) {
	var transition, oldLease, targetLease string
	var membership []uuid.UUID
	var old, nextPrepared, withdrawal, serving []byte
	var oldExpiry, preparedExpiry, withdrawalExpiry, servingExpiry time.Time
	err := tx.QueryRow(ctx, `SELECT decision_transition,old_lease_identity,target_lease_identity,membership_snapshot,old_serving_envelope,new_prepared_envelope,old_withdrawal_envelope,new_serving_envelope,old_serving_expires_at,new_prepared_expires_at,old_withdrawal_expires_at,new_serving_expires_at FROM pool_vip_ownership_handoff_provenance WHERE operation_id=$1 AND org_id=$2 AND site_id=$3 AND cluster_id=$4 AND pool_id=$5 AND old_node_id=$6 AND new_node_id=$7 AND expected_generation=$8 AND target_generation=$9`, intent.OperationID, intent.Scope.OrgID, intent.Scope.SiteID, intent.Scope.ClusterID, intent.Scope.PoolID, intent.ExpectedActiveID, intent.CandidateID, int64(intent.ExpectedGeneration), int64(intent.TargetGeneration)).Scan(&transition, &oldLease, &targetLease, &membership, &old, &nextPrepared, &withdrawal, &serving, &oldExpiry, &preparedExpiry, &withdrawalExpiry, &servingExpiry)
	if errors.Is(err, pgx.ErrNoRows) {
		return k8s.DurableHandoffPlan{}, false, nil
	}
	if err != nil {
		return k8s.DurableHandoffPlan{}, false, err
	}
	if transition != string(intent.Decision.Transition) || oldLease == "" || targetLease == "" {
		return k8s.DurableHandoffPlan{}, false, nil
	}
	oldEnvelope, okOld := decodePoolVIPOwnershipFreshHandoffEnvelope(old)
	preparedEnvelope, okPrepared := decodePoolVIPOwnershipFreshHandoffEnvelope(nextPrepared)
	withdrawalEnvelope, okWithdrawal := decodePoolVIPOwnershipFreshHandoffEnvelope(withdrawal)
	servingEnvelope, okServing := decodePoolVIPOwnershipFreshHandoffEnvelope(serving)
	if !okOld || !okPrepared || !okWithdrawal || !okServing {
		return k8s.DurableHandoffPlan{}, false, nil
	}
	plan := k8s.DurableHandoffPlan{OldLeaseIdentity: oldLease, TargetLeaseIdentity: targetLease, Plan: k8s.HandoffPlan{OperationID: intent.OperationID, Scope: intent.Scope, ExpectedActiveID: intent.ExpectedActiveID, CandidateID: intent.CandidateID, ExpectedGeneration: intent.ExpectedGeneration, TargetGeneration: intent.TargetGeneration, Decision: intent.Decision,
		OldServing: freshArtifactFromEnvelope(oldEnvelope, oldExpiry, k8s.Serving), NewPrepared: freshArtifactFromEnvelope(preparedEnvelope, preparedExpiry, k8s.PreparedNonServing), OldWithdrawal: freshArtifactFromEnvelope(withdrawalEnvelope, withdrawalExpiry, k8s.PreparedNonServing), NewServing: freshArtifactFromEnvelope(servingEnvelope, servingExpiry, k8s.Serving)}}
	if k8s.ValidateDurableHandoffPlan(plan) != nil || !freshPlanMatchesIntent(plan, intent) {
		return k8s.DurableHandoffPlan{}, false, nil
	}
	if !validPoolVIPOwnershipFreshHandoffMembership(ctx, tx, intent, membership) ||
		!validStoredPoolVIPOwnershipFreshHandoffCapabilities(ctx, tx, plan) ||
		!validStoredPoolVIPOwnershipFreshHandoffServiceUIDs(ctx, tx, plan) {
		return k8s.DurableHandoffPlan{}, false, nil
	}
	return plan, true, nil
}

// decodePoolVIPOwnershipFreshHandoffEnvelope intentionally unmarshals before
// returning the value. Returning `e, json.Unmarshal(...) == nil` evaluates the
// result value before the side effect, which would pair a zero envelope with a
// successful validation and make every restart fail closed downstream.
func decodePoolVIPOwnershipFreshHandoffEnvelope(raw []byte) (PoolVIPOwnershipDeliveryEnvelopeV3, bool) {
	var envelope PoolVIPOwnershipDeliveryEnvelopeV3
	if json.Unmarshal(raw, &envelope) != nil || ValidatePoolVIPOwnershipDeliveryEnvelopeV3(envelope) != nil {
		return PoolVIPOwnershipDeliveryEnvelopeV3{}, false
	}
	return envelope, true
}

// decodeLegacyPoolVIPOwnershipFreshHandoffEnvelopeV2 is compatibility-only.
// It can inspect historical pre-v3 bodies, but no authority interface or
// fresh-plan path calls it.
func decodeLegacyPoolVIPOwnershipFreshHandoffEnvelopeV2(raw []byte) (PoolVIPOwnershipDeliveryEnvelopeV2, bool) {
	var envelope PoolVIPOwnershipDeliveryEnvelopeV2
	if json.Unmarshal(raw, &envelope) != nil || ValidatePoolVIPOwnershipDeliveryEnvelopeV2(envelope) != nil {
		return PoolVIPOwnershipDeliveryEnvelopeV2{}, false
	}
	return envelope, true
}

func validPoolVIPOwnershipFreshHandoffMembership(ctx context.Context, tx pgx.Tx, intent HandoffTickIntent, snapshot []uuid.UUID) bool {
	if len(snapshot) != len(intent.OrderedCandidateIDs) || len(snapshot) < 2 {
		return false
	}
	for i, node := range snapshot {
		if node != intent.OrderedCandidateIDs[i] {
			return false
		}
	}
	plan := k8s.HandoffPlan{Scope: intent.Scope, ExpectedActiveID: intent.ExpectedActiveID, CandidateID: intent.CandidateID, ExpectedGeneration: intent.ExpectedGeneration}
	if !validPoolVIPOwnershipFreshHandoffMembershipSnapshot(ctx, tx, plan, snapshot) {
		return false
	}
	return true
}

func validPoolVIPOwnershipFreshHandoffMembershipSnapshot(ctx context.Context, tx pgx.Tx, plan k8s.HandoffPlan, snapshot []uuid.UUID) bool {
	if len(snapshot) < 2 || len(snapshot) > 512 {
		return false
	}
	seen := make(map[uuid.UUID]struct{}, len(snapshot))
	for _, node := range snapshot {
		if node == uuid.Nil {
			return false
		}
		if _, duplicate := seen[node]; duplicate {
			return false
		}
		seen[node] = struct{}{}
	}
	if _, old := seen[plan.ExpectedActiveID]; !old {
		return false
	}
	if _, candidate := seen[plan.CandidateID]; !candidate {
		return false
	}
	var active uuid.UUID
	var generation int64
	if err := tx.QueryRow(ctx, `SELECT p.active_node_id,p.generation FROM k8s_connector_pools p WHERE p.id=$1 AND p.org_id=$2 AND p.site_id=$3 AND p.cluster_id=$4 FOR SHARE`, plan.Scope.PoolID, plan.Scope.OrgID, plan.Scope.SiteID, plan.Scope.ClusterID).Scan(&active, &generation); err != nil {
		return false
	}
	if active != plan.ExpectedActiveID || generation != int64(plan.ExpectedGeneration) {
		return false
	}
	rows, err := tx.Query(ctx, `SELECT node_id FROM k8s_connector_pool_members WHERE pool_id=$1 AND org_id=$2 AND site_id=$3 ORDER BY admin_priority DESC,node_id FOR SHARE`, plan.Scope.PoolID, plan.Scope.OrgID, plan.Scope.SiteID)
	if err != nil {
		return false
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var node uuid.UUID
		if err := rows.Scan(&node); err != nil || count >= len(snapshot) || node != snapshot[count] {
			return false
		}
		count++
	}
	return rows.Err() == nil && count == len(snapshot)
}

func validStoredPoolVIPOwnershipFreshHandoffCapabilities(ctx context.Context, tx pgx.Tx, plan k8s.DurableHandoffPlan) bool {
	p := plan.Plan
	rows, err := tx.Query(ctx, `SELECT node_id,wire_version,delivery_row_id,receipt_time,expires_at FROM pool_vip_ownership_handoff_provenance_capabilities WHERE operation_id=$1 AND org_id=$2 AND site_id=$3 AND cluster_id=$4 AND pool_id=$5 ORDER BY node_id`, p.OperationID, p.Scope.OrgID, p.Scope.SiteID, p.Scope.ClusterID, p.Scope.PoolID)
	if err != nil {
		return false
	}
	var values []PoolVIPOwnershipFreshHandoffCapability
	for rows.Next() {
		var value PoolVIPOwnershipFreshHandoffCapability
		if err := rows.Scan(&value.NodeID, &value.WireVersion, &value.DeliveryRowID, &value.ReceiptTime, &value.ExpiresAt); err != nil {
			return false
		}
		value.ReceiptTime, value.ExpiresAt = value.ReceiptTime.UTC(), value.ExpiresAt.UTC()
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		return false
	}
	rows.Close()
	for _, value := range values {
		expectedRole := string(k8s.PreparedNonServing)
		if value.NodeID == p.ExpectedActiveID {
			expectedRole = string(k8s.Serving)
		}
		var current int
		if err := tx.QueryRow(ctx, `SELECT 1 FROM pool_vip_ownership_deliveries d JOIN pool_vip_ownership_delivery_ack_receipts a ON a.delivery_row_id=d.id AND a.org_id=d.org_id JOIN nodes n ON n.id=d.target_node_id AND n.org_id=d.org_id AND n.site_id=d.site_id WHERE d.id=$1 AND d.org_id=$2 AND d.site_id=$3 AND d.cluster_id=$4 AND d.pool_id=$5 AND d.connector_node_id=$6 AND d.target_node_id=$6 AND d.wire_version=$9 AND d.promotion_generation=$10 AND d.role=$11 AND n.status='active' AND n.revoked_at IS NULL AND a.receipt_time=$7 AND d.expires_at=$8 AND a.receipt_time >= now()-interval '5 minutes' AND a.receipt_time <= now()+interval '5 seconds' AND d.expires_at > now() AND a.applied_role=d.role AND a.applied_manifest_identity=d.manifest_identity AND a.applied_promotion_generation=d.promotion_generation AND a.applied_manifest_revision=d.manifest_revision AND a.owned_route_digest=d.expected_route_digest AND a.applied_lease_epoch=CASE WHEN d.role='withdrawal' THEN d.prior_lease_epoch ELSE d.lease_epoch END AND ((d.role='serving' AND a.vip_map_digest=d.expected_vip_map_digest) OR (d.role IN ('prepared_non_serving','withdrawal') AND a.vip_map_digest='')) AND a.applied_manifest=d.ownership_manifest AND a.applied_manifest IS NOT NULL AND d.ownership_manifest<>'{}'::jsonb FOR UPDATE OF d,a,n`, value.DeliveryRowID, p.Scope.OrgID, p.Scope.SiteID, p.Scope.ClusterID, p.Scope.PoolID, value.NodeID, value.ReceiptTime, value.ExpiresAt, PoolVIPOwnershipDeliveryHandoffVersion, int64(p.ExpectedGeneration), expectedRole).Scan(&current); err != nil || current != 1 {
			return false
		}
	}
	return validPoolVIPOwnershipFreshHandoffCapabilities(values, plan)
}

func validStoredPoolVIPOwnershipFreshHandoffServiceUIDs(ctx context.Context, tx pgx.Tx, plan k8s.DurableHandoffPlan) bool {
	p := plan.Plan
	rows, err := tx.Query(ctx, `SELECT active_node_id,promotion_generation,namespace,service,service_uid,observation_revision FROM pool_vip_ownership_handoff_provenance_service_uids WHERE operation_id=$1 AND org_id=$2 AND site_id=$3 AND cluster_id=$4 AND pool_id=$5 ORDER BY promotion_generation,namespace,service`, p.OperationID, p.Scope.OrgID, p.Scope.SiteID, p.Scope.ClusterID, p.Scope.PoolID)
	if err != nil {
		return false
	}
	var values []PoolVIPOwnershipFreshHandoffServiceUID
	for rows.Next() {
		var generation, revision int64
		var value PoolVIPOwnershipFreshHandoffServiceUID
		if err := rows.Scan(&value.ActiveNodeID, &generation, &value.Namespace, &value.Service, &value.UID, &revision); err != nil || generation <= 0 || revision <= 0 {
			return false
		}
		value.PromotionGeneration, value.ObservationRevision = uint64(generation), uint64(revision)
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		return false
	}
	rows.Close()
	for _, value := range values {
		var current bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM k8s_service_uid_observation_ledgers l JOIN k8s_service_uid_observation_current c ON c.ledger_id=l.id AND c.org_id=l.org_id JOIN k8s_service_uid_observation_current_attributions a ON a.ledger_id=c.ledger_id AND a.org_id=c.org_id AND a.namespace=c.namespace AND a.service=c.service AND a.replay_sequence=c.replay_sequence JOIN k8s_service_uid_observation_replay_states r ON r.id=a.replay_state_id AND r.org_id=a.org_id AND r.site_id=l.site_id AND r.cluster_id=l.cluster_id WHERE l.org_id=$1 AND l.site_id=$2 AND l.cluster_id=$3 AND r.connector_node_id=$4 AND c.namespace=$5 AND c.service=$6 AND c.uid=$7 AND c.state='live' AND c.replay_sequence=$8)`, p.Scope.OrgID, p.Scope.SiteID, p.Scope.ClusterID, value.ActiveNodeID, value.Namespace, value.Service, value.UID, int64(value.ObservationRevision)).Scan(&current); err != nil || !current {
			return false
		}
	}
	return validPoolVIPOwnershipFreshHandoffServiceUIDs(values, plan)
}

func freshArtifactFromEnvelope(e PoolVIPOwnershipDeliveryEnvelopeV3, expiry time.Time, role k8s.OwnershipRole) k8s.ArtifactPrerequisite {
	org, _ := uuid.Parse(e.OrgID)
	site, _ := uuid.Parse(e.SiteID)
	cluster, _ := uuid.Parse(e.ClusterID)
	pool, _ := uuid.Parse(e.PoolID)
	node, _ := uuid.Parse(e.ConnectorNodeID)
	return k8s.ArtifactPrerequisite{Scope: k8s.OwnershipScope{OrgID: org, SiteID: site, ClusterID: cluster, PoolID: pool, ConnectorID: node}, PromotionGeneration: e.PromotionGeneration, ManifestRevision: e.ManifestRevision, ManifestIdentity: e.ManifestIdentity, ExpectedRouteDigest: e.ExpectedRouteDigest, ExpectedVIPMapDigest: e.ExpectedVIPMapDigest, IdentityValidated: true, Lease: k8s.CPOwnershipLease{Epoch: e.LeaseEpoch, ExpiresAt: expiry.UTC(), CPIssuedValidated: true}, Role: role}
}

// Keep compile-time range validation alongside the schema's bigint checks.
func freshHandoffBigint(value uint64) bool { return value > 0 && value <= uint64(math.MaxInt64) }
