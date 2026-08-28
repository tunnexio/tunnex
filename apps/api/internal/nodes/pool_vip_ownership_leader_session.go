package nodes

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PoolVIPOwnershipHandoffLeadershipEpoch is deliberately local to P2. A later
// P1 coordinator can mechanically convert its durable leadership epoch to this
// backend-session proof without importing scheduler or operation types here.
type PoolVIPOwnershipHandoffLeadershipEpoch struct {
	BackendPID      int32
	AdvisoryLockKey int64
}

// PoolVIPOwnershipHandoffLeaderSession binds one acquired PostgreSQL session to
// the epoch that granted its advisory leadership lock. Conn is never replaced
// by the general pool while an issue transaction is in flight.
type PoolVIPOwnershipHandoffLeaderSession struct {
	Epoch PoolVIPOwnershipHandoffLeadershipEpoch
	Conn  *pgxpool.Conn
}

var ErrPoolVIPOwnershipHandoffLeaderSession = errors.New("ownership handoff leader session is invalid")

// IssuePoolVIPOwnershipHandoffDeliveryV2LeaderBound is the only handoff issue
// path. It verifies backend PID and advisory-lock ownership on the supplied
// connection before and immediately before the write transaction. The existing
// unbound v2 writer remains available only to non-handoff callers.
func (s *PostgresPoolVIPOwnershipDeliveryStore) IssuePoolVIPOwnershipHandoffDeliveryV2LeaderBound(ctx context.Context, session PoolVIPOwnershipHandoffLeaderSession, envelope PoolVIPOwnershipDeliveryEnvelopeV2, expiresAt time.Time) error {
	if s == nil || s.pool == nil {
		return fmt.Errorf("ownership delivery store is not configured")
	}
	if err := validPoolVIPOwnershipHandoffLeaderSession(ctx, session); err != nil {
		return err
	}
	input, err := preparePoolVIPOwnershipDeliveryV2Issue(envelope, expiresAt)
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
	if s.leaderBoundPreWriteHook != nil {
		if err := s.leaderBoundPreWriteHook(ctx, session.Conn); err != nil {
			return err
		}
	}
	if err := validPoolVIPOwnershipHandoffLeaderSessionTx(ctx, tx, session.Epoch); err != nil {
		return err
	}
	return issuePoolVIPOwnershipDeliveryV2Tx(ctx, tx, input, true)
}

// IssuePoolVIPOwnershipHandoffDeliveryV3LeaderBound is the only authoritative
// handoff issue path. The CP expiry is part of the envelope and is revalidated
// on the same advisory-lock session immediately before the durable insert.
func (s *PostgresPoolVIPOwnershipDeliveryStore) IssuePoolVIPOwnershipHandoffDeliveryV3LeaderBound(ctx context.Context, session PoolVIPOwnershipHandoffLeaderSession, envelope PoolVIPOwnershipDeliveryEnvelopeV3) error {
	if s == nil || s.pool == nil {
		return fmt.Errorf("ownership delivery store is not configured")
	}
	if err := validPoolVIPOwnershipHandoffLeaderSession(ctx, session); err != nil {
		return err
	}
	input, err := preparePoolVIPOwnershipDeliveryV3Issue(envelope)
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
	if s.leaderBoundPreWriteHook != nil {
		if err := s.leaderBoundPreWriteHook(ctx, session.Conn); err != nil {
			return err
		}
	}
	if err := validPoolVIPOwnershipHandoffLeaderSessionTx(ctx, tx, session.Epoch); err != nil {
		return err
	}
	return issuePoolVIPOwnershipDeliveryV3Tx(ctx, tx, input)
}

func validPoolVIPOwnershipHandoffLeaderSession(ctx context.Context, session PoolVIPOwnershipHandoffLeaderSession) error {
	if session.Conn == nil || session.Epoch.BackendPID <= 0 || session.Epoch.AdvisoryLockKey == 0 {
		return ErrPoolVIPOwnershipHandoffLeaderSession
	}
	var pid int32
	var granted bool
	if err := session.Conn.QueryRow(ctx, poolVIPOwnershipHandoffLeaderSessionSQL, advisoryLockClassID(session.Epoch.AdvisoryLockKey), advisoryLockObjectID(session.Epoch.AdvisoryLockKey)).Scan(&pid, &granted); err != nil {
		return fmt.Errorf("%w: verify backend session: %v", ErrPoolVIPOwnershipHandoffLeaderSession, err)
	}
	if pid != session.Epoch.BackendPID || !granted {
		return ErrPoolVIPOwnershipHandoffLeaderSession
	}
	return nil
}

func validPoolVIPOwnershipHandoffLeaderSessionTx(ctx context.Context, tx pgx.Tx, epoch PoolVIPOwnershipHandoffLeadershipEpoch) error {
	if epoch.BackendPID <= 0 || epoch.AdvisoryLockKey == 0 {
		return ErrPoolVIPOwnershipHandoffLeaderSession
	}
	var pid int32
	var granted bool
	if err := tx.QueryRow(ctx, poolVIPOwnershipHandoffLeaderSessionSQL, advisoryLockClassID(epoch.AdvisoryLockKey), advisoryLockObjectID(epoch.AdvisoryLockKey)).Scan(&pid, &granted); err != nil {
		return fmt.Errorf("%w: verify transaction session: %v", ErrPoolVIPOwnershipHandoffLeaderSession, err)
	}
	if pid != epoch.BackendPID || !granted {
		return ErrPoolVIPOwnershipHandoffLeaderSession
	}
	return nil
}

const poolVIPOwnershipHandoffLeaderSessionSQL = `
	SELECT pg_backend_pid(), EXISTS (
		SELECT 1 FROM pg_locks
		WHERE locktype='advisory' AND pid=pg_backend_pid() AND granted
		  AND classid=$1::oid AND objid=$2::oid AND objsubid=1
	)`

func advisoryLockClassID(key int64) uint32  { return uint32(uint64(key) >> 32) }
func advisoryLockObjectID(key int64) uint32 { return uint32(uint64(key)) }

// PoolVIPOwnershipHandoffAppliedAttestationRead is an exact P2-local read
// projection. It preserves validated stored v2 applied evidence, CP receipt,
// and issued expiry without exposing route addresses, delivery nonce, or a
// latest-by-node search surface.
type PoolVIPOwnershipHandoffAppliedAttestationRead struct {
	WireVersion                int
	AppliedRole                string
	AppliedManifestIdentity    string
	AppliedPromotionGeneration uint64
	AppliedManifestRevision    uint64
	AppliedLeaseEpoch          uint64
	ReceiptTime                time.Time
	ExpiresAt                  time.Time
	OwnedRouteDigest           string
	VIPMapDigest               string
}

// ReadPoolVIPOwnershipHandoffAppliedAttestation reads one exact artifact only.
// It projects only the coherent, validated v2 row returned by the generic
// reader. The applied fields always come from the stored acknowledgement, not
// from the requested artifact or issued envelope.
func (s *PostgresPoolVIPOwnershipDeliveryStore) ReadPoolVIPOwnershipHandoffAppliedAttestation(ctx context.Context, artifact PoolVIPOwnershipHandoffArtifact) (PoolVIPOwnershipHandoffAppliedAttestationRead, bool, error) {
	if s == nil || s.pool == nil {
		return PoolVIPOwnershipHandoffAppliedAttestationRead{}, false, fmt.Errorf("ownership delivery store is not configured")
	}
	if err := validPoolVIPOwnershipHandoffArtifact(artifact); err != nil {
		return PoolVIPOwnershipHandoffAppliedAttestationRead{}, false, err
	}
	attestation, found, err := s.LoadPoolVIPOwnershipAppliedAttestation(ctx, poolVIPOwnershipHandoffAttestationScope(artifact))
	if err != nil || !found {
		return PoolVIPOwnershipHandoffAppliedAttestationRead{}, found, err
	}
	return PoolVIPOwnershipHandoffAppliedAttestationRead{
		WireVersion:                attestation.Envelope.Version,
		AppliedRole:                attestation.Ack.AppliedRole,
		AppliedManifestIdentity:    attestation.Ack.AppliedManifestIdentity,
		AppliedPromotionGeneration: attestation.Ack.AppliedPromotionGeneration,
		AppliedManifestRevision:    attestation.Ack.AppliedManifestRevision,
		AppliedLeaseEpoch:          attestation.Ack.AppliedLeaseEpoch,
		ReceiptTime:                attestation.ReceiptTime.UTC(),
		ExpiresAt:                  attestation.ExpiresAt.UTC(),
		OwnedRouteDigest:           attestation.Ack.OwnedRouteDigest,
		VIPMapDigest:               attestation.Ack.VIPMapDigest,
	}, true, nil
}
