package connectivity

import (
	"context"
	"encoding/json"
	"errors"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

const (
	SessionTTL      = 10 * time.Minute
	MaxMessages     = 64
	MaxPayloadBytes = 16 * 1024
)

var ErrPayload = errors.New("invalid connectivity snapshot")

// Store is an internal transactional mailbox, not an authentication boundary.
// Public callers must construct Principal from authenticated server context.
type Store struct{ pool *pgxpool.Pool }

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

type Mailbox struct {
	Session                       Session
	DevicePayload, GatewayPayload json.RawMessage
}

// Create supersedes the previous generation. Only the canonical device owner
// can create; a gateway cannot nominate an arbitrary device or owner.
func (s *Store) Create(ctx context.Context, p Principal, device uuid.UUID) (out Mailbox, err error) {
	if p.Side != DeviceSide {
		return out, ErrDenied
	}
	err = s.transaction(ctx, p, device, func(q *sqlc.Queries, e sqlc.LockConnectivityEligibilityRow, now time.Time) error {
		id, err := uuid.NewRandom()
		if err != nil {
			return err
		}
		row, err := q.ReplaceConnectivitySession(ctx, sqlc.ReplaceConnectivitySessionParams{
			DeviceID: e.DeviceID, OrgID: e.OrgID, OwnerID: e.OwnerID, GatewayID: e.GatewayID,
			SessionID: id, CreatedAt: now, ExpiresAt: now.Add(SessionTTL),
		})
		if err == nil {
			out = mailbox(row)
		}
		return err
	})
	if err != nil {
		return Mailbox{}, err
	}
	return out, nil
}

func (s *Store) Read(ctx context.Context, p Principal, device, session uuid.UUID, generation uint64) (Mailbox, error) {
	return s.operate(ctx, p, device, session, generation, nil)
}

func (s *Store) Publish(ctx context.Context, p Principal, device, session uuid.UUID, generation, sequence uint64, payload json.RawMessage) (Mailbox, error) {
	// Bound work before a database transaction. Candidate semantic validation is
	// required at the eventual ICE contract layer, not claimed by JSON validation.
	if !validPayload(payload) {
		return Mailbox{}, ErrPayload
	}
	return s.operate(ctx, p, device, session, generation, func(row *sqlc.ConnectivitySession, snap Snapshot, now time.Time) error {
		if sequence > MaxMessages {
			return ErrDenied
		}
		next, err := mailbox(*row).Session.Accept(p, snap, now, sequence)
		if err != nil {
			return err
		}
		row.DeviceSequence, row.GatewaySequence = int64(next.DeviceSequence), int64(next.GatewaySequence)
		if p.Side == DeviceSide {
			row.DevicePayload = payload
		} else {
			row.GatewayPayload = payload
		}
		return nil
	})
}

func (s *Store) Close(ctx context.Context, p Principal, device, session uuid.UUID, generation uint64) error {
	_, err := s.operate(ctx, p, device, session, generation, func(row *sqlc.ConnectivitySession, _ Snapshot, _ time.Time) error {
		row.Revoked = true
		row.DevicePayload, row.GatewayPayload = []byte("{}"), []byte("{}")
		return nil
	})
	return err
}

type change func(*sqlc.ConnectivitySession, Snapshot, time.Time) error

func (s *Store) operate(ctx context.Context, p Principal, device, session uuid.UUID, generation uint64, mutate change) (out Mailbox, err error) {
	if session == uuid.Nil || generation == 0 {
		return out, ErrDenied
	}
	err = s.transaction(ctx, p, device, func(q *sqlc.Queries, e sqlc.LockConnectivityEligibilityRow, now time.Time) error {
		row, err := q.GetConnectivitySession(ctx, sqlc.GetConnectivitySessionParams{OrgID: p.OrgID, DeviceID: device})
		if err != nil {
			return err
		}
		// A separate administrative writer can hold the mailbox lock. Evaluate
		// expiry after that wait, never at transaction start or before the lock.
		now, err = q.ConnectivityWallClock(ctx)
		if err != nil {
			return err
		}
		if row.SessionID != session || uint64(row.Generation) != generation {
			return ErrDenied
		}
		snap := Snapshot{
			Current: Binding{session, e.OrgID, e.OwnerID, e.DeviceID, e.GatewayID, generation},
			OptedIn: true, OwnerActiveMember: true, DeviceEligible: true, GatewayEligible: true,
		}
		if err := mailbox(row).Session.Authorize(p, snap, now); err != nil {
			return err
		}
		if mutate != nil {
			if err := mutate(&row, snap, now); err != nil {
				return err
			}
			row, err = q.SaveConnectivitySnapshot(ctx, sqlc.SaveConnectivitySnapshotParams{
				OrgID: row.OrgID, DeviceID: row.DeviceID, SessionID: row.SessionID, Generation: row.Generation,
				DeviceSequence: row.DeviceSequence, GatewaySequence: row.GatewaySequence,
				DevicePayload: row.DevicePayload, GatewayPayload: row.GatewayPayload, Revoked: row.Revoked,
			})
			if err != nil {
				return err
			}
		}
		out = mailbox(row)
		return nil
	})
	if err != nil {
		return Mailbox{}, err
	}
	return out, nil
}

func (s *Store) transaction(ctx context.Context, p Principal, device uuid.UUID, fn func(*sqlc.Queries, sqlc.LockConnectivityEligibilityRow, time.Time) error) error {
	if s == nil || s.pool == nil || p.OrgID == uuid.Nil || p.SubjectID == uuid.Nil || device == uuid.Nil || (p.Side != DeviceSide && p.Side != GatewaySide) {
		return ErrDenied
	}
	// Bound lock waits even if the caller forgot its own request deadline.
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := sqlc.New(tx)
	e, err := q.LockConnectivityEligibility(ctx, sqlc.LockConnectivityEligibilityParams{DeviceID: device, OrgID: p.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrDenied
	}
	if err != nil {
		return err
	}
	if (p.Side == DeviceSide && p.SubjectID != e.OwnerID) || (p.Side == GatewaySide && p.SubjectID != e.GatewayID) {
		return ErrDenied
	}
	now, err := q.ConnectivityWallClock(ctx)
	if err != nil {
		return err
	}
	if err = fn(q, e, now); errors.Is(err, pgx.ErrNoRows) {
		return ErrDenied
	}
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func mailbox(row sqlc.ConnectivitySession) Mailbox {
	return Mailbox{Session: Session{
		Binding:   Binding{row.SessionID, row.OrgID, row.OwnerID, row.DeviceID, row.GatewayID, uint64(row.Generation)},
		CreatedAt: row.CreatedAt, ExpiresAt: row.ExpiresAt, Revoked: row.Revoked,
		DeviceSequence: uint64(row.DeviceSequence), GatewaySequence: uint64(row.GatewaySequence),
	}, DevicePayload: row.DevicePayload, GatewayPayload: row.GatewayPayload}
}

func validPayload(raw json.RawMessage) bool {
	if len(raw) == 0 || len(raw) > MaxPayloadBytes || !utf8.Valid(raw) {
		return false
	}
	var object map[string]json.RawMessage
	return json.Unmarshal(raw, &object) == nil && object != nil
}
