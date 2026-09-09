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
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
)

const (
	SessionTTL      = 10 * time.Minute
	MaxMessages     = 64
	MaxPayloadBytes = 16 * 1024
)

var ErrPayload = errors.New("invalid connectivity snapshot")
var ErrGatewayChanged = errors.New("connectivity gateway changed")

// Store is an internal transactional mailbox, not an authentication boundary.
// Public callers must construct Principal from authenticated server context.
type Store struct {
	pool   *pgxpool.Pool
	sealer *crypto.Sealer
	limits IssuanceLimits
}

func NewStore(pool *pgxpool.Pool, sealers ...*crypto.Sealer) *Store {
	s := &Store{pool: pool, limits: DefaultIssuanceLimits()}
	if len(sealers) > 0 {
		s.sealer = sealers[0]
	}
	return s
}

type Mailbox struct {
	DevicePublicKey               string
	GatewayPublicKey              string
	Relay                         *RelayAccess
	principal                     Principal
	Session                       Session
	DevicePayload, GatewayPayload json.RawMessage
}

// Create supersedes the previous generation. Only the canonical device owner
// can create; a gateway cannot nominate an arbitrary device or owner.
func (s *Store) Create(ctx context.Context, p Principal, device uuid.UUID) (out Mailbox, err error) {
	if p.Side != DeviceSide {
		return out, ErrDenied
	}
	err = s.transaction(ctx, p, device, false, func(ctx context.Context, q *sqlc.Queries, e sqlc.LockConnectivityEligibilityRow, now time.Time) error {
		id, err := uuid.NewRandom()
		if err != nil {
			return err
		}
		now, err = s.reserveIssuance(ctx, q, Binding{SessionID: id, OrgID: e.OrgID, OwnerID: e.OwnerID, DeviceID: e.DeviceID}, DeviceSide, now)
		if err != nil {
			return err
		}
		row, err := q.ReplaceConnectivitySession(ctx, sqlc.ReplaceConnectivitySessionParams{
			DeviceID: e.DeviceID, OrgID: e.OrgID, OwnerID: e.OwnerID, GatewayID: e.GatewayID,
			SessionID: id, CreatedAt: now, ExpiresAt: now.Add(SessionTTL),
		})
		if err == nil {
			out = mailbox(row)
			out.DevicePublicKey, out.GatewayPublicKey = e.DevicePublicKey, e.GatewayPublicKey
			out.principal = p
			err = s.relayAccess(ctx, q, &out, now)
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
	err = s.transaction(ctx, p, device, mutate == nil, func(ctx context.Context, q *sqlc.Queries, e sqlc.LockConnectivityEligibilityRow, now time.Time) error {
		var row sqlc.ConnectivitySession
		var err error
		if mutate == nil {
			row, err = q.ShareConnectivitySession(ctx, sqlc.ShareConnectivitySessionParams{OrgID: p.OrgID, DeviceID: device})
		} else {
			row, err = q.GetConnectivitySession(ctx, sqlc.GetConnectivitySessionParams{OrgID: p.OrgID, DeviceID: device})
		}
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
		// A transfer must never expose recovery for the previous owner's session.
		// Check immutable ownership before classifying a gateway-only change.
		if row.OrgID != e.OrgID || row.DeviceID != e.DeviceID || row.OwnerID != e.OwnerID {
			return ErrDenied
		}
		// Only an otherwise eligible owner may learn that its live session's
		// gateway moved. Revoked/expired sessions and gateway callers still deny.
		if p.Side == DeviceSide && !row.Revoked && row.ExpiresAt.After(now) && row.GatewayID != e.GatewayID {
			return ErrGatewayChanged
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
		out.DevicePublicKey, out.GatewayPublicKey = e.DevicePublicKey, e.GatewayPublicKey
		out.principal = p
		if !row.Revoked {
			return s.relayAccess(ctx, q, &out, now)
		}
		return nil
	})
	if err != nil {
		return Mailbox{}, err
	}
	return out, nil
}

func (s *Store) transaction(ctx context.Context, p Principal, device uuid.UUID, shared bool, fn func(context.Context, *sqlc.Queries, sqlc.LockConnectivityEligibilityRow, time.Time) error) error {
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
	var e sqlc.LockConnectivityEligibilityRow
	if shared {
		row, readErr := q.ShareConnectivityEligibility(ctx, sqlc.ShareConnectivityEligibilityParams{DeviceID: device, OrgID: p.OrgID})
		e, err = sqlc.LockConnectivityEligibilityRow(row), readErr
	} else {
		e, err = q.LockConnectivityEligibility(ctx, sqlc.LockConnectivityEligibilityParams{DeviceID: device, OrgID: p.OrgID})
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrDenied
	}
	if err != nil {
		return err
	}
	if p.Side == DeviceSide && p.SubjectID != e.OwnerID {
		return ErrDenied
	}
	// Hold promotion, binding and key/status inputs stable across the canonical
	// selection and the session operation. Never elect independently in SQL.
	if _, err = q.ShareConnectivityHubSet(ctx, p.OrgID); err != nil {
		return err
	}
	if _, err = q.ShareConnectivityTopologyNodes(ctx, p.OrgID); err != nil {
		return err
	}
	if _, err = q.ShareConnectivityTopologySites(ctx, p.OrgID); err != nil {
		return err
	}
	now, err := q.ConnectivityWallClock(ctx)
	if err != nil {
		return err
	}
	effective, key, derived, err := nodes.EffectiveConnectivityGateway(ctx, q, p.OrgID, e.GatewayID, now)
	if err != nil {
		return err
	}
	if derived {
		e.GatewayID, e.GatewayPublicKey = effective, key
	}
	if p.Side == GatewaySide && p.SubjectID != e.GatewayID {
		return ErrDenied
	}
	if err = fn(ctx, q, e, now); errors.Is(err, pgx.ErrNoRows) {
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
