package workflowprovenance

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

var (
	ErrInvalidKey           = errors.New("workflow provenance signing key is invalid")
	ErrKeyAlreadyRegistered = errors.New("workflow provenance signing key ID is already registered")
)

type Outcome struct {
	ID, AssertionID uuid.UUID
	State, Reason   string
}

// Record is the safe read projection for an immutable assertion receipt. Chain
// is populated only after cryptographic verification; callers must never infer
// a workflow or initiating subject from an unverified receipt.
type Record struct {
	ID, AssertionID      uuid.UUID
	KeyID, State, Reason string
	ReceivedAt           time.Time
	Chain                *Claims
}

type Service struct {
	pool *pgxpool.Pool
	q    *sqlc.Queries
	now  func() time.Time
}

func New(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool, q: sqlc.New(pool), now: time.Now}
}

// RegisterKey adds one public verification key to its current managed agent.
// A key ID cannot be silently replaced: repeat registration is idempotent only
// when the exact same public half is supplied.
func (s *Service) RegisterKey(ctx context.Context, orgID, deviceID uuid.UUID, keyID string, publicKey ed25519.PublicKey) error {
	if s == nil || s.q == nil || orgID == uuid.Nil || deviceID == uuid.Nil || !bounded(keyID, 128) || len(publicKey) != ed25519.PublicKeySize {
		return ErrInvalidKey
	}
	current, err := s.q.GetAgentWorkflowSigningKey(ctx, sqlc.GetAgentWorkflowSigningKeyParams{OrgID: orgID, DeviceID: deviceID, KeyID: keyID})
	if err == nil {
		if current.State == "active" && bytes.Equal(current.PublicKey, publicKey) {
			return nil
		}
		return ErrKeyAlreadyRegistered
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	created, err := s.q.CreateAgentWorkflowSigningKey(ctx, sqlc.CreateAgentWorkflowSigningKeyParams{OrgID: orgID, DeviceID: deviceID, KeyID: keyID, PublicKey: publicKey})
	if err == nil {
		if created.State == "active" && bytes.Equal(created.PublicKey, publicKey) {
			return nil
		}
		return ErrKeyAlreadyRegistered
	}
	// A concurrent registration wins the unique constraint. Re-read to retain
	// the same no-replacement rule rather than treating the race as success.
	current, readErr := s.q.GetAgentWorkflowSigningKey(ctx, sqlc.GetAgentWorkflowSigningKeyParams{OrgID: orgID, DeviceID: deviceID, KeyID: keyID})
	if readErr == nil && current.State == "active" && bytes.Equal(current.PublicKey, publicKey) {
		return nil
	}
	if readErr == nil {
		return ErrKeyAlreadyRegistered
	}
	return err
}

// Report persists every received assertion as immutable evidence. Only a
// first-use, correctly signed assertion becomes verified; failures retain no
// inferred initiator or workflow meaning outside the signed fields themselves.
func (s *Service) Report(ctx context.Context, orgID, deviceID uuid.UUID, assertion Assertion) (Outcome, error) {
	if s == nil || s.q == nil || s.pool == nil || orgID == uuid.Nil || deviceID == uuid.Nil {
		return Outcome{}, ErrMalformed
	}
	claims := assertion.Claims
	if _, err := CanonicalBytes(assertion.Version, claims); err != nil {
		return s.record(ctx, orgID, deviceID, assertion, "unverified", "malformed")
	}
	key, err := s.q.GetAgentWorkflowSigningKey(ctx, sqlc.GetAgentWorkflowSigningKeyParams{OrgID: orgID, DeviceID: deviceID, KeyID: claims.KeyID})
	if errors.Is(err, pgx.ErrNoRows) {
		return s.record(ctx, orgID, deviceID, assertion, "unverified", "unknown_key")
	}
	if err != nil {
		return Outcome{}, err
	}
	if key.State != "active" {
		return s.record(ctx, orgID, deviceID, assertion, "unverified", "revoked_key")
	}
	if err := Verify(ed25519.PublicKey(key.PublicKey), assertion, s.now()); err != nil {
		return s.record(ctx, orgID, deviceID, assertion, "unverified", reasonFor(err))
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Outcome{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.q.WithTx(tx)
	_, err = q.ClaimAgentWorkflowAssertion(ctx, sqlc.ClaimAgentWorkflowAssertionParams{DeviceID: deviceID, AssertionID: claims.AssertionID})
	if errors.Is(err, pgx.ErrNoRows) {
		if err := tx.Commit(ctx); err != nil {
			return Outcome{}, err
		}
		return s.record(ctx, orgID, deviceID, assertion, "unverified", "replay")
	}
	if err != nil {
		return Outcome{}, err
	}
	row, err := q.CreateAgentWorkflowProvenance(ctx, provenanceParams(orgID, deviceID, assertion, "verified", "verified"))
	if err != nil {
		return Outcome{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Outcome{}, err
	}
	return Outcome{ID: row.ID, AssertionID: row.AssertionID, State: row.VerificationState, Reason: row.VerificationReason}, nil
}

func (s *Service) List(ctx context.Context, orgID, deviceID uuid.UUID) ([]Record, error) {
	if s == nil || s.q == nil || orgID == uuid.Nil || deviceID == uuid.Nil {
		return nil, ErrMalformed
	}
	rows, err := s.q.ListAgentWorkflowProvenance(ctx, sqlc.ListAgentWorkflowProvenanceParams{OrgID: orgID, DeviceID: deviceID, PageSize: 50})
	if err != nil {
		return nil, err
	}
	out := make([]Record, 0, len(rows))
	for _, row := range rows {
		record := Record{ID: row.ID, AssertionID: row.AssertionID, KeyID: row.KeyID, State: row.VerificationState, Reason: row.VerificationReason, ReceivedAt: row.ReceivedAt}
		if row.VerificationState == "verified" && row.VerificationReason == "verified" && row.WorkflowID != nil && row.RunID != nil && row.TriggerKind != nil && row.InitiatingSubjectRef != nil && row.Tool != nil && row.Resource != nil && row.IssuedAt.Valid && row.ExpiresAt.Valid {
			record.Chain = &Claims{AssertionID: row.AssertionID, WorkflowID: *row.WorkflowID, RunID: *row.RunID, TriggerKind: *row.TriggerKind, InitiatingSubjectRef: *row.InitiatingSubjectRef, Tool: *row.Tool, Resource: *row.Resource, IssuedAt: row.IssuedAt.Time, ExpiresAt: row.ExpiresAt.Time, KeyID: row.KeyID}
		}
		out = append(out, record)
	}
	return out, nil
}

func (s *Service) record(ctx context.Context, orgID, deviceID uuid.UUID, assertion Assertion, state, reason string) (Outcome, error) {
	row, err := s.q.CreateAgentWorkflowProvenance(ctx, provenanceParams(orgID, deviceID, assertion, state, reason))
	if err != nil {
		return Outcome{}, err
	}
	return Outcome{ID: row.ID, AssertionID: row.AssertionID, State: row.VerificationState, Reason: row.VerificationReason}, nil
}

func provenanceParams(orgID, deviceID uuid.UUID, assertion Assertion, state, reason string) sqlc.CreateAgentWorkflowProvenanceParams {
	c := normalizeClaims(assertion.Claims)
	value := func(s string) *string {
		s = strings.TrimSpace(s)
		if s == "" {
			return nil
		}
		return &s
	}
	timestamp := func(t time.Time) pgtype.Timestamptz {
		if t.IsZero() {
			return pgtype.Timestamptz{}
		}
		return pgtype.Timestamptz{Time: t, Valid: true}
	}
	return sqlc.CreateAgentWorkflowProvenanceParams{ID: uuid.New(), OrgID: orgID, DeviceID: deviceID, AssertionID: c.AssertionID, KeyID: strings.TrimSpace(c.KeyID), WorkflowID: value(c.WorkflowID), RunID: value(c.RunID), TriggerKind: value(c.TriggerKind), InitiatingSubjectRef: value(c.InitiatingSubjectRef), Tool: value(c.Tool), Resource: value(c.Resource), IssuedAt: timestamp(c.IssuedAt), ExpiresAt: timestamp(c.ExpiresAt), Signature: value(assertion.Signature), VerificationState: state, VerificationReason: reason}
}

func reasonFor(err error) string {
	switch {
	case errors.Is(err, ErrExpired):
		return "expired"
	case errors.Is(err, ErrNotYetValid):
		return "not_yet_valid"
	case errors.Is(err, ErrLifetimeExceeded):
		return "lifetime_exceeded"
	case errors.Is(err, ErrBadSignature):
		return "bad_signature"
	default:
		return "malformed"
	}
}
