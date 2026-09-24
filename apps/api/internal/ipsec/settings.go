package ipsec

import (
	"context"
	"encoding/json"
	"errors"
	"math"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrSettingsUnavailable    = errors.New("IPsec settings unavailable")
	ErrSettingsOrgUnavailable = errors.New("IPsec organization unavailable")
	ErrSettingsConflict       = errors.New("IPsec settings revision changed")
	ErrSettingsInvalid        = errors.New("IPsec settings revision invalid")
)

// Settings describes organization opt-in, not gateway readiness or connectivity.
// Revision zero is the implicit, unwritten default.
type Settings struct {
	Enabled  bool  `json:"enabled"`
	Revision int64 `json:"revision"`
}

type SettingsStore struct{ pool *pgxpool.Pool }

func NewSettingsStore(pool *pgxpool.Pool) *SettingsStore { return &SettingsStore{pool: pool} }

// Read does not materialize the default or mutate the organization. One query
// supplies a consistent live-organization/settings snapshot.
func (s *SettingsStore) Read(ctx context.Context, orgID uuid.UUID) (Settings, error) {
	if s == nil || s.pool == nil {
		return Settings{}, ErrSettingsUnavailable
	}
	var result Settings
	err := s.pool.QueryRow(ctx, `SELECT coalesce(s.enabled,false),coalesce(s.revision,0)
 FROM organizations o LEFT JOIN ipsec_org_settings s ON s.org_id=o.id
 WHERE o.id=$1 AND o.deleted_at IS NULL`, orgID).Scan(&result.Enabled, &result.Revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return Settings{}, ErrSettingsOrgUnavailable
	}
	if err != nil {
		return Settings{}, ErrSettingsUnavailable
	}
	return result, nil
}

// Configure requires a caller already authorized for ipsec:manage with a verified
// human principal. orgID must be the authorized scope and actorID the verified
// principal identity; neither may come from the request body.
// Every accepted request advances the revision, including an unchanged value.
func (s *SettingsStore) Configure(ctx context.Context, orgID, actorID uuid.UUID, enabled bool, expectedRevision int64) (Settings, error) {
	if expectedRevision < 0 || expectedRevision == math.MaxInt64 {
		return Settings{}, ErrSettingsInvalid
	}
	if s == nil || s.pool == nil {
		return Settings{}, ErrSettingsUnavailable
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Settings{}, ErrSettingsUnavailable
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	// Lock the organization before even looking for the optional setting. This
	// serializes first writes and closes concurrent soft-deletion races.
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, orgID.String()); err != nil {
		return Settings{}, ErrSettingsUnavailable
	}
	var locked uuid.UUID
	err = tx.QueryRow(ctx, `SELECT id FROM organizations WHERE id=$1 AND deleted_at IS NULL FOR UPDATE`, orgID).Scan(&locked)
	if errors.Is(err, pgx.ErrNoRows) {
		return Settings{}, ErrSettingsOrgUnavailable
	}
	if err != nil {
		return Settings{}, ErrSettingsUnavailable
	}
	var current Settings
	err = tx.QueryRow(ctx, `SELECT enabled,revision FROM ipsec_org_settings WHERE org_id=$1 FOR UPDATE`, orgID).Scan(&current.Enabled, &current.Revision)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return Settings{}, ErrSettingsUnavailable
	}
	if current.Revision != expectedRevision {
		return Settings{}, ErrSettingsConflict
	}
	if !enabled {
		var blocked bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM ipsec_connections WHERE org_id=$1 AND desired_intent='enabled') OR EXISTS(SELECT 1 FROM ipsec_runtime_state WHERE org_id=$1 AND current_cleanup_id IS NOT NULL) OR EXISTS(SELECT 1 FROM ipsec_retained_guards WHERE org_id=$1)`, orgID).Scan(&blocked); err != nil {
			return Settings{}, ErrSettingsUnavailable
		}
		if blocked {
			return Settings{}, ErrSettingsConflict
		}
	}
	result := Settings{Enabled: enabled, Revision: expectedRevision + 1}
	// Schema 158 permits only disabled or finalized-deleted connections: opt-out
	// cannot abandon delivered state. An enabled lifecycle requires a cleanup gate
	// here before its schema constraint is broadened.
	if current.Revision == 0 {
		_, err = tx.Exec(ctx, `INSERT INTO ipsec_org_settings(org_id,enabled,revision) VALUES($1,$2,1)`, orgID, enabled)
	} else {
		_, err = tx.Exec(ctx, `UPDATE ipsec_org_settings SET enabled=$2,revision=$3 WHERE org_id=$1`, orgID, enabled, result.Revision)
	}
	if err != nil {
		return Settings{}, ErrSettingsUnavailable
	}
	metadata, _ := json.Marshal(struct {
		Enabled          bool  `json:"enabled"`
		Revision         int64 `json:"revision"`
		PreviousEnabled  bool  `json:"previous_enabled"`
		PreviousRevision int64 `json:"previous_revision"`
	}{enabled, result.Revision, current.Enabled, current.Revision})
	_, err = tx.Exec(ctx, `INSERT INTO audit_logs(org_id,actor_user_id,action,target_type,target_id,metadata)
 VALUES($1,$2,'ipsec.settings_changed','organization',$3,$4)`, orgID, actorID, orgID.String(), metadata)
	if err != nil {
		return Settings{}, ErrSettingsUnavailable
	}
	if err = tx.Commit(ctx); err != nil {
		return Settings{}, ErrSettingsUnavailable
	}
	return result, nil
}
