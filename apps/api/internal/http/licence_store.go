package http

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/licence"
)

// licenceStore is the licence's durable home in system_settings.
//
// ⚠ IT LIVES HERE, NOT IN `licence`, SO THAT PACKAGE KEEPS ITS NO-NETWORK, NO-DATABASE SHAPE — the
// offline promise S12.2 made is about the package, and a sqlc import would blur it.
type licenceStore struct{ q *sqlc.Queries }

// NewLicenceStore adapts the pool to licence.Store.
func NewLicenceStore(pool *pgxpool.Pool) licence.Store { return licenceStore{q: sqlc.New(pool)} }

// Get returns the stored key, or "" when none is installed.
//
// ⛔ pgx.ErrNoRows IS NOT AN ERROR HERE, AND CONFLATING THEM WOULD INVERT THE WHOLE DESIGN. "no row" means
// the customer has no licence — a healthy, supported state that must read as Community. A real error means
// we could not find out, and the manager keeps its last good verdict rather than downgrading anyone.
func (s licenceStore) Get(ctx context.Context) (string, error) {
	v, err := s.q.GetSystemSetting(ctx, licence.SettingKey)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return v, nil
}

func (s licenceStore) Put(ctx context.Context, wire string) error {
	return s.q.UpsertSystemSetting(ctx, sqlc.UpsertSystemSettingParams{Key: licence.SettingKey, Value: wire})
}
