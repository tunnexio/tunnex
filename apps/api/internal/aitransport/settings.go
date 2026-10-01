// Package aitransport owns the deployment-wide opt-in for AI over HTTP.
package aitransport

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

type Settings struct {
	AllowHTTP bool
	Revision  int64
}

type Service struct{ pool *pgxpool.Pool }

func New(pool *pgxpool.Pool) *Service { return &Service{pool: pool} }

// Reads are deliberately uncached: disabling HTTP applies to subsequent
// requests across all replicas, without an API or engine restart.
func (s *Service) Get(ctx context.Context) (Settings, error) {
	var v Settings
	err := s.pool.QueryRow(ctx, `SELECT allow_http, revision FROM server_ai_transport_settings WHERE singleton`).Scan(&v.AllowHTTP, &v.Revision)
	return v, err
}

func (s *Service) Save(ctx context.Context, actor uuid.UUID, in Settings) (Settings, error) {
	if in.Revision < 1 {
		return Settings{}, apierr.BadRequest("ai_transport_settings_invalid", "Reload AI transport settings before saving.")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Settings{}, err
	}
	defer tx.Rollback(ctx)
	var out Settings
	err = tx.QueryRow(ctx, `UPDATE server_ai_transport_settings SET allow_http=$1, revision=revision+1 WHERE singleton AND revision=$2 RETURNING allow_http, revision`, in.AllowHTTP, in.Revision).Scan(&out.AllowHTTP, &out.Revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return Settings{}, apierr.Conflict("ai_transport_settings_changed", "AI transport settings changed. Reload them before saving.")
	}
	if err != nil {
		return Settings{}, err
	}
	metadata, err := json.Marshal(map[string]any{"allow_http": out.AllowHTTP, "revision": out.Revision})
	if err != nil {
		return Settings{}, err
	}
	targetType, targetID := "server_ai_transport_settings", "deployment"
	_, err = sqlc.New(tx).InsertAuditLog(ctx, sqlc.InsertAuditLogParams{
		ActorUserID: pgtype.UUID{Bytes: actor, Valid: true}, Action: "server.ai_transport_settings_updated",
		TargetType: &targetType, TargetID: &targetID, Metadata: metadata,
	})
	if err != nil {
		return Settings{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return Settings{}, err
	}
	return out, nil
}
