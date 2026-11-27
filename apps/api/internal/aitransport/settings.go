// Package aitransport owns the deployment-wide policy for AI over HTTP:
// one switch for HTTP inside the VPN and one for public HTTP.
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

// Settings holds two independent switches. AllowVPNHTTP covers only HTTP
// inside the WireGuard VPN: the gateway relay route and the member VPN
// endpoint it advertises. AllowHTTP covers only plaintext HTTP on public AI
// paths, which carry provider keys and workload tokens. Neither implies the
// other, and HTTPS is gated by neither.
type Settings struct {
	AllowHTTP    bool
	AllowVPNHTTP bool
	Revision     int64
}

type Service struct{ pool *pgxpool.Pool }

func New(pool *pgxpool.Pool) *Service { return &Service{pool: pool} }

// Reads are deliberately uncached: disabling HTTP applies to subsequent
// requests across all replicas, without an API or engine restart.
func (s *Service) Get(ctx context.Context) (Settings, error) {
	var v Settings
	err := s.pool.QueryRow(ctx, `SELECT allow_http, allow_vpn_http, revision FROM server_ai_transport_settings WHERE singleton`).Scan(&v.AllowHTTP, &v.AllowVPNHTTP, &v.Revision)
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
	err = tx.QueryRow(ctx, `UPDATE server_ai_transport_settings SET allow_http=$1, allow_vpn_http=$2, revision=revision+1 WHERE singleton AND revision=$3 RETURNING allow_http, allow_vpn_http, revision`, in.AllowHTTP, in.AllowVPNHTTP, in.Revision).Scan(&out.AllowHTTP, &out.AllowVPNHTTP, &out.Revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return Settings{}, apierr.Conflict("ai_transport_settings_changed", "AI transport settings changed. Reload them before saving.")
	}
	if err != nil {
		return Settings{}, err
	}
	metadata, err := json.Marshal(map[string]any{"allow_http": out.AllowHTTP, "allow_vpn_http": out.AllowVPNHTTP, "revision": out.Revision})
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
