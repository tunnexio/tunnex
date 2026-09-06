// Package dbconn applies the CP's authentication contract to every connection.
package dbconn

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// requireBinding also requires SCRAM authentication: channel_binding alone only
// constrains SCRAM negotiation in pgx, not trust/password/MD5 authentication.
// Apply this to the parsed configuration so URL and environment inputs agree.
func requireBinding(cfg *pgx.ConnConfig) {
	if cfg.ChannelBinding == "require" {
		cfg.RequireAuth = "scram-sha-256"
	}
}

func ParseConfig(raw string) (*pgx.ConnConfig, error) {
	cfg, err := pgx.ParseConfig(raw)
	if err != nil {
		return nil, err
	}
	requireBinding(cfg)
	return cfg, nil
}

// NewPool retains all pool settings and applies the requirement to each dial,
// including reconnects; a one-time preflight would not enforce that invariant.
func NewPool(ctx context.Context, raw string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(raw)
	if err != nil {
		return nil, err
	}
	requireBinding(cfg.ConnConfig)
	return pgxpool.NewWithConfig(ctx, cfg)
}
