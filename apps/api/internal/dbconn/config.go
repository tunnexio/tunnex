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
	// Pool options belong to pgx, not PostgreSQL startup GUCs. Consume them
	// on migration/preflight connections too so one DSN works for every path.
	poolCfg, err := pgxpool.ParseConfig(raw)
	if err != nil {
		return nil, err
	}
	cfg := poolCfg.ConnConfig
	requireBinding(cfg)
	return cfg, nil
}

// NewPool retains all pool settings and applies the requirement to each dial,
// including reconnects; a one-time preflight would not enforce that invariant.
func NewPool(ctx context.Context, raw string) (*pgxpool.Pool, error) {
	cfg, err := ParsePoolConfig(raw)
	if err != nil {
		return nil, err
	}
	return pgxpool.NewWithConfig(ctx, cfg)
}

// ParsePoolConfig leaves explicit operator budgets authoritative. pgx's default
// four-connection pool on small hosts leaves just three after leader election;
// independent CP background work and interactive requests need bounded headroom.
func ParsePoolConfig(raw string) (*pgxpool.Config, error) {
	input, err := pgx.ParseConfig(raw)
	if err != nil {
		return nil, err
	}
	cfg, err := pgxpool.ParseConfig(raw)
	if err != nil {
		return nil, err
	}
	if _, explicit := input.RuntimeParams["pool_max_conns"]; !explicit && cfg.MaxConns < 16 {
		cfg.MaxConns = 16
	}
	requireBinding(cfg.ConnConfig)
	return cfg, nil
}
