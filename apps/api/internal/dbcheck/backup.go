package dbcheck

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/internal/dbconn"
)

func SupportedVersion(version int) bool { return version >= 160000 && version < 190000 }

// NativeToolPath never falls back to a different major or a PATH override.
func NativeToolPath(version int, tool string) (string, error) {
	if !SupportedVersion(version) || (tool != "pg_dump" && tool != "pg_restore") {
		return "", errors.New("database_backup_version_unsupported: PostgreSQL 16, 17 or 18 required")
	}
	return fmt.Sprintf("/usr/libexec/postgresql%d/%s", version/10000, tool), nil
}

// DumpTool detects the actual server, not a provider name or caller-supplied major.
func DumpTool(parent context.Context, raw string, requireTLS bool) (string, error) {
	if err := ValidateURL(raw, requireTLS); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	cfg, err := dbconn.ParseConfig(raw)
	if err != nil {
		return "", errors.New("database_config_invalid")
	}
	cfg.ConnectTimeout = 10 * time.Second
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return "", errors.New(SafeError(err))
	}
	defer conn.Close(ctx)
	var version int
	if err := conn.QueryRow(ctx, "SELECT current_setting('server_version_num')::int").Scan(&version); err != nil {
		return "", errors.New(SafeError(err))
	}
	return NativeToolPath(version, "pg_dump")
}
