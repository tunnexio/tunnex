// Command migrate applies or rolls back database migrations.
//
//	migrate up        apply all pending migrations
//	migrate down      roll back one migration
//	migrate version   print the current schema version
//
// Migrations are embedded (see db.MigrationsFS), so this binary is standalone.
package main

import (
	"log/slog"
	"os"

	"github.com/tunnexio/tunnex/apps/api/db"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		logger.Error("migrate_config_error", slog.String("error", "DATABASE_URL is required"))
		os.Exit(1)
	}

	cmd := "up"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}

	switch cmd {
	case "up":
		if err := db.Up(databaseURL); err != nil {
			logger.Error("migrate_failed", slog.String("cmd", cmd), slog.String("error", err.Error()))
			os.Exit(1)
		}
		v, dirty, _, _ := db.Version(databaseURL)
		logger.Info("migrate_up_complete", slog.Uint64("version", uint64(v)), slog.Bool("dirty", dirty))
	case "down":
		if err := db.DownOne(databaseURL); err != nil {
			logger.Error("migrate_failed", slog.String("cmd", cmd), slog.String("error", err.Error()))
			os.Exit(1)
		}
		v, dirty, ok, _ := db.Version(databaseURL)
		logger.Info("migrate_down_complete", slog.Uint64("version", uint64(v)), slog.Bool("dirty", dirty), slog.Bool("has_version", ok))
	case "version":
		v, dirty, ok, err := db.Version(databaseURL)
		if err != nil {
			logger.Error("migrate_failed", slog.String("cmd", cmd), slog.String("error", err.Error()))
			os.Exit(1)
		}
		logger.Info("migrate_version", slog.Uint64("version", uint64(v)), slog.Bool("dirty", dirty), slog.Bool("has_version", ok))
	default:
		logger.Error("migrate_usage_error", slog.String("error", "unknown command: "+cmd), slog.String("usage", "up|down|version"))
		os.Exit(2)
	}
}
