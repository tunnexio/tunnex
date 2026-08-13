// Command backupctl emits and verifies the control-plane backup manifest (S11 D2).
//
// Two subcommands, matching the runbook in docs/backup-restore.md:
//
//	backupctl manifest   > backup.manifest.json   # take: record WHICH master key this dump is sealed under
//	backupctl verify     < backup.manifest.json   # restore: refuse unless THIS CP holds that key
//
// It loads the master key exactly as the server does, so "the key this tool sees" is by construction the key
// the control plane would use — a verification against a differently-loaded key would prove nothing.
//
// verify EXITS NON-ZERO ON MISMATCH and writes the reason to stderr, so it composes with a restore script:
//
//	backupctl verify < m.json && pg_restore ...
//
// That ordering is the point. The catastrophic outcome is not a failed restore; it is a restore that
// SUCCEEDS under the wrong key, producing a control plane that starts, serves, and cannot read its own agent
// CA — silently orphaning every enrolled gateway.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/internal/backup"
	"github.com/tunnexio/tunnex/apps/api/internal/config"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/secrets"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cfg := config.Load()
	sec, err := secrets.LoadOrInitExt(cfg.SecretsDir, secrets.ExternalSecrets{
		Master:  secrets.ExternalSource{File: cfg.MasterKeyFile, Value: cfg.MasterKey},
		Session: secrets.ExternalSource{File: cfg.SessionSecretFile, Value: cfg.SessionSecret},
	})
	if err != nil {
		fatal("master key: %v\n\nThe key is the separate artifact you were asked to custody; it is never "+
			"contained in a backup.", err)
	}
	sealer, err := crypto.NewSealer(sec.MasterKey)
	if err != nil {
		fatal("sealer: %v", err)
	}

	switch os.Args[1] {
	case "manifest":
		m := backup.NewManifest(sealer, schemaVersion(cfg), noteFromArgs())
		if err := m.Write(os.Stdout); err != nil {
			fatal("write manifest: %v", err)
		}
	case "verify":
		m, err := backup.Read(os.Stdin)
		if err != nil {
			// Name the FIX, not only the condition (S11 walk WF-S11-3). The bare `read manifest: EOF` this
			// used to print is accurate and useless: it says what failed, not what to type. An operator meets
			// it mid-restore, which is the worst moment to be guessing at argument syntax — the manifest
			// arrives on STDIN, and forgetting the redirect is the overwhelmingly likely cause.
			fatal("%v\n\nThe manifest is read from STDIN — redirect it in:\n"+
				"    backupctl verify < backup.manifest.json\n"+
				"(in a container: docker compose exec -T api backupctl verify < backup.manifest.json)", err)
		}
		if err := backup.Verify(m, sealer); err != nil {
			// Loud, actionable, and non-zero — so `verify && pg_restore` cannot proceed.
			fmt.Fprintf(os.Stderr, "REFUSING TO RESTORE\n\n%v\n", err)
			if errors.Is(err, backup.ErrKeyMismatch) {
				os.Exit(2) // distinct code: "wrong key", not "malformed input"
			}
			os.Exit(1)
		}
		fmt.Fprintf(os.Stdout, "ok: this control plane holds the master key this backup was sealed under "+
			"(fingerprint %s, taken %s, schema version %d)\n",
			m.MasterKeyFingerprint, m.TakenAt.Format("2006-01-02 15:04:05 UTC"), m.SchemaVersion)
	default:
		usage()
	}
}

// schemaVersion reads the applied migration version, so a restore into an older binary is caught rather than
// discovered through confusing failures. Best-effort: a manifest is still useful without it.
func schemaVersion(cfg config.Config) int64 {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return 0
	}
	defer pool.Close()
	var v int64
	if err := pool.QueryRow(ctx, "SELECT version FROM schema_migrations LIMIT 1").Scan(&v); err != nil {
		return 0
	}
	return v
}

func noteFromArgs() string {
	if len(os.Args) > 2 {
		return os.Args[2]
	}
	return ""
}

func usage() {
	fmt.Fprint(os.Stderr, `tunnex backupctl — backup manifest tooling

  backupctl manifest [note]  > backup.manifest.json
  backupctl verify           < backup.manifest.json

The manifest records a KEYED FINGERPRINT of the master key — never the key. Run verify BEFORE
pg_restore: a restore under the wrong key produces a control plane that cannot read its own agent CA.
`)
	os.Exit(64)
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}
