package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/tunnexio/tunnex/apps/api/internal/config"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAppPreflightLocalDatabase(t *testing.T) {
	pool := proxyCLIChildPool(t)
	ctx := context.Background()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{DatabaseURL: pool.Config().ConnString(), AppAccessRestoreMarker: filepath.Join(dir, "pending.json")}
	call := func(deny bool) {
		t.Helper()
		var out bytes.Buffer
		err := appPreflight(ctx, cfg, nil, &out)
		if deny {
			if err == nil || out.Len() != 0 {
				t.Fatal("unsafe preflight admitted or emitted partial state")
			}
			if strings.Contains(err.Error(), pool.Config().ConnString()) {
				t.Fatal("database disclosed")
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		var got appPreflightResult
		if json.Unmarshal(out.Bytes(), &got) != nil || got.SchemaVersion != 175 || got.SupportedSchemaVersion != 175 || !got.RecoveryCompleted {
			t.Fatal("safe same-schema projection invalid")
		}
	}
	call(false)
	exec := func(sql string) {
		t.Helper()
		if _, err = pool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	exec("UPDATE schema_migrations SET dirty=true")
	call(true)
	exec("UPDATE schema_migrations SET dirty=false,version=176")
	call(true)
	exec("UPDATE schema_migrations SET version=172")
	call(true)
	exec("UPDATE schema_migrations SET version=175")
	exec("UPDATE app_access_installation_authority SET recovery_completed_at=NULL")
	call(true)
	exec("UPDATE app_access_installation_authority SET recovery_completed_at=now()")
	if err = os.WriteFile(cfg.AppAccessRestoreMarker, []byte("pending"), 0600); err != nil {
		t.Fatal(err)
	}
	call(true)
	if err = os.Remove(cfg.AppAccessRestoreMarker); err != nil {
		t.Fatal(err)
	}
	call(false)
	exec("DELETE FROM app_access_installation_authority")
	call(true)
}
