package ipsec_test

import (
	"context"
	"errors"
	"math"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
)

// The caller supplies the guarded, isolated fixture admin database.
// Each test creates and removes only its own uniquely named scratch database.
func settingsFixture(t *testing.T) (context.Context, *pgxpool.Pool, uuid.UUID, uuid.UUID) {
	t.Helper()
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to the isolated fixture database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	name := "tnx_ipsec_settings_" + uuid.NewString()[:8]
	if _, err = admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+name+" WITH (FORCE)"); err != nil {
			t.Errorf("scratch database cleanup: %v", err)
		}
	})
	parsed.Path = "/" + name
	if err = db.MigrateTo(parsed.String(), 160); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	org, actor := uuid.New(), uuid.New()
	if _, err = pool.Exec(ctx, `INSERT INTO organizations(id,name,slug,pool_cidr) VALUES($1,'IPsec settings',$2,'10.199.0.0/24')`, org, "ipsec-"+org.String()); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO users(id,email) VALUES($1,$2)`, actor, actor.String()+"@ipsec-settings.test"); err != nil {
		t.Fatal(err)
	}
	return ctx, pool, org, actor
}

func TestSettingsDefaultReadDoesNotWrite(t *testing.T) {
	ctx, pool, org, _ := settingsFixture(t)
	var before, after time.Time
	if err := pool.QueryRow(ctx, `SELECT updated_at FROM organizations WHERE id=$1`, org).Scan(&before); err != nil {
		t.Fatal(err)
	}
	got, err := ipsec.NewSettingsStore(pool).Read(ctx, org)
	if err != nil || got.Enabled || got.Revision != 0 {
		t.Fatalf("default=%+v err=%v", got, err)
	}
	var settings, audits int
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM ipsec_org_settings WHERE org_id=$1),(SELECT count(*) FROM audit_logs WHERE org_id=$1),updated_at FROM organizations WHERE id=$1`, org).Scan(&settings, &audits, &after); err != nil {
		t.Fatal(err)
	}
	if settings != 0 || audits != 0 || !before.Equal(after) {
		t.Fatalf("read wrote state: settings=%d audits=%d org changed=%v", settings, audits, !before.Equal(after))
	}
}

func TestSettingsConfigureCASAndAudit(t *testing.T) {
	ctx, pool, org, actor := settingsFixture(t)
	store := ipsec.NewSettingsStore(pool)
	for _, step := range []struct {
		enabled  bool
		expected int64
	}{{false, 0}, {true, 1}, {false, 2}} {
		got, err := store.Configure(ctx, org, actor, step.enabled, step.expected)
		if err != nil || got.Enabled != step.enabled || got.Revision != step.expected+1 {
			t.Fatalf("configure=%+v err=%v", got, err)
		}
	}
	for _, revision := range []int64{0, 1, 2, 4} {
		if _, err := store.Configure(ctx, org, actor, true, revision); !errors.Is(err, ipsec.ErrSettingsConflict) {
			t.Fatalf("stale/future revision %d: %v", revision, err)
		}
	}
	var audits int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE org_id=$1 AND actor_user_id=$2 AND action='ipsec.settings_changed' AND target_type='organization' AND target_id=$3 AND (metadata->>'revision')::bigint BETWEEN 1 AND 3 AND (metadata->>'enabled')::boolean=((metadata->>'revision')::bigint=2)`, org, actor, org.String()).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits != 3 {
		t.Fatalf("exact audits=%d want 3", audits)
	}
	if _, err := store.Configure(ctx, org, actor, false, 2); !errors.Is(err, ipsec.ErrSettingsConflict) {
		t.Fatalf("stale identical update: %v", err)
	}
	got, err := store.Read(ctx, org)
	if err != nil || got.Enabled || got.Revision != 3 {
		t.Fatalf("after refusals=%+v err=%v", got, err)
	}
	same, err := store.Configure(ctx, org, actor, false, 3)
	if err != nil || same.Enabled || same.Revision != 4 {
		t.Fatalf("same value successor=%+v err=%v", same, err)
	}
	other := uuid.New()
	if _, err = store.Read(ctx, other); !errors.Is(err, ipsec.ErrSettingsOrgUnavailable) {
		t.Fatalf("absent org read: %v", err)
	}
	if _, err = store.Configure(ctx, other, actor, true, 0); !errors.Is(err, ipsec.ErrSettingsOrgUnavailable) {
		t.Fatalf("absent org write: %v", err)
	}
}

func TestSettingsConcurrentCAS(t *testing.T) {
	for _, initial := range []int64{0, 1} {
		t.Run(string(rune('0'+initial)), func(t *testing.T) {
			ctx, pool, org, actor := settingsFixture(t)
			store := ipsec.NewSettingsStore(pool)
			if initial == 1 {
				if _, err := store.Configure(ctx, org, actor, false, 0); err != nil {
					t.Fatal(err)
				}
			}
			start := make(chan struct{})
			results := make(chan error, 2)
			var wg sync.WaitGroup
			for range 2 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					_, err := store.Configure(ctx, org, actor, true, initial)
					results <- err
				}()
			}
			close(start)
			wg.Wait()
			close(results)
			success, conflicts := 0, 0
			for err := range results {
				if err == nil {
					success++
				} else if errors.Is(err, ipsec.ErrSettingsConflict) {
					conflicts++
				} else {
					t.Fatal(err)
				}
			}
			if success != 1 || conflicts != 1 {
				t.Fatalf("success=%d conflicts=%d", success, conflicts)
			}
			got, err := store.Read(ctx, org)
			if err != nil || !got.Enabled || got.Revision != initial+1 {
				t.Fatalf("winner=%+v err=%v", got, err)
			}
			var audits int
			if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE org_id=$1`, org).Scan(&audits); err != nil {
				t.Fatal(err)
			}
			if int64(audits) != initial+1 {
				t.Fatalf("audits=%d", audits)
			}
		})
	}
}

func TestSettingsRejectDeletedOrg(t *testing.T) {
	ctx, pool, org, actor := settingsFixture(t)
	store := ipsec.NewSettingsStore(pool)
	if _, err := store.Configure(ctx, org, actor, true, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE organizations SET deleted_at=now() WHERE id=$1`, org); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Read(ctx, org); !errors.Is(err, ipsec.ErrSettingsOrgUnavailable) {
		t.Fatalf("deleted read: %v", err)
	}
	if _, err := store.Configure(ctx, org, actor, false, 1); !errors.Is(err, ipsec.ErrSettingsOrgUnavailable) {
		t.Fatalf("deleted write: %v", err)
	}
}

func TestSettingsAuditFailureRollsBack(t *testing.T) {
	ctx, pool, org, actor := settingsFixture(t)
	store := ipsec.NewSettingsStore(pool)
	for _, expected := range []int64{0, 1} {
		if expected == 1 {
			if _, err := store.Configure(ctx, org, actor, false, 0); err != nil {
				t.Fatal(err)
			}
		}
		var before, after time.Time
		if err := pool.QueryRow(ctx, `SELECT updated_at FROM organizations WHERE id=$1`, org).Scan(&before); err != nil {
			t.Fatal(err)
		}
		got, err := store.Configure(ctx, org, uuid.New(), true, expected)
		if !errors.Is(err, ipsec.ErrSettingsUnavailable) || got != (ipsec.Settings{}) {
			t.Fatalf("audit failure exposed result=%+v err=%v", got, err)
		}
		if err := pool.QueryRow(ctx, `SELECT updated_at FROM organizations WHERE id=$1`, org).Scan(&after); err != nil {
			t.Fatal(err)
		}
		if !before.Equal(after) {
			t.Fatal("audit rollback changed organization timestamp")
		}
		got, err = store.Read(ctx, org)
		if err != nil || got.Enabled || got.Revision != expected {
			t.Fatalf("rollback=%+v err=%v", got, err)
		}
	}
	var audits int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE org_id=$1`, org).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits != 1 {
		t.Fatalf("audit rollback count=%d", audits)
	}
}

func TestSettingsInvalidRevisions(t *testing.T) {
	ctx, pool, org, actor := settingsFixture(t)
	store := ipsec.NewSettingsStore(pool)
	for _, rev := range []int64{-1, math.MinInt64, math.MaxInt64} {
		if _, err := store.Configure(ctx, org, actor, true, rev); !errors.Is(err, ipsec.ErrSettingsInvalid) {
			t.Fatalf("invalid revision %d: %v", rev, err)
		}
	}
	got, err := store.Read(ctx, org)
	if err != nil || got != (ipsec.Settings{}) {
		t.Fatalf("invalid writes changed default=%+v err=%v", got, err)
	}
}
