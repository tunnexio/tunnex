package aitransport

import (
	"errors"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
	"net/url"
	"os"
	"sync"
	"testing"
)

// Migration 0247 splits the one HTTP switch in two. An installation that had
// the old switch on keeps both on, so nothing stops working on upgrade; one
// that had it off gets HTTP inside the VPN on and public HTTP still off.
func TestAITransportVPNHTTPMigrationUpgradeRule(t *testing.T) {
	for _, tc := range []struct {
		name                string
		before              bool
		wantPublic, wantVPN bool
	}{
		{"old switch on keeps both on", true, true, true},
		{"old switch off gets VPN on and public off", false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, pool := testpostgres.NewAtVersion(t, 246)
			if _, err := pool.Exec(ctx, `UPDATE server_ai_transport_settings SET allow_http=$1, revision=7 WHERE singleton`, tc.before); err != nil {
				t.Fatal(err)
			}
			u, err := url.Parse(os.Getenv("TUNNEX_TEST_DATABASE_URL"))
			if err != nil {
				t.Fatal("fixture endpoint")
			}
			u.Path = "/" + pool.Config().ConnConfig.Database
			if err = db.MigrateTo(u.String(), 247); err != nil {
				t.Fatal(err)
			}
			value, err := New(pool).Get(ctx)
			// The revision an administrator last loaded stays valid across the upgrade.
			if err != nil || value.AllowHTTP != tc.wantPublic || value.AllowVPNHTTP != tc.wantVPN || value.Revision != 7 {
				t.Fatalf("upgraded policy %+v: %v", value, err)
			}
			down, err := db.MigrationsFS.ReadFile("migrations/0247_ai_transport_vpn_http.down.sql")
			if err != nil {
				t.Fatal(err)
			}
			if _, err = pool.Exec(ctx, string(down)); err != nil {
				t.Fatal(err)
			}
			var public bool
			var revision int64
			if err = pool.QueryRow(ctx, `SELECT allow_http, revision FROM server_ai_transport_settings WHERE singleton`).Scan(&public, &revision); err != nil || public != tc.before || revision != 7 {
				t.Fatalf("downgrade changed the public switch: %v %d %v", public, revision, err)
			}
			var present bool
			if err = pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='server_ai_transport_settings' AND column_name='allow_vpn_http')`).Scan(&present); err != nil || present {
				t.Fatal("downgrade kept the VPN column", err)
			}
		})
	}
}

func TestAITransportPersistence(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	actor := uuid.New()
	if _, err := pool.Exec(ctx, "INSERT INTO users(id,email) VALUES($1,'transport-admin@example.test')", actor); err != nil {
		t.Fatal(err)
	}
	service := New(pool)
	value, err := service.Get(ctx)
	// A new installation allows HTTP inside the VPN and refuses public HTTP.
	if err != nil || value.AllowHTTP || !value.AllowVPNHTTP || value.Revision != 1 {
		t.Fatalf("fresh default %+v: %v", value, err)
	}
	var results [2]error
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, results[i] = service.Save(ctx, actor, Settings{AllowHTTP: true, AllowVPNHTTP: true, Revision: 1})
		}(i)
	}
	wg.Wait()
	successes, conflicts := 0, 0
	for _, err := range results {
		if err == nil {
			successes++
			continue
		}
		var e *apierr.Error
		if errors.As(err, &e) && e.Code == "ai_transport_settings_changed" {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatal("concurrent save did not reject stale revision")
	}
	// A new service models another replica or restarted process.
	replica := New(pool)
	value, err = replica.Get(ctx)
	if err != nil || !value.AllowHTTP || !value.AllowVPNHTTP || value.Revision != 2 {
		t.Fatalf("persisted opt-in %+v: %v", value, err)
	}
	// The two switches are saved independently: public off leaves VPN on.
	value, err = replica.Save(ctx, actor, Settings{AllowHTTP: false, AllowVPNHTTP: true, Revision: 2})
	if err != nil || value.AllowHTTP || !value.AllowVPNHTTP || value.Revision != 3 {
		t.Fatalf("disable public %+v: %v", value, err)
	}
	value, err = service.Get(ctx)
	if err != nil || value.AllowHTTP || !value.AllowVPNHTTP || value.Revision != 3 {
		t.Fatal("original replica kept stale policy", err)
	}
	// VPN off with public on is also representable; neither implies the other.
	value, err = replica.Save(ctx, actor, Settings{AllowHTTP: true, AllowVPNHTTP: false, Revision: 3})
	if err != nil || !value.AllowHTTP || value.AllowVPNHTTP || value.Revision != 4 {
		t.Fatalf("disable VPN only %+v: %v", value, err)
	}
	value, err = service.Save(ctx, actor, Settings{AllowHTTP: false, AllowVPNHTTP: false, Revision: 4})
	if err != nil || value.AllowHTTP || value.AllowVPNHTTP || value.Revision != 5 {
		t.Fatalf("disable both %+v: %v", value, err)
	}
	var count int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action='server.ai_transport_settings_updated' AND actor_user_id=$1 AND org_id IS NULL`, actor).Scan(&count); err != nil || count != 4 {
		t.Fatalf("audit count %d: %v", count, err)
	}
	// Every save records both switches and the revision it produced.
	rows, err := pool.Query(ctx, `SELECT (metadata->>'allow_http')::boolean,(metadata->>'allow_vpn_http')::boolean,(metadata->>'revision')::bigint FROM audit_logs WHERE action='server.ai_transport_settings_updated' ORDER BY (metadata->>'revision')::bigint`)
	if err != nil {
		t.Fatal(err)
	}
	type audited struct {
		public, vpn bool
		revision    int64
	}
	var got []audited
	for rows.Next() {
		var a audited
		if err = rows.Scan(&a.public, &a.vpn, &a.revision); err != nil {
			t.Fatal(err)
		}
		got = append(got, a)
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	want := []audited{{true, true, 2}, {false, true, 3}, {true, false, 4}, {false, false, 5}}
	if len(got) != len(want) {
		t.Fatalf("audit rows %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("audit row %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	if _, err = pool.Exec(ctx, `CREATE FUNCTION transport_audit_refuse() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='server.ai_transport_settings_updated' THEN RAISE EXCEPTION 'injected failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER transport_audit_refuse BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION transport_audit_refuse()`); err != nil {
		t.Fatal(err)
	}
	if _, err = service.Save(ctx, actor, Settings{AllowHTTP: true, AllowVPNHTTP: true, Revision: 5}); err == nil {
		t.Fatal("audit failure accepted")
	}
	value, err = service.Get(ctx)
	if err != nil || value.AllowHTTP || value.AllowVPNHTTP || value.Revision != 5 {
		t.Fatal("audit failure did not roll back policy", err)
	}
	if _, err = service.Save(ctx, actor, Settings{AllowHTTP: true, Revision: 0}); err == nil {
		t.Fatal("missing revision accepted")
	}
	if _, err = pool.Exec(ctx, "DELETE FROM server_ai_transport_settings"); err != nil {
		t.Fatal(err)
	}
	if _, err = service.Get(ctx); err == nil {
		t.Fatal("missing policy fabricated a default")
	}
}
