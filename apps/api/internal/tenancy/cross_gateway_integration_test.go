package tenancy

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

func TestCrossGatewaySettingDatabaseAtomicityAndMigration(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	org, other, actor := uuid.New(), uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{org, other} {
		if _, err := pool.Exec(ctx, "INSERT INTO organizations(id,name,slug) VALUES($1,'cross gateway',$2)", id, id.String()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, "INSERT INTO users(id,email,name) VALUES($1,$2,'administrator')", actor, actor.String()+"@test.local"); err != nil {
		t.Fatal(err)
	}
	ctx = authctx.WithPrincipal(ctx, &authctx.Principal{UserID: actor})
	q := sqlc.New(pool)
	initial, err := q.GetOrganizationByID(ctx, org)
	if err != nil || initial.CrossGatewayClientsEnabled {
		t.Fatalf("default not disabled: %+v %v", initial, err)
	}
	svc := NewService(pool)
	for _, enabled := range []bool{true, false} {
		saved, err := svc.SetCrossGatewayClientsEnabled(ctx, org, enabled)
		if err != nil || saved.CrossGatewayClientsEnabled != enabled {
			t.Fatalf("save: %+v %v", saved, err)
		}
	}
	rows, err := pool.Query(ctx, "SELECT actor_user_id,metadata FROM audit_logs WHERE org_id=$1 AND action='org.cross_gateway_clients_updated' ORDER BY created_at", org)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for rows.Next() {
		var who uuid.UUID
		var raw []byte
		var metadata struct{ From, To bool }
		if err := rows.Scan(&who, &raw); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &metadata); err != nil {
			t.Fatal(err)
		}
		if who != actor || metadata.From != (count == 1) || metadata.To != (count == 0) {
			t.Fatalf("wrong audit: %s", raw)
		}
		count++
	}
	rows.Close()
	if rows.Err() != nil || count != 2 {
		t.Fatalf("audit count=%d err=%v", count, rows.Err())
	}
	// Hold a competing update open: the audited "from" value must be read
	// after that writer commits, rather than captured before waiting on UPDATE.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := sqlc.New(tx).GetCrossGatewaySettingForUpdate(ctx, org); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := svc.SetCrossGatewayClientsEnabled(ctx, org, false); done <- err }()
	deadline := time.Now().Add(3 * time.Second)
	for {
		var waiting bool
		if err := pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock')").Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("concurrent setting write did not wait for row lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := tx.Exec(ctx, "UPDATE organizations SET cross_gateway_clients_enabled=true WHERE id=$1", org); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	var from, to bool
	if err := pool.QueryRow(ctx, "SELECT (metadata->>'from')::boolean,(metadata->>'to')::boolean FROM audit_logs WHERE org_id=$1 AND action='org.cross_gateway_clients_updated' ORDER BY created_at DESC LIMIT 1", org).Scan(&from, &to); err != nil || !from || to {
		t.Fatalf("concurrent audit captured stale state: from=%t to=%t err=%v", from, to, err)
	}
	// A failing audit insert must roll back the setting, not only suppress the wake.
	if _, err := pool.Exec(ctx, `CREATE FUNCTION reject_cross_gateway_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='org.cross_gateway_clients_updated' THEN RAISE EXCEPTION 'injected audit refusal'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_cross_gateway_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_cross_gateway_audit()`); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SetCrossGatewayClientsEnabled(ctx, org, true); err == nil {
		t.Fatal("audit failure accepted")
	}
	for _, id := range []uuid.UUID{org, other} {
		got, err := q.GetOrganizationByID(ctx, id)
		if err != nil || got.CrossGatewayClientsEnabled {
			t.Fatalf("rollback or tenant isolation failed: %v %v", got, err)
		}
	}
	// Execute the exact reversible migration in this disposable fixture only.
	for _, name := range []string{"0166_cross_gateway_clients.down.sql", "0166_cross_gateway_clients.up.sql"} {
		body, err := db.MigrationsFS.ReadFile("migrations/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, string(body)); err != nil {
			t.Fatal(err)
		}
		settings, err := q.GetOrganizationPolicySnapshotSettings(ctx, org)
		if err != nil || settings.CrossGatewayClientsEnabled {
			t.Fatalf("migration fallback: %+v %v", settings, err)
		}
	}
}
