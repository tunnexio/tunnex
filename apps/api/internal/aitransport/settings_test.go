package aitransport

import (
	"errors"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
	"sync"
	"testing"
)

func TestAITransportPersistence(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	actor := uuid.New()
	if _, err := pool.Exec(ctx, "INSERT INTO users(id,email) VALUES($1,'transport-admin@example.test')", actor); err != nil {
		t.Fatal(err)
	}
	service := New(pool)
	value, err := service.Get(ctx)
	if err != nil || value.AllowHTTP || value.Revision != 1 {
		t.Fatalf("fresh default %+v: %v", value, err)
	}
	var results [2]error
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, results[i] = service.Save(ctx, actor, Settings{AllowHTTP: true, Revision: 1})
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
	if err != nil || !value.AllowHTTP || value.Revision != 2 {
		t.Fatalf("persisted opt-in %+v: %v", value, err)
	}
	value, err = replica.Save(ctx, actor, Settings{AllowHTTP: false, Revision: 2})
	if err != nil || value.AllowHTTP || value.Revision != 3 {
		t.Fatalf("disable %+v: %v", value, err)
	}
	value, err = service.Get(ctx)
	if err != nil || value.AllowHTTP || value.Revision != 3 {
		t.Fatal("original replica kept stale policy", err)
	}
	var count int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action='server.ai_transport_settings_updated' AND actor_user_id=$1 AND org_id IS NULL`, actor).Scan(&count); err != nil || count != 2 {
		t.Fatalf("audit count %d: %v", count, err)
	}
	var allowed bool
	var revision int64
	if err = pool.QueryRow(ctx, `SELECT (metadata->>'allow_http')::boolean,(metadata->>'revision')::bigint FROM audit_logs WHERE action='server.ai_transport_settings_updated' ORDER BY created_at DESC LIMIT 1`).Scan(&allowed, &revision); err != nil || allowed || revision != 3 {
		t.Fatal("audit omitted saved policy", err)
	}
	if _, err = pool.Exec(ctx, `CREATE FUNCTION transport_audit_refuse() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='server.ai_transport_settings_updated' THEN RAISE EXCEPTION 'injected failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER transport_audit_refuse BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION transport_audit_refuse()`); err != nil {
		t.Fatal(err)
	}
	if _, err = service.Save(ctx, actor, Settings{AllowHTTP: true, Revision: 3}); err == nil {
		t.Fatal("audit failure accepted")
	}
	value, err = service.Get(ctx)
	if err != nil || value.AllowHTTP || value.Revision != 3 {
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
