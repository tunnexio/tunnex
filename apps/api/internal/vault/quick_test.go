package vault

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
)

func TestVaultQuickPersistenceAndConfiguration(t *testing.T) {
	ctx, pool, s := newTestService(t)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, e := pool.Exec(ctx, q, args...); e != nil {
			t.Fatal(e)
		}
	}
	org, otherOrg, alice, admin, bob := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{org, otherOrg} {
		exec(`INSERT INTO organizations(id,name,slug) VALUES($1,'Quick fixture',$2)`, id, id.String())
	}
	for user, role := range map[uuid.UUID]string{alice: "member", admin: "admin", bob: "member"} {
		exec(`INSERT INTO users(id,email,email_verified_at) VALUES($1,$2,now())`, user, user.String()+"@quick.test")
		exec(`INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,$3)`, org, user, role)
	}
	exec(`INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'member')`, otherOrg, alice)
	const original = "quick-original-fixture-password"
	request := api.VaultQuickCreateInput{RequestId: uuid.New(), Secret: ptr(original)}
	var wg sync.WaitGroup
	results := make(chan api.VaultEntry, 6)
	failures := make(chan error, 6)
	for range 6 {
		wg.Add(1)
		go func() { defer wg.Done(); v, e := s.QuickCreate(ctx, org, alice, request); results <- v; failures <- e }()
	}
	wg.Wait()
	close(results)
	close(failures)
	for e := range failures {
		if e != nil {
			t.Fatal(e)
		}
	}
	var draft api.VaultEntry
	for v := range results {
		if draft.Id == uuid.Nil {
			draft = v
		}
		if v.Id != draft.Id {
			t.Fatal("concurrent Copy retries created duplicate entries")
		}
	}
	if draft.Configured || draft.Title != "" || draft.ServiceName != "" || draft.ServiceId != nil || draft.Username != "" || draft.CurrentVersion != 1 || draft.Visibility != "personal" || draft.OwnerUserId != alice {
		t.Fatal("quick entry contains invented configuration or wrong ownership")
	}
	for _, table := range []string{"vault_entries", "vault_versions", "vault_quick_requests"} {
		var n int
		if e := pool.QueryRow(ctx, "SELECT count(*) FROM "+table+" WHERE org_id=$1", org).Scan(&n); e != nil || n != 1 {
			t.Fatal("idempotent Copy did not commit one entry, history and request")
		}
	}
	var count int
	if e := pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='vault.quick_created'`, org).Scan(&count); e != nil || count != 1 {
		t.Fatal("replay duplicated create audit")
	}
	services, e := s.Services(ctx, org, admin)
	if e != nil || len(services) != 0 {
		t.Fatal("quick entry created a fake catalog service")
	}
	for _, user := range []uuid.UUID{admin, bob} {
		index, e := s.List(ctx, org, user, 50, 0, "")
		if e != nil || index.Total != 0 {
			t.Fatal("private draft leaked into another actor's index")
		}
		_, e = s.Configure(ctx, org, user, draft.Id, api.VaultConfigureInput{Title: "Unauthorized", Visibility: "personal", ServiceName: ptr("Private"), ExpectedVersion: 1})
		status(t, e, 404)
		_, e = s.Reveal(ctx, org, user, draft.Id, 0)
		status(t, e, 404)
	}
	changed := request
	changed.Secret = ptr("different-candidate")
	_, e = s.QuickCreate(ctx, org, alice, changed)
	status(t, e, 409)
	_, e = s.Update(ctx, org, alice, draft.Id, api.VaultUpdateInput{Title: "No metadata yet", Secret: ptr("must-not-rotate"), ExpectedVersion: 1})
	status(t, e, 409)
	_, e = s.Configure(ctx, otherOrg, alice, draft.Id, api.VaultConfigureInput{Title: "Foreign", Visibility: "personal", ServiceName: ptr("Private"), ExpectedVersion: 1})
	status(t, e, 404)
	_, e = s.Configure(ctx, org, alice, draft.Id, api.VaultConfigureInput{Title: "Stale", Visibility: "personal", ServiceName: ptr("Private"), ExpectedVersion: 2})
	status(t, e, 409)
	_, e = s.Configure(ctx, org, alice, draft.Id, api.VaultConfigureInput{Title: "Missing service", Visibility: "personal", ExpectedVersion: 1})
	status(t, e, 400)
	configured, e := s.Configure(ctx, org, alice, draft.Id, api.VaultConfigureInput{Title: "Configured login", Visibility: "personal", ServiceName: ptr("Real private service"), Username: ptr("service-user"), ExpectedVersion: 1})
	if e != nil || !configured.Configured || configured.Kind != "password" || configured.CurrentVersion != 2 || configured.Username != "service-user" {
		t.Fatalf("configure did not append metadata version: %v", e)
	}
	for version, username := range map[int]string{1: "", 2: "service-user"} {
		secret, e := s.Reveal(ctx, org, alice, draft.Id, version)
		if e != nil || secret.Value != original || secret.Username != username {
			t.Fatal("configure replaced the original password or username history")
		}
	}
	_, e = s.Configure(ctx, org, alice, draft.Id, api.VaultConfigureInput{Title: "Again", Visibility: "personal", ServiceName: ptr("Other"), ExpectedVersion: 2})
	status(t, e, 409)
	// Reusing a UUID in another creator or tenant namespace is independent.
	bobDraft, e := s.QuickCreate(ctx, org, bob, request)
	if e != nil || bobDraft.Id == draft.Id {
		t.Fatal("request UUID crossed creator namespace")
	}
	foreignDraft, e := s.QuickCreate(ctx, otherOrg, alice, request)
	if e != nil || foreignDraft.Id == draft.Id {
		t.Fatal("request UUID crossed tenant namespace")
	}
	if e = s.Delete(ctx, org, bob, bobDraft.Id, 1); e != nil {
		t.Fatal(e)
	}
	var tombstone bool
	if e = pool.QueryRow(ctx, `SELECT org_id=$1 AND entry_id IS NULL FROM vault_quick_requests WHERE org_id=$1 AND owner_user_id=$2 AND request_id=$3`, org, bob, request.RequestId).Scan(&tombstone); e != nil || !tombstone {
		t.Fatal("deletion did not preserve a tenant-scoped request tombstone")
	}
	_, e = s.QuickCreate(ctx, org, bob, request)
	status(t, e, 409)
	index, e := s.List(ctx, org, bob, 50, 0, "")
	if e != nil || index.Total != 0 {
		t.Fatal("Copy retry resurrected a deleted entry")
	}
	// Revocation is checked before looking up an otherwise valid request replay.
	exec(`UPDATE memberships SET access_revoked_at=now() WHERE org_id=$1 AND user_id=$2`, org, alice)
	_, e = s.QuickCreate(ctx, org, alice, request)
	status(t, e, 403)
	exec(`UPDATE memberships SET access_revoked_at=NULL WHERE org_id=$1 AND user_id=$2`, org, alice)
	t.Run("configure race has one winner", func(t *testing.T) {
		v, e := s.QuickCreate(ctx, org, alice, api.VaultQuickCreateInput{RequestId: uuid.New(), Secret: ptr("race-candidate")})
		if e != nil {
			t.Fatal(e)
		}
		errs := make(chan error, 2)
		for range 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, e := s.Configure(ctx, org, alice, v.Id, api.VaultConfigureInput{Title: "Race login", Visibility: "personal", ServiceName: ptr("Real service"), ExpectedVersion: 1})
				errs <- e
			}()
		}
		wg.Wait()
		close(errs)
		success := 0
		for e := range errs {
			if e == nil {
				success++
			} else {
				status(t, e, 409)
			}
		}
		if success != 1 {
			t.Fatal("configure race had no unique winner")
		}
		h, e := s.Versions(ctx, org, alice, v.Id, 50, 0)
		if e != nil || h.Total != 2 {
			t.Fatal("configure retry appended extra versions")
		}
	})
	t.Run("admin draft assignment and original replay", func(t *testing.T) {
		catalog, e := s.AddService(ctx, org, admin, "Actual service")
		if e != nil {
			t.Fatal(e)
		}
		r := api.VaultQuickCreateInput{RequestId: uuid.New(), Secret: ptr("admin-original-candidate")}
		v, e := s.QuickCreate(ctx, org, admin, r)
		if e != nil {
			t.Fatal(e)
		}
		subjectKind := api.VaultConfigureInputSubjectKind("user")
		config := api.VaultConfigureInput{Title: "Assigned password", Visibility: "assigned", ServiceId: &catalog.Id, SubjectKind: &subjectKind, SubjectId: &bob, Username: ptr("assigned-login"), ExpectedVersion: 1}
		exec(`UPDATE memberships SET role='member' WHERE org_id=$1 AND user_id=$2`, org, admin)
		_, e = s.Configure(ctx, org, admin, v.Id, config)
		status(t, e, 403)
		exec(`UPDATE memberships SET role='admin' WHERE org_id=$1 AND user_id=$2`, org, admin)
		v, e = s.Configure(ctx, org, admin, v.Id, config)
		if e != nil || !v.Configured || v.Visibility != "assigned" {
			t.Fatalf("admin cannot configure assignment: %v", e)
		}
		_, e = s.Configure(ctx, org, bob, v.Id, config)
		status(t, e, 404)
		_, e = s.Update(ctx, org, bob, v.Id, api.VaultUpdateInput{Title: v.Title, Secret: ptr("later-rotation-value"), ExpectedVersion: 2})
		if e != nil {
			t.Fatal(e)
		}
		replay, e := s.QuickCreate(ctx, org, admin, r)
		if e != nil || replay.Id != v.Id || replay.CurrentVersion != 3 {
			t.Fatal("exact replay failed after configure and rotation")
		}
		r.Secret = ptr("later-rotation-value")
		_, e = s.QuickCreate(ctx, org, admin, r)
		status(t, e, 409)
		exec(`UPDATE memberships SET role='member' WHERE org_id=$1 AND user_id=$2`, org, admin)
		r.Secret = ptr("admin-original-candidate")
		_, e = s.QuickCreate(ctx, org, admin, r)
		status(t, e, 404)
		exec(`UPDATE memberships SET role='admin' WHERE org_id=$1 AND user_id=$2`, org, admin)
	})
	raw, _ := json.Marshal(configured)
	if strings.Contains(string(raw), original) {
		t.Fatal("configured metadata leaked the password")
	}
}

func TestVaultQuickAndConfigureAuditFailuresAreAtomic(t *testing.T) {
	ctx, pool, s := newTestService(t)
	org, user := uuid.New(), uuid.New()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, e := pool.Exec(ctx, q, args...); e != nil {
			t.Fatal(e)
		}
	}
	exec(`INSERT INTO organizations(id,name,slug) VALUES($1,'Audit fixture',$2)`, org, org.String())
	exec(`INSERT INTO users(id,email,email_verified_at) VALUES($1,$2,now())`, user, user.String()+"@audit.test")
	exec(`INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'member')`, org, user)
	exec(`CREATE FUNCTION quick_test_refuse_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action IN ('vault.quick_created','vault.configured') THEN RAISE EXCEPTION 'fixture unavailable'; END IF; RETURN NEW; END; $$`)
	exec(`CREATE TRIGGER quick_test_refuse_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION quick_test_refuse_audit()`)
	request := api.VaultQuickCreateInput{RequestId: uuid.New(), Secret: ptr("atomic-candidate")}
	if v, e := s.QuickCreate(ctx, org, user, request); e == nil || v.Id != uuid.Nil {
		t.Fatal("quick save returned success without audit")
	}
	var n int
	for _, table := range []string{"vault_entries", "vault_versions", "vault_quick_requests"} {
		if e := pool.QueryRow(ctx, "SELECT count(*) FROM "+table+" WHERE org_id=$1", org).Scan(&n); e != nil || n != 0 {
			t.Fatal("failed save left partial data")
		}
	}
	exec(`DROP TRIGGER quick_test_refuse_audit ON audit_logs`)
	v, e := s.QuickCreate(ctx, org, user, request)
	if e != nil {
		t.Fatal(e)
	}
	exec(`CREATE TRIGGER quick_test_refuse_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION quick_test_refuse_audit()`)
	_, e = s.Configure(ctx, org, user, v.Id, api.VaultConfigureInput{Title: "Atomic configure", Visibility: "personal", ServiceName: ptr("Service"), ExpectedVersion: 1})
	if e == nil {
		t.Fatal("configure succeeded without audit")
	}
	exec(`DROP TRIGGER quick_test_refuse_audit ON audit_logs`)
	index, e := s.List(ctx, org, user, 50, 0, "")
	if e != nil || index.Total != 1 || index.Entries[0].Configured || index.Entries[0].CurrentVersion != 1 {
		t.Fatal("failed configure partially changed metadata")
	}
	h, e := s.Versions(ctx, org, user, v.Id, 50, 0)
	if e != nil || h.Total != 1 {
		t.Fatal("failed configure left an extra version")
	}
}
