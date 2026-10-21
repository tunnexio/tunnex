package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

func ptr[T any](v T) *T { return &v }

func status(t *testing.T, err error, want int) {
	t.Helper()
	var v *apierr.Error
	if !errors.As(err, &v) || v.Status != want {
		t.Fatalf("error status: got %v, want %d", err, want)
	}
}

func newTestService(t *testing.T) (context.Context, *pgxpool.Pool, *Service) {
	t.Helper()
	ctx, pool := testpostgres.New(t)
	sealer, err := crypto.NewSealer(bytes.Repeat([]byte{29}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return ctx, pool, New(pool, sealer)
}

func TestEnvelopeRejectsSwappedEntryTenantVersionAndKey(t *testing.T) {
	sealer, err := crypto.NewSealer(bytes.Repeat([]byte{31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	s := New(nil, sealer)
	org, id := uuid.New(), uuid.New()
	sealed, err := s.seal(org, id, 3, "fixture-password", "service-account")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sealed, "fixture-password") || strings.Contains(sealed, "service-account") {
		t.Fatal("plaintext in encrypted envelope")
	}
	v, err := s.open(org, id, 3, sealed)
	if err != nil || v.Value != "fixture-password" || v.Username != "service-account" {
		t.Fatal("envelope round trip failed")
	}
	for _, tc := range []struct {
		org, id uuid.UUID
		version int
	}{{uuid.New(), id, 3}, {org, uuid.New(), 3}, {org, id, 4}} {
		v, err = s.open(tc.org, tc.id, tc.version, sealed)
		status(t, err, 500)
		if v.Value != "" {
			t.Fatal("unbound secret returned")
		}
	}
	wrong, _ := crypto.NewSealer(bytes.Repeat([]byte{32}, 32))
	v, err = New(nil, wrong).open(org, id, 3, sealed)
	status(t, err, 500)
	if v.Value != "" {
		t.Fatal("wrong-key secret returned")
	}
	status(t, func() error { _, e := s.open(org, id, 3, "invalid ciphertext"); return e }(), 500)
}

func TestVaultIdentityPrivacyAssignmentsAndVersionTransactions(t *testing.T) {
	ctx, pool, s := newTestService(t)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	org, otherOrg := uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{org, otherOrg} {
		exec(`INSERT INTO organizations(id,name,slug) VALUES($1,'Vault fixture',$2)`, id, id.String())
	}
	admin, alice, bob, otherUser := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for i, id := range []uuid.UUID{admin, alice, bob, otherUser} {
		exec(`INSERT INTO users(id,email,name,email_verified_at) VALUES($1,$2,'Fixture actor',now())`, id, id.String()+"@vault.test")
		role, tenant := "member", org
		if i == 0 {
			role = "admin"
		}
		if i == 3 {
			tenant = otherOrg
		}
		exec(`INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,$3)`, tenant, id, role)
	}
	personal, err := s.Create(ctx, org, alice, api.VaultCreateInput{Title: "Personal API", Kind: "api_key", Visibility: "personal", ServiceName: ptr("Private service"), Secret: ptr("fixture-personal-secret"), Username: ptr("personal-login")})
	if err != nil {
		t.Fatal(err)
	}
	if personal.CurrentVersion != 1 || !personal.CanEdit || !personal.CanDelete || personal.Username != "personal-login" {
		t.Fatal("personal entry metadata missing")
	}
	for _, user := range []uuid.UUID{admin, bob} {
		workspace, e := s.List(ctx, org, user, 50, 0, "")
		if e != nil {
			t.Fatal(e)
		}
		if workspace.Total != 0 || len(workspace.Entries) != 0 {
			t.Fatal("private entry visible to another actor")
		}
		_, e = s.Reveal(ctx, org, user, personal.Id, 0)
		status(t, e, 404)
		_, e = s.Versions(ctx, org, user, personal.Id, 50, 0)
		status(t, e, 404)
		_, e = s.Update(ctx, org, user, personal.Id, api.VaultUpdateInput{Title: "Takeover", Secret: ptr("fixture-takeover"), ExpectedVersion: 1})
		status(t, e, 404)
		status(t, s.Delete(ctx, org, user, personal.Id, 1), 404)
	}
	_, err = s.Reveal(ctx, otherOrg, otherUser, personal.Id, 0)
	status(t, err, 404)
	_, err = s.Reveal(ctx, org, otherUser, personal.Id, 0)
	status(t, err, 403)
	services, err := s.Services(ctx, org, admin)
	if err != nil || len(services) != 0 {
		t.Fatal("private service leaked into catalog")
	}
	_, err = s.AddService(ctx, org, alice, "Team service")
	status(t, err, 403)
	catalog, err := s.AddService(ctx, org, admin, "Team service")
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range []struct {
		id         uuid.UUID
		action     string
		targetType string
	}{{catalog.Id, "vault.service_created", "vault_service"}, {personal.Id, "vault.created", "vault_entry"}} {
		var targetType string
		if err = pool.QueryRow(ctx, `SELECT target_type FROM audit_logs WHERE org_id=$1 AND target_id=$2 AND action=$3`, org, record.id.String(), record.action).Scan(&targetType); err != nil {
			t.Fatal(err)
		}
		if targetType != record.targetType {
			t.Fatalf("audit target type for %s: got %s, want %s", record.action, targetType, record.targetType)
		}
	}
	_, err = s.AddService(ctx, org, admin, "team SERVICE")
	status(t, err, 409)
	otherCatalog, err := func() (api.VaultService, error) {
		exec(`UPDATE memberships SET role='admin' WHERE org_id=$1 AND user_id=$2`, otherOrg, otherUser)
		return s.AddService(ctx, otherOrg, otherUser, "Other service")
	}()
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Create(ctx, org, alice, api.VaultCreateInput{Title: "Foreign service", Kind: "password", Visibility: "personal", ServiceId: &otherCatalog.Id, Secret: ptr("fixture-other")})
	status(t, err, 400)
	_, err = s.Create(ctx, org, alice, api.VaultCreateInput{Title: "Unauthorized assignment", Kind: "password", Visibility: "assigned", ServiceId: &catalog.Id, Secret: ptr("fixture-assignment"), SubjectKind: ptr(api.VaultCreateInputSubjectKind("user")), SubjectId: &bob})
	status(t, err, 403)
	_, err = s.Create(ctx, org, admin, api.VaultCreateInput{Title: "Foreign user", Kind: "password", Visibility: "assigned", ServiceId: &catalog.Id, Secret: ptr("fixture-assignment"), SubjectKind: ptr(api.VaultCreateInputSubjectKind("user")), SubjectId: &otherUser})
	status(t, err, 400)
	assigned, err := s.Create(ctx, org, admin, api.VaultCreateInput{Title: "Team account", Kind: "password", Visibility: "assigned", ServiceId: &catalog.Id, Secret: ptr("fixture-first-secret"), Username: ptr("first-account"), SubjectKind: ptr(api.VaultCreateInputSubjectKind("user")), SubjectId: &alice})
	if err != nil {
		t.Fatal(err)
	}
	for _, user := range []uuid.UUID{admin, alice} {
		v, e := s.Reveal(ctx, org, user, assigned.Id, 0)
		if e != nil || v.Value != "fixture-first-secret" {
			t.Fatal("assigned entry unavailable to allowed actor")
		}
	}
	_, err = s.Reveal(ctx, org, bob, assigned.Id, 0)
	status(t, err, 404)
	workspace, err := s.List(ctx, org, alice, 1, 0, "Team account")
	if err != nil || workspace.Total != 1 || len(workspace.Entries) != 1 || workspace.Entries[0].CanDelete {
		t.Fatal("assigned entry listing/authority wrong")
	}
	updated, err := s.Update(ctx, org, alice, assigned.Id, api.VaultUpdateInput{Title: "Team account", Secret: ptr("fixture-second-secret"), Username: ptr("second-account"), ExpectedVersion: 1})
	if err != nil || updated.CurrentVersion != 2 {
		t.Fatal("recipient cannot rotate assigned entry")
	}
	_, err = s.Update(ctx, org, admin, assigned.Id, api.VaultUpdateInput{Title: "Stale", Secret: ptr("fixture-stale-secret"), ExpectedVersion: 1})
	status(t, err, 409)
	history, err := s.Versions(ctx, org, alice, assigned.Id, 50, 0)
	if err != nil || history.Total != 2 || history.CurrentVersion != 2 || len(history.Versions) != 2 || history.Versions[0].ChangedBy != alice {
		t.Fatal("version metadata not preserved")
	}
	old, err := s.Reveal(ctx, org, alice, assigned.Id, 1)
	if err != nil || old.Value != "fixture-first-secret" || old.Username != "first-account" {
		t.Fatal("prior version overwritten")
	}
	current, err := s.Reveal(ctx, org, admin, assigned.Id, 0)
	if err != nil || current.Value != "fixture-second-secret" || current.Username != "second-account" {
		t.Fatal("current version not updated")
	}
	for _, v := range []any{workspace, history, updated} {
		raw, _ := json.Marshal(v)
		if strings.Contains(string(raw), "fixture-first-secret") || strings.Contains(string(raw), "fixture-second-secret") {
			t.Fatal("plaintext secret leaked into metadata")
		}
	}
	var ciphertext string
	if err = pool.QueryRow(ctx, `SELECT sealed_payload FROM vault_versions WHERE org_id=$1 AND entry_id=$2 AND version=1`, org, assigned.Id).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ciphertext, "fixture-first-secret") || strings.Contains(ciphertext, "first-account") {
		t.Fatal("version plaintext persisted")
	}
	if _, err = pool.Exec(ctx, `UPDATE vault_versions SET sealed_payload='rewrite' WHERE org_id=$1 AND entry_id=$2`, org, assigned.Id); err == nil {
		t.Fatal("existing versions can be rewritten")
	}
	var auditMeta string
	if err = pool.QueryRow(ctx, `SELECT coalesce(string_agg(metadata::text,','),'') FROM audit_logs WHERE org_id=$1 AND action LIKE 'vault.%'`, org).Scan(&auditMeta); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(auditMeta, "fixture-") || strings.Contains(auditMeta, "account") {
		t.Fatal("secret or username logged in audit")
	}
	status(t, s.Delete(ctx, org, alice, assigned.Id, 2), 403)
	status(t, s.Delete(ctx, org, admin, assigned.Id, 1), 409)

	t.Run("current group authority", func(t *testing.T) {
		group := uuid.New()
		exec(`INSERT INTO user_groups(id,org_id,name) VALUES($1,$2,'Vault group')`, group, org)
		exec(`INSERT INTO group_members(org_id,group_id,user_id) VALUES($1,$2,$3)`, org, group, bob)
		entry, e := s.Create(ctx, org, admin, api.VaultCreateInput{Title: "Group key", Kind: "api_key", Visibility: "assigned", ServiceId: &catalog.Id, Secret: ptr("fixture-group-key"), SubjectKind: ptr(api.VaultCreateInputSubjectKind("group")), SubjectId: &group})
		if e != nil {
			t.Fatal(e)
		}
		if _, e = s.Reveal(ctx, org, bob, entry.Id, 0); e != nil {
			t.Fatal(e)
		}
		exec(`DELETE FROM group_members WHERE org_id=$1 AND group_id=$2 AND user_id=$3`, org, group, bob)
		_, e = s.Reveal(ctx, org, bob, entry.Id, 0)
		status(t, e, 404)
		_, e = s.Versions(ctx, org, bob, entry.Id, 50, 0)
		status(t, e, 404)
	})
	t.Run("live membership and account status", func(t *testing.T) {
		exec(`UPDATE memberships SET access_revoked_at=now() WHERE org_id=$1 AND user_id=$2`, org, alice)
		_, e := s.Reveal(ctx, org, alice, personal.Id, 0)
		status(t, e, 403)
		exec(`UPDATE memberships SET access_revoked_at=NULL WHERE org_id=$1 AND user_id=$2`, org, alice)
		exec(`UPDATE users SET status='deactivated' WHERE id=$1`, alice)
		_, e = s.Reveal(ctx, org, alice, personal.Id, 0)
		status(t, e, 403)
		exec(`UPDATE users SET status='active' WHERE id=$1`, alice)
	})
	t.Run("concurrent rotations cannot overwrite", func(t *testing.T) {
		var wg sync.WaitGroup
		errs := make(chan error, 2)
		for range 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, e := s.Update(ctx, org, alice, personal.Id, api.VaultUpdateInput{Title: "Personal API", Secret: ptr("fixture-concurrent-key"), ExpectedVersion: 1})
				errs <- e
			}()
		}
		wg.Wait()
		close(errs)
		success, stale := 0, 0
		for e := range errs {
			if e == nil {
				success++
			} else {
				status(t, e, 409)
				stale++
			}
		}
		if success != 1 || stale != 1 {
			t.Fatal("concurrent update did not preserve one winner")
		}
		h, e := s.Versions(ctx, org, alice, personal.Id, 50, 0)
		if e != nil || h.Total != 2 {
			t.Fatal("concurrent rotation lost or duplicated history")
		}
	})
	t.Run("audit failure prevents reveal", func(t *testing.T) {
		exec(`CREATE FUNCTION vault_test_refuse_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='vault.revealed' THEN RAISE EXCEPTION 'fixture audit unavailable'; END IF; RETURN NEW; END; $$`)
		exec(`CREATE TRIGGER vault_test_refuse_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION vault_test_refuse_audit()`)
		v, e := s.Reveal(ctx, org, admin, assigned.Id, 0)
		if e == nil || v.Value != "" {
			t.Fatal("secret returned without durable audit")
		}
		exec(`DROP TRIGGER vault_test_refuse_audit ON audit_logs`)
	})
	if err = s.Delete(ctx, org, admin, assigned.Id, 2); err != nil {
		t.Fatal(err)
	}
	_, err = s.Reveal(ctx, org, alice, assigned.Id, 0)
	status(t, err, 404)
	var remaining int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM vault_versions WHERE org_id=$1 AND entry_id=$2`, org, assigned.Id).Scan(&remaining); err != nil || remaining != 0 {
		t.Fatal("explicit deletion did not remove versions")
	}
}

func TestInputValidationDoesNotRequireDatabase(t *testing.T) {
	for _, in := range []api.VaultCreateInput{
		{Title: "Missing secret", Kind: "password", Visibility: "personal", ServiceName: ptr("Service")},
		{Title: "Missing service", Kind: "password", Visibility: "personal", Secret: ptr("value")},
		{Title: "Personal assignment", Kind: "password", Visibility: "personal", ServiceName: ptr("Service"), Secret: ptr("value"), SubjectId: ptr(uuid.New())},
		{Title: "Private assigned service", Kind: "password", Visibility: "assigned", ServiceName: ptr("Service"), Secret: ptr("value"), SubjectId: ptr(uuid.New()), SubjectKind: ptr(api.VaultCreateInputSubjectKind("user"))},
	} {
		_, _, _, _, err := createFields(in)
		status(t, err, 400)
	}
	_, _, err := pagination(101, 0)
	status(t, err, 400)
}
