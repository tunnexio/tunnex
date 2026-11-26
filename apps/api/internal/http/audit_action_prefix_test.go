package http

import (
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"github.com/tunnexio/tunnex/apps/api/internal/tenancy"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

// VAULT-UX-2 W1: an action family filter is a literal "family." prefix. Anything that could widen it
// (LIKE metacharacters, no trailing dot, upper case, overlong) is refused before any read.
func TestListAuditLogsActionPrefixRejectsUnsafePrefixes(t *testing.T) {
	s := apiServer{}
	org := uuid.New()
	ctx := principalWithRole(org, rbac.RoleAdmin)
	for _, bad := range []string{"", "vault", "vault.%", "vault._", "%.", "Vault.", "vault.created", ".", "vault..", strings.Repeat("a", 64) + "."} {
		prefix := bad
		_, err := s.ListAuditLogs(ctx, api.ListAuditLogsRequestObject{OrgId: org, Params: api.ListAuditLogsParams{ActionPrefix: &prefix}})
		if !hasCode(err, 400, "invalid_action_filter") {
			t.Fatalf("prefix %q: want 400 invalid_action_filter, got %v", bad, err)
		}
	}
}

// Every vault.* action is one family whatever its target type, and the member self-scope still holds.
func TestListAuditLogsActionPrefixSelectsTheWholeFamily(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	org, admin, member := uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, "INSERT INTO organizations(id,name,slug) VALUES($1,'audit prefix',$2)", org, org.String()); err != nil {
		t.Fatal(err)
	}
	for _, user := range []uuid.UUID{admin, member} {
		if _, err := pool.Exec(ctx, "INSERT INTO users(id,email,name) VALUES($1,$2,'audit user')", user, user.String()+"@test.local"); err != nil {
			t.Fatal(err)
		}
	}
	rows := []struct {
		actor          *uuid.UUID
		action, target string
	}{
		{&admin, "vault.created", "vault_entry"},
		{&admin, "vault.service_created", "vault_service"},
		{nil, "vault.personal_entries_purged", "user"},
		{&member, "vault.revealed", "vault_entry"},
		{&admin, "vaultx.created", "vault_entry"},
		{&admin, "beam.share.created", "beam_share"},
	}
	for _, r := range rows {
		var err error
		if r.actor == nil {
			_, err = pool.Exec(ctx, "INSERT INTO audit_logs(org_id,actor_system,action,target_type,target_id) VALUES($1,'vault',$2,$3,$4)", org, r.action, r.target, uuid.NewString())
		} else {
			_, err = pool.Exec(ctx, "INSERT INTO audit_logs(org_id,actor_user_id,action,target_type,target_id) VALUES($1,$2,$3,$4,$5)", org, *r.actor, r.action, r.target, uuid.NewString())
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	s := apiServer{orgs: tenancy.NewService(pool)}
	list := func(user uuid.UUID, role string, params api.ListAuditLogsParams) []api.AuditLogEntry {
		t.Helper()
		p := &authctx.Principal{UserID: user, EmailVerified: true, Roles: map[uuid.UUID]string{org: role}}
		result, err := s.ListAuditLogs(authctx.WithPrincipal(ctx, p), api.ListAuditLogsRequestObject{OrgId: org, Params: params})
		if err != nil {
			t.Fatal(err)
		}
		return result.(api.ListAuditLogs200JSONResponse).Body
	}
	vault := "vault."
	got := map[string]bool{}
	for _, e := range list(admin, rbac.RoleAdmin, api.ListAuditLogsParams{ActionPrefix: &vault}) {
		got[e.Action] = true
	}
	want := []string{"vault.created", "vault.service_created", "vault.personal_entries_purged", "vault.revealed"}
	if len(got) != len(want) {
		t.Fatalf("vault family = %v, want exactly %v", got, want)
	}
	for _, action := range want {
		if !got[action] {
			t.Fatalf("vault family is missing %s: %v", action, got)
		}
	}
	// Composes with the other filters.
	target := "vault_service"
	if rows := list(admin, rbac.RoleAdmin, api.ListAuditLogsParams{ActionPrefix: &vault, TargetType: &target}); len(rows) != 1 || rows[0].Action != "vault.service_created" {
		t.Fatalf("prefix plus target type: %+v", rows)
	}
	// A member still reads only their own rows through the family filter.
	if rows := list(member, rbac.RoleMember, api.ListAuditLogsParams{ActionPrefix: &vault}); len(rows) != 1 || rows[0].Action != "vault.revealed" {
		t.Fatalf("member self-scope leaked through the prefix filter: %+v", rows)
	}
}
