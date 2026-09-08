package http

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"github.com/tunnexio/tunnex/apps/api/internal/tenancy"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

// TestListAuditLogsHalfCursorRejected: a keyset cursor is both halves or neither.
// A half-cursor is rejected 400 BEFORE any DB read (an authed principal is enough
// to pass authorize), so it never silently resets to page 1.
func TestListAuditLogsHalfCursorRejected(t *testing.T) {
	s := apiServer{}
	org := uuid.New()
	ctx := principalWithRole(org, rbac.RoleMember) // PermOrgView is enough
	ts := time.Now()
	_, err := s.ListAuditLogs(ctx, api.ListAuditLogsRequestObject{
		OrgId:  org,
		Params: api.ListAuditLogsParams{CursorTs: &ts}, // ts without id
	})
	if !hasCode(err, 400, "invalid_cursor") {
		t.Fatalf("half-cursor (ts only): want 400 invalid_cursor, got %v", err)
	}
	id := openapi_types.UUID(uuid.New())
	_, err = s.ListAuditLogs(ctx, api.ListAuditLogsRequestObject{
		OrgId:  org,
		Params: api.ListAuditLogsParams{CursorId: &id}, // id without ts
	})
	if !hasCode(err, 400, "invalid_cursor") {
		t.Fatalf("half-cursor (id only): want 400 invalid_cursor, got %v", err)
	}
}

func TestAuditActorScopeMembersAreSelfOnly(t *testing.T) {
	org := uuid.New()
	member := uuid.New()
	p := &authctx.Principal{UserID: member, Roles: map[uuid.UUID]string{org: rbac.RoleMember}}
	got := auditActorScope(p, org)
	if got == nil || *got != member {
		t.Fatalf("member scope = %v, want own actor %s", got, member)
	}
	admin := &authctx.Principal{UserID: uuid.New(), Roles: map[uuid.UUID]string{org: rbac.RoleAdmin}}
	if got := auditActorScope(admin, org); got != nil {
		t.Fatalf("admin scope = %v, want organization-wide nil actor filter", got)
	}
}

func TestAuditLogAIRolesCannotReadOtherActors(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	org, viewer, other := uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, "INSERT INTO organizations(id,name,slug) VALUES($1,'audit roles',$2)", org, org.String()); err != nil {
		t.Fatal(err)
	}
	for _, user := range []uuid.UUID{viewer, other} {
		if _, err := pool.Exec(ctx, "INSERT INTO users(id,email,name) VALUES($1,$2,'audit user')", user, user.String()+"@test.local"); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, "INSERT INTO audit_logs(org_id,actor_user_id,action) VALUES($1,$2,'device.created')", org, user); err != nil {
			t.Fatal(err)
		}
	}
	s := apiServer{orgs: tenancy.NewService(pool)}
	for _, roles := range [][]string{{"member"}, {"ai-view"}, {"ai-admin"}, {"ai-admin", "member"}, {"ai-view", "member"}, {"admin", "ai-view"}, {"owner", "ai-admin"}} {
		t.Run(strings.Join(roles, "+"), func(t *testing.T) {
			p := &authctx.Principal{UserID: viewer, EmailVerified: true, Roles: map[uuid.UUID]string{org: roles[0]}, RoleSets: map[uuid.UUID][]string{org: roles}}
			principalCtx := authctx.WithPrincipal(ctx, p)
			for _, actorFilter := range []*openapi_types.UUID{nil, &other} {
				result, err := s.ListAuditLogs(principalCtx, api.ListAuditLogsRequestObject{OrgId: org, Params: api.ListAuditLogsParams{Actor: actorFilter}})
				if err != nil {
					t.Fatal(err)
				}
				rows := result.(api.ListAuditLogs200JSONResponse).Body
				admin := roles[0] == "admin" || roles[0] == "owner"
				if admin {
					want := 2
					if actorFilter != nil {
						want = 1
					}
					if len(rows) != want {
						t.Fatalf("administrator got %d events, want %d", len(rows), want)
					}
				} else if len(rows) != 1 || rows[0].ActorId == nil || *rows[0].ActorId != viewer {
					t.Fatalf("AI/member audit scope leaked another actor: %+v", rows)
				}
			}
		})
	}
}

// TestToAuditLogEntrySecretFreeRender is watch-item (e): the viewer renders a
// secret-adjacent event (sso.config_updated) and must surface only the KEYED
// fingerprint — never the secret or any sealed material. S4.5 proved the write
// side keeps metadata secret-free; this is where a future write-side regression
// would become visible, so the display asserts it too.
func TestToAuditLogEntrySecretFreeRender(t *testing.T) {
	actor := uuid.New()
	// Exactly what SetConfig writes: provider/client_id/enabled + the 12-hex keyed
	// fingerprint. No secret, no sealed bytes.
	meta := []byte(`{"provider":"google","client_id":"gid-123","enabled":true,"secret_fingerprint":"a1b2c3d4e5f6"}`)
	e := toAuditLogEntry(sqlc.AuditLog{
		ID:          uuid.New(),
		Action:      "sso.config_updated",
		CreatedAt:   time.Now(),
		ActorUserID: pgtype.UUID{Bytes: [16]byte(actor), Valid: true},
		Metadata:    meta,
	})

	if e.ActorId == nil {
		t.Fatal("actor should be attributed")
	}
	fp, _ := e.Details["secret_fingerprint"].(string)
	if fp != "a1b2c3d4e5f6" || len(fp) != 12 {
		t.Fatalf("details must surface the 12-hex fingerprint, got %q", fp)
	}
	// No secret material: no client_secret / sealed key, and no key mentioning
	// "secret" other than the (safe) keyed fingerprint.
	if _, ok := e.Details["client_secret"]; ok {
		t.Fatal("details leaked a client_secret key")
	}
	for k, v := range e.Details {
		lk := strings.ToLower(k)
		if (strings.Contains(lk, "secret") && lk != "secret_fingerprint") || strings.Contains(lk, "sealed") {
			t.Fatalf("details carries a secret-looking key %q=%v", k, v)
		}
	}
}
