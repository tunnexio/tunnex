package http

import (
	"net/url"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/licence"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

// An active gateway makes a successful mutation exercise pushOrg after commit.
// A typed-nil notifier previously panicked there, returning an unknown outcome
// to the HTTP caller although the group and attributed audit were committed.
func TestPolicyNilHubGroupMutationIntegration(t *testing.T) {
	if os.Getenv("APP_ACCESS_LOCAL_INTEGRATION") == "1" {
		secret := os.Getenv("AA0_DB_PASSWORD")
		if secret == "" {
			t.Fatal("owned local inputs required")
		}
		u := url.URL{Scheme: "postgres", User: url.UserPassword("aa0", secret), Host: "postgres:5432", Path: "/aa0", RawQuery: "sslmode=disable"}
		t.Setenv("TUNNEX_TEST_DATABASE_URL", u.String())
	}
	ctx, pool := testpostgres.New(t)
	org, actor, gateway := uuid.New(), uuid.New(), uuid.New()
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{"INSERT INTO users(id,email,email_verified_at) VALUES($1,$2,now())", []any{actor, "nilhub-" + actor.String() + "@example.test"}},
		{"INSERT INTO organizations(id,name,slug) VALUES($1,'Nil hub',$2)", []any{org, "nilhub-" + org.String()}},
		{"INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'owner')", []any{org, actor}},
		{"INSERT INTO nodes(id,org_id,name,cert_serial,status,enrolled_kind) VALUES($1,$2,'nilhub-gateway',$3,'active','gateway')", []any{gateway, org, gateway.String()}},
	} {
		if _, err := pool.Exec(ctx, q.sql, q.args...); err != nil {
			t.Fatal("disposable fixture seed failed", err)
		}
	}
	ctx = authctx.WithOrg(authctx.WithPrincipal(ctx, &authctx.Principal{UserID: actor, EmailVerified: true, Roles: map[uuid.UUID]string{org: "owner"}}), org)
	for name, port := range map[string]policyPort{"plain": NewPolicyPort(pool, nil), "fqdn": NewPolicyPortWithFQDN(pool, nil, &licence.Manager{})} {
		t.Run(name, func(t *testing.T) {
			group, err := port.CreateGroup(ctx, org, "nilhub-"+name, "disposable regression")
			if err != nil {
				t.Fatal(err)
			}
			var audit int
			if err = pool.QueryRow(ctx, "SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='group.created' AND target_id=$2 AND actor_user_id=$3", org, group.ID.String(), actor).Scan(&audit); err != nil || audit != 1 {
				t.Fatalf("attributed committed audit count=%d err=%v", audit, err)
			}
			members, err := port.ListGroups(ctx, org)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, g := range members {
				found = found || g.ID == group.ID
			}
			if !found {
				t.Fatal("successful group absent from readback")
			}
		})
	}
}
