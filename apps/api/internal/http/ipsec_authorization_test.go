package http

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

// Exercise the existing authorization seam. No IPsec HTTP handler exists yet.
func TestIPsecManagementAuthorization(t *testing.T) {
	org := uuid.New()
	if _, err := authorize(context.Background(), org, rbac.PermIPsecManage); !hasCode(err, 401, "unauthenticated") {
		t.Fatal("anonymous IPsec authority must be refused")
	}
	for _, role := range []string{rbac.RoleOwner, rbac.RoleAdmin} {
		t.Run(role, func(t *testing.T) {
			p := &authctx.Principal{UserID: uuid.New(), Roles: map[uuid.UUID]string{org: role}}
			ctx := authctx.WithPrincipal(context.Background(), p)
			if _, err := authorize(ctx, org, rbac.PermIPsecManage); !hasCode(err, 403, "email_not_verified") {
				t.Fatal("unverified manager must not administer IPsec")
			}
			p.EmailVerified = true
			allowed, err := authorize(ctx, org, rbac.PermIPsecManage)
			if err != nil {
				t.Fatal("verified manager should hold IPsec authority")
			}
			if got, ok := authctx.OrgFrom(allowed); !ok || got != org {
				t.Fatal("authorized organization context missing")
			}
			if _, err := authorize(ctx, uuid.New(), rbac.PermIPsecManage); !hasCode(err, 404, "org_not_found") {
				t.Fatal("manager authority must not cross organizations")
			}
			p.MustChangePassword = true
			if _, err := authorize(ctx, org, rbac.PermIPsecManage); !hasCode(err, 403, "password_change_required") {
				t.Fatal("bootstrap password wall must precede IPsec authority")
			}
		})
	}
	for _, role := range []string{rbac.RoleMember, rbac.RoleAIAdmin, rbac.RoleAIView, rbac.RoleAgent, rbac.RoleOperator} {
		t.Run(role, func(t *testing.T) {
			p := &authctx.Principal{UserID: uuid.New(), EmailVerified: true, Roles: map[uuid.UUID]string{org: role}}
			if role == rbac.RoleOperator {
				p.UserID, p.MachineID, p.AuthMethod = uuid.Nil, uuid.New(), authctx.AuthMachine
				p.EmailVerified = false
			}
			if _, err := authorize(authctx.WithPrincipal(context.Background(), p), org, rbac.PermIPsecManage); !hasCode(err, 403, "forbidden") {
				t.Fatal("unrelated or machine authority must not manage IPsec")
			}
		})
	}
}
