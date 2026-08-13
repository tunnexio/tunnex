package http

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
)

// The DEPLOYMENT-level gate (S12.11). requireCPAdmin is the only door to the cross-tenant grant surface, so
// every arm of it is a security boundary rather than a validation step.
func TestRequireCPAdmin(t *testing.T) {
	ctxWith := func(p *authctx.Principal) context.Context {
		return authctx.WithPrincipal(context.Background(), p)
	}
	holder := func() *authctx.Principal {
		return &authctx.Principal{UserID: uuid.New(), Email: "a@t.local", EmailVerified: true, CPAdmin: true}
	}

	if _, err := requireCPAdmin(ctxWith(holder())); err != nil {
		t.Fatalf("⛔ a holder was refused — the capability is unreachable and the surface is dead: %v", err)
	}

	// ⛔ THE REFUSAL IS THE RULING. Without it the boundary is "signed in vs not", which every invited
	// member of every tenant trivially clears — and they would be granting themselves ownership of orgs
	// they have never been in.
	p := holder()
	p.CPAdmin = false
	assertRefusal(t, "a non-holder", 403, "cp_admin_required", requireCPAdminErr(ctxWith(p)))

	// ⛔ THE FORCED-PASSWORD WALL COVERS THIS ROUTE, and it is the reason requireCPAdmin WRAPS
	// requireVerifiedUser instead of hand-rolling its checks beside it.
	//
	// The bootstrap administrator holds `cp_admin` AND the one-time password that was printed to
	// `docker compose logs` — shipped, aggregated, searchable. A gate that asked only "is this a holder"
	// would let that public credential grant itself ownership of every organization on the deployment
	// BEFORE being changed. Create-org shipped exactly that hole once already (see requireVerifiedUser).
	p = holder()
	p.MustChangePassword = true
	assertRefusal(t, "the un-rotated bootstrap credential", 403, "password_change_required", requireCPAdminErr(ctxWith(p)))

	p = holder()
	p.EmailVerified = false
	assertRefusal(t, "an unverified account", 403, "email_not_verified", requireCPAdminErr(ctxWith(p)))

	assertRefusal(t, "an unauthenticated caller", 401, "unauthenticated", requireCPAdminErr(context.Background()))
}

// ⛔ THE GATE IN PLACE, NOT THE GATE IN ISOLATION — and this session is why.
//
// TestRequireCPAdmin above calls the function directly, so every arm of it can be right while the
// COMPOSITION is wrong. The one real defect found while building this surface lived exactly there: both
// routes answered `400 validation_failed` to a sessionless caller because the spec validator ran ahead of
// authentication, and no test of the gate itself could have seen it.
//
// ⚠ THE SERVICE IS NIL ON PURPOSE. If a refusal ever stops happening before the service call, this panics
// instead of quietly passing — the failure is structural rather than an assertion nobody wrote.
func TestTheAdminHandlersRefuseBeforeDoingAnything(t *testing.T) {
	s := apiServer{} // no orgs service: reaching it is the failure
	org, user := uuid.New(), uuid.New()
	role := api.ChangeRoleRequestRole("member")

	nonHolder := &authctx.Principal{UserID: uuid.New(), EmailVerified: true, CPAdmin: false}
	walled := &authctx.Principal{UserID: uuid.New(), EmailVerified: true, CPAdmin: true, MustChangePassword: true}

	for _, tc := range []struct {
		who  string
		p    *authctx.Principal
		code string
	}{
		{"a signed-in member of some org", nonHolder, "cp_admin_required"},
		{"the un-rotated bootstrap credential", walled, "password_change_required"},
	} {
		ctx := authctx.WithPrincipal(context.Background(), tc.p)

		_, err := s.AdminSetOrgRole(ctx, api.AdminSetOrgRoleRequestObject{
			OrgId: org, UserId: user,
			Body: &api.ChangeRoleRequest{Role: role},
		})
		assertRefusal(t, tc.who+" (grant a role)", 403, tc.code, err)

		_, err = s.AdminSetCpAdmin(ctx, api.AdminSetCpAdminRequestObject{
			UserId: user,
			Body:   &api.CpAdminRequest{Granted: true},
		})
		assertRefusal(t, tc.who+" (grant the capability)", 403, tc.code, err)
	}
}

func requireCPAdminErr(ctx context.Context) error {
	_, err := requireCPAdmin(ctx)
	return err
}

func assertRefusal(t *testing.T, who string, status int, code string, err error) {
	t.Helper()
	var ae *apierr.Error
	if !errors.As(err, &ae) {
		t.Fatalf("⛔ %s WAS ADMITTED to the cross-tenant grant surface (err = %v)", who, err)
	}
	if ae.Status != status || ae.Code != code {
		t.Errorf("%s: refusal = %d %s; want %d %s", who, ae.Status, ae.Code, status, code)
	}
}

// ⛔ THE TRAP, PINNED: the capability must be asked BESIDE RoleIn, never inside it.
//
// The shortcut this test exists to catch is a two-line one — `if p.CPAdmin { return authctx.WithOrg(ctx,
// orgID), nil }` at the top of authorize(), or an owner entry synthesised into Principal.Roles at session
// build. Either makes `RoleIn` LIE, and `RoleIn` is what EVERY org-scoped handler in the product asks: one
// deployment-level capability would silently become full access to every tenant's devices, policies,
// audit feed and settings at once.
//
// ⚠ A SOURCE ASSERTION, DELIBERATELY. The behavioural version of this check would have to enumerate every
// org-scoped endpoint and prove a CP admin is refused by each — a census that goes stale the day someone
// adds the eighty-first route. The seam is one function; guard the seam.
func TestAuthorizeDoesNotAskTheDeploymentQuestion(t *testing.T) {
	src, err := os.ReadFile("handlers.go")
	if err != nil {
		t.Fatal(err)
	}
	body := funcBody(string(src), "func authorize(")
	if body == "" {
		t.Fatal("could not find authorize() — this guard has stopped guarding anything")
	}
	for _, needle := range []string{"CPAdmin", "cp_admin"} {
		if strings.Contains(body, needle) {
			t.Errorf("⛔ authorize() NOW READS %q. The org-scoped gate has been given a deployment-level "+
				"bypass: every membership check in the product returns true for a holder, in tenants they "+
				"are not in. The cross-tenant surface has its own gate (requireCPAdmin) on its own route "+
				"prefix — put it there.", needle)
		}
	}

	authctxSrc, err := os.ReadFile("../authctx/authctx.go")
	if err != nil {
		t.Fatal(err)
	}
	roleIn := funcBody(string(authctxSrc), "func (p *Principal) RoleIn(")
	if roleIn == "" {
		t.Fatal("could not find RoleIn()")
	}
	if strings.Contains(roleIn, "CPAdmin") {
		t.Error("⛔ RoleIn() NOW READS CPAdmin — it answers 'what is this person's role in this org', and a " +
			"deployment capability is not a role in any org. Every caller of RoleIn would start believing " +
			"the holder is a member.")
	}

	// And the Roles map itself must not be seeded from the capability at session/bearer build time — the
	// same lie, told one layer earlier, where no gate can see it.
	for _, f := range []string{"session.go", "bearer.go"} {
		b, e := os.ReadFile(f)
		if e != nil {
			t.Fatal(e)
		}
		for _, line := range strings.Split(string(b), "\n") {
			l := strings.TrimSpace(line)
			if strings.HasPrefix(l, "//") {
				continue
			}
			if strings.Contains(l, "Roles[") && strings.Contains(l, "CPAdmin") {
				t.Errorf("⛔ %s SYNTHESISES A ROLE FROM THE CAPABILITY: %s", f, l)
			}
		}
	}
}

// funcBody returns the source of the function starting with the given prefix, up to its closing brace at
// column 0. Crude on purpose: it must not need a Go parser to keep working.
func funcBody(src, prefix string) string {
	i := strings.Index(src, prefix)
	if i < 0 {
		return ""
	}
	rest := src[i:]
	if j := strings.Index(rest, "\n}\n"); j > 0 {
		return rest[:j]
	}
	return rest
}
