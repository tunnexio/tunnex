package http

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/redis/go-redis/v9"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/invites"
	"github.com/tunnexio/tunnex/apps/api/internal/mail"
	"github.com/tunnexio/tunnex/apps/api/internal/mfa"
	"github.com/tunnexio/tunnex/apps/api/internal/password"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"github.com/tunnexio/tunnex/apps/api/internal/session"
	"github.com/tunnexio/tunnex/apps/api/internal/tenancy"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

// RBAC-0 regression tests: each one is an attack from docs/RBAC-0-people-management-security.md, driven
// through the handler an attacker would call, and asserting the attack is refused.

const rbac0Password = "rbac0-correct-horse-battery"

type rbac0Mailer struct{ fail bool }

func (rbac0Mailer) Kind() string { return "rbac0" }

func (m rbac0Mailer) Send(context.Context, mail.Message) error {
	if m.fail {
		return errors.New("smtp down")
	}
	return nil
}

type rbac0Fixture struct {
	ctx    context.Context
	pool   *pgxpool.Pool
	q      *sqlc.Queries
	server apiServer
	store  *session.Store
	orgA   uuid.UUID
	orgB   uuid.UUID
	// ownerA is the SOLE owner of A; adminA is an admin of A; memberA a plain member of A; outsider is
	// a member of B only; multi is a member of A and the owner of B.
	ownerA, adminA, memberA, outsider, multi sqlc.User
}

func newRBAC0Fixture(t *testing.T, mailFails bool) *rbac0Fixture {
	t.Helper()
	ctx, pool := testpostgres.New(t)
	q := sqlc.New(pool)
	f := &rbac0Fixture{ctx: ctx, pool: pool, q: q, orgA: uuid.New(), orgB: uuid.New()}
	for _, org := range []uuid.UUID{f.orgA, f.orgB} {
		if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'RBAC-0',$2)`, org, "rbac0-"+org.String()); err != nil {
			t.Fatal(err)
		}
	}
	hash, err := password.Hash(rbac0Password)
	if err != nil {
		t.Fatal(err)
	}
	mk := func(name string, memberships map[uuid.UUID]string) sqlc.User {
		u, e := q.CreateUser(ctx, sqlc.CreateUserParams{Email: name + "-" + uuid.NewString()[:8] + "@rbac0.test", Name: name})
		if e != nil {
			t.Fatal(e)
		}
		if _, e = pool.Exec(ctx, `UPDATE users SET email_verified_at=now(), password_hash=$2 WHERE id=$1`, u.ID, hash); e != nil {
			t.Fatal(e)
		}
		for org, role := range memberships {
			if _, e = pool.Exec(ctx, `INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,$3)`, org, u.ID, role); e != nil {
				t.Fatal(e)
			}
		}
		u, e = q.GetUserByID(ctx, u.ID)
		if e != nil {
			t.Fatal(e)
		}
		return u
	}
	f.ownerA = mk("owner-a", map[uuid.UUID]string{f.orgA: "owner"})
	f.adminA = mk("admin-a", map[uuid.UUID]string{f.orgA: "admin"})
	f.memberA = mk("member-a", map[uuid.UUID]string{f.orgA: "member"})
	f.outsider = mk("outsider", map[uuid.UUID]string{f.orgB: "member"})
	f.multi = mk("multi", map[uuid.UUID]string{f.orgA: "member", f.orgB: "owner"})

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1})
	t.Cleanup(func() { _ = rdb.Close() })
	f.store = session.NewWithClient(rdb, time.Hour, 24*time.Hour)
	sealer, err := crypto.NewSealer(bytes.Repeat([]byte{41}, crypto.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	f.server = apiServer{
		system:            q,
		sessions:          f.store,
		mfa:               mfa.NewService(pool, sealer, nil, logger),
		members:           tenancy.NewMembershipService(pool, f.store),
		invites:           invites.NewService(pool, rbac0Mailer{fail: mailFails}, "https://rbac0.test", logger),
		orgs:              tenancy.NewService(pool),
		mfaEnforceEnabled: true,
	}
	return f
}

// as returns a context for u signed in with a real browser session, with u's current memberships.
func (f *rbac0Fixture) as(t *testing.T, u sqlc.User) context.Context {
	t.Helper()
	parent, err := f.store.CreateWithAuthority(f.ctx, u.ID, authctx.AuthLocalPassword, u.AppAuthEpoch)
	if err != nil {
		t.Fatal(err)
	}
	c := mfaHandlerContext(f.ctx, parent)
	p, _ := authctx.PrincipalFrom(c)
	ms, err := f.q.ListMembershipsByUser(f.ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	p.Email = u.Email
	p.Roles = map[uuid.UUID]string{}
	p.RoleSets = map[uuid.UUID][]string{}
	for _, m := range ms {
		p.Roles[m.OrgID] = m.Role
		p.RoleSets[m.OrgID] = m.Roles
	}
	return c
}

func (f *rbac0Fixture) role(t *testing.T, org, user uuid.UUID) string {
	t.Helper()
	var role string
	if err := f.pool.QueryRow(f.ctx, `SELECT role FROM memberships WHERE org_id=$1 AND user_id=$2`, org, user).Scan(&role); err != nil {
		t.Fatal(err)
	}
	return role
}

func (f *rbac0Fixture) status(t *testing.T, user uuid.UUID) string {
	t.Helper()
	var status string
	if err := f.pool.QueryRow(f.ctx, `SELECT status FROM users WHERE id=$1`, user).Scan(&status); err != nil {
		t.Fatal(err)
	}
	return status
}

// D1: an admin must not be able to demote the sole owner by inviting the owner's own address.
func TestRBAC0InviteForExistingMemberIsRefused(t *testing.T) {
	f := newRBAC0Fixture(t, true)
	_, err := f.server.CreateInvitation(f.as(t, f.adminA), api.CreateInvitationRequestObject{OrgId: f.orgA,
		Body: &api.CreateInvitationJSONRequestBody{Email: openapi_types.Email(f.ownerA.Email), Role: "member"}})
	if mfaHandlerErrorCode(err) != "already_member" {
		t.Fatalf("inviting an existing member must be refused already_member, got %v", err)
	}
	if got := f.role(t, f.orgA, f.ownerA.ID); got != "owner" {
		t.Fatalf("owner role changed to %q", got)
	}
}

// D1: even a pending invitation that predates the fix (or races a join) must never rewrite roles on
// accept, and the token alone must not attach an existing account.
func TestRBAC0AcceptNeverReplacesRolesOrAttachesWithoutSignIn(t *testing.T) {
	f := newRBAC0Fixture(t, true)
	insertInvite := func(org uuid.UUID, email, role string) string {
		t.Helper()
		raw := "rbac0-token-" + uuid.NewString()
		if _, err := f.q.CreateInvitation(f.ctx, sqlc.CreateInvitationParams{OrgID: org, Email: email, Role: role,
			TokenHash: rbac0HashToken(raw), ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
		return raw
	}
	// The pre-existing pending invite for the sole owner, accepted with the token alone.
	tok := insertInvite(f.orgA, f.ownerA.Email, "member")
	if _, err := f.server.AcceptInvitation(f.ctx, api.AcceptInvitationRequestObject{Body: &api.AcceptInvitationJSONRequestBody{Token: tok}}); err == nil {
		t.Fatal("token-only accept for an existing account must be refused")
	}
	if got := f.role(t, f.orgA, f.ownerA.ID); got != "owner" {
		t.Fatalf("sole owner demoted to %q via invite accept", got)
	}
	// Signed in as the owner, the accept still never lowers roles.
	if _, err := f.server.AcceptInvitation(f.as(t, f.ownerA), api.AcceptInvitationRequestObject{Body: &api.AcceptInvitationJSONRequestBody{Token: tok}}); mfaHandlerErrorCode(err) != "already_member" {
		t.Fatalf("accept by an existing member must be refused already_member, got %v", err)
	}
	if got := f.role(t, f.orgA, f.ownerA.ID); got != "owner" {
		t.Fatalf("sole owner demoted to %q via signed-in accept", got)
	}

	// An existing account that is NOT yet a member: token alone → sign in required; signed in → joins.
	tok = insertInvite(f.orgA, f.outsider.Email, "member")
	if _, err := f.server.AcceptInvitation(f.ctx, api.AcceptInvitationRequestObject{Body: &api.AcceptInvitationJSONRequestBody{Token: tok}}); mfaHandlerErrorCode(err) != "sign_in_required" {
		t.Fatalf("token-only accept for an existing account: want sign_in_required, got %v", err)
	}
	if _, err := f.server.AcceptInvitation(f.as(t, f.memberA), api.AcceptInvitationRequestObject{Body: &api.AcceptInvitationJSONRequestBody{Token: tok}}); mfaHandlerErrorCode(err) != "invite_account_mismatch" {
		t.Fatalf("accept while signed in as someone else: want invite_account_mismatch, got %v", err)
	}
	if _, err := f.server.AcceptInvitation(f.as(t, f.outsider), api.AcceptInvitationRequestObject{Body: &api.AcceptInvitationJSONRequestBody{Token: tok}}); err != nil {
		t.Fatalf("signed-in invitee must be able to accept: %v", err)
	}
	if got := f.role(t, f.orgA, f.outsider.ID); got != "member" {
		t.Fatalf("invitee role = %q", got)
	}
}

// D1: an admin cannot invite an owner (regression pin), and the raw token is not handed to the admin
// when the email was actually delivered.
func TestRBAC0InviteOwnerRoleAndTokenExposure(t *testing.T) {
	f := newRBAC0Fixture(t, false)
	_, err := f.server.CreateInvitation(f.as(t, f.adminA), api.CreateInvitationRequestObject{OrgId: f.orgA,
		Body: &api.CreateInvitationJSONRequestBody{Email: "new-owner@rbac0.test", Role: "owner"}})
	if mfaHandlerErrorCode(err) != "forbidden" {
		t.Fatalf("admin inviting an owner must be forbidden, got %v", err)
	}
	out, err := f.server.CreateInvitation(f.as(t, f.adminA), api.CreateInvitationRequestObject{OrgId: f.orgA,
		Body: &api.CreateInvitationJSONRequestBody{Email: "new-member@rbac0.test", Role: "member"}})
	if err != nil {
		t.Fatal(err)
	}
	body := out.(api.CreateInvitation202JSONResponse).Body
	if body.Delivered == nil || !*body.Delivered || body.InviteToken != nil {
		t.Fatalf("a delivered invitation must not return the raw token to the admin: %+v", body)
	}
}

// D2: an MFA reset must target a member of the caller's org, and an admin cannot reset an owner.
func TestRBAC0AdminMFAResetIsOrgScopedAndOwnerProtected(t *testing.T) {
	f := newRBAC0Fixture(t, true)
	_, err := f.server.AdminResetMfa(f.as(t, f.adminA), api.AdminResetMfaRequestObject{OrgId: f.orgA, UserId: f.outsider.ID})
	if mfaHandlerErrorCode(err) != "member_not_found" {
		t.Fatalf("cross-org MFA reset must be member_not_found, got %v", err)
	}
	_, err = f.server.AdminResetMfa(f.as(t, f.adminA), api.AdminResetMfaRequestObject{OrgId: f.orgA, UserId: f.ownerA.ID})
	if mfaHandlerErrorCode(err) != "forbidden" {
		t.Fatalf("admin resetting an owner's MFA must be forbidden, got %v", err)
	}
	// D9: resetting a member's factor requires step-up.
	_, err = f.server.AdminResetMfa(f.as(t, f.adminA), api.AdminResetMfaRequestObject{OrgId: f.orgA, UserId: f.memberA.ID})
	if mfaHandlerErrorCode(err) != "current_password_required" {
		t.Fatalf("MFA reset without re-authentication: want current_password_required, got %v", err)
	}
}

// D3: an admin cannot deactivate an owner, even one who is not the last owner.
func TestRBAC0AdminCannotDeactivateOwner(t *testing.T) {
	f := newRBAC0Fixture(t, true)
	if _, err := f.pool.Exec(f.ctx, `UPDATE memberships SET role='owner' WHERE org_id=$1 AND user_id=$2`, f.orgA, f.memberA.ID); err != nil {
		t.Fatal(err)
	}
	_, err := f.server.DeactivateMember(f.as(t, f.adminA), api.DeactivateMemberRequestObject{OrgId: f.orgA, UserId: f.ownerA.ID})
	if mfaHandlerErrorCode(err) != "forbidden" {
		t.Fatalf("admin deactivating an owner must be forbidden, got %v", err)
	}
	if got := f.status(t, f.ownerA.ID); got != "active" {
		t.Fatalf("owner status = %q", got)
	}
	_, err = f.server.ReactivateMember(f.as(t, f.adminA), api.ReactivateMemberRequestObject{OrgId: f.orgA, UserId: f.ownerA.ID})
	if mfaHandlerErrorCode(err) != "forbidden" {
		t.Fatalf("admin reactivating an owner must be forbidden, got %v", err)
	}
}

// D9: a role change requires recent re-authentication, even by an owner.
func TestRBAC0RoleChangeRequiresStepUp(t *testing.T) {
	f := newRBAC0Fixture(t, true)
	_, err := f.server.ChangeMemberRoles(f.as(t, f.ownerA), api.ChangeMemberRolesRequestObject{OrgId: f.orgA, UserId: f.memberA.ID,
		Body: &api.ChangeMemberRolesJSONRequestBody{Roles: []api.ChangeRolesRequestRoles{"admin"}}})
	if mfaHandlerErrorCode(err) != "current_password_required" {
		t.Fatalf("role change without re-authentication: want current_password_required, got %v", err)
	}
	if got := f.role(t, f.orgA, f.memberA.ID); got != "member" {
		t.Fatalf("role changed to %q without step-up", got)
	}
	_, err = f.server.ChangeMemberRole(f.as(t, f.ownerA), api.ChangeMemberRoleRequestObject{OrgId: f.orgA, UserId: f.memberA.ID,
		Body: &api.ChangeMemberRoleJSONRequestBody{Role: "admin"}})
	if mfaHandlerErrorCode(err) != "current_password_required" {
		t.Fatalf("legacy role change without re-authentication: want current_password_required, got %v", err)
	}
}

// D7: a deployment administrator cannot grant a machine role; the answer is a clean 400.
func TestRBAC0CPAdminGrantRejectsMachineRoles(t *testing.T) {
	f := newRBAC0Fixture(t, true)
	for _, role := range []string{rbac.RoleOperator, rbac.RoleAgent} {
		err := f.server.orgs.GrantOrgRole(f.ctx, f.adminA.ID, f.adminA.Email, f.orgA, f.memberA.ID, role)
		if !hasCode(err, 400, "invalid_role") {
			t.Fatalf("granting %q: want 400 invalid_role, got %v", role, err)
		}
	}
}

// D4: the GitOps operator may author and delete rules, and nothing else policy-wide.
func TestRBAC0OperatorCannotAdministerPolicy(t *testing.T) {
	if rbac.Can(rbac.RoleOperator, rbac.PermPolicyManage) {
		t.Fatal("operator must not hold policy:manage (Zero Trust mode, groups, IdP sync, resources)")
	}
	if !rbac.Can(rbac.RoleOperator, rbac.PermPolicyRuleManage) {
		t.Fatal("operator must keep rule authoring (policy_rule:manage) for TunnexGrant")
	}
	for _, role := range []string{rbac.RoleOwner, rbac.RoleAdmin} {
		if !rbac.Can(role, rbac.PermPolicyRuleManage) || !rbac.Can(role, rbac.PermPolicyManage) {
			t.Fatalf("%s must keep both policy permissions", role)
		}
	}
	org := uuid.New()
	machine := authctx.WithPrincipal(context.Background(), &authctx.Principal{MachineID: uuid.New(), MachineName: "gitops",
		AuthMethod: authctx.AuthMachine, Roles: map[uuid.UUID]string{org: rbac.RoleOperator}})
	for name, call := range map[string]func() error{
		"zero trust mode": func() error {
			_, e := (apiServer{}).SetZeroTrustMode(machine, api.SetZeroTrustModeRequestObject{OrgId: org, Body: &api.SetZeroTrustModeJSONRequestBody{Mode: "open"}})
			return e
		},
		"add group member": func() error {
			_, e := (apiServer{}).AddGroupMember(machine, api.AddGroupMemberRequestObject{OrgId: org, GroupId: uuid.New(), Body: &api.AddGroupMemberJSONRequestBody{UserId: uuid.New()}})
			return e
		},
		"create group": func() error {
			_, e := (apiServer{}).CreateGroup(machine, api.CreateGroupRequestObject{OrgId: org, Body: &api.CreateGroupJSONRequestBody{Name: "x"}})
			return e
		},
	} {
		if err := call(); !hasCode(err, 403, "forbidden") {
			t.Fatalf("operator %s: want 403 forbidden, got %v", name, err)
		}
	}
}

// D5: mutations gated on org:view still require a verified email.
func TestRBAC0OrgViewMutationsRequireVerifiedEmail(t *testing.T) {
	org := uuid.New()
	unverified := authctx.WithPrincipal(context.Background(), &authctx.Principal{UserID: uuid.New(), EmailVerified: false,
		AuthMethod: authctx.AuthLocalPassword, Roles: map[uuid.UUID]string{org: rbac.RoleMember}})
	full := true
	for name, call := range map[string]func() error{
		"update device mode": func() error {
			_, e := (apiServer{}).UpdateDeviceMode(unverified, api.UpdateDeviceModeRequestObject{OrgId: org, DeviceId: uuid.New(), Params: api.UpdateDeviceModeParams{FullTunnel: &full}})
			return e
		},
		"update agent profile": func() error {
			_, e := (apiServer{}).UpdateAgentProfile(unverified, api.UpdateAgentProfileRequestObject{OrgId: org, DeviceId: uuid.New(), Body: &api.UpdateAgentProfileJSONRequestBody{}})
			return e
		},
		"create agent access request": func() error {
			_, e := (apiServer{}).CreateAgentAccessRequest(unverified, api.CreateAgentAccessRequestRequestObject{OrgId: org, Body: &api.CreateAgentAccessRequestJSONRequestBody{}})
			return e
		},
		"start agent MCP OAuth": func() error {
			_, e := (apiServer{}).StartAgentMCPOAuthConnection(unverified, api.StartAgentMCPOAuthConnectionRequestObject{OrgId: org, DeviceId: uuid.New(), Body: &api.StartAgentMCPOAuthConnectionJSONRequestBody{}})
			return e
		},
	} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("%s: reached the service before the verified-email gate (%v)", name, r)
				}
			}()
			if err := call(); !hasCode(err, 403, "email_not_verified") {
				t.Fatalf("%s: want 403 email_not_verified, got %v", name, err)
			}
		}()
	}
}

func rbac0HashToken(raw string) []byte { h := sha256.Sum256([]byte(raw)); return h[:] }

// D9: deactivate and MFA reset had no body; a bodyless request from an older client must reach the
// handler (and its clear refusal), not die on a decode error before authorization.
func TestRBAC0BodylessStepUpRoutesReachTheHandler(t *testing.T) {
	f := newRBAC0Fixture(t, true)
	h := vaultSecurityRouter(t, Deps{Members: f.server.members, Mfa: f.server.mfa, System: f.q, Sessions: f.store, MfaEnforceEnabled: true,
		AuthFn: func(*http.Request) *authctx.Principal {
			return &authctx.Principal{UserID: f.adminA.ID, SessionID: "vault-security-session", EmailVerified: true,
				AuthMethod: authctx.AuthLocalPassword, Roles: map[uuid.UUID]string{f.orgA: "admin"}}
		}})
	for _, verb := range []string{"deactivate", "mfa-reset"} {
		path := "/api/v1/organizations/" + f.orgA.String() + "/members/" + f.ownerA.ID.String() + "/" + verb
		r := httptest.NewRequest(http.MethodPost, path, nil)
		r.AddCookie(&http.Cookie{Name: "tunnex_session", Value: "vault-security-session"})
		r.Header.Set("X-Tunnex-CSRF", "1")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		// An admin acting on an owner: the handler's relational refusal, which proves the request got there.
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "Only an owner") {
			t.Fatalf("bodyless %s: %d %s", verb, w.Code, w.Body.String())
		}
	}
}

// D3 + D9: with re-authentication, an admin deactivates a multi-org member here only; the member keeps
// their other organization and their account.
func TestRBAC0StepUpDeactivationIsOrgScoped(t *testing.T) {
	f := newRBAC0Fixture(t, true)
	pw := rbac0Password
	if _, err := f.server.DeactivateMember(f.as(t, f.adminA), api.DeactivateMemberRequestObject{OrgId: f.orgA, UserId: f.multi.ID,
		Body: &api.DeactivateMemberJSONRequestBody{CurrentPassword: &pw}}); err != nil {
		t.Fatal(err)
	}
	if got := f.status(t, f.multi.ID); got != "active" {
		t.Fatalf("account status = %q", got)
	}
	var revokedA, revokedB bool
	if err := f.pool.QueryRow(f.ctx, `SELECT
		bool_or(access_revoked_at IS NOT NULL) FILTER (WHERE org_id=$1),
		bool_or(access_revoked_at IS NOT NULL) FILTER (WHERE org_id=$2)
		FROM memberships WHERE user_id=$3`, f.orgA, f.orgB, f.multi.ID).Scan(&revokedA, &revokedB); err != nil {
		t.Fatal(err)
	}
	if !revokedA || revokedB {
		t.Fatalf("revoked A=%v B=%v", revokedA, revokedB)
	}
	// The roster says so, per organization.
	out, err := f.server.ListMembers(f.as(t, f.adminA), api.ListMembersRequestObject{OrgId: f.orgA})
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range out.(api.ListMembers200JSONResponse).Body {
		if m.UserId == f.multi.ID && (m.Status != "deactivated" || m.DeactivatedBy == nil || *m.DeactivatedBy != "organization") {
			t.Fatalf("roster row = %+v", m)
		}
	}
	// A wrong password is refused without acting.
	bad := "wrong-password"
	if _, err := f.server.DeactivateMember(f.as(t, f.adminA), api.DeactivateMemberRequestObject{OrgId: f.orgA, UserId: f.memberA.ID,
		Body: &api.DeactivateMemberJSONRequestBody{CurrentPassword: &bad}}); mfaHandlerErrorCode(err) != "invalid_credentials" {
		t.Fatalf("wrong password: %v", err)
	}
	if got := f.status(t, f.memberA.ID); got != "active" {
		t.Fatalf("deactivated despite a wrong password: %q", got)
	}
}

// D2: a deployment administrator's factor can be reset only by another deployment administrator, and the
// caller's own factor never through this route.
func TestRBAC0MFAResetProtectsCPAdminAndSelf(t *testing.T) {
	f := newRBAC0Fixture(t, true)
	if _, err := f.pool.Exec(f.ctx, `UPDATE users SET cp_admin=true WHERE id=$1`, f.memberA.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.server.AdminResetMfa(f.as(t, f.ownerA), api.AdminResetMfaRequestObject{OrgId: f.orgA, UserId: f.memberA.ID}); mfaHandlerErrorCode(err) != "forbidden" {
		t.Fatalf("owner resetting a deployment administrator: %v", err)
	}
	if _, err := f.server.AdminResetMfa(f.as(t, f.ownerA), api.AdminResetMfaRequestObject{OrgId: f.orgA, UserId: f.ownerA.ID}); mfaHandlerErrorCode(err) != "self_reset" {
		t.Fatalf("self reset: %v", err)
	}
	pw := rbac0Password
	if _, err := f.server.AdminResetMfa(f.as(t, f.adminA), api.AdminResetMfaRequestObject{OrgId: f.orgA, UserId: f.multi.ID,
		Body: &api.AdminResetMfaJSONRequestBody{CurrentPassword: &pw}}); err != nil {
		t.Fatalf("admin resetting a member with step-up: %v", err)
	}
}

// D9: the roster's /me carries what a step-up will ask for.
func TestRBAC0CurrentUserReportsReauthentication(t *testing.T) {
	f := newRBAC0Fixture(t, true)
	out, err := f.server.CurrentUser(f.as(t, f.adminA), api.CurrentUserRequestObject{})
	if err != nil {
		t.Fatal(err)
	}
	r := out.(api.CurrentUser200JSONResponse).Body.Reauthentication
	if r == nil || !r.Password || r.Mfa || !r.Available {
		t.Fatalf("reauthentication = %+v", r)
	}
}
