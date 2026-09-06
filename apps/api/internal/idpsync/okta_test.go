package idpsync

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"testing"
	"time"
)

func TestOktaConnectionBinding(t *testing.T) {
	org := uuid.New()
	revision := int64(3)
	c := sqlc.SsoConnection{OrgID: org, Provider: "okta", IssuerUrl: "https://company.okta.com/oauth2/default", Enabled: true, Revision: revision, TestedRevision: &revision}
	if !oktaConnectionMatches(c, org, "https://company.okta.com") {
		t.Fatal("valid binding refused")
	}
	for _, mutate := range []func(*sqlc.SsoConnection){
		func(c *sqlc.SsoConnection) { c.OrgID = uuid.New() },
		func(c *sqlc.SsoConnection) { c.Provider = "oidc" },
		func(c *sqlc.SsoConnection) { c.Enabled = false },
		func(c *sqlc.SsoConnection) { c.IssuerUrl = "https://other.okta.com" },
		func(c *sqlc.SsoConnection) { c.Revision++ },
	} {
		bad := c
		mutate(&bad)
		if oktaConnectionMatches(bad, org, "https://company.okta.com") {
			t.Fatal("wrong directory/connection accepted")
		}
	}
}

func TestOktaPaginationStaysWithinAuthorizedGroup(t *testing.T) {
	p := &OktaProvider{origin: "https://company.okta.com"}
	for _, target := range []string{"https://evil.example/api/v1/groups/team/users", "http://company.okta.com/api/v1/groups/team/users", "https://company.okta.com/api/v1/groups/other/users", "https://user:secret@company.okta.com/api/v1/groups/team/users"} {
		if _, err := p.nextPage([]string{"<" + target + ">; rel=\"next\""}, "/api/v1/groups/team/users"); err == nil {
			t.Fatalf("accepted untrusted next page %s", target)
		}
	}
}

func TestOktaUnknownStatusIsNotAnActiveGrant(t *testing.T) {
	for _, status := range []string{"", "NEW_STATUS", "PASSWORD_EXPIRED", "LOCKED_OUT"} {
		if _, err := oktaStatus(status); err == nil {
			t.Fatalf("unknown status granted access: %s", status)
		}
	}
}

type conflictingDirectoryStore struct {
	*fakeStore
	conflict string
}

func (s *conflictingDirectoryStore) ResolveDirectoryMember(ctx context.Context, org, group uuid.UUID, provider string, m DirectoryMember) (uuid.UUID, bool, error) {
	if m.ExternalID == s.conflict {
		return uuid.Nil, false, errors.New("directory identity conflict")
	}
	return s.ResolveOrgUser(ctx, org, m.Email)
}
func TestOktaImportConflictDoesNotStrandDisabledLeaver(t *testing.T) {
	base := baseStore()
	base.ext = map[uuid.UUID]string{}
	base.current[grp] = []uuid.UUID{uBob}
	base.ext[uBob] = "bob"
	store := &conflictingDirectoryStore{base, "conflicting-joiner"}
	p := &fakeProvider{members: []DirectoryMember{{ExternalID: "conflicting-joiner", Email: "collision@example.com", Status: StatusActive}, {ExternalID: "bob", Email: "bob@acme.com", Status: StatusDisabled}}}
	d := &fakeDeprov{}
	r := NewReconciler(p, store, d, time.Now).WithProvisioningGate(func() bool { return true })
	if e := r.ReconcileConfig(context.Background(), org, "okta"); e == nil {
		t.Fatal("conflict should remain visible in health")
	}
	if len(base.removed) != 1 || base.removed[0].user != uBob || len(d.deactivated) != 1 || d.deactivated[0] != uBob {
		t.Fatal("joiner conflict prevented leaver revocation")
	}
}
func TestOktaUnresolvedExistingIdentityRetainsItsOwnGrant(t *testing.T) {
	base := baseStore()
	base.ext = map[uuid.UUID]string{}
	base.current[grp] = []uuid.UUID{uAli, uBob}
	base.ext[uAli] = "alice"
	base.ext[uBob] = "bob"
	store := &conflictingDirectoryStore{base, "alice"}
	p := &fakeProvider{members: []DirectoryMember{{ExternalID: "alice", Email: "alice@acme.com", Status: StatusActive}, {ExternalID: "bob", Email: "bob@acme.com", Status: StatusDisabled}}}
	d := &fakeDeprov{}
	r := NewReconciler(p, store, d, time.Now)
	if e := r.ReconcileConfig(context.Background(), org, "okta"); e == nil {
		t.Fatal("resolution failure should degrade health")
	}
	if len(base.removed) != 1 || base.removed[0].user != uBob {
		t.Fatal("unresolved existing identity lost its grant")
	}
}
