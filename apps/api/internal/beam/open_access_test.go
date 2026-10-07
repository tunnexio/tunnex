package beam

import (
	"github.com/google/uuid"
	"testing"
)

func openMode(v bool) *bool { return &v }
func TestBeamOpenForAllUsersPublishingReviewAndWithdrawal(t *testing.T) {
	f := newFixture(t)
	original, e := f.s.GetPolicy(f.ctx, f.org, f.a)
	if e != nil || original.OpenForAllUsers {
		t.Fatal("restricted default", original, e)
	}
	cred := uuid.New()
	f.exec(`INSERT INTO cli_credentials(id,user_id,token_hash,fingerprint,expires_at)VALUES($1,$2,$3,'open-member',now()+interval '1 day')`, cred, f.outsider, hash("tnx_open_fixture"))
	member := Actor{ID: f.outsider, CredentialID: cred}
	if _, e = f.s.Audience(f.ctx, f.org, member); e == nil {
		t.Fatal("restricted member published")
	}
	admin := f.login(f.owner)
	admin.ManagePolicy = true
	input := PolicyInput{ExpectedVersion: original.Version, Enabled: true, OpenForAllUsers: openMode(true), MaxDuration: 3600, MaxShares: 5}
	opened, e := f.s.UpdatePolicy(f.ctx, f.org, admin, input)
	if e != nil || !opened.OpenForAllUsers {
		t.Fatal("open mode needs allowlists", opened, e)
	}
	// Old policy writers omit the new field; they must preserve the saved mode.
	input.ExpectedVersion = opened.Version
	input.OpenForAllUsers = nil
	opened, e = f.s.UpdatePolicy(f.ctx, f.org, admin, input)
	if e != nil || !opened.OpenForAllUsers {
		t.Fatal("old writer cleared open mode", opened, e)
	}
	f.exec(`INSERT INTO group_members(org_id,group_id,user_id)VALUES($1,$2,$3)`, f.org, f.group, f.reviewer)
	audience, e := f.s.Audience(f.ctx, f.org, member)
	if e != nil || len(audience.Users) != 3 || len(audience.Groups) != 1 {
		t.Fatal("organization directory", audience, e)
	}
	grant := []Grant{{"user", f.reviewer}, {"group", f.group}}
	if e = f.s.validateSubjects(f.ctx, f.pool, f.org, f.outsider, opened, grant); e != nil {
		t.Fatal("open reviewer choices", e)
	}
	foreign := uuid.New()
	f.exec(`INSERT INTO organizations(id,name,slug)VALUES($1,'Foreign open fixture',$2)`, foreign, foreign.String())
	foreignGroup := uuid.New()
	f.exec(`INSERT INTO user_groups(id,org_id,name)VALUES($1,$2,'Foreign group')`, foreignGroup, foreign)
	if e = f.s.validateSubjects(f.ctx, f.pool, f.org, f.outsider, opened, []Grant{{"group", foreignGroup}}); e == nil {
		t.Fatal("cross-organization group grant")
	}
	external := uuid.New()
	f.exec(`INSERT INTO users(id,email,name,email_verified_at)VALUES($1,$2,'External',now())`, external, external.String()+"@beam.test")
	if e = f.s.validateSubjects(f.ctx, f.pool, f.org, f.outsider, opened, []Grant{{"user", external}}); e == nil {
		t.Fatal("nonmember grant")
	}
	if e = f.s.publisher(f.ctx, f.pool, f.org, external, opened); e == nil {
		t.Fatal("nonmember published")
	}
	policy, e := f.s.GetPolicy(f.ctx, f.org, member)
	if e != nil || !policy.CanPublish {
		t.Fatal("member publish projection", policy, e)
	}
	// A publisher does not need a group; reviewers do not need native credentials.
	f.a = member
	r, _ := f.connect(f.create())
	token := f.browser(r, f.login(f.reviewer))
	lease, e := f.s.Authorize(f.ctx, r.Binding(), token, Metadata{Method: "GET", Path: "/"})
	if e != nil {
		t.Fatal("browser-only reviewer", e)
	}
	if e = f.s.reviewer(f.ctx, f.pool, r, f.owner, opened); e == nil {
		t.Fatal("open mode granted content implicitly to admin")
	}
	page, e := f.s.List(f.ctx, f.org, Actor{ID: f.reviewer}, true, 20, 0)
	if e != nil || len(page.Items) != 1 {
		t.Fatal("open publisher disappeared from inventory", page, e)
	}
	impact, e := f.s.PreviewGrants(f.ctx, f.org, r.ID, member, GrantsInput{ExpectedVersion: r.Version, Grants: []Grant{}})
	if e != nil || impact.AffectedReviewerCount != 2 || impact.AffectedReviewerSessionCount != 1 {
		t.Fatal("open reviewer removal impact", impact, e)
	}
	input = PolicyInput{ExpectedVersion: opened.Version, Enabled: true, OpenForAllUsers: openMode(false), PublisherGroups: original.PublisherGroups, ReviewerUsers: original.ReviewerUsers, ReviewerGroups: original.ReviewerGroups, MaxDuration: 3600, MaxShares: 5}
	preview, e := f.s.PreviewPolicy(f.ctx, f.org, admin, input)
	if e != nil || preview.AffectedShareCount != 1 || preview.AffectedReviewerSessionCount != 1 || !preview.RequiresConfirmation {
		t.Fatal("restricting impact", preview, e)
	}
	if _, e = f.s.UpdatePolicy(f.ctx, f.org, admin, input); e == nil {
		t.Fatal("mode restricted without current impact confirmation")
	}
	if _, e = f.s.Renew(f.ctx, r.Binding(), lease.StreamID); e != nil {
		t.Fatal("rejected save revoked stream", e)
	}
	input.ConfirmEndActiveShares = true
	closed, e := f.s.UpdatePolicy(f.ctx, f.org, admin, input)
	if e != nil || closed.OpenForAllUsers {
		t.Fatal("restricted save", closed, e)
	}
	if _, e = f.s.Renew(f.ctx, r.Binding(), lease.StreamID); e == nil {
		t.Fatal("restricted member retained live stream")
	}
	if e = f.s.publisher(f.ctx, f.pool, f.org, f.outsider, closed); e == nil {
		t.Fatal("restricted member still published")
	}
	if _, e = f.s.UpdatePolicy(f.ctx, f.org, member, PolicyInput{OpenForAllUsers: openMode(true)}); e == nil {
		t.Fatal("member changed admin policy")
	}
}
func TestBeamOpenModeStillRequiresEligibleMembersAndServingSetup(t *testing.T) {
	f := newFixture(t)
	p, e := f.s.policy(f.ctx, f.pool, f.org)
	if e != nil {
		t.Fatal(e)
	}
	p.OpenForAllUsers = true
	for _, change := range []string{"status='deactivated'", "must_change_password=true", "email_verified_at=NULL"} {
		f.exec(`UPDATE users SET `+change+` WHERE id=$1`, f.outsider)
		if e = f.s.publisher(f.ctx, f.pool, f.org, f.outsider, p); e == nil {
			t.Fatal("ineligible publisher", change)
		}
		if e = f.s.validateSubjects(f.ctx, f.pool, f.org, f.owner, p, []Grant{{"user", f.outsider}}); e == nil {
			t.Fatal("ineligible reviewer", change)
		}
		f.exec(`UPDATE users SET status='active',must_change_password=false,email_verified_at=now() WHERE id=$1`, f.outsider)
	}
	p.Enabled = false
	if e = f.s.publisher(f.ctx, f.pool, f.org, f.outsider, p); e == nil {
		t.Fatal("disabled Beam published")
	}
	p.Enabled = true
	p.DomainReady = false
	if e = f.s.publisher(f.ctx, f.pool, f.org, f.outsider, p); e == nil {
		t.Fatal("unqualified serving published")
	}
}
