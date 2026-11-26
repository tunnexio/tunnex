package beam

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// LS-UX-3: reviewer group choices carry a member count so clients can say "Developers · 3 members".
// The count is org-scoped, counts only current active members and rides only on groups the caller
// may already list; it never names anyone.
func TestBeamAudienceGroupMemberCount(t *testing.T) {
	f := newFixture(t)
	// The fixture group already holds the owner. Add an active reviewer, a deactivated user and a
	// member whose organization access was revoked; only the first counts.
	f.exec(`INSERT INTO group_members(org_id,group_id,user_id)VALUES($1,$2,$3)`, f.org, f.group, f.reviewer)
	f.exec(`INSERT INTO group_members(org_id,group_id,user_id)VALUES($1,$2,$3)`, f.org, f.group, f.outsider)
	f.exec(`UPDATE users SET status='deactivated' WHERE id=$1`, f.outsider)
	revoked := uuid.New()
	f.exec(`INSERT INTO users(id,email,name,email_verified_at)VALUES($1,$2,'Revoked',now())`, revoked, revoked.String()+"@beam.test")
	f.exec(`INSERT INTO memberships(org_id,user_id,role,access_revoked_at)VALUES($1,$2,'member',now())`, f.org, revoked)
	f.exec(`INSERT INTO group_members(org_id,group_id,user_id)VALUES($1,$2,$3)`, f.org, f.group, revoked)
	empty := uuid.New()
	f.exec(`INSERT INTO user_groups(id,org_id,name)VALUES($1,$2,'Empty reviewers')`, empty, f.org)
	// The reviewer also belongs to another organization's group: it must neither appear nor count.
	foreign, foreignGroup := uuid.New(), uuid.New()
	f.exec(`INSERT INTO organizations(id,name,slug)VALUES($1,'Foreign count fixture',$2)`, foreign, foreign.String())
	f.exec(`INSERT INTO memberships(org_id,user_id,role)VALUES($1,$2,'member')`, foreign, f.reviewer)
	f.exec(`INSERT INTO user_groups(id,org_id,name)VALUES($1,$2,'Foreign reviewers')`, foreignGroup, foreign)
	f.exec(`INSERT INTO group_members(org_id,group_id,user_id)VALUES($1,$2,$3)`, foreign, foreignGroup, f.reviewer)

	admin := f.login(f.owner)
	admin.ManagePolicy = true
	audience, e := f.s.Audience(f.ctx, f.org, admin)
	if e != nil {
		t.Fatal(e)
	}
	counts := map[uuid.UUID]int{}
	for _, g := range audience.Groups {
		counts[g.ID] = g.MemberCount
	}
	if len(counts) != 2 || counts[f.group] != 2 || counts[empty] != 0 {
		t.Fatalf("group member counts %+v", audience.Groups)
	}
	if _, ok := counts[foreignGroup]; ok {
		t.Fatal("another organization's group listed")
	}
	body, e := json.Marshal(audience.Groups[0])
	if e != nil || !strings.Contains(string(body), `"member_count":`) || strings.Contains(string(body), "@") {
		t.Fatalf("group projection %s %v", body, e)
	}
}
