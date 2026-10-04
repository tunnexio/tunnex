package appaccess

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestGrantListFiltersBeforePaginationLocalDatabase(t *testing.T) {
	f := newCompanyFixture(t)
	now := f.service.now().Truncate(time.Microsecond)
	f.service.config.Now = func() time.Time { return now }
	seq := 0
	add := func(name string, enabled bool, start, end *time.Time) Grant {
		t.Helper()
		user := uuid.New()
		f.exec("INSERT INTO users(id,email,name,email_verified_at)VALUES($1,$2,$3,now())", user, user.String()+"@filters.fixture", name)
		f.exec("INSERT INTO memberships(org_id,user_id,role)VALUES($1,$2,'member')", f.org, user)
		grant, err := f.service.CreateGrant(f.ctx, f.org, f.admin, GrantInput{AppID: f.app.ID, SubjectKind: "user", SubjectID: user, Enabled: enabled, StartsAt: start, ExpiresAt: end}, true)
		if err != nil {
			t.Fatal(err)
		}
		seq++
		f.exec("UPDATE app_access_grants SET created_at=$2 WHERE id=$1", grant.ID, now.Add(time.Duration(seq)*time.Second))
		return grant
	}
	// Search targets deliberately occur beyond the first unfiltered page.
	for i := 0; i < 22; i++ {
		add(fmt.Sprintf("Ordinary person %02d", i), true, nil, nil)
	}
	target := add("Needle_% Person", true, nil, nil)
	f.exec("UPDATE users SET name='Current Person',email='needle.filter@filters.fixture' WHERE id=$1", target.SubjectID)
	group := uuid.New()
	f.exec("INSERT INTO user_groups(id,org_id,name)VALUES($1,$2,'Needle Team')", group, f.org)
	team, err := f.service.CreateGrant(f.ctx, f.org, f.admin, GrantInput{AppID: f.app.ID, SubjectKind: "group", SubjectID: group, Enabled: true}, true)
	if err != nil {
		t.Fatal(err)
	}
	seq++
	f.exec("UPDATE app_access_grants SET created_at=$2 WHERE id=$1", team.ID, now.Add(time.Duration(seq)*time.Second))
	f.exec("UPDATE user_groups SET name='Renamed Team' WHERE id=$1", group)
	future, end, past := now.Add(time.Microsecond), now.Add(time.Hour), now.Add(-time.Hour)
	scheduled := add("Scheduled target", true, &future, &end)
	expired := add("Expired target", true, &past, &now)
	disabled := add("Disabled target", false, &future, &end)
	unavailable := add("Unavailable target", false, &past, &now)
	f.exec("UPDATE users SET status='deactivated' WHERE id=$1", unavailable.SubjectID)
	revoked := add("Revoked target", false, &past, &now)
	if _, err = f.service.RevokeGrant(f.ctx, f.org, f.admin, revoked.ID, revoked.Version); err != nil {
		t.Fatal(err)
	}
	f.exec("UPDATE users SET status='deactivated' WHERE id=$1", revoked.SubjectID)

	list := func(filter GrantListFilter, limit, offset int32) []Grant {
		t.Helper()
		out, err := f.service.ListGrants(f.ctx, f.org, &f.app.ID, "", nil, limit, offset, filter)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	for _, tc := range []struct {
		search string
		id     uuid.UUID
	}{
		{"  NEEDLE.FILTER@FILTERS.FIXTURE  ", target.ID},
		{"Current Person", target.ID},
		{"%", target.ID},
		{"_", target.ID},
		{"Renamed Team", team.ID},
		{"Needle Team", team.ID},
	} {
		out := list(GrantListFilter{Search: tc.search}, 100, 0)
		if len(out) != 1 || out[0].ID != tc.id {
			t.Fatalf("literal/current/snapshot search %q: %+v", tc.search, out)
		}
	}
	first := list(GrantListFilter{Search: "needle"}, 1, 0)
	second := list(GrantListFilter{Search: "needle"}, 1, 1)
	last := list(GrantListFilter{Search: "needle"}, 1, 2)
	if len(first) != 1 || first[0].ID != target.ID || len(second) != 1 || second[0].ID != team.ID || len(last) != 0 {
		t.Fatal("search applied after pagination", first, second, last)
	}
	all := list(GrantListFilter{}, 100, 0)
	byAppName := list(GrantListFilter{Search: f.app.Draft.Name}, 100, 0)
	if len(byAppName) != len(all) {
		t.Fatal("application display name omitted", len(byAppName), len(all))
	}
	for _, tc := range []struct {
		status string
		id     uuid.UUID
	}{
		{"scheduled", scheduled.ID}, {"expired", expired.ID}, {"disabled", disabled.ID}, {"subject_unavailable", unavailable.ID}, {"revoked", revoked.ID},
	} {
		out := list(GrantListFilter{Status: tc.status}, 1, 0)
		if len(out) != 1 || out[0].ID != tc.id || out[0].Status != tc.status {
			t.Fatalf("status precedence/paging %s: %+v", tc.status, out)
		}
	}
	if got := list(GrantListFilter{Status: "expired", Search: "Scheduled target"}, 100, 0); len(got) != 0 {
		t.Fatal("search/status were not ANDed")
	}
	if got := list(GrantListFilter{Status: "active"}, 20, 20); len(got) != 4 {
		t.Fatal("active pages exclude non-active statuses", got)
	}
	// Existing app/subject filters remain intersections with the new filters.
	scoped, err := f.service.ListGrants(f.ctx, f.org, &f.app.ID, "group", &group, 100, 0, GrantListFilter{Search: "needle", Status: "active"})
	if err != nil || len(scoped) != 1 || scoped[0].ID != team.ID {
		t.Fatal("subject filters changed", scoped, err)
	}
	other, err := f.service.ListGrants(f.ctx, f.org, &f.second.ID, "", nil, 100, 0, GrantListFilter{Search: "needle"})
	if err != nil || len(other) != 0 {
		t.Fatal("application filter changed", other, err)
	}
	foreign, err := f.service.ListGrants(f.ctx, f.other, nil, "", nil, 100, 0, GrantListFilter{Search: "needle"})
	if err != nil || len(foreign) != 0 {
		t.Fatal("cross-org search disclosed grants", foreign, err)
	}
	_, err = f.service.ListGrants(f.ctx, f.other, &f.app.ID, "", nil, 100, 0, GrantListFilter{Search: "needle"})
	code(t, err, "application_not_found")
	for _, filter := range []GrantListFilter{{Status: "unknown"}, {Search: strings.Repeat("界", 201)}} {
		_, err = f.service.ListGrants(f.ctx, f.org, nil, "", nil, 50, 0, filter)
		code(t, err, "invalid_grant_filter")
	}
}

func TestGrantListStatusTimeAndDirectoryBoundariesLocalDatabase(t *testing.T) {
	f := newCompanyFixture(t)
	start := f.service.now().Truncate(time.Microsecond)
	end := start.Add(time.Second)
	now := start.Add(-time.Microsecond)
	f.service.config.Now = func() time.Time { return now }
	grant, err := f.service.CreateGrant(f.ctx, f.org, f.admin, GrantInput{AppID: f.app.ID, SubjectKind: "user", SubjectID: f.member, Enabled: true, StartsAt: &start, ExpiresAt: &end}, true)
	if err != nil {
		t.Fatal(err)
	}
	check := func(want string) {
		t.Helper()
		for _, status := range []string{"scheduled", "active", "expired", "disabled", "revoked", "subject_unavailable"} {
			rows, err := f.service.ListGrants(f.ctx, f.org, &f.app.ID, "user", &f.member, 1, 0, GrantListFilter{Status: status})
			if err != nil {
				t.Fatal(err)
			}
			if status == want {
				if len(rows) != 1 || rows[0].ID != grant.ID || rows[0].Status != want {
					t.Fatalf("boundary want %s: %+v", want, rows)
				}
			} else if len(rows) != 0 {
				t.Fatalf("incorrect status %s at %s: %+v", status, now, rows)
			}
		}
	}
	check("scheduled")
	now = start
	check("active")
	now = end
	check("expired")
	f.exec("UPDATE memberships SET access_revoked_at=now() WHERE org_id=$1 AND user_id=$2", f.org, f.member)
	check("subject_unavailable")
	f.exec("UPDATE app_access_grants SET revoked_at=now(),enabled=false WHERE id=$1", grant.ID)
	check("revoked")
}
