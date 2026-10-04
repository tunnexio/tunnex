package appaccess

import (
	"github.com/google/uuid"
	"testing"
	"time"
)

func TestGrantViewValidation(t *testing.T) {
	for _, tc := range []struct {
		view, status string
		valid        bool
	}{
		{"", "", true}, {"", "expired", true}, {"current", "", true}, {"current", "active", true},
		{"current", "disabled", true}, {"current", "scheduled", true}, {"current", "subject_unavailable", true},
		{"history", "", true}, {"history", "revoked", true}, {"history", "expired", true},
		{"current", "expired", false}, {"current", "revoked", false}, {"history", "active", false},
		{"history", "disabled", false}, {"history", "scheduled", false}, {"history", "subject_unavailable", false},
		{"unknown", "", false}, {"current", "unknown", false},
	} {
		_, err := NormalizeGrantListFilter(GrantListFilter{View: tc.view, Status: tc.status})
		if (err == nil) != tc.valid {
			t.Fatalf("view=%q status=%q valid=%v: %v", tc.view, tc.status, tc.valid, err)
		}
	}
}

func TestGrantViewsGlobalAndScopedBeforePaginationLocalDatabase(t *testing.T) {
	f := newCompanyFixture(t)
	f.policy(&f.manager, false)
	now := f.service.now().Truncate(time.Microsecond)
	f.service.config.Now = func() time.Time { return now }
	past, end, future := now.Add(-time.Hour), now, now.Add(time.Hour)
	add := func(label string, enabled bool, start, expiry *time.Time) Grant {
		t.Helper()
		user := uuid.New()
		f.exec("INSERT INTO users(id,email,name,email_verified_at)VALUES($1,$2,$3,now())", user, user.String()+"@views.fixture", label)
		f.exec("INSERT INTO memberships(org_id,user_id,role)VALUES($1,$2,'member')", f.org, user)
		grant, err := f.service.CreateGrant(f.ctx, f.org, f.admin, GrantInput{AppID: f.app.ID, SubjectKind: "user", SubjectID: user, Enabled: enabled, StartsAt: start, ExpiresAt: expiry}, true)
		if err != nil {
			t.Fatal(err)
		}
		return grant
	}
	active := add("Visible active", true, nil, nil)
	// Disabled precedes expiry; unavailable precedes disabled and expiry.
	disabled := add("Visible disabled expired", false, &past, &end)
	expired := add("Visible expired", true, &past, &end)
	revoked := add("Visible revoked", true, nil, nil)
	if _, err := f.service.RevokeGrant(f.ctx, f.org, f.admin, revoked.ID, revoked.Version); err != nil {
		t.Fatal(err)
	}
	scheduled := add("Visible scheduled", true, &future, nil)
	unavailable := add("Visible unavailable", false, &past, &end)
	f.exec("UPDATE users SET status='deactivated' WHERE id=$1", unavailable.SubjectID)
	for _, tc := range []struct {
		filter GrantListFilter
		ids    []uuid.UUID
	}{
		{GrantListFilter{}, []uuid.UUID{active.ID, disabled.ID, expired.ID, revoked.ID, scheduled.ID, unavailable.ID}},
		{GrantListFilter{View: "current"}, []uuid.UUID{active.ID, disabled.ID}},
		{GrantListFilter{View: "current", Status: "scheduled"}, []uuid.UUID{scheduled.ID}},
		{GrantListFilter{View: "current", Status: "subject_unavailable"}, []uuid.UUID{unavailable.ID}},
		{GrantListFilter{View: "history"}, []uuid.UUID{expired.ID, revoked.ID}},
		{GrantListFilter{View: "history", Status: "revoked"}, []uuid.UUID{revoked.ID}},
		{GrantListFilter{View: "history", Search: "EXPIRED"}, []uuid.UUID{expired.ID}},
	} {
		for _, scoped := range []bool{false, true} {
			seen := map[uuid.UUID]bool{}
			for page := 0; page <= len(tc.ids); page++ {
				var rows []Grant
				var err error
				if scoped {
					rows, err = f.service.ManagedGrants(f.ctx, f.org, f.manager, f.app.ID, 1, int32(page), tc.filter)
				} else {
					rows, err = f.service.ListGrants(f.ctx, f.org, &f.app.ID, "", nil, 1, int32(page), tc.filter)
				}
				if err != nil {
					t.Fatal(err)
				}
				if page == len(tc.ids) {
					if len(rows) != 0 {
						t.Fatal("filter applied after pagination", tc, scoped, rows)
					}
					break
				}
				if len(rows) != 1 || seen[rows[0].ID] {
					t.Fatal("missing or duplicate filtered page", tc, scoped, rows)
				}
				seen[rows[0].ID] = true
			}
			for _, id := range tc.ids {
				if !seen[id] {
					t.Fatal("wrong view membership", tc, scoped, id)
				}
			}
		}
	}
	for _, filter := range []GrantListFilter{{View: "current", Status: "expired"}, {View: "history", Status: "subject_unavailable"}, {View: "unknown"}} {
		_, err := f.service.ManagedGrants(f.ctx, f.org, f.manager, f.app.ID, 20, 0, filter)
		code(t, err, "invalid_grant_filter")
	}
	if _, err := f.service.ManagedGrants(f.ctx, f.org, f.member, f.app.ID, 20, 0, GrantListFilter{View: "history"}); err == nil {
		t.Fatal("ordinary member gained scoped authority")
	}
	if _, err := f.service.ManagedGrants(f.ctx, f.org, f.manager, f.second.ID, 20, 0, GrantListFilter{View: "current"}); err == nil {
		t.Fatal("assigned owner gained another app")
	}
	if _, err := f.service.ManagedGrants(f.ctx, f.other, f.manager, f.app.ID, 20, 0, GrantListFilter{View: "history"}); err == nil {
		t.Fatal("cross-organization scope accepted")
	}
}
