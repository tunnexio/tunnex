package beam

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

// LS-UX-4: refusals read as plain sentences with the same lifetime words as the console and the
// desktop client; error codes are unchanged.
func TestBeamHumanDuration(t *testing.T) {
	for seconds, want := range map[int]string{60: "1 minute", 2700: "45 minutes", 3600: "1 hour", 3660: "1 hour 1 minute", 5400: "1 hour 30 minutes", 7200: "2 hours", 86400: "24 hours"} {
		if got := humanDuration(seconds); got != want {
			t.Errorf("humanDuration(%d) = %q, want %q", seconds, got, want)
		}
	}
}

func TestBeamExtendRefusalNamesTheMaximumLifetime(t *testing.T) {
	f := newFixture(t)
	r := f.create()
	beyond := r.CreatedAt.Add(2 * time.Hour)
	_, e := f.s.Action(f.ctx, f.org, r.ID, f.a, ActionInput{Action: "extend", ExpectedVersion: r.Version, ExpiresAt: &beyond})
	var refusal *apierr.Error
	if !errors.As(e, &refusal) || refusal.Code != "beam_invalid" {
		t.Fatalf("extend beyond the ceiling: %v", e)
	}
	if !strings.Contains(refusal.Message, "maximum lifetime of 1 hour from when the share was created") || strings.Contains(refusal.Message, "ceiling") {
		t.Fatalf("extend refusal wording: %q", refusal.Message)
	}
	_, e = f.s.Create(f.ctx, f.org, f.a, CreateInput{Name: "Too long", Target: Target{Protocol: "http", Address: "127.0.0.1", Port: 3000}, Duration: 7200, Grants: []Grant{{"user", f.reviewer}}, IdempotencyKey: uuid.New()})
	if !errors.As(e, &refusal) || refusal.Code != "beam_invalid" || !strings.Contains(refusal.Message, "maximum of 1 hour") {
		t.Fatalf("create beyond the policy lifetime: %v", e)
	}
	if e = missing(); !errors.As(e, &refusal) || refusal.Code != "beam_share_not_found" || refusal.Message == "Share not found" {
		t.Fatalf("not-found wording: %v", e)
	}
}

// LS-UX-4: managed share projections name their reviewers so the My shares list can say
// "reviewer, Developers group +1" without loading the organization directory. Only the publisher and
// managers get names; reviewers never do. The publisher's own grant, people who are no longer active
// members and groups of other organizations are never named.
func TestBeamShareReviewerNamesPermissionBoundary(t *testing.T) {
	f := newFixture(t)
	f.exec(`UPDATE users SET name='Rae Reviewer' WHERE id=$1`, f.reviewer)
	r := f.create()
	gone, foreignGroup, foreign := uuid.New(), uuid.New(), uuid.New()
	f.exec(`INSERT INTO users(id,email,name,email_verified_at,status)VALUES($1,$2,'Gone Person',now(),'deactivated')`, gone, gone.String()+"@beam.test")
	f.exec(`INSERT INTO memberships(org_id,user_id,role)VALUES($1,$2,'member')`, f.org, gone)
	f.exec(`INSERT INTO organizations(id,name,slug)VALUES($1,'Foreign names fixture',$2)`, foreign, foreign.String())
	f.exec(`INSERT INTO user_groups(id,org_id,name)VALUES($1,$2,'Foreign group')`, foreignGroup, foreign)
	f.exec(`INSERT INTO beam_grants(org_id,share_id,subject_kind,subject_id)VALUES($1,$2,'group',$3),($1,$2,'user',$4),($1,$2,'group',$5)`, f.org, r.ID, f.group, gone, foreignGroup)

	want := []Reviewer{{SubjectKind: "user", SubjectID: f.reviewer, Name: "Rae Reviewer", Email: f.reviewer.String() + "@beam.test"}, {SubjectKind: "group", SubjectID: f.group, Name: "Beam publishers"}}
	check := func(label string, got []Reviewer) {
		t.Helper()
		if len(got) != len(want) {
			t.Fatalf("%s reviewers %+v", label, got)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("%s reviewer %d = %+v, want %+v", label, i, got[i], want[i])
			}
		}
	}
	owned, e := f.s.Get(f.ctx, f.org, r.ID, f.a)
	if e != nil {
		t.Fatal(e)
	}
	check("publisher", owned.Reviewers)
	if len(owned.Grants) != 5 {
		t.Fatalf("grants are still reported in full: %+v", owned.Grants)
	}
	listed, e := f.s.List(f.ctx, f.org, f.a, false, 20, 0)
	if e != nil || len(listed.Items) != 1 {
		t.Fatalf("my shares %v %+v", e, listed.Items)
	}
	check("my shares list", listed.Items[0].Reviewers)

	manager := f.login(f.outsider)
	manager.ManageAll = true
	managed, e := f.s.Get(f.ctx, f.org, r.ID, manager)
	if e != nil {
		t.Fatal(e)
	}
	check("manager", managed.Reviewers)

	f.connect(r)
	reviewer := f.login(f.reviewer)
	seen, e := f.s.Get(f.ctx, f.org, r.ID, reviewer)
	if e != nil {
		t.Fatal(e)
	}
	if seen.Reviewers != nil || seen.Grants != nil {
		t.Fatalf("reviewer projection carries reviewers %+v grants %+v", seen.Reviewers, seen.Grants)
	}
	body, e := json.Marshal(seen)
	if e != nil || strings.Contains(string(body), `"reviewers"`) || strings.Contains(string(body), "Gone Person") {
		t.Fatalf("reviewer JSON %s %v", body, e)
	}
	shared, e := f.s.List(f.ctx, f.org, reviewer, true, 20, 0)
	if e != nil {
		t.Fatal(e)
	}
	for _, item := range shared.Items {
		if item.Reviewers != nil {
			t.Fatalf("shared-with-me projection carries reviewers %+v", item.Reviewers)
		}
	}
	body, e = json.Marshal(owned)
	if e != nil || !strings.Contains(string(body), `"reviewers":[`) || strings.Contains(string(body), "Gone Person") || strings.Contains(string(body), "Foreign group") {
		t.Fatalf("publisher JSON %s %v", body, e)
	}
}
