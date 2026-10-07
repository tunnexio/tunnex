package beam

import (
	"encoding/json"
	"github.com/google/uuid"
	"strings"
	"testing"
)

func TestBeamVersionedPolicyAndReviewerImpact(t *testing.T) {
	f := newFixture(t)
	r, _ := f.connect(f.create())
	token := f.browser(r, f.login(f.reviewer))
	lease, e := f.s.Authorize(f.ctx, r.Binding(), token, Metadata{Method: "GET", Path: "/"})
	if e != nil {
		t.Fatal(e)
	}
	grants := GrantsInput{ExpectedVersion: r.Version, Grants: []Grant{{"user", f.owner}}}
	impact, e := f.s.PreviewGrants(f.ctx, f.org, r.ID, f.a, grants)
	if e != nil || impact.RemovedGrantCount != 1 || impact.AffectedReviewerCount != 1 || impact.AffectedReviewerSessionCount != 1 || !impact.RequiresConfirmation {
		t.Fatal(impact, e)
	}
	if _, e = f.s.UpdateGrants(f.ctx, f.org, r.ID, f.a, grants); e == nil {
		t.Fatal("removed reviewers without confirmation")
	}
	if _, e = f.s.Renew(f.ctx, r.Binding(), lease.StreamID); e != nil {
		t.Fatal("preview or rejected mutation revoked current stream", e)
	}
	grants.ConfirmReviewerRemoval = true
	updated, e := f.s.UpdateGrants(f.ctx, f.org, r.ID, f.a, grants)
	if e != nil || updated.Binding() != r.Binding() {
		t.Fatal(updated, e)
	}
	if _, e = f.s.Renew(f.ctx, r.Binding(), lease.StreamID); e == nil {
		t.Fatal("removed reviewer retained lease")
	}
	if _, e = f.s.PreviewGrants(f.ctx, f.org, r.ID, f.a, grants); e == nil {
		t.Fatal("stale preview accepted")
	}
	p, e := f.s.GetPolicy(f.ctx, f.org, f.a)
	if e != nil {
		t.Fatal(e)
	}
	input := PolicyInput{ExpectedVersion: p.Version, Enabled: false, PublisherGroups: p.PublisherGroups, ReviewerUsers: p.ReviewerUsers, ReviewerGroups: p.ReviewerGroups, MaxDuration: p.MaxDuration, MaxShares: p.MaxShares}
	browser := f.login(f.owner)
	browser.ManagePolicy = true
	policyImpact, e := f.s.PreviewPolicy(f.ctx, f.org, browser, input)
	if e != nil || policyImpact.ActiveShareCount != 1 || policyImpact.AffectedShareCount != 1 || !policyImpact.RequiresConfirmation {
		t.Fatal(policyImpact, e)
	}
	if _, e = f.s.UpdatePolicy(f.ctx, f.org, browser, input); e == nil {
		t.Fatal("disabled live shares without confirmation")
	}
	if _, e = f.s.Channel(f.ctx, r.Binding(), *r.Serial); e != nil {
		t.Fatal("preview changed authority", e)
	}
	input.ConfirmEndActiveShares = true
	if _, e = f.s.UpdatePolicy(f.ctx, f.org, browser, input); e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.Channel(f.ctx, r.Binding(), *r.Serial); e == nil {
		t.Fatal("disabled policy retained channel")
	}
}
func TestBeamScopedSearchHistoryAndSafeDiagnostics(t *testing.T) {
	f := newFixture(t)
	r := f.create()
	page, e := f.s.ListFiltered(f.ctx, f.org, f.a, false, 50, 0, "FIXTURE")
	if e != nil || len(page.Items) != 1 {
		t.Fatal(page, e)
	}
	page, e = f.s.ListFiltered(f.ctx, f.org, f.a, false, 50, 0, "%")
	if e != nil || len(page.Items) != 0 {
		t.Fatal("search interpreted SQL wildcard", page, e)
	}
	if _, e = f.s.ListFiltered(f.ctx, f.org, f.a, false, 50, 0, strings.Repeat("x", 201)); e == nil {
		t.Fatal("oversized search accepted")
	}
	page, e = f.s.ListQuery(f.ctx, f.org, f.a, false, 50, 0, "", "starting", "offline")
	if e != nil || len(page.Items) != 1 {
		t.Fatal(page, e)
	}
	page, e = f.s.ListQuery(f.ctx, f.org, f.a, false, 50, 0, "", "starting", "online")
	if e != nil || len(page.Items) != 0 {
		t.Fatal(page, e)
	}
	events, e := f.s.ShareEvents(f.ctx, f.org, r.ID, f.a, 50, 0, EventFilter{Action: "beam.share.created"})
	if e != nil || len(events.Items) != 1 || events.Items[0].ShareID != r.ID.String() {
		t.Fatal(events, e)
	}
	outsider := Actor{ID: f.reviewer}
	if _, e = f.s.ShareEvents(f.ctx, f.org, r.ID, outsider, 50, 0, EventFilter{}); e == nil {
		t.Fatal("reviewer read owner history")
	}
	if _, e = f.s.Diagnostics(f.ctx, f.org, r.ID, outsider); e == nil {
		t.Fatal("reviewer read owner diagnostics")
	}
	d, e := f.s.Diagnostics(f.ctx, f.org, r.ID, f.a)
	if e != nil || d.Reason != "connector_offline" {
		t.Fatal(d, e)
	}
	raw, _ := json.Marshal(d)
	for _, secret := range []string{"target", "127.0.0.1", "digest", "certificate", "credential", "token", "session"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("unsafe diagnostic field", secret)
		}
	}
	f.exec(`UPDATE cli_credentials SET revoked_at=now() WHERE id=$1`, f.a.CredentialID)
	page, e = f.s.ListQuery(f.ctx, f.org, f.a, false, 50, 0, "", "starting", "")
	if e != nil || len(page.Items) != 0 {
		t.Fatal("health filter retained withdrawn publisher", page, e)
	}
	page, e = f.s.ListQuery(f.ctx, f.org, f.a, false, 50, 0, "", "revoked", "")
	if e != nil || len(page.Items) != 1 || page.Items[0].State != "revoked" {
		t.Fatal("health filter omitted projected withdrawal", page, e)
	}

	if _, e = f.s.Diagnostics(f.ctx, uuid.New(), r.ID, f.a); e == nil {
		t.Fatal("cross-tenant diagnostic")
	}
}
