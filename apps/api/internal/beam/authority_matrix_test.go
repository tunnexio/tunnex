package beam

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestBeamCurrentIdentityWithdrawalMatrix(t *testing.T) {
	for _, change := range []string{"publisher-status", "publisher-membership", "publisher-role", "publisher-credential-expiry", "organization-deleted", "reviewer-parent-expiry", "reviewer-auth-epoch"} {
		t.Run(change, func(t *testing.T) {
			f := newFixture(t)
			r, _ := f.connect(f.create())
			parent := f.login(f.reviewer)
			token := f.browser(r, parent)
			lease, e := f.s.Authorize(f.ctx, r.Binding(), token, Metadata{Method: "GET", Path: "/"})
			if e != nil {
				t.Fatal(e)
			}
			switch change {
			case "publisher-status":
				f.exec(`UPDATE users SET status='deactivated' WHERE id=$1`, f.owner)
			case "publisher-membership":
				f.exec(`DELETE FROM memberships WHERE org_id=$1 AND user_id=$2`, f.org, f.owner)
			case "publisher-role":
				f.exec(`UPDATE memberships SET role='ai-view',roles=ARRAY['ai-view'] WHERE org_id=$1 AND user_id=$2`, f.org, f.owner)
			case "publisher-credential-expiry":
				f.exec(`UPDATE cli_credentials SET expires_at=now()-interval '1 second' WHERE id=$1`, f.a.CredentialID)
			case "organization-deleted":
				f.exec(`UPDATE organizations SET deleted_at=now() WHERE id=$1`, f.org)
			case "reviewer-parent-expiry":
				sess, _, err := f.store.GetNoTouch(f.ctx, parent.SessionID)
				if err != nil {
					t.Fatal(err)
				}
				sess.ExpiresAt = time.Now().Add(-time.Second)
				data, err := json.Marshal(sess)
				if err != nil {
					t.Fatal(err)
				}
				if err = f.store.Client().Set(f.ctx, "sess:"+parent.SessionID, data, time.Hour).Err(); err != nil {
					t.Fatal(err)
				}
			case "reviewer-auth-epoch":
				f.exec(`UPDATE users SET app_auth_epoch=app_auth_epoch+1 WHERE id=$1`, f.reviewer)
			}
			if _, e = f.s.Renew(f.ctx, r.Binding(), lease.StreamID); e == nil {
				t.Fatal("changed current identity retained its old stream")
			}
			if _, e = f.s.Authorize(f.ctx, r.Binding(), token, Metadata{Method: "GET", Path: "/"}); e == nil {
				t.Fatal("changed current identity admitted a new request")
			}
			if change != "reviewer-parent-expiry" && change != "reviewer-auth-epoch" {
				if _, e = f.s.Channel(f.ctx, r.Binding(), *r.Serial); e == nil {
					t.Fatal("withdrawn publisher retained its connector")
				}
			} else if _, e = f.s.Channel(f.ctx, r.Binding(), *r.Serial); e != nil {
				t.Fatal("reviewer withdrawal terminated an unrelated publisher channel", e)
			}
		})
	}
}

func TestBeamOverlappingGrantsPreserveOtherEligibleReviewers(t *testing.T) {
	f := newFixture(t)
	policy, e := f.s.GetPolicy(f.ctx, f.org, f.a)
	if e != nil {
		t.Fatal(e)
	}
	browser := f.a
	browser.CredentialID = uuid.Nil
	browser.SessionID = "fixture-policy"
	_, e = f.s.UpdatePolicy(f.ctx, f.org, browser, PolicyInput{Enabled: true, ExpectedVersion: policy.Version, PublisherGroups: []uuid.UUID{f.group}, ReviewerUsers: []uuid.UUID{f.reviewer, f.outsider}, ReviewerGroups: []uuid.UUID{f.group}, MaxDuration: 3600, MaxShares: 5})
	if e != nil {
		t.Fatal(e)
	}
	f.exec(`INSERT INTO group_members(org_id,group_id,user_id)VALUES($1,$2,$3)`, f.org, f.group, f.reviewer)
	r := f.create()
	r, e = f.s.UpdateGrants(f.ctx, f.org, r.ID, f.a, GrantsInput{ConfirmReviewerRemoval: true, ExpectedVersion: r.Version, Grants: []Grant{{"user", f.reviewer}, {"group", f.group}, {"user", f.outsider}}})
	if e != nil {
		t.Fatal(e)
	}
	r, _ = f.connect(r)
	firstToken, otherToken := f.browser(r, f.login(f.reviewer)), f.browser(r, f.login(f.outsider))
	firstLease, e := f.s.Authorize(f.ctx, r.Binding(), firstToken, Metadata{Method: "GET", Path: "/"})
	if e != nil {
		t.Fatal(e)
	}
	otherLease, e := f.s.Authorize(f.ctx, r.Binding(), otherToken, Metadata{Method: "GET", Path: "/"})
	if e != nil {
		t.Fatal(e)
	}
	preview, e := f.s.PreviewGrants(f.ctx, f.org, r.ID, f.a, GrantsInput{ExpectedVersion: r.Version, Grants: []Grant{{"group", f.group}, {"user", f.outsider}}})
	if e != nil || !preview.RequiresConfirmation || preview.AffectedReviewerCount != 0 || preview.AffectedReviewerSessionCount != 0 {
		t.Fatal("overlap warning incorrectly counts unaffected reviewers", preview, e)
	}

	updated, e := f.s.UpdateGrants(f.ctx, f.org, r.ID, f.a, GrantsInput{ConfirmReviewerRemoval: true, ExpectedVersion: r.Version, Grants: []Grant{{"group", f.group}, {"user", f.outsider}}})
	if e != nil || updated.Binding() != r.Binding() {
		t.Fatal("audience mutation replaced the serving identity", e)
	}
	for _, lease := range []Decision{firstLease, otherLease} {
		if _, e = f.s.Renew(f.ctx, r.Binding(), lease.StreamID); e != nil {
			t.Fatal("overlapping or unrelated valid grant lost its stream", e)
		}
	}
	_, e = f.s.UpdateGrants(f.ctx, f.org, r.ID, f.a, GrantsInput{ConfirmReviewerRemoval: true, ExpectedVersion: updated.Version, Grants: []Grant{{"user", f.outsider}}})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.Renew(f.ctx, r.Binding(), firstLease.StreamID); e == nil {
		t.Fatal("removal of final matching grant did not deny")
	}
	if _, e = f.s.Renew(f.ctx, r.Binding(), otherLease.StreamID); e != nil {
		t.Fatal("unrelated eligible reviewer lost its stream", e)
	}
}
