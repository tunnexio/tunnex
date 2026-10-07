package beam

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestBeamInventoryQuotaIgnoresPaginationAndFilters(t *testing.T) {
	f := newFixture(t)
	r := f.create()
	f.exec(`INSERT INTO beam_shares(org_id,publisher_id,source_credential_id,name,hostname,target,digest,idempotency_key,request_digest,state,created_at,expires_at)
 SELECT org_id,CASE WHEN i=6 THEN $2::uuid ELSE publisher_id END,source_credential_id,'Quota fixture','p-'||md5(i::text)||'.beam.other.net',target,digest,uuid_generate_v7(),request_digest,
 CASE WHEN i=1 THEN 'starting' WHEN i=2 THEN 'active' WHEN i=3 THEN 'paused' WHEN i=4 THEN 'stopped' ELSE 'active' END,
 now()-interval '2 minutes',CASE WHEN i=5 THEN now()-interval '1 minute' ELSE now()+interval '10 minutes' END
 FROM beam_shares CROSS JOIN generate_series(1,6) i WHERE id=$1`, r.ID, f.reviewer)
	for _, tc := range []struct {
		search, state, connectivity string
		limit, offset               int
	}{
		{"", "", "", 1, 0},
		{"missing search", "", "", 1, 0},
		{"", "stopped", "", 1, 0},
		{"", "", "online", 1, 0},
		{"", "", "", 1, 100},
	} {
		page, e := f.s.ListQuery(f.ctx, f.org, f.a, false, tc.limit, tc.offset, tc.search, tc.state, tc.connectivity)
		if e != nil || page.Quota == nil || page.Quota.ActiveShares != 4 || page.Quota.MaxShares != 5 {
			t.Fatalf("filtered inventory quota = %+v, err=%v", page.Quota, e)
		}
	}
	shared, e := f.s.List(f.ctx, f.org, f.a, true, 1, 0)
	if e != nil || shared.Quota != nil {
		t.Fatalf("reviewer page contains publisher quota: %+v err=%v", shared.Quota, e)
	}
	raw, e := json.Marshal(shared)
	if e != nil || strings.Contains(string(raw), `"quota"`) {
		t.Fatal("reviewer JSON must omit quota", e)
	}
}

func TestBeamAccessEvidencePreservesTenantIdentityShareAndKeyset(t *testing.T) {
	f := newFixture(t)
	r, _ := f.connect(f.create())
	token := f.browser(r, f.login(f.reviewer))
	if _, e := f.s.Authorize(f.ctx, r.Binding(), token, Metadata{Method: "GET", Path: "/"}); e != nil {
		t.Fatal(e)
	}
	f.s.auditDenied(f.ctx, r.Binding(), token)
	a := Actor{ID: f.owner, SessionID: "fixture-audit"}
	beforeID := uuid.MustParse("ffffffff-ffff-ffff-ffff-ffffffffffff")
	before := time.Now().Add(time.Hour)
	// The share can be terminal: retained admission evidence is not a live
	// content authority. Evidence itself remains append-only.
	f.exec(`UPDATE beam_shares SET state='stopped' WHERE id=$1`, r.ID)
	foreignOrg := uuid.New()
	f.exec(`INSERT INTO organizations(id,name,slug)VALUES($1,'Evidence foreign',$2)`, foreignOrg, foreignOrg.String())
	f.exec(`INSERT INTO memberships(org_id,user_id,role)VALUES($1,$2,'owner')`, foreignOrg, f.owner)
	f.exec(`INSERT INTO audit_logs(org_id,actor_user_id,action,target_type,target_id,metadata)VALUES($1,$2,'beam.access.denied','beam_share',$3,'{"reason":"authority_unavailable","outcome":"denied"}')`, foreignOrg, f.reviewer, r.ID.String())
	all, e := f.s.AccessEvents(f.ctx, f.org, a, nil, nil, false, before, beforeID, 100)
	if e != nil || len(all) != 2 {
		t.Fatalf("tenant admission evidence=%+v err=%v", all, e)
	}
	for _, v := range all {
		if v.ShareID != r.ID || v.UserID == nil || *v.UserID != f.reviewer || (v.Reason != "admission" && v.Reason != "authority_unavailable") {
			t.Fatalf("unexpected admission projection: %+v", v)
		}
	}
	// Equal timestamps exercise the secondary ID cursor using new retained
	// fixture rows, without updating the append-only evidence from real admission.
	keysetTime := time.Now().Add(-time.Minute).UTC().Truncate(time.Microsecond)
	for i := 0; i < 2; i++ {
		f.exec(`INSERT INTO audit_logs(org_id,actor_user_id,action,target_type,target_id,metadata,created_at)VALUES($1,$2,'beam.access.allowed','beam_share',$3,'{"reason":"admission","outcome":"allowed"}',$4)`, f.org, f.reviewer, r.ID.String(), keysetTime)
	}
	page1, e := f.s.AccessEvents(f.ctx, f.org, a, nil, &r.ID, false, keysetTime.Add(time.Second), beforeID, 1)
	if e != nil || len(page1) != 1 {
		t.Fatal("first evidence page", page1, e)
	}
	page2, e := f.s.AccessEvents(f.ctx, f.org, a, nil, &r.ID, false, page1[0].CreatedAt, page1[0].ID, 1)
	if e != nil || len(page2) != 1 || page2[0].ID == page1[0].ID {
		t.Fatal("evidence cursor overlapped or skipped equal-time event", page2, e)
	}
	denied, e := f.s.AccessEvents(f.ctx, f.org, a, &f.reviewer, &r.ID, true, before, beforeID, 100)
	if e != nil || len(denied) != 1 || denied[0].Action != "beam.access.denied" {
		t.Fatal("denied identity and share filter", denied, e)
	}
	unknown := uuid.New()
	for _, filter := range []struct{ user, share *uuid.UUID }{{&unknown, nil}, {nil, &unknown}} {
		got, e := f.s.AccessEvents(f.ctx, f.org, a, filter.user, filter.share, false, before, beforeID, 100)
		if e != nil || len(got) != 0 {
			t.Fatal("historical exact filter returned other evidence", got, e)
		}
	}
	if _, e = f.s.AccessEvents(f.ctx, f.org, Actor{ID: f.reviewer, SessionID: "fixture"}, nil, nil, false, before, beforeID, 100); e == nil {
		t.Fatal("member read organization audit evidence")
	}
	if _, e = f.s.AccessEvents(f.ctx, f.org, f.a, nil, nil, false, before, beforeID, 100); e == nil {
		t.Fatal("native credential read human audit evidence")
	}
	f.exec(`UPDATE users SET status='deactivated' WHERE id=$1`, f.owner)
	if _, e = f.s.AccessEvents(f.ctx, f.org, a, nil, nil, false, before, beforeID, 100); e == nil {
		t.Fatal("suspended actor retained access to evidence")
	}
}

func TestBeamReviewerInventoryOmitsEndedSharesBeforePagination(t *testing.T) {
	f := newFixture(t)
	active, _ := f.connect(f.create())
	paused, _ := f.connect(f.create())
	f.exec(`UPDATE beam_shares SET state='paused' WHERE id=$1`, paused.ID)
	// Newer stopped shares must not fill the first page and conceal usable apps.
	f.exec(`INSERT INTO beam_shares(org_id,publisher_id,source_credential_id,name,hostname,target,digest,idempotency_key,request_digest,state,created_at,expires_at)
 SELECT org_id,publisher_id,source_credential_id,'Ended fixture','p-'||md5(i::text)||'.beam.other.net',target,digest,uuid_generate_v7(),request_digest,
 CASE WHEN i=21 THEN 'expired' WHEN i=22 THEN 'revoked' ELSE 'stopped' END,now()+interval '1 minute',now()+interval '10 minutes'
 FROM beam_shares CROSS JOIN generate_series(1,22) i WHERE id=$1`, active.ID)
	f.exec(`INSERT INTO beam_grants(org_id,share_id,subject_kind,subject_id)
 SELECT org_id,id,'user',$2 FROM beam_shares WHERE org_id=$1 AND name='Ended fixture'`, f.org, f.reviewer)
	actor := Actor{ID: f.reviewer, SessionID: "reviewer-inventory"}
	first, e := f.s.List(f.ctx, f.org, actor, true, 1, 0)
	if e != nil || len(first.Items) != 1 || first.Items[0].ID != paused.ID {
		t.Fatalf("first reviewer page=%+v err=%v", first, e)
	}
	second, e := f.s.List(f.ctx, f.org, actor, true, 1, 1)
	if e != nil || len(second.Items) != 1 || second.Items[0].ID != active.ID {
		t.Fatalf("second reviewer page=%+v err=%v", second, e)
	}
	owner, e := f.s.List(f.ctx, f.org, f.a, false, 50, 0)
	if e != nil || len(owner.Items) != 24 {
		t.Fatalf("owner history=%+v err=%v", owner, e)
	}
	f.exec(`UPDATE beam_shares SET created_at=now()-interval '2 minutes',expires_at=now()-interval '1 second' WHERE id=$1`, paused.ID)
	visible, e := f.s.List(f.ctx, f.org, actor, true, 20, 0)
	if e != nil || len(visible.Items) != 1 || visible.Items[0].ID != active.ID {
		t.Fatalf("elapsed share visible=%+v err=%v", visible, e)
	}
	f.exec(`UPDATE cli_credentials SET revoked_at=now() WHERE id=$1`, f.a.CredentialID)
	visible, e = f.s.List(f.ctx, f.org, actor, true, 20, 0)
	if e != nil || len(visible.Items) != 0 {
		t.Fatalf("effectively revoked share visible=%+v err=%v", visible, e)
	}
}
