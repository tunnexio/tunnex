package beam

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/color"
	"image/png"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/internal/session"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

func TestBeamRoomProjectPresetsCannotChangeExistingAuthority(t *testing.T) {
	f := newFixture(t)
	owner := f.login(f.owner)
	input := ProjectInput{Name: "Checkout", Target: Target{Protocol: "http", Address: "127.0.0.1", Port: 3000}, Duration: 1800, Grants: []Grant{{"user", f.reviewer}}}
	project, e := f.s.SaveProject(f.ctx, f.org, uuid.Nil, owner, input)
	if e != nil {
		t.Fatal(e)
	}
	in := CreateInput{ProjectID: &project.ID, Name: project.Name, Target: project.Target, Duration: project.Duration, Grants: project.Grants, IdempotencyKey: uuid.New()}
	first, e := f.s.Create(f.ctx, f.org, f.a, in)
	if e != nil {
		t.Fatal(e)
	}
	input.Target.Port = 4000
	input.Grants = []Grant{}
	input.ExpectedVersion = project.Version
	updated, e := f.s.SaveProject(f.ctx, f.org, project.ID, owner, input)
	if e != nil {
		t.Fatal(e)
	}
	preserved, e := f.s.Get(f.ctx, f.org, first.ID, f.a)
	if e != nil || preserved.Target.Port != 3000 || len(preserved.Grants) != 2 || preserved.Version != first.Version || preserved.Generation != first.Generation {
		t.Fatal("Preset edit changed live share", preserved, e)
	}
	if updated.Version != 2 {
		t.Fatal(updated)
	}
	if _, e = f.s.SaveProject(f.ctx, f.org, project.ID, owner, input); e == nil {
		t.Fatal("Stale project update accepted")
	}
	if _, e = f.s.GetProject(f.ctx, f.org, project.ID, f.login(f.reviewer)); e == nil {
		t.Fatal("Reviewer read private project target")
	}
	if _, e = f.s.GetProject(f.ctx, uuid.New(), project.ID, owner); e == nil {
		t.Fatal("Cross tenant project read")
	}
	f.exec(`UPDATE beam_shares SET state='stopped' WHERE id=$1`, first.ID)
	in.IdempotencyKey = uuid.New()
	second, e := f.s.Create(f.ctx, f.org, f.a, in)
	if e != nil {
		t.Fatal(e)
	}
	if second.ID == first.ID || second.Hostname == first.Hostname {
		t.Fatal("Fresh publication reused ended authority")
	}
	active, e := f.s.ProjectSessions(f.ctx, f.org, project.ID, owner, 1, 0, "active")
	if e != nil || len(active.Items) != 1 || active.Items[0].ID != second.ID {
		t.Fatal(active, e)
	}
	history, e := f.s.ProjectSessions(f.ctx, f.org, project.ID, owner, 1, 0, "history")
	if e != nil || len(history.Items) != 1 || history.Items[0].ID != first.ID {
		t.Fatal(history, e)
	}
	// Even an eligible different publisher cannot attach a session to another owner's room.
	f.exec(`INSERT INTO group_members(org_id,group_id,user_id) VALUES($1,$2,$3)`, f.org, f.group, f.reviewer)
	id := uuid.New()
	f.exec(`INSERT INTO cli_credentials(id,user_id,token_hash,fingerprint,expires_at) VALUES($1,$2,$3,'reviewer-cli',now()+interval '1 day')`, id, f.reviewer, hash("room-other-owner"))
	if _, e = f.s.Create(f.ctx, f.org, Actor{ID: f.reviewer, CredentialID: id}, in); e == nil {
		t.Fatal("Session attached to another owner's room")
	}
}
func TestBeamRoomFeedbackWithdrawalAndSanitizedScreenshot(t *testing.T) {
	f := newFixture(t)
	share := f.create()
	share, _ = f.connect(share)
	owner, reviewer, outsider := f.login(f.owner), f.login(f.reviewer), f.login(f.outsider)
	img := image.NewRGBA(image.Rect(0, 0, 2, 2))
	img.Set(0, 0, color.RGBA{R: 255, A: 255})
	var buf bytes.Buffer
	if e := png.Encode(&buf, img); e != nil {
		t.Fatal(e)
	}
	original := append(buf.Bytes(), []byte("secret-exif-like-trailer")...)
	feedback, e := f.s.AddFeedback(f.ctx, f.org, share.ID, reviewer, FeedbackInput{Body: "Mobile button overlaps", Status: "changes_requested", ScreenshotBase64: base64.StdEncoding.EncodeToString(original)})
	if e != nil {
		t.Fatal(e)
	}
	shot, e := f.s.FeedbackScreenshot(f.ctx, f.org, share.ID, feedback.ID, owner)
	if e != nil || bytes.Contains(shot, []byte("secret-exif")) {
		t.Fatal("Untrusted image metadata retained", e)
	}
	if _, format, e := image.Decode(bytes.NewReader(shot)); e != nil || format != "png" {
		t.Fatal("Screenshot not reencoded", format, e)
	}
	if _, e = f.s.FeedbackScreenshot(f.ctx, f.org, share.ID, feedback.ID, outsider); e == nil {
		t.Fatal("Outsider viewed screenshot")
	}
	if _, e = f.s.AddFeedback(f.ctx, f.org, share.ID, f.a, FeedbackInput{Body: "No bearer feedback", Status: "comment"}); e == nil {
		t.Fatal("Native credential submitted feedback")
	}
	page, e := f.s.Feedback(f.ctx, f.org, share.ID, reviewer, 20, 0)
	if e != nil || len(page.Items) != 1 || page.Items[0].ScreenshotURL == "" {
		t.Fatal(page, e)
	}
	notifications, e := f.s.Notifications(f.ctx, f.org, owner, 20, 0)
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, n := range notifications.Items {
		if n.Kind == "feedback" && n.ShareID == share.ID {
			found = true
		}
	}
	if !found {
		t.Fatal("Feedback notification absent")
	}
	f.exec(`DELETE FROM beam_grants WHERE share_id=$1 AND subject_id=$2`, share.ID, f.reviewer)
	if _, e = f.s.Feedback(f.ctx, f.org, share.ID, reviewer, 20, 0); e == nil {
		t.Fatal("Removed reviewer read feedback")
	}
	if _, e = f.s.FeedbackScreenshot(f.ctx, f.org, share.ID, feedback.ID, reviewer); e == nil {
		t.Fatal("Removed reviewer read attachment")
	}
	if _, e = f.s.AddFeedback(f.ctx, f.org, share.ID, reviewer, FeedbackInput{Status: "approved"}); e == nil {
		t.Fatal("Removed reviewer approved preview")
	}
	f.exec(`UPDATE beam_shares SET state='stopped' WHERE id=$1`, share.ID)
	if _, e = f.s.Feedback(f.ctx, f.org, share.ID, owner, 20, 0); e != nil {
		t.Fatal("Owner lost own history", e)
	}
	if _, e = f.s.AddFeedback(f.ctx, f.org, share.ID, owner, FeedbackInput{Status: "approved"}); e == nil {
		t.Fatal("Ended preview accepted new review")
	}
}
func TestBeamRoomInputBoundaries(t *testing.T) {
	for _, in := range []FeedbackInput{{Status: "comment"}, {Status: "admin"}, {Status: "comment", Body: strings.Repeat("x", 4001)}, {Status: "approved", ScreenshotBase64: "data:image/png;base64,AAAA"}, {Status: "approved", ScreenshotBase64: strings.Repeat("a", 400000)}} {
		if _, e := validateFeedback(&in); e == nil {
			t.Fatal("Unsafe feedback accepted")
		}
	}
	for _, status := range []string{"approved", "changes_requested"} {
		in := FeedbackInput{Status: status}
		if _, e := validateFeedback(&in); e != nil {
			t.Fatal(e)
		}
	}
	imageBomb := image.NewRGBA(image.Rect(0, 0, 2049, 2))
	var out bytes.Buffer
	_ = png.Encode(&out, imageBomb)
	if _, e := sanitizedScreenshot(base64.StdEncoding.EncodeToString(out.Bytes())); e == nil {
		t.Fatal("Oversized image dimensions accepted")
	}
	in := ProjectInput{Name: "Unsafe target", Target: Target{Protocol: "http", Address: "169.254.169.254", Port: 80}}
	if validateProject(&in) == nil {
		t.Fatal("Project preset allowed non-loopback")
	}
}
func TestBeamRoomInventoryScopesExcludeTerminalBeforePagination(t *testing.T) {
	f := newFixture(t)
	active := f.create()
	stopped := f.create()
	f.exec(`UPDATE beam_shares SET state='stopped' WHERE id=$1`, stopped.ID)
	page, e := f.s.ListQueryScope(f.ctx, f.org, f.a, false, 1, 0, "", "", "", "active")
	if e != nil || len(page.Items) != 1 || page.Items[0].ID != active.ID {
		t.Fatal(page, e)
	}
	history, e := f.s.ListQueryScope(f.ctx, f.org, f.a, false, 1, 0, "", "", "", "history")
	if e != nil || len(history.Items) != 1 || history.Items[0].ID != stopped.ID {
		t.Fatal(history, e)
	}
}

func TestBeamRoomFeedbackParentLogoutAndPolicyWithdrawal(t *testing.T) {
	f := newFixture(t)
	r := f.create()
	r, _ = f.connect(r)
	reviewer := f.login(f.reviewer)
	feedback, e := f.s.AddFeedback(f.ctx, f.org, r.ID, reviewer, FeedbackInput{Status: "approved"})
	if e != nil {
		t.Fatal(e)
	}
	if e = f.store.Delete(f.ctx, reviewer.SessionID); e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.Feedback(f.ctx, f.org, r.ID, reviewer, 20, 0); e == nil {
		t.Fatal("Logged out parent retained feedback access")
	}
	reviewer = f.login(f.reviewer)
	f.exec(`UPDATE beam_policies SET enabled=false WHERE org_id=$1`, f.org)
	if _, e = f.s.Feedback(f.ctx, f.org, r.ID, reviewer, 20, 0); e == nil {
		t.Fatal("Policy withdrawal retained reviewer history access")
	}
	if _, e = f.s.FeedbackScreenshot(f.ctx, f.org, r.ID, feedback.ID, reviewer); e == nil {
		t.Fatal("Withdrawn source retained attachment access")
	}
}

func TestBeamRoomMigrationPreservesSharesAndGuardsReviewData(t *testing.T) {
	ctx, pool := testpostgres.NewAtVersion(t, 212)
	var name string
	if e := pool.QueryRow(ctx, `SELECT current_database()`).Scan(&name); e != nil || !strings.HasPrefix(name, "tnx_test_") {
		t.Fatal("requires disposable database", e)
	}
	u, e := url.Parse(os.Getenv("TUNNEX_TEST_DATABASE_URL"))
	if e != nil {
		t.Fatal(e)
	}
	u.Path = "/" + name
	u.RawPath = ""
	params := u.Query()
	params.Del("database")
	params.Del("dbname")
	u.RawQuery = params.Encode()
	org, user, share := uuid.New(), uuid.New(), uuid.New()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, e := pool.Exec(ctx, q, args...); e != nil {
			t.Fatal(e)
		}
	}
	exec(`INSERT INTO organizations(id,name,slug)VALUES($1,'Room migration',$2)`, org, org.String())
	exec(`INSERT INTO users(id,email,name)VALUES($1,$2,'Owner')`, user, user.String()+"@migration.test")
	exec(`INSERT INTO beam_shares(id,org_id,publisher_id,name,hostname,target,digest,idempotency_key,request_digest,expires_at)VALUES($1,$2,$3,'Existing session','p-existing.beam.test','{"protocol":"http","address":"127.0.0.1","port":3000}',$4,$5,$4,now()+interval '1 hour')`, share, org, user, strings.Repeat("a", 64), uuid.New())
	if e = db.MigrateTo(u.String(), 213); e != nil {
		t.Fatal(e)
	}
	var version int
	var dirty bool
	var count int
	if e = pool.QueryRow(ctx, `SELECT version,dirty,(SELECT count(*) FROM beam_shares WHERE id=$1 AND project_id IS NULL AND state='starting' AND version=1) FROM schema_migrations`, share).Scan(&version, &dirty, &count); e != nil || version != 213 || dirty || count != 1 {
		t.Fatal("Upgrade changed existing session", version, dirty, count, e)
	}
	project := uuid.New()
	exec(`INSERT INTO beam_projects(id,org_id,owner_id,name,target,duration_seconds)VALUES($1,$2,$3,'Saved app','{}',1800)`, project, org, user)
	down, e := db.MigrationsFS.ReadFile("migrations/0213_beam_review_rooms.down.sql")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = pool.Exec(ctx, string(down)); e == nil || !strings.Contains(e.Error(), "Export and remove") {
		t.Fatal("Review data rollback not guarded", e)
	}
	exec(`DELETE FROM beam_projects WHERE id=$1`, project)
	exec(`INSERT INTO beam_feedback(org_id,share_id,author_id,body,status)VALUES($1,$2,$3,'Preserve this review','comment')`, org, share, user)
	if _, e = pool.Exec(ctx, string(down)); e == nil || !strings.Contains(e.Error(), "Export and remove") {
		t.Fatal("Feedback rollback not guarded", e)
	}
	exec(`DELETE FROM beam_feedback WHERE share_id=$1`, share)
	if e = db.MigrateTo(u.String(), 212); e != nil {
		t.Fatal(e)
	}
	if e = db.MigrateTo(u.String(), 213); e != nil {
		t.Fatal(e)
	}
	if e = pool.QueryRow(ctx, `SELECT count(*) FROM beam_shares WHERE id=$1 AND project_id IS NULL AND version=1 AND state='starting'`, share).Scan(&count); e != nil || count != 1 {
		t.Fatal("Rollback/reupgrade changed independent shares", count, e)
	}
}

func TestBeamRoomFeedbackRequiresFreshMFAWhenPolicyChanges(t *testing.T) {
	f := newFixture(t)
	r := f.create()
	r, _ = f.connect(r)
	reviewer := f.login(f.reviewer)
	if _, e := f.s.AddFeedback(f.ctx, f.org, r.ID, reviewer, FeedbackInput{Status: "approved"}); e != nil {
		t.Fatal(e)
	}
	f.exec(`UPDATE beam_policies SET require_mfa=true WHERE org_id=$1`, f.org)
	if _, e := f.s.Feedback(f.ctx, f.org, r.ID, reviewer, 20, 0); e == nil {
		t.Fatal("Policy MFA step up bypassed for reviews")
	}
	sess, e := f.store.CreateWithMFAAuthority(f.ctx, f.reviewer, "local_password", 1, time.Now(), session.MFAAssuranceLocalTOTP)
	if e != nil {
		t.Fatal(e)
	}
	reviewer.SessionID = sess.ID
	if _, e = f.s.Feedback(f.ctx, f.org, r.ID, reviewer, 20, 0); e != nil {
		t.Fatal("Fresh MFA rejected", e)
	}
	f.exec(`UPDATE users SET app_auth_epoch=2 WHERE id=$1`, f.reviewer)
	if _, e = f.s.Feedback(f.ctx, f.org, r.ID, reviewer, 20, 0); e == nil {
		t.Fatal("Changed auth epoch kept feedback access")
	}
}
