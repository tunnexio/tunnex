package appaccess

import (
	"context"
	"errors"
	"fmt"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/internal/policy"
	"github.com/tunnexio/tunnex/apps/api/internal/tenancy"
)

func TestGrantWindowDatabasePrecision(t *testing.T) {
	a := time.Date(2026, 10, 3, 0, 0, 0, 1, time.UTC)
	b := a.Add(time.Nanosecond)
	code(t, validWindow(&a, &b), "invalid_grant_window")
}
func grantPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if os.Getenv("APP_ACCESS_LOCAL_INTEGRATION") != "1" {
		t.Skip("run owned local integration harness")
	}
	password := os.Getenv("AA0_DB_PASSWORD")
	if password == "" {
		t.Fatal("owned password required")
	}
	ctx := context.Background()
	admin, e := pgxpool.New(ctx, fmt.Sprintf("postgres://aa0:%s@postgres:5432/aa0?sslmode=disable", password))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(admin.Close)
	name := "aa2_grants_" + uuid.New().String()[:8]
	if _, e = admin.Exec(ctx, "CREATE DATABASE "+name); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if _, e := admin.Exec(context.Background(), "DROP DATABASE "+name+" WITH (FORCE)"); e != nil {
			t.Errorf("owned child DB cleanup: %v", e)
		}
	})
	dsn := fmt.Sprintf("postgres://aa0:%s@postgres:5432/%s?sslmode=disable", password, name)
	if e = db.MigrateTo(dsn, 167); e != nil {
		t.Fatal(e)
	}
	pool, e := pgxpool.New(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(pool.Close)
	if e = db.MigrateTo(dsn, 168); e != nil {
		t.Fatal(e)
	}
	if e = db.MigrateTo(dsn, 167); e != nil {
		t.Fatal("empty grant down", e)
	}
	if e = db.MigrateTo(dsn, 168); e != nil {
		t.Fatal(e)
	}
	if e = db.MigrateTo(dsn, 169); e != nil {
		t.Fatal(e)
	}
	if e = db.MigrateTo(dsn, 168); e != nil {
		t.Fatal("empty connector down", e)
	}
	if e = db.MigrateTo(dsn, 169); e != nil {
		t.Fatal(e)
	}
	if e = db.MigrateTo(dsn, 172); e != nil {
		t.Fatal(e)
	}
	return pool
}
func TestGrantsLocalDatabase(t *testing.T) {
	pool := grantPool(t)
	// Directory lifecycle uses current generated user projections.
	if e := db.MigrateTo(pool.Config().ConnString(), 174); e != nil {
		t.Fatal(e)
	}
	ctx := context.Background()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, e := pool.Exec(ctx, sql, args...); e != nil {
			t.Fatal(e)
		}
	}
	org, other, actor, u1, u2, foreign, gateway, group := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec("INSERT INTO organizations(id,name,slug) VALUES($1,'GrantOrg','grants'),($2,'Foreign','foreign')", org, other)
	for i, user := range []uuid.UUID{actor, u1, u2, foreign} {
		exec("INSERT INTO users(id,email,name,email_verified_at) VALUES($1,$2,$3,now())", user, fmt.Sprintf("u%d@test.fixture", i), fmt.Sprintf("User%d", i))
	}
	exec("INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'owner'),($1,$3,'member'),($1,$4,'member'),($5,$6,'member')", org, actor, u1, u2, other, foreign)
	exec("INSERT INTO nodes(id,org_id,name,cert_serial,enrolled_kind) VALUES($1,$2,'gateway','grantgateway','gateway')", gateway, org)
	exec("INSERT INTO user_groups(id,org_id,name) VALUES($1,$2,'App Team')", group, org)
	exec("INSERT INTO group_members(org_id,group_id,user_id) VALUES($1,$2,$3),($1,$2,$4)", org, group, u1, u2)
	now := time.Now().UTC().Truncate(time.Microsecond)
	s := NewService(pool, Config{AppBaseDomain: "apps.fixture.test", ConsoleHosts: []string{"console.other.test"}, Now: func() time.Time { return now }})
	_, e := s.UpdateSettings(ctx, org, actor, true, 1, true)
	if e != nil {
		t.Fatal(e)
	}
	app, e := s.CreateDraft(ctx, org, actor, DraftInput{Name: "DraftApp", OriginURL: "http://origin", GatewayID: gateway, PublicHostname: "grants.apps.fixture.test", IdleTimeoutSeconds: 60, AbsoluteTimeoutSeconds: 300}, true)
	if e != nil {
		t.Fatal(e)
	}
	preview := func(user uuid.UUID, entitled bool) Preview {
		t.Helper()
		p, e := s.EffectiveAccess(ctx, org, app.ID, user, entitled)
		if e != nil {
			t.Fatal(e)
		}
		if p.AccessAllowed {
			t.Fatal("draft falsely permits traffic")
		}
		return p
	}
	if p := preview(actor, true); p.GrantMatch || p.DenyReason != "no_active_grant" {
		t.Fatalf("implicit admin grant %+v", p)
	}
	end1, end2 := now.Add(10*time.Minute), now.Add(20*time.Minute)
	direct, e := s.CreateGrant(ctx, org, actor, GrantInput{AppID: app.ID, SubjectKind: "user", SubjectID: u1, Enabled: true, StartsAt: &now, ExpiresAt: &end1}, true)
	if e != nil {
		t.Fatal(e)
	}
	team, e := s.CreateGrant(ctx, org, actor, GrantInput{AppID: app.ID, SubjectKind: "group", SubjectID: group, Enabled: true, StartsAt: &now, ExpiresAt: &end2}, true)
	if e != nil {
		t.Fatal(e)
	}
	if p := preview(u1, true); !p.GrantMatch || len(p.MatchingGrantIDs) != 2 || p.DenyReason != "app_unpublished" || p.NextExpiryAt == nil || !p.NextExpiryAt.Equal(end1) {
		t.Fatalf("grant union %+v", p)
	}
	impact, e := s.RevokeImpact(ctx, org, direct.ID)
	if e != nil || impact.MatchingUserCount != 1 || impact.UsersLosingGrantMatchCount != 0 || impact.GrantVersion != 1 || impact.SessionImpactAvailable {
		t.Fatalf("direct impact %+v %v", impact, e)
	}
	impact, e = s.RevokeImpact(ctx, org, team.ID)
	if e != nil || impact.MatchingUserCount != 2 || impact.UsersLosingGrantMatchCount != 1 {
		t.Fatalf("group impact %+v %v", impact, e)
	}
	_, e = s.CreateGrant(ctx, org, actor, GrantInput{AppID: app.ID, SubjectKind: "user", SubjectID: u1, Enabled: false}, true)
	code(t, e, "grant_already_exists")
	_, e = s.CreateGrant(ctx, org, actor, GrantInput{AppID: app.ID, SubjectKind: "user", SubjectID: foreign, Enabled: true}, true)
	code(t, e, "application_not_found")
	foreignGroup := uuid.New()
	exec("INSERT INTO user_groups(id,org_id,name) VALUES($1,$2,'Foreign')", foreignGroup, other)
	_, e = s.CreateGrant(ctx, org, actor, GrantInput{AppID: app.ID, SubjectKind: "group", SubjectID: foreignGroup, Enabled: true}, true)
	code(t, e, "application_not_found")
	_, e = s.GetGrant(ctx, other, direct.ID)
	code(t, e, "application_not_found")
	list, e := s.ListGrants(ctx, other, nil, "", nil, 10, 0)
	if e != nil || len(list) != 0 {
		t.Fatal("grant tenant leak", e)
	}
	// Tenant FKs defend direct SQL as well as the service subject lookup.
	for _, kind := range []string{"user", "group"} {
		column, target, constraint := "user_id", foreign, "app_access_grants_org_id_user_id_fkey"
		if kind == "group" {
			column, target, constraint = "group_id", foreignGroup, "app_access_grants_group_id_org_id_fkey"
		}
		_, e = pool.Exec(ctx, "INSERT INTO app_access_grants(org_id,app_id,subject_kind,subject_id,subject_label,"+column+") VALUES($1,$2,$3,$4,'foreign',$4)", org, app.ID, kind, target)
		var pg *pgconn.PgError
		if !errors.As(e, &pg) || pg.Code != "23503" || pg.ConstraintName != constraint {
			t.Fatalf("wrong %s FK failure: %v", kind, e)
		}
	}
	// NULL SQL CHECK results must not permit a fresh grant with no FK subject.
	if _, e = pool.Exec(ctx, "INSERT INTO app_access_grants(org_id,app_id,subject_kind,subject_id,subject_label) VALUES($1,$2,'user',$3,'invalid')", org, app.ID, uuid.New()); e == nil {
		t.Fatal("NULL-target fresh grant accepted")
	}
	if _, e = pool.Exec(ctx, "UPDATE app_access_grants SET subject_id=$2 WHERE id=$1", direct.ID, u2); e == nil {
		t.Fatal("immutable subject changed")
	}
	now = end1
	if p := preview(u1, true); !p.GrantMatch || len(p.MatchingGrantIDs) != 1 || !p.NextExpiryAt.Equal(end2) {
		t.Fatalf("half-open expiry %+v", p)
	}
	now = end2
	if p := preview(u1, true); p.GrantMatch {
		t.Fatal("grant active at exclusive expiry")
	}
	now = end1.Add(-10 * time.Minute)
	// Feature loss and opt-out do not erase matches or imply actual app access.
	if p := preview(u1, false); !p.GrantMatch || p.DenyReason != "feature_unavailable" {
		t.Fatalf("feature loss %+v", p)
	}
	_, e = s.UpdateSettings(ctx, org, actor, false, 2, false)
	if e != nil {
		t.Fatal(e)
	}
	if p := preview(u1, true); !p.GrantMatch || p.DenyReason != "feature_disabled" {
		t.Fatalf("opt out %+v", p)
	}
	_, e = s.UpdateGrant(ctx, org, actor, direct.ID, GrantUpdate{Enabled: false, StartsAt: direct.StartsAt, ExpiresAt: direct.ExpiresAt}, 1, false)
	if e != nil {
		t.Fatal("disable after feature loss", e)
	}
	_, e = s.UpdateGrant(ctx, org, actor, direct.ID, GrantUpdate{Enabled: true, StartsAt: direct.StartsAt, ExpiresAt: direct.ExpiresAt}, 2, false)
	code(t, e, "feature_unavailable")
	_, e = s.UpdateSettings(ctx, org, actor, true, 3, true)
	if e != nil {
		t.Fatal(e)
	}
	_, e = s.UpdateGrant(ctx, org, actor, direct.ID, GrantUpdate{Enabled: true, StartsAt: direct.StartsAt, ExpiresAt: direct.ExpiresAt}, 1, true)
	code(t, e, "version_conflict")
	direct, e = s.UpdateGrant(ctx, org, actor, direct.ID, GrantUpdate{Enabled: true, StartsAt: direct.StartsAt, ExpiresAt: direct.ExpiresAt}, 2, true)
	if e != nil {
		t.Fatal(e)
	}
	exec("UPDATE users SET email_verified_at=NULL WHERE id=$1", u1)
	if p := preview(u1, true); !p.GrantMatch || p.DenyReason != "email_not_verified" {
		t.Fatalf("email gate %+v", p)
	}
	exec("UPDATE users SET email_verified_at=now(),must_change_password=true WHERE id=$1", u1)
	if p := preview(u1, true); !p.GrantMatch || p.DenyReason != "password_change_required" {
		t.Fatalf("password gate %+v", p)
	}
	exec("UPDATE users SET must_change_password=false WHERE id=$1", u1)
	exec("UPDATE memberships SET role='ai-admin',roles=ARRAY['ai-admin'] WHERE org_id=$1 AND user_id=$2", org, u1)
	if p := preview(u1, true); !p.GrantMatch || p.DenyReason != "no_use_permission" {
		t.Fatalf("named use gate %+v", p)
	}
	impact, e = s.RevokeImpact(ctx, org, team.ID)
	if e != nil || impact.MatchingUserCount != 1 {
		t.Fatalf("impact role eligibility %+v %v", impact, e)
	}
	exec("UPDATE memberships SET role='member',roles=ARRAY['member'] WHERE org_id=$1 AND user_id=$2", org, u1)
	exec("UPDATE memberships SET access_revoked_at=now() WHERE org_id=$1 AND user_id=$2", org, u1)
	if p := preview(u1, true); p.GrantMatch || p.DenyReason != "membership_unavailable" {
		t.Fatalf("logical revoke %+v", p)
	}
	exec("UPDATE memberships SET access_revoked_at=NULL WHERE org_id=$1 AND user_id=$2", org, u1)
	members := tenancy.NewMembershipService(pool, nil)
	if e = members.DeactivateMember(ctx, actor, org, u1); e != nil {
		t.Fatal(e)
	}
	if p := preview(u1, true); p.GrantMatch || p.DenyReason != "user_inactive" {
		t.Fatalf("deactivation %+v", p)
	}
	exec("UPDATE users SET status='active' WHERE id=$1", u1)
	exec("DELETE FROM group_members WHERE org_id=$1 AND group_id=$2 AND user_id=$3", org, group, u2)
	if p := preview(u2, true); p.GrantMatch {
		t.Fatal("removed group member retained grant")
	}
	exec("INSERT INTO group_members(org_id,group_id,user_id) VALUES($1,$2,$3)", org, group, u2)
	// Grant creation cannot survive a failed actor audit.
	_, e = s.CreateGrant(ctx, org, uuid.New(), GrantInput{AppID: app.ID, SubjectKind: "user", SubjectID: u2, Enabled: true}, true)
	if e == nil {
		t.Fatal("missing audit actor accepted")
	}
	var partial int
	if e = pool.QueryRow(ctx, "SELECT count(*) FROM app_access_grants WHERE org_id=$1 AND subject_kind='user' AND subject_id=$2", org, u2).Scan(&partial); e != nil || partial != 0 {
		t.Fatal("unaudited grant survived", e)
	}
	// Audited physical group deletion must preserve history and rollback on audit failure.
	exec(`CREATE FUNCTION aa2_fail_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='app_access.grant_subject_removed' THEN RAISE EXCEPTION 'injected audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER aa2_fail_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION aa2_fail_audit()`)
	groups := policy.NewService(pool)
	if e = groups.DeleteGroup(ctx, org, group); e == nil {
		t.Fatal("directory deletion swallowed audit failure")
	}
	retained, e := s.GetGrant(ctx, org, team.ID)
	if e != nil || retained.RevokedAt != nil || retained.Version != 1 {
		t.Fatalf("failed directory deletion changed grant %+v %v", retained, e)
	}
	exec("DROP TRIGGER aa2_fail_audit ON audit_logs; DROP FUNCTION aa2_fail_audit()")
	if e = groups.DeleteGroup(ctx, org, group); e != nil {
		t.Fatal("existing group delete blocked", e)
	}
	retained, e = s.GetGrant(ctx, org, team.ID)
	if e != nil || retained.Status != "revoked" || retained.SubjectID != group || retained.SubjectLabel != "App Team" || retained.Version != 2 {
		t.Fatalf("group history %+v %v", retained, e)
	}
	if p := preview(u2, true); p.GrantMatch {
		t.Fatal("physical group deletion retained access")
	}
	var actorSystem, kind string
	var version int64
	if e = pool.QueryRow(ctx, "SELECT actor_system,metadata->>'subject_kind',(metadata->>'version')::bigint FROM audit_logs WHERE action='app_access.grant_subject_removed' AND target_id=$1", team.ID.String()).Scan(&actorSystem, &kind, &version); e != nil || actorSystem != "app-access-subject-removal" || kind != "group" || version != 2 {
		t.Fatal("directory audit attribution", e)
	}
	if e = members.RemoveMember(ctx, &actor, "owner", org, u1); e != nil {
		t.Fatal("existing member remove blocked", e)
	}
	retained, e = s.GetGrant(ctx, org, direct.ID)
	if e != nil || retained.RevokedAt == nil || retained.SubjectID != u1 {
		t.Fatalf("member history %+v %v", retained, e)
	}
	if p := preview(u1, true); p.GrantMatch {
		t.Fatal("removed member matched")
	}
	exec("INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'member')", org, u1)
	if p := preview(u1, true); p.GrantMatch {
		t.Fatal("recreated membership resurrected retired grant")
	}
	fresh, e := s.CreateGrant(ctx, org, actor, GrantInput{AppID: app.ID, SubjectKind: "user", SubjectID: u1, Enabled: true}, true)
	if e != nil {
		t.Fatal("fresh grant after subject removal", e)
	}
	exec("UPDATE users SET deleted_at=now() WHERE id=$1", u1)
	if p := preview(u1, true); p.GrantMatch {
		t.Fatal("softdeleted user matched")
	}
	exec("UPDATE users SET deleted_at=NULL WHERE id=$1", u1)
	_, e = s.RevokeGrant(ctx, org, actor, fresh.ID, 2)
	code(t, e, "version_conflict")
	revoked, e := s.RevokeGrant(ctx, org, actor, fresh.ID, 1)
	if e != nil {
		t.Fatal(e)
	}
	repeat, e := s.RevokeGrant(ctx, org, actor, fresh.ID, 1)
	if e != nil || repeat.Version != revoked.Version {
		t.Fatal("revoke not idempotent", e)
	}
	var audits int
	if e = pool.QueryRow(ctx, "SELECT count(*) FROM audit_logs WHERE action='app_access.grant_revoked' AND target_id=$1", fresh.ID.String()).Scan(&audits); e != nil || audits != 1 {
		t.Fatal("repeated revoke duplicated audit", e)
	}
	// Scheduled grants do not match before inclusive start or at exclusive expiry.
	baseNow := now
	futureStart, futureEnd := now.Add(time.Hour), now.Add(2*time.Hour)
	scheduled, e := s.CreateGrant(ctx, org, actor, GrantInput{AppID: app.ID, SubjectKind: "user", SubjectID: u2, Enabled: true, StartsAt: &futureStart, ExpiresAt: &futureEnd}, true)
	if e != nil || scheduled.Status != "scheduled" {
		t.Fatalf("scheduled grant %+v %v", scheduled, e)
	}
	if p := preview(u2, true); p.GrantMatch {
		t.Fatal("scheduled grant matched early")
	}
	now = futureStart
	if p := preview(u2, true); !p.GrantMatch {
		t.Fatal("grant failed inclusive start")
	}
	now = futureEnd
	if p := preview(u2, true); p.GrantMatch {
		t.Fatal("scheduled grant matched exclusive expiry")
	}
	now = baseNow
	_, e = s.UpdateSettings(ctx, org, actor, false, 4, false)
	if e != nil {
		t.Fatal(e)
	}
	_, e = s.RevokeGrant(ctx, org, actor, scheduled.ID, scheduled.Version)
	if e != nil {
		t.Fatal("revoke during feature off", e)
	}
	// Directory deletion locks a subject before its FK updates the grant. An
	// additive edit must wait on that subject without holding the grant row.
	_, e = s.UpdateSettings(ctx, org, actor, true, 5, true)
	if e != nil {
		t.Fatal(e)
	}
	raceGroup := uuid.New()
	exec("INSERT INTO user_groups(id,org_id,name) VALUES($1,$2,'Concurrent deletion')", raceGroup, org)
	raceGrant, e := s.CreateGrant(ctx, org, actor, GrantInput{AppID: app.ID, SubjectKind: "group", SubjectID: raceGroup, Enabled: true}, true)
	if e != nil {
		t.Fatal(e)
	}
	directory, e := pool.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer directory.Rollback(ctx)
	if _, e = directory.Exec(ctx, "SELECT id FROM user_groups WHERE id=$1 FOR UPDATE", raceGroup); e != nil {
		t.Fatal(e)
	}
	editCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, editErr := s.UpdateGrant(editCtx, org, actor, raceGrant.ID, GrantUpdate{Enabled: true}, 1, true)
		done <- editErr
	}()
	deadline := time.Now().Add(3 * time.Second)
	blocked := false
	for time.Now().Before(deadline) {
		if e = pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%LockAppAccessGroupSubject%')").Scan(&blocked); e != nil {
			t.Fatal(e)
		}
		if blocked {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !blocked {
		t.Fatal("additive edit did not reach subject-lock barrier")
	}
	if _, e = directory.Exec(editCtx, "DELETE FROM user_groups WHERE org_id=$1 AND id=$2", org, raceGroup); e != nil {
		t.Fatal("directory-delete/edit lock inversion", e)
	}
	if e = directory.Commit(editCtx); e != nil {
		t.Fatal(e)
	}
	editErr := <-done
	var apiFailure *apierr.Error
	if !errors.As(editErr, &apiFailure) || (apiFailure.Status != 404 && apiFailure.Code != "grant_revoked") {
		t.Fatalf("edit after subject deletion must refuse safely: %v", editErr)
	}
	retained, e = s.GetGrant(ctx, org, raceGrant.ID)
	if e != nil || retained.Status != "revoked" || retained.Version != 2 {
		t.Fatalf("concurrent deletion grant history %+v %v", retained, e)
	}
	// Nonempty down refuses destruction without altering migration metadata.
	down, e := db.MigrationsFS.ReadFile("migrations/0168_app_access_grants.down.sql")
	if e != nil {
		t.Fatal(e)
	}
	tx, e := pool.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	_, e = tx.Exec(ctx, string(down))
	_ = tx.Rollback(ctx)
	if e == nil {
		t.Fatal("grant history down erased")
	}
	exec("UPDATE organizations SET deleted_at=now() WHERE id=$1", org)
	_, e = s.ListGrants(ctx, org, nil, "", nil, 10, 0)
	code(t, e, "application_not_found")
	_, e = s.GetGrant(ctx, org, fresh.ID)
	code(t, e, "application_not_found")
}
