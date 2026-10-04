package appaccess

import (
	"context"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"strings"
	"testing"
	"time"
)

func TestDurableAuthorityLocalDatabase(t *testing.T) {
	p := grantPool(t)
	ctx := context.Background()
	if e := db.MigrateTo(p.Config().ConnString(), 173); e != nil {
		t.Fatal(e)
	}
	q := sqlc.New(p)
	initial, e := q.GetAppAccessInstallationAuthority(ctx)
	if e != nil || initial.Version != 1 || !initial.RecoveryCompletedAt.Valid {
		t.Fatal("initial authority", e)
	}
	// Even an initially empty database can have Redis authority minted under UUID1;
	// unsupported downgrade must refuse before deleting that durable UUID.
	if e = db.MigrateTo(p.Config().ConnString(), 172); e == nil || !strings.Contains(e.Error(), "forward-only") {
		t.Fatal("initial authority downgrade refusal", e)
	}
	// Only disposable child migration bookkeeping is restored after the expected refusal.
	if _, e = p.Exec(ctx, "UPDATE schema_migrations SET version=173,dirty=false"); e != nil {
		t.Fatal(e)
	}
	org, other, user, app := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec := func(s string, a ...any) {
		t.Helper()
		if _, e := p.Exec(ctx, s, a...); e != nil {
			t.Fatal(e)
		}
	}
	reject := func(s string, a ...any) {
		t.Helper()
		if _, e := p.Exec(ctx, s, a...); e == nil {
			t.Fatal("unsafe data accepted", s)
		}
	}
	exec("INSERT INTO organizations(id,name,slug)VALUES($1,'Durable',$2),($3,'Other',$4)", org, org.String(), other, other.String())
	exec("INSERT INTO users(id,email,name)VALUES($1,$2,'Durable user')", user, user.String()+"@fixture.test")
	// Explicit child-only registry rows use a deferred immutable revision fixture.
	tx, e := p.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	_, e = tx.Exec(ctx, "INSERT INTO app_access_applications(id,org_id)VALUES($1,$2)", app, org)
	if e != nil {
		t.Fatal(e)
	}
	gw := uuid.New()
	_, e = tx.Exec(ctx, "INSERT INTO nodes(id,org_id,name,enrolled_kind,cert_serial,cert_not_after)VALUES($1,$2,'durable','gateway','durable',now()+interval '1 day')", gw, org)
	if e != nil {
		t.Fatal(e)
	}
	_, e = tx.Exec(ctx, "INSERT INTO app_access_hostnames(hostname,org_id,app_id)VALUES('durable.apps.test',$1,$2)", org, app)
	if e != nil {
		t.Fatal(e)
	}
	_, e = tx.Exec(ctx, "INSERT INTO app_access_revisions(org_id,app_id,revision,name,icon,origin_url,gateway_id,public_hostname,idle_timeout_seconds,absolute_timeout_seconds,digest)VALUES($1,$2,1,'Durable','app','http://origin',$3,'durable.apps.test',60,300,repeat('0',64))", org, app, gw)
	if e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	initial, e = q.GetAppAccessInstallationAuthority(ctx)
	if e != nil {
		t.Fatal(e)
	}
	session := uuid.New()
	insert := `INSERT INTO app_access_session_revocations(org_id,app_id,user_id,live_user_id,session_id,installation_generation,absolute_expires_at,actor_user_id,actor_user_snapshot,reason)VALUES($1,$2,$3,$3,$4,$5,now()-interval '1 day',$3,$3,'self')`
	reject(insert, other, app, user, session, initial.Generation)
	exec(insert, org, app, user, session, initial.Generation)
	args := sqlc.AppAccessSessionRevokedParams{OrgID: org, AppID: app, UserID: user, SessionID: session, InstallationGeneration: initial.Generation}
	yes, e := q.AppAccessSessionRevoked(ctx, args)
	if e != nil || !yes {
		t.Fatal("expired snapshot tombstone not retained", e)
	}
	args.OrgID = other
	yes, e = q.AppAccessSessionRevoked(ctx, args)
	if e != nil || yes {
		t.Fatal("foreign tombstone disclosure", e)
	}
	args.OrgID = org
	if row, e := q.GetAppAccessSessionRevocationForUser(ctx, sqlc.GetAppAccessSessionRevocationForUserParams{OrgID: org, UserID: user, SessionID: session}); e != nil || row.AppID != app {
		t.Fatal("self retry lookup", e)
	}
	if _, e := q.GetAppAccessSessionRevocationForUser(ctx, sqlc.GetAppAccessSessionRevocationForUserParams{OrgID: other, UserID: user, SessionID: session}); e == nil {
		t.Fatal("foreign self retry disclosure")
	}
	if row, e := q.GetAppAccessSessionRevocationForApplication(ctx, sqlc.GetAppAccessSessionRevocationForApplicationParams{OrgID: org, AppID: app, SessionID: session}); e != nil || row.UserID != user {
		t.Fatal("administrator retry lookup", e)
	}
	reject("UPDATE app_access_session_revocations SET session_id=$1", uuid.New())
	exec("DELETE FROM users WHERE id=$1", user)
	yes, e = q.AppAccessSessionRevoked(ctx, args)
	if e != nil || !yes {
		t.Fatal("user deletion lost tombstone", e)
	}
	var live, actor *uuid.UUID
	var snapshot uuid.UUID
	if e = p.QueryRow(ctx, "SELECT live_user_id,actor_user_id,actor_user_snapshot FROM app_access_session_revocations WHERE session_id=$1", session).Scan(&live, &actor, &snapshot); e != nil || live != nil || actor != nil || snapshot != user {
		t.Fatal("identity history", e)
	}
	if _, e = q.RotateAppAccessInstallationAuthority(ctx, initial.Version+1); e == nil {
		t.Fatal("stale rotate accepted")
	}
	changed, e := q.RotateAppAccessInstallationAuthority(ctx, initial.Version)
	if e != nil || changed.Generation == initial.Generation || changed.Version != 2 || changed.RecoveryCompletedAt.Valid {
		t.Fatal("rotation fence", e)
	}
	if _, e = q.ConfirmAppAccessInstallationRecovery(ctx, sqlc.ConfirmAppAccessInstallationRecoveryParams{ExpectedGeneration: initial.Generation, ExpectedVersion: changed.Version}); e == nil {
		t.Fatal("stale generation confirmation")
	}
	if _, e = q.ConfirmAppAccessInstallationRecovery(ctx, sqlc.ConfirmAppAccessInstallationRecoveryParams{ExpectedGeneration: changed.Generation, ExpectedVersion: changed.Version}); e != nil {
		t.Fatal(e)
	}
	recoveryUser, proxyID := uuid.New(), uuid.New()
	exec("INSERT INTO users(id,email,name)VALUES($1,$2,'Recovery')", recoveryUser, recoveryUser.String()+"@fixture.test")
	exec("INSERT INTO app_access_proxy_credentials(id,name,token_hash)VALUES($1,'Recovery proxy',decode(repeat('cc',32),'hex'))", proxyID)
	exec("INSERT INTO app_access_serving_publications(org_id,app_id,gateway_id,revision,digest,hostname,state)VALUES($1,$2,$3,1,repeat('0',64),'durable.apps.test','active')", org, app, gw)
	if n, e := q.RevokeAllAppAccessProxyCredentials(ctx); e != nil || n != 1 {
		t.Fatal("proxy recovery count", n, e)
	}
	if n, e := q.DisableAllAppAccessServingPublications(ctx); e != nil || n != 1 {
		t.Fatal("serving recovery count", n, e)
	}
	if n, e := q.AdvanceAllUserAppAuthEpoch(ctx); e != nil || n != 1 {
		t.Fatal("parent recovery count", n, e)
	}
	var epoch int64
	if e = p.QueryRow(ctx, "SELECT app_auth_epoch FROM users WHERE id=$1", recoveryUser).Scan(&epoch); e != nil || epoch != 2 {
		t.Fatal("parent recovery epoch", epoch, e)
	}
	var proxyVersion, authorityVersion int64
	var revoked bool
	var state string
	if e = p.QueryRow(ctx, "SELECT version,revoked_at IS NOT NULL FROM app_access_proxy_credentials WHERE id=$1", proxyID).Scan(&proxyVersion, &revoked); e != nil || proxyVersion != 2 || !revoked {
		t.Fatal("proxy recovery", e)
	}
	if e = p.QueryRow(ctx, "SELECT state,authority_version FROM app_access_serving_publications WHERE org_id=$1 AND app_id=$2", org, app).Scan(&state, &authorityVersion); e != nil || state != "disabled" || authorityVersion != 2 {
		t.Fatal("serving recovery", e)
	}
	event := `INSERT INTO app_access_events(org_id,app_id,installation_generation,event_kind,outcome,reason,created_at)VALUES($1,$2,$3,'request_denied','denied',$4,$5)`
	reject(event, other, app, changed.Generation, "session_invalid", time.Now())
	reject(event, org, app, changed.Generation, "Cookie: secret", time.Now())
	for i := 0; i < 5; i++ {
		exec(event, org, app, changed.Generation, "session_invalid", time.Now().Add(time.Duration(-i)*time.Minute))
	}
	rows, e := q.ListAppAccessEvents(ctx, sqlc.ListAppAccessEventsParams{OrgID: org, PageLimit: 2})
	if e != nil || len(rows) != 2 {
		t.Fatal("event page", e)
	}
	n, e := q.PruneAppAccessEvents(ctx, sqlc.PruneAppAccessEventsParams{OrgID: org, BeforeTime: time.Now().Add(-time.Hour), RetainedRows: 2, BatchLimit: 1})
	if e != nil || n != 1 {
		t.Fatal("bounded prune", n, e)
	}
	rows, e = q.ListAppAccessEvents(ctx, sqlc.ListAppAccessEventsParams{OrgID: other, PageLimit: 100})
	if e != nil || len(rows) != 0 {
		t.Fatal("event tenant", e)
	}
	yes, e = q.AppAccessSessionRevoked(ctx, args)
	if e != nil || !yes {
		t.Fatal("event prune removed revocation", e)
	}
	producer := &EventProducer{pool: p}
	validEvent := Event{OrgID: org, AppID: app, InstallationGeneration: changed.Generation, Kind: "request_denied", Outcome: "denied", Reason: "session_invalid"}
	if e = producer.writeBatch(ctx, []Event{validEvent}); e != nil {
		t.Fatal("typed batch", e)
	}
	var beforeCount, afterCount int64
	if e = p.QueryRow(ctx, "SELECT count(*) FROM app_access_events WHERE org_id=$1", org).Scan(&beforeCount); e != nil {
		t.Fatal(e)
	}
	invalidEvent := validEvent
	invalidEvent.Reason = "Cookie: fixture"
	if e = producer.writeBatch(ctx, []Event{validEvent, invalidEvent}); e == nil {
		t.Fatal("private arbitrary event text persisted")
	}
	foreignEvent := validEvent
	foreignEvent.OrgID = other
	if e = producer.writeBatch(ctx, []Event{validEvent, foreignEvent}); e == nil {
		t.Fatal("foreign app tuple event persisted")
	}
	if e = p.QueryRow(ctx, "SELECT count(*) FROM app_access_events WHERE org_id=$1", org).Scan(&afterCount); e != nil || afterCount != beforeCount {
		t.Fatal("failed typed batch partially persisted", e)
	}
	exec(event, org, app, changed.Generation, "session_invalid", time.Now().Add(-31*24*time.Hour))
	exec("CREATE FUNCTION app_event_prune_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture retention failure'; END $$; CREATE TRIGGER app_event_prune_failure BEFORE DELETE ON app_access_events FOR EACH ROW EXECUTE FUNCTION app_event_prune_failure()")
	if e = p.QueryRow(ctx, "SELECT count(*) FROM app_access_events WHERE org_id=$1", org).Scan(&beforeCount); e != nil {
		t.Fatal(e)
	}
	if e = producer.writeBatch(ctx, []Event{validEvent}); e == nil {
		t.Fatal("retention failure accepted")
	}
	if e = p.QueryRow(ctx, "SELECT count(*) FROM app_access_events WHERE org_id=$1", org).Scan(&afterCount); e != nil || afterCount != beforeCount {
		t.Fatal("retention failure did not roll back append", e)
	}
	exec("DROP TRIGGER app_event_prune_failure ON app_access_events; DROP FUNCTION app_event_prune_failure()")
	// Historical tenants produce no new event after restart. Enumeration must
	// still discover them with a bounded keyset page instead of an in-memory map.
	quietTx, e := p.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	_, e = quietTx.Exec(ctx, `CREATE TEMP TABLE quiet_app_event_fixture AS SELECT uuid_generate_v7() AS org_id,uuid_generate_v7() AS app_id,uuid_generate_v7() AS gateway_id FROM generate_series(1,65);
 INSERT INTO organizations(id,name,slug)SELECT org_id,'Quiet',org_id::text FROM quiet_app_event_fixture;
 INSERT INTO nodes(id,org_id,name,enrolled_kind,cert_serial,cert_not_after)SELECT gateway_id,org_id,'Quiet','gateway',gateway_id::text,now()+interval '1 day' FROM quiet_app_event_fixture;
 INSERT INTO app_access_applications(id,org_id)SELECT app_id,org_id FROM quiet_app_event_fixture;
 INSERT INTO app_access_hostnames(hostname,org_id,app_id)SELECT 'quiet-'||app_id::text||'.apps.test',org_id,app_id FROM quiet_app_event_fixture;
 INSERT INTO app_access_revisions(org_id,app_id,revision,name,icon,origin_url,gateway_id,public_hostname,idle_timeout_seconds,absolute_timeout_seconds,digest)SELECT org_id,app_id,1,'Quiet','app','http://origin',gateway_id,'quiet-'||app_id::text||'.apps.test',60,300,repeat('0',64) FROM quiet_app_event_fixture;`)
	if e != nil {
		t.Fatal(e)
	}
	_, e = quietTx.Exec(ctx, "INSERT INTO app_access_events(org_id,app_id,installation_generation,event_kind,outcome,reason,created_at)SELECT org_id,app_id,$1,'request_denied','denied','none',now()-interval '31 days' FROM quiet_app_event_fixture", changed.Generation)
	if e != nil {
		t.Fatal(e)
	}
	if e = quietTx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	first, e := q.ListAppAccessEventRetentionOrganizations(ctx, sqlc.ListAppAccessEventRetentionOrganizationsParams{AfterOrgID: uuid.Nil, PageLimit: 1000})
	if e != nil || len(first) != 64 {
		t.Fatal("quiet retention page bound", len(first), e)
	}
	second, e := q.ListAppAccessEventRetentionOrganizations(ctx, sqlc.ListAppAccessEventRetentionOrganizationsParams{AfterOrgID: first[len(first)-1], PageLimit: 64})
	if e != nil || len(second) != 2 {
		t.Fatal("quiet retention next page", len(second), e)
	}
	for _, id := range second {
		if id.String() <= first[len(first)-1].String() {
			t.Fatal("retention cursor repeated")
		}
	}
	last, e := q.ListAppAccessEventRetentionOrganizations(ctx, sqlc.ListAppAccessEventRetentionOrganizationsParams{AfterOrgID: second[len(second)-1], PageLimit: 64})
	if e != nil || len(last) != 0 {
		t.Fatal("retention cursor terminal", e)
	}
	var quietOrg uuid.UUID
	if e = p.QueryRow(ctx, "SELECT org_id FROM app_access_events WHERE org_id<>$1 AND created_at<now()-interval '30 days' LIMIT 1", org).Scan(&quietOrg); e != nil {
		t.Fatal(e)
	}
	quietVisible, e := q.ListAppAccessEvents(ctx, sqlc.ListAppAccessEventsParams{OrgID: quietOrg, PageLimit: 100})
	if e != nil || len(quietVisible) != 0 {
		t.Fatal("age expired pending cleanup rows exposed", e)
	}
	sweepCtx, cancelSweep := context.WithTimeout(ctx, 2*time.Second)
	cursor := producer.sweep(sweepCtx, uuid.Nil)
	cancelSweep()
	if cursor != first[len(first)-1] {
		t.Fatal("quiet sweep cursor", cursor)
	}
	var expiredRemaining int64
	if e = p.QueryRow(ctx, "SELECT count(*) FROM app_access_events WHERE created_at<now()-interval '30 days'").Scan(&expiredRemaining); e != nil || expiredRemaining != 2 {
		t.Fatal("quiet first sweep", expiredRemaining, e)
	}
	sweepCtx, cancelSweep = context.WithTimeout(ctx, 2*time.Second)
	cursor = producer.sweep(sweepCtx, cursor)
	cancelSweep()
	if e = p.QueryRow(ctx, "SELECT count(*) FROM app_access_events WHERE created_at<now()-interval '30 days'").Scan(&expiredRemaining); e != nil || expiredRemaining != 0 {
		t.Fatal("quiet second sweep", expiredRemaining, e)
	}
	if next := producer.sweep(ctx, cursor); next != uuid.Nil {
		t.Fatal("quiet sweep failed to cycle cursor", next)
	}
	if e = db.MigrateTo(p.Config().ConnString(), 172); e == nil {
		t.Fatal("history down accepted")
	}
}
