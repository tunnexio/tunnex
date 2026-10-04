package appaccess

import (
	"context"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"testing"
	"time"
)

// This exercises SQL authority guards with explicit child-DB proof fixtures;
// it does not qualify public DNS/TLS or the production readiness worker.
func TestPublicationLocalDatabase(t *testing.T) {
	p := grantPool(t)
	ctx := context.Background()
	if e := db.MigrateTo(p.Config().ConnString(), 171); e != nil {
		t.Fatal("empty down", e)
	}
	if e := db.MigrateTo(p.Config().ConnString(), 172); e != nil {
		t.Fatal("up", e)
	}
	exec := func(s string, a ...any) {
		t.Helper()
		if _, e := p.Exec(ctx, s, a...); e != nil {
			t.Fatal(e)
		}
	}
	reject := func(s string, a ...any) {
		t.Helper()
		if _, e := p.Exec(ctx, s, a...); e == nil {
			t.Fatal("unsafe SQL accepted", s)
		}
	}
	if e := db.MigrateTo(p.Config().ConnString(), 174); e != nil {
		t.Fatal(e)
	}
	org, user, gw := uuid.New(), uuid.New(), uuid.New()
	exec("INSERT INTO organizations(id,name,slug)VALUES($1,'Publication',$2)", org, org.String())
	exec("INSERT INTO users(id,email,name)VALUES($1,$2,'Publisher')", user, user.String()+"@fixture.test")
	exec("INSERT INTO nodes(id,org_id,name,cert_serial,cert_not_after,enrolled_kind)VALUES($1,$2,'pub','cert',now()+interval '1 day','gateway')", gw, org)
	s := NewService(p, Config{AppBaseDomain: "apps.fixture.test", ConsoleHosts: []string{"console.other.test"}})
	if _, e := s.UpdateSettings(ctx, org, user, true, 1, true); e != nil {
		t.Fatal(e)
	}
	app, e := s.CreateDraft(ctx, org, user, DraftInput{Name: "Publication", Icon: "app", OriginURL: "http://origin", GatewayID: gw, PublicHostname: "pub.apps.fixture.test", IdleTimeoutSeconds: 60, AbsoluteTimeoutSeconds: 300}, true)
	if e != nil {
		t.Fatal(e)
	}
	generation, check, proxy := uuid.New(), uuid.New(), uuid.New()
	exec("INSERT INTO app_access_connector_assignments(org_id,app_id,gateway_id,revision,digest,generation)VALUES($1,$2,$3,1,$4,$5)", org, app.ID, gw, app.Draft.Digest, generation)
	exec("INSERT INTO app_access_origin_checks(id,org_id,app_id,gateway_id,revision,digest,generation,status,completed_at,completed_cert_serial)VALUES($1,$2,$3,$4,1,$5,$6,'succeeded',now(),'cert')", check, org, app.ID, gw, app.Draft.Digest, generation)
	exec("INSERT INTO app_access_proxy_credentials(id,name,token_hash)VALUES($1,'Fixture',decode(repeat('ab',32),'hex'))", proxy)
	q := sqlc.New(p)
	args := sqlc.CreateAppAccessPublicationOperationParams{OrgID: org, AppID: app.ID, ActorUserID: user, IdempotencyKey: uuid.New(), ReviewedAppVersion: 1, ExpectedAppVersion: 2, Revision: 1, Digest: app.Draft.Digest, OriginCheckID: check, GatewayID: gw, Hostname: app.Draft.PublicHostname, GatewayCertSerial: "cert", Deadline: time.Now().Add(55 * time.Second)}
	bad := args
	bad.OrgID = uuid.New()
	if _, e = q.CreateAppAccessPublicationOperation(ctx, bad); e == nil {
		t.Fatal("foreign tuple accepted")
	}
	if v, e := q.AdvanceAppAccessApplicationAuthorityVersion(ctx, sqlc.AdvanceAppAccessApplicationAuthorityVersionParams{OrgID: org, AppID: app.ID, ExpectedVersion: 1}); e != nil || v != 2 {
		t.Fatal("stage authority version", v, e)
	}
	op, e := q.CreateAppAccessPublicationOperation(ctx, args)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = q.CreateAppAccessPublicationOperation(ctx, args); e == nil {
		t.Fatal("duplicate key accepted")
	}
	args.IdempotencyKey = uuid.New()
	if _, e = q.CreateAppAccessPublicationOperation(ctx, args); e == nil {
		t.Fatal("second pending accepted")
	}
	reject("UPDATE app_access_publication_operations SET digest=repeat('0',64) WHERE id=$1", op.ID)
	reject("DELETE FROM app_access_origin_checks WHERE id=$1", check)
	activate := func(want int64) {
		t.Helper()
		n, e := q.ActivateAppAccessServingPublication(ctx, sqlc.ActivateAppAccessServingPublicationParams{OrgID: org, AppID: app.ID, OperationID: op.ID, ExpectedVersion: 1})
		if e != nil || n != want {
			t.Fatal("activation", n, want, e)
		}
	}
	activate(0)
	exec("UPDATE app_access_publication_operations SET status='checking',proxy_credential_id=$2,proxy_credential_version=1,proxy_instance_token_hash=decode(repeat('cd',32),'hex'),public_dns_status='passed',public_tls_status='passed',connector_dns_status='passed',connector_connect_status='passed',connector_tls_status='skipped',origin_proof_completed_at=now(),public_proof_completed_at=now() WHERE id=$1", op.ID, proxy)
	activate(0) // Origin-check capability cannot substitute browser capability.
	exec("INSERT INTO app_access_browser_gateway_runtime(org_id,gateway_id,capability_version,reported_cert_serial)VALUES($1,$2,1,'cert')", org, gw)
	exec("UPDATE nodes SET cert_serial='rotated' WHERE id=$1", gw)
	activate(0)
	exec("UPDATE nodes SET cert_serial='cert' WHERE id=$1", gw)
	exec("UPDATE app_access_origin_checks SET completed_at=now()-interval '6 minutes' WHERE id=$1", check)
	activate(0)
	exec("UPDATE app_access_origin_checks SET completed_at=now() WHERE id=$1", check)
	exec("UPDATE app_access_publication_operations SET origin_proof_completed_at=now()-interval '11 seconds' WHERE id=$1", op.ID)
	activate(0)
	exec("UPDATE app_access_publication_operations SET origin_proof_completed_at=now() WHERE id=$1", op.ID)
	activate(1)
	pub, e := q.GetAppAccessServingPublication(ctx, sqlc.GetAppAccessServingPublicationParams{OrgID: org, AppID: app.ID})
	if e != nil || pub.Generation != op.Generation || pub.AuthorityVersion != 1 {
		t.Fatal("exact pointer", e)
	}
	exec("UPDATE app_access_publication_operations SET status='activated',completed_at=now() WHERE id=$1", op.ID)
	history, e := q.ListPreviouslyActivatedAppAccessRevisions(ctx, sqlc.ListPreviouslyActivatedAppAccessRevisionsParams{OrgID: org, AppID: app.ID, PageLimit: 50})
	if e != nil || len(history) != 1 || history[0].Revision != 1 || history[0].Name != "Publication" || history[0].ActivatedAt.IsZero() {
		t.Fatal("activated history projection", e, history)
	}
	if v, e := q.AdvanceAppAccessApplicationAuthorityVersion(ctx, sqlc.AdvanceAppAccessApplicationAuthorityVersionParams{OrgID: org, AppID: app.ID, ExpectedVersion: 2}); e != nil || v != 3 {
		t.Fatal("second stage authority version", v, e)
	}
	args.ReviewedAppVersion = 2
	args.ExpectedAppVersion = 3
	args.ExpectedActiveAuthorityVersion = 1
	args.IdempotencyKey = uuid.New()
	pending, e := q.CreateAppAccessPublicationOperation(ctx, args)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = q.FailAppAccessPublicationOperation(ctx, sqlc.FailAppAccessPublicationOperationParams{OrgID: org, AppID: app.ID, OperationID: pending.ID, ExpectedVersion: 1, ErrorCode: "connector_failed"}); e != nil {
		t.Fatal(e)
	}
	after, e := q.GetAppAccessServingPublication(ctx, sqlc.GetAppAccessServingPublicationParams{OrgID: org, AppID: app.ID})
	if e != nil || after.Generation != pub.Generation || after.State != "active" {
		t.Fatal("failed stage changed active", e)
	}
	if _, e = q.DisableAppAccessServingPublication(ctx, sqlc.DisableAppAccessServingPublicationParams{OrgID: org, AppID: app.ID}); e != nil {
		t.Fatal(e)
	}
	archive := func(want int64) {
		t.Helper()
		n, e := q.ArchiveAppAccessApplication(ctx, sqlc.ArchiveAppAccessApplicationParams{OrgID: org, AppID: app.ID, ExpectedVersion: 3})
		if e != nil || n != want {
			t.Fatal("archive", n, want, e)
		}
	}
	archive(0)
	if _, e = q.ConfirmAppAccessPublicationWithdrawal(ctx, sqlc.ConfirmAppAccessPublicationWithdrawalParams{OrgID: org, AppID: app.ID, ExpectedAuthorityVersion: 1, ExpectedGeneration: pub.Generation}); e == nil {
		t.Fatal("stale withdrawal confirmation")
	}
	if _, e = q.ConfirmAppAccessPublicationWithdrawal(ctx, sqlc.ConfirmAppAccessPublicationWithdrawalParams{OrgID: org, AppID: app.ID, ExpectedAuthorityVersion: 2, ExpectedGeneration: pub.Generation}); e != nil {
		t.Fatal(e)
	}
	archive(1)
	ordinary, e := q.ListAppAccessApplicationIDs(ctx, sqlc.ListAppAccessApplicationIDsParams{OrgID: org, PageLimit: 100})
	if e != nil || len(ordinary) != 0 {
		t.Fatal("archived remained in ordinary inventory", e, ordinary)
	}
	retained, e := q.GetAppAccessApplication(ctx, sqlc.GetAppAccessApplicationParams{OrgID: org, ID: app.ID})
	if e != nil || retained.State != "archived" {
		t.Fatal("archived detail lost", e)
	}
	if _, e = q.GetPreviouslyActivatedAppAccessRevision(ctx, sqlc.GetPreviouslyActivatedAppAccessRevisionParams{OrgID: org, AppID: app.ID, Revision: 1}); e != nil {
		t.Fatal("archived publication history lost", e)
	}

	if e = q.AdvanceAppAccessDraft(ctx, sqlc.AdvanceAppAccessDraftParams{OrgID: org, ID: app.ID}); e != nil {
		t.Fatal(e)
	}
	var version int64
	if e = p.QueryRow(ctx, "SELECT version FROM app_access_applications WHERE id=$1", app.ID).Scan(&version); e != nil || version != 4 {
		t.Fatal("archived draft advanced", version, e)
	}
	if e = db.MigrateTo(p.Config().ConnString(), 171); e == nil {
		t.Fatal("retained history down allowed")
	}
}
