package appaccess

import (
	"context"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db"
	"image/color"
	"testing"
	"time"
)

func TestPublicationServiceLocalDatabase(t *testing.T) {
	pool := grantPool(t)
	if err := db.MigrateTo(pool.Config().ConnString(), 174); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, e := pool.Exec(ctx, sql, args...); e != nil {
			t.Fatal(e)
		}
	}
	org, actor, gw := uuid.New(), uuid.New(), uuid.New()
	exec("INSERT INTO organizations(id,name,slug)VALUES($1,'PublicationService','publication-service')", org)
	exec("INSERT INTO users(id,email,name,email_verified_at)VALUES($1,'publication-service@fixture.test','Owner',now())", actor)
	exec("INSERT INTO memberships(org_id,user_id,role)VALUES($1,$2,'owner')", org, actor)
	exec("INSERT INTO nodes(id,org_id,name,cert_serial,cert_not_after,enrolled_kind)VALUES($1,$2,'publication','abc1',now()+interval '1 day','gateway')", gw, org)
	s := NewService(pool, Config{AppBaseDomain: "apps.example.net", ConsoleHosts: []string{"console.example.com"}, ConsoleURL: "https://console.example.com"})
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	_, e := s.UpdateSettings(ctx, org, actor, true, 1, true)
	must(e)
	app, e := s.CreateDraft(ctx, org, actor, DraftInput{Name: "Published original", IconDataURL: iconFixture(t, "png", 24, color.Black), OriginURL: "http://origin.fixture.test", GatewayID: gw, PublicHostname: "publication.apps.example.net", IdleTimeoutSeconds: 60, AbsoluteTimeoutSeconds: 300}, true)
	must(e)
	gateway := AuthenticatedGateway{org, gw, "abc1"}
	_, e = s.ReportCapability(ctx, gateway, 1)
	must(e)
	check, e := s.RequestCheck(ctx, org, actor, app.ID, app.Version, true)
	must(e)
	_, e = s.DesiredForGateway(ctx, gateway, true)
	must(e)
	_, e = s.CompleteCheck(ctx, gateway, Result{RequestID: check.ID, AppID: app.ID, Generation: check.Generation, Revision: check.Revision, Digest: check.Digest, Purpose: "origin_check", DNSStatus: "passed", ConnectStatus: "passed", TLSStatus: "skipped"}, true)
	must(e)
	input := PublicationInput{ExpectedVersion: app.Version, Revision: app.DraftRevision, Digest: app.Draft.Digest, CheckID: check.ID, IdempotencyKey: uuid.New()}
	if _, e = s.CreatePublicationOperation(ctx, org, actor, app.ID, input, true); e == nil {
		t.Fatal("missing browser capability accepted")
	}
	_, e = s.ReportBrowserCapability(ctx, gateway, 1)
	must(e)
	op, e := s.CreatePublicationOperation(ctx, org, actor, app.ID, input, true)
	must(e)
	current, e := s.GetApplication(ctx, org, app.ID)
	must(e)
	if current.Version != app.Version+1 || current.DraftRevision != app.DraftRevision {
		t.Fatal("staging did not preserve reviewed draft and advance version")
	}
	replay, e := s.CreatePublicationOperation(ctx, org, actor, app.ID, input, true)
	must(e)
	if replay.ID != op.ID || replay.Version != op.Version {
		t.Fatal("same-key original input recovery changed operation")
	}
	if _, e = s.DisablePublication(ctx, org, actor, app.ID, app.Version, 0); e == nil {
		t.Fatal("stale disable cancelled later stage")
	}
	deadlineConfig := s.config
	deadlineConfig.Now = func() time.Time { return op.Deadline }
	expiredService := NewService(pool, deadlineConfig)
	for _, read := range []func() (PublicationOperation, error){func() (PublicationOperation, error) {
		return expiredService.GetPublicationOperation(ctx, org, app.ID, op.ID)
	}, func() (PublicationOperation, error) {
		return expiredService.GetPublicationOperationByKey(ctx, org, app.ID, input.IdempotencyKey)
	}, func() (PublicationOperation, error) {
		return expiredService.CreatePublicationOperation(ctx, org, actor, app.ID, input, true)
	}} {
		expired, err := read()
		must(err)
		if expired.Status != "expired" || expired.ErrorCode != "deadline_exceeded" {
			t.Fatal("deadline readback wedged recovery")
		}
	}
	expiryState, e := expiredService.GetPublication(ctx, org, app.ID)
	must(e)
	if expiryState.PendingOperation != nil || expiryState.LastOperation == nil || expiryState.LastOperation.Status != "expired" {
		t.Fatal("deadline pending projection inconsistent")
	}
	cred, secret, e := s.IssueProxyCredential(ctx, "Publication fixture")
	must(e)
	proxy, e := s.AuthenticateProxy(ctx, secret)
	must(e)
	if proxy.CredentialID != cred.ID {
		t.Fatal("credential binding")
	}
	instance, e := randomAppSecret("")
	must(e)
	work, e := s.ClaimPublicationReadiness(ctx, proxy, instance, true)
	must(e)
	if len(work) != 1 || work[0].OperationID != op.ID {
		t.Fatalf("claimed work %+v", work)
	}
	w := work[0]
	lease, e := s.ChannelAuthorize(ctx, proxy, w.Route.RouteBinding, "abc1", true)
	must(e)
	if !lease.After(time.Now()) || lease.After(time.Now().Add(4*time.Second)) {
		t.Fatal("lease bound")
	}
	if _, e = s.LookupRoute(ctx, proxy, w.Route.Hostname, true); e == nil {
		t.Fatal("pending tuple became public route")
	}
	report := ReadinessReport{OperationID: op.ID, ExpectedOperationVersion: w.Version, Binding: w.Route.RouteBinding, ReadinessRequestID: w.ReadinessRequestID, InstanceToken: instance, ChallengeToken: w.ChallengeToken, CertificateSerial: "abc1", PublicDNSStatus: "passed", PublicTLSStatus: "passed", DNSStatus: "passed", ConnectStatus: "passed", TLSStatus: "skipped"}
	bad := report
	bad.ChallengeToken = "wrong"
	if _, e = s.ReportPublicationReadiness(ctx, proxy, bad, true); e == nil {
		t.Fatal("wrong instance proof accepted")
	}
	activated, e := s.ReportPublicationReadiness(ctx, proxy, report, true)
	must(e)
	if activated.Status != "activated" {
		t.Fatalf("activation %+v", activated)
	}
	_, e = s.CreateGrant(ctx, org, actor, GrantInput{AppID: app.ID, SubjectKind: "user", SubjectID: actor, Enabled: true}, true)
	must(e)
	preview, e := s.EffectiveAccess(ctx, org, app.ID, actor, true)
	must(e)
	if !preview.AccessAllowed || preview.DenyReason != "" {
		t.Fatalf("published eligibility preview %+v", preview)
	}
	route, e := s.LookupRoute(ctx, proxy, app.Draft.PublicHostname, true)
	must(e)
	if route.Generation != op.Generation {
		t.Fatal("serving wrong generation")
	}
	// A failed replacement leaves the exact active generation untouched.
	current, e = s.GetApplication(ctx, org, app.ID)
	must(e)
	replacement := current.Draft.DraftInput
	replacement.Name = "Unready new draft"
	replacement.IconDataURL = ""
	replacement.IconDataURLSet = true
	replacement.AllowedDestinationCIDRsSet = true
	replacement.OriginCAPEMSet = true
	edited, e := s.UpdateDraft(ctx, org, actor, app.ID, replacement, current.Version, true)
	must(e)
	replacementCheck, e := s.RequestCheck(ctx, org, actor, app.ID, edited.Version, true)
	must(e)
	_, e = s.DesiredForGateway(ctx, gateway, true)
	must(e)
	_, e = s.CompleteCheck(ctx, gateway, Result{RequestID: replacementCheck.ID, AppID: app.ID, Generation: replacementCheck.Generation, Revision: replacementCheck.Revision, Digest: replacementCheck.Digest, Purpose: "origin_check", DNSStatus: "passed", ConnectStatus: "passed", TLSStatus: "skipped"}, true)
	must(e)
	replacementInput := PublicationInput{ExpectedVersion: edited.Version, Revision: edited.DraftRevision, Digest: edited.Draft.Digest, CheckID: replacementCheck.ID, IdempotencyKey: uuid.New()}
	failedOp, e := s.CreatePublicationOperation(ctx, org, actor, app.ID, replacementInput, true)
	must(e)
	work, e = s.ClaimPublicationReadiness(ctx, proxy, instance, true)
	must(e)
	if len(work) != 1 {
		t.Fatal("replacement work")
	}
	w = work[0]
	failedReport := ReadinessReport{OperationID: failedOp.ID, ExpectedOperationVersion: w.Version, Binding: w.Route.RouteBinding, ReadinessRequestID: w.ReadinessRequestID, InstanceToken: instance, ChallengeToken: w.ChallengeToken, CertificateSerial: "abc1", PublicDNSStatus: "passed", PublicTLSStatus: "failed", DNSStatus: "passed", ConnectStatus: "passed", TLSStatus: "skipped", ErrorCode: "public_tls_failed"}
	failed, e := s.ReportPublicationReadiness(ctx, proxy, failedReport, true)
	must(e)
	if failed.Status != "failed" {
		t.Fatal("failed public TLS activated")
	}
	retained, e := s.LookupRoute(ctx, proxy, route.Hostname, true)
	must(e)
	if retained.Generation != route.Generation {
		t.Fatal("failed replacement displaced active")
	}
	current, e = s.GetApplication(ctx, org, app.ID)
	must(e)
	replacementInput.ExpectedVersion = current.Version
	replacementInput.IdempotencyKey = uuid.New()
	pending, e := s.CreatePublicationOperation(ctx, org, actor, app.ID, replacementInput, true)
	must(e)
	cancelled, e := s.CancelPublicationOperation(ctx, org, actor, app.ID, pending.ID, pending.Version)
	must(e)
	if cancelled.Status != "cancelled" {
		t.Fatal("cancel did not withdraw pending")
	}
	repeated, e := s.CancelPublicationOperation(ctx, org, actor, app.ID, pending.ID, pending.Version)
	must(e)
	if repeated.Version != cancelled.Version {
		t.Fatal("cancel replay changed history")
	}
	retained, e = s.LookupRoute(ctx, proxy, route.Hostname, true)
	must(e)
	if retained.Generation != route.Generation {
		t.Fatal("cancel displaced active")
	}
	// Same-node valid rotation retains immutable serving pointer, but stale browser
	// capability and the old certificate never authorize a channel.
	exec("UPDATE nodes SET cert_serial='abc2' WHERE id=$1", gw)
	if _, e = s.LookupRoute(ctx, proxy, route.Hostname, true); e == nil {
		t.Fatal("stale capability served rotated gateway")
	}
	gateway.CertSerial = "abc2"
	_, e = s.ReportBrowserCapability(ctx, gateway, 1)
	must(e)
	rotated, e := s.LookupRoute(ctx, proxy, route.Hostname, true)
	must(e)
	if rotated.Generation != route.Generation {
		t.Fatal("rotation changed active publication")
	}
	if _, e = s.ChannelAuthorize(ctx, proxy, route.RouteBinding, "abc1", true); e == nil {
		t.Fatal("old serial admitted")
	}
	_, e = s.ChannelAuthorize(ctx, proxy, route.RouteBinding, "abc2", true)
	must(e)
	// Old wait cannot re-confirm after a new stage and cancellation.
	current, e = s.GetApplication(ctx, org, app.ID)
	must(e)
	_, e = s.ReportCapability(ctx, gateway, 1)
	must(e)
	fresh, e := s.RequestCheck(ctx, org, actor, app.ID, current.Version, true)
	must(e)
	_, e = s.DesiredForGateway(ctx, gateway, true)
	must(e)
	_, e = s.CompleteCheck(ctx, gateway, Result{RequestID: fresh.ID, AppID: app.ID, Generation: fresh.Generation, Revision: fresh.Revision, Digest: fresh.Digest, Purpose: "origin_check", DNSStatus: "passed", ConnectStatus: "passed", TLSStatus: "skipped"}, true)
	must(e)
	done := make(chan error, 1)
	go func() {
		_, err := s.DisablePublication(ctx, org, actor, app.ID, current.Version, route.AuthorityVersion)
		done <- err
	}()
	var state PublicationState
	deadline := time.Now().Add(2 * time.Second)
	for {
		state, e = s.GetPublication(ctx, org, app.ID)
		must(e)
		if state.Active != nil && state.Active.State == "disabled" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("disable commit not observed")
		}
		time.Sleep(10 * time.Millisecond)
	}
	racing, e := s.CreatePublicationOperation(ctx, org, actor, app.ID, PublicationInput{ExpectedVersion: state.ApplicationVersion, Revision: current.DraftRevision, Digest: current.Draft.Digest, CheckID: fresh.ID, IdempotencyKey: uuid.New()}, true)
	must(e)
	_, e = s.CancelPublicationOperation(ctx, org, actor, app.ID, racing.ID, racing.Version)
	must(e)
	if err := <-done; err == nil {
		t.Fatal("old disable wait re-confirmed newer stage")
	}
	state, e = s.GetPublication(ctx, org, app.ID)
	must(e)
	if state.Active.WithdrawalConfirmed {
		t.Fatal("stale withdrawal confirmation persisted")
	}
	if e = s.ArchiveApplication(ctx, org, actor, app.ID, state.ApplicationVersion); e == nil {
		t.Fatal("archive bypassed fresh wait")
	}
	start := time.Now()
	state, e = s.DisablePublication(ctx, org, actor, app.ID, state.ApplicationVersion, state.Active.AuthorityVersion)
	must(e)
	if time.Since(start) < 5*time.Second || state.Active == nil || !state.Active.WithdrawalConfirmed {
		t.Fatal("withdrawal was not postcommit monotonic confirmed")
	}
	preview, e = s.EffectiveAccess(ctx, org, app.ID, actor, true)
	must(e)
	if preview.AccessAllowed || preview.DenyReason != "app_unpublished" {
		t.Fatal("disabled preview allowed")
	}
	if _, e = s.LookupRoute(ctx, proxy, route.Hostname, true); e == nil {
		t.Fatal("disabled route served")
	}
	rollback, e := s.RollbackDraft(ctx, org, actor, app.ID, state.ApplicationVersion, app.DraftRevision, true)
	must(e)
	if rollback.DraftRevision == app.DraftRevision || rollback.Draft.Digest != app.Draft.Digest || rollback.Draft.IconDataURL != app.Draft.IconDataURL {
		t.Fatal("rollback did not create reviewed draft")
	}
	must(s.ArchiveApplication(ctx, org, actor, app.ID, rollback.Version))
	archived, e := s.GetApplication(ctx, org, app.ID)
	must(e)
	if archived.State != "archived" || archived.PublicationState != "archived" {
		t.Fatal("archive projection")
	}
}
