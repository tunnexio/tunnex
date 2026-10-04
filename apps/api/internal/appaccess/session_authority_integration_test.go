package appaccess

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	appcrypto "github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/mfa"
	"github.com/tunnexio/tunnex/apps/api/internal/session"
)

func TestSessionAuthorityLocalDatabaseRedis(t *testing.T) {
	pool := grantPool(t)
	if e := db.MigrateTo(pool.Config().ConnString(), 174); e != nil {
		t.Fatal(e)
	}
	ctx := context.Background()
	authority, e := sqlc.New(pool).GetAppAccessInstallationAuthority(ctx)
	if e != nil {
		t.Fatal(e)
	}
	generation := authority.Generation
	org, user, gateway := uuid.New(), uuid.New(), uuid.New()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, e := pool.Exec(ctx, query, args...); e != nil {
			t.Fatal(e)
		}
	}
	exec("INSERT INTO organizations(id,name,slug)VALUES($1,'App session',$2)", org, org.String())
	exec("INSERT INTO users(id,email,name,email_verified_at)VALUES($1,$2,'Session',now())", user, user.String()+"@fixture.test")
	exec("INSERT INTO memberships(org_id,user_id,role)VALUES($1,$2,'owner')", org, user)
	exec("INSERT INTO nodes(id,org_id,name,enrolled_kind,cert_serial,cert_not_after)VALUES($1,$2,'Session gateway','gateway',$3,now()+interval '1 day')", gateway, org, gateway.String())
	rdb := redis.NewClient(&redis.Options{Addr: "redis:6379", DB: 0})
	defer rdb.Close()
	parents := session.NewWithClient(rdb, time.Hour, time.Hour)
	apps := NewAppSessionStore(rdb)
	key := make([]byte, 32)
	if _, e := rand.Read(key); e != nil {
		t.Fatal(e)
	}
	sealer, e := appcrypto.NewSealer(key)
	if e != nil {
		t.Fatal(e)
	}
	mf := mfa.NewService(pool, sealer, nil, nil)
	s := NewService(pool, Config{AppBaseDomain: "apps.example.net", ConsoleHosts: []string{"console.example.com"}, ConsoleURL: "https://console.example.com"}).WithSessionAuthority(parents, apps, sealer, mf.IsEnrollmentGated)
	if _, e = s.UpdateSettings(ctx, org, user, true, 1, true); e != nil {
		t.Fatal(e)
	}
	app, e := s.CreateDraft(ctx, org, user, DraftInput{Name: "Published session", Description: "Serving metadata", Icon: "app", OriginURL: "http://origin", GatewayID: gateway, PublicHostname: "session-" + appFixtureHost(org) + ".apps.example.net", IdleTimeoutSeconds: 60, AbsoluteTimeoutSeconds: 300}, true)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.ReportBrowserCapability(ctx, AuthenticatedGateway{OrgID: org, GatewayID: gateway, CertSerial: gateway.String()}, 1); e != nil {
		t.Fatal(e)
	}
	// Only this disposable child database gets an active publication; no native serving state is manufactured.
	exec("INSERT INTO app_access_serving_publications(org_id,app_id,gateway_id,revision,digest,hostname,state)VALUES($1,$2,$3,$4,$5,$6,'active')", org, app.ID, gateway, app.Draft.Revision, app.Draft.Digest, app.Draft.PublicHostname)
	if _, e = s.CreateGrant(ctx, org, user, GrantInput{AppID: app.ID, SubjectKind: "user", SubjectID: user, Enabled: true}, true); e != nil {
		t.Fatal(e)
	}
	_, secret, e := s.IssueProxyCredential(ctx, "isolated-session")
	if e != nil {
		t.Fatal(e)
	}
	proxy, e := s.AuthenticateProxy(ctx, secret)
	if e != nil {
		t.Fatal(e)
	}
	route, e := s.LookupRoute(ctx, proxy, app.Draft.PublicHostname, true)
	if e != nil {
		t.Fatal(e)
	}
	var parentIDs, tokens, codes, nonces []string
	var streamIDs []uuid.UUID
	defer func() {
		for _, token := range tokens {
			if record, _, e := apps.Peek(ctx, token); e == nil {
				_ = apps.RevokeOwn(ctx, org, user, record.ID)
			}
		}
		for _, id := range parentIDs {
			_ = parents.Delete(ctx, id)
			rdb.Del(ctx, "aa:launch-parent:"+generation.String()+":"+secretHash(id), "aa:session-parent:"+generation.String()+":"+secretHash(id))
		}
		for _, code := range codes {
			rdb.Del(ctx, launchKey(code))
		}
		for _, nonce := range nonces {
			member := pendingKey(secretHash(nonce))
			rdb.Del(ctx, member)
			for _, index := range pendingIndexes(PendingLaunch{InstallationGeneration: generation, ProxyID: proxy.CredentialID, Binding: route.RouteBinding}) {
				rdb.ZRem(ctx, index, member)
			}
		}
		for _, id := range streamIDs {
			rdb.Del(ctx, "aa:stream:"+id.String())
		}
		for _, token := range tokens {
			rdb.Del(ctx, "aa:stream-session:"+secretHash(token))
		}
		indexes := sessionIndexes(AppSessionRecord{InstallationGeneration: generation, UserID: user, Binding: route.RouteBinding})
		rdb.Del(ctx, indexes[:3]...)
	}()
	newParent := func(method string, epoch int64) session.Session {
		t.Helper()
		p, e := parents.CreateWithAuthority(ctx, user, method, epoch)
		if e != nil {
			t.Fatal(e)
		}
		parentIDs = append(parentIDs, p.ID)
		return p
	}
	newCode := func(parent session.Session) (string, string) {
		t.Helper()
		nonce, e := randomAppSecret("")
		if e != nil {
			t.Fatal(e)
		}
		nonces = append(nonces, nonce)
		if _, e = s.RegisterPendingLaunch(ctx, proxy, route.RouteBinding, secretHash(nonce), "/form?q=1", true); e != nil {
			t.Fatal(e)
		}
		launched, e := s.LaunchApp(ctx, org, app.ID, user, parent.ID, secretHash(nonce), "/form?q=1", true)
		if e != nil {
			t.Fatal(e)
		}
		parsed, e := url.Parse(launched.RedirectURL)
		if e != nil {
			t.Fatal(e)
		}
		code := parsed.Query().Get("code")
		codes = append(codes, code)
		return code, nonce
	}
	mint := func(parent session.Session) string {
		t.Helper()
		code, nonce := newCode(parent)
		out, e := s.RedeemApp(ctx, proxy, code, nonce, route.Hostname, true)
		if e != nil {
			t.Fatal(e)
		}
		tokens = append(tokens, out.AppSessionToken)
		return out.AppSessionToken
	}
	parent := newParent(authctx.AuthLocalPassword, 1)
	if _, e = s.LaunchApp(ctx, org, app.ID, user, parent.ID, secretHash("not-registered"), "/form?q=1", true); e == nil {
		t.Fatal("launch bypassed proxy pending registration")
	}
	code, nonce := newCode(parent)
	if _, e = s.LaunchApp(ctx, org, app.ID, user, parent.ID, secretHash(nonce), "/form?q=1", true); e == nil {
		t.Fatal("pending launch replay accepted")
	}
	wrong, _ := randomAppSecret("")
	if _, e = s.RedeemApp(ctx, proxy, code, wrong, route.Hostname, true); e == nil {
		t.Fatal("nonce mismatch accepted")
	}
	if _, e = s.RedeemApp(ctx, proxy, code, nonce, "foreign.apps.example.net", true); e == nil {
		t.Fatal("cross-host callback accepted")
	}
	var wg sync.WaitGroup
	results := make(chan RedeemResult, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, e := s.RedeemApp(ctx, proxy, code, nonce, route.Hostname, true)
			if e == nil {
				results <- out
			}
		}()
	}
	wg.Wait()
	close(results)
	var token string
	success := 0
	for out := range results {
		token = out.AppSessionToken
		success++
		if out.RelativeTarget != "/form?q=1" {
			t.Fatal("target changed")
		}
	}
	if success != 1 {
		t.Fatal("code consumed more or less than once", success)
	}
	tokens = append(tokens, token)
	if _, e = s.RedeemApp(ctx, proxy, code, nonce, route.Hostname, true); e == nil {
		t.Fatal("redeemed code replay")
	}
	record, _, e := apps.Peek(ctx, token)
	if e != nil || record.ParentEpoch != 1 || record.ParentHash != secretHash(parent.ID) || record.ParentSealed == parent.ID || record.ExpiresAt.After(parent.ExpiresAt) {
		t.Fatal("session binding/lifetime", e)
	}
	request := RequestInput{Binding: route.RouteBinding, SessionToken: token, Method: "GET", RelativePath: "/asset"}
	authorize := func(in RequestInput, entitled bool) Decision {
		t.Helper()
		out, e := s.AuthorizeRequest(ctx, proxy, in, entitled)
		if e != nil || !out.Allowed || out.StreamID == uuid.Nil || out.LeaseUntil == nil || out.LeaseUntil.After(time.Now().Add(4*time.Second)) {
			t.Fatal("positive exact request", e)
		}
		streamIDs = append(streamIDs, out.StreamID)
		return out
	}
	nativeBefore := rdb.PTTL(ctx, "sess:"+parent.ID).Val()
	idleBefore := rdb.PTTL(ctx, appSessionKey(token)).Val()
	decision := authorize(request, true)
	if rdb.PTTL(ctx, appSessionKey(token)).Val() > idleBefore || rdb.PTTL(ctx, "sess:"+parent.ID).Val() > nativeBefore {
		t.Fatal("passive request touched idle")
	}
	renewed, e := s.RenewLease(ctx, proxy, LeaseInput{StreamID: decision.StreamID, Binding: route.RouteBinding}, true)
	if e != nil || !renewed.Allowed {
		t.Fatal("renew", e)
	}
	if rdb.PTTL(ctx, appSessionKey(token)).Val() > idleBefore || rdb.PTTL(ctx, "sess:"+parent.ID).Val() > nativeBefore {
		t.Fatal("renew touched idle")
	}
	if e = rdb.PExpire(ctx, appSessionKey(token), 5*time.Second).Err(); e != nil {
		t.Fatal(e)
	}
	rdb.PExpire(ctx, sessionIDKey(record.ID), 5*time.Second)
	foreground := request
	foreground.FetchMode = "navigate"
	foreground.FetchDest = "document"
	foreground.FetchUser = "?1"
	authorize(foreground, true)
	if rdb.PTTL(ctx, appSessionKey(token)).Val() < 50*time.Second || rdb.PTTL(ctx, "sess:"+parent.ID).Val() > nativeBefore {
		t.Fatal("foreground idle policy")
	}
	deny := func(in RequestInput, entitled bool) {
		t.Helper()
		out, e := s.AuthorizeRequest(ctx, proxy, in, entitled)
		if e == nil && out.Allowed {
			t.Fatal("unavailable authority allowed")
		}
	}
	mismatched := request
	mismatched.Binding.Generation = uuid.New()
	deny(mismatched, true)
	cross := request
	cross.Method = "POST"
	cross.Origin = "https://other.apps.example.net"
	deny(cross, true)
	deny(request, false)
	// Current membership, user standing, grant and feature state are rechecked, not cached in the token.
	for _, change := range []struct{ disable, restore string }{
		{"UPDATE users SET status='deactivated' WHERE id=$1", "UPDATE users SET status='active' WHERE id=$1"},
		{"UPDATE memberships SET access_revoked_at=now() WHERE user_id=$1", "UPDATE memberships SET access_revoked_at=NULL WHERE user_id=$1"},
		{"UPDATE app_access_grants SET enabled=false WHERE user_id=$1", "UPDATE app_access_grants SET enabled=true WHERE user_id=$1"},
	} {
		exec(change.disable, user)
		deny(request, true)
		exec(change.restore, user)
	}
	exec("UPDATE app_access_settings SET enabled=false WHERE org_id=$1", org)
	deny(request, true)
	exec("UPDATE app_access_settings SET enabled=true WHERE org_id=$1", org)
	// Union access lasts through the latest matching grant, and current group membership is required.
	group := uuid.New()
	exec("INSERT INTO user_groups(id,org_id,name)VALUES($1,$2,'Session group')", group, org)
	exec("INSERT INTO group_members(org_id,group_id,user_id)VALUES($1,$2,$3)", org, group, user)
	groupGrant, e := s.CreateGrant(ctx, org, user, GrantInput{AppID: app.ID, SubjectKind: "group", SubjectID: group, Enabled: true}, true)
	if e != nil {
		t.Fatal(e)
	}
	short := time.Now().Add(time.Second).Truncate(time.Microsecond)
	exec("UPDATE app_access_grants SET expires_at=$1 WHERE org_id=$2 AND user_id=$3", short, org, user)
	union := authorize(request, true)
	if union.LeaseUntil.Before(time.Now().Add(2 * time.Second)) {
		t.Fatal("short direct grant truncated unbounded group union")
	}
	end := time.Now().Add(3 * time.Second).Truncate(time.Microsecond)
	exec("UPDATE app_access_grants SET expires_at=$1 WHERE id=$2", end, groupGrant.ID)
	union = authorize(request, true)
	if union.LeaseUntil.After(end) || union.LeaseUntil.Before(short) {
		t.Fatal("finite grant union lease bound")
	}
	exec("UPDATE app_access_grants SET enabled=false WHERE org_id=$1 AND user_id=$2", org, user)
	exec("DELETE FROM group_members WHERE org_id=$1 AND group_id=$2 AND user_id=$3", org, group, user)
	deny(request, true)
	exec("UPDATE app_access_grants SET enabled=true,expires_at=NULL WHERE org_id=$1 AND user_id=$2", org, user)
	if _, e = s.RevokeGrant(ctx, org, user, groupGrant.ID, groupGrant.Version); e != nil {
		t.Fatal(e)
	}
	// Existing MFA service gates local-password authority; the mint-time SSO method retains its exemption.
	if e = mf.SetOrgEnforce(ctx, org, user, true); e != nil {
		t.Fatal(e)
	}
	deny(request, true)
	ssoParent := newParent(authctx.AuthSSO, 1)
	ssoToken := mint(ssoParent)
	ssoRequest := request
	ssoRequest.SessionToken = ssoToken
	authorize(ssoRequest, true)
	if e = mf.SetOrgEnforce(ctx, org, user, false); e != nil {
		t.Fatal(e)
	}
	// Exact parent logout denies a retained/restored native snapshot without relying on Redis deletion.
	hash, e := hex.DecodeString(secretHash(parent.ID))
	if e != nil {
		t.Fatal(e)
	}
	if e = sqlc.New(pool).RecordAppParentLogout(ctx, sqlc.RecordAppParentLogoutParams{ParentHash: hash, UserID: user, ParentExpiresAt: parent.ExpiresAt}); e != nil {
		t.Fatal(e)
	}
	deny(request, true)
	if out, e := s.RenewLease(ctx, proxy, LeaseInput{StreamID: decision.StreamID, Binding: route.RouteBinding}, true); e == nil && out.Allowed {
		t.Fatal("logout lease resumed")
	}
	// Epoch changes invalidate other surviving parents, including SSO snapshots.
	exec("UPDATE users SET app_auth_epoch=app_auth_epoch+1 WHERE id=$1", user)
	deny(ssoRequest, true)
	legacy, e := parents.Create(ctx, user, authctx.AuthSSO)
	if e != nil {
		t.Fatal(e)
	}
	parentIDs = append(parentIDs, legacy.ID)
	if _, _, e = s.validateParent(ctx, user, legacy.ID, 0); e == nil {
		t.Fatal("legacy parent acquired app authority")
	}
	freshParent := newParent(authctx.AuthSSO, 2)
	freshToken := mint(freshParent)
	freshRequest := request
	freshRequest.SessionToken = freshToken
	authorize(freshRequest, true)
	own, _, e := apps.Peek(ctx, freshToken)
	if e != nil {
		t.Fatal(e)
	}
	catalog, e := s.MyApps(ctx, org, user, freshParent.ID, "Published", 1, 0, true)
	if e != nil || len(catalog.Items) != 1 || catalog.Items[0].ID != app.ID || catalog.Items[0].Name != "Published session" {
		t.Fatal("safe serving catalog", e)
	}
	listed, e := s.MySessions(ctx, org, user, freshParent.ID, 100, 0)
	if e != nil {
		t.Fatal(e)
	}
	foundOwn := false
	for _, entry := range listed {
		if entry.ID == own.ID {
			foundOwn = entry.CurrentParent && entry.AppID == app.ID && entry.AppLabel == "Published session"
		}
	}
	if !foundOwn {
		t.Fatal("own session projection lost exact current parent label")
	}
	if _, e = s.MySessions(ctx, org, uuid.New(), freshParent.ID, 100, 0); e == nil {
		t.Fatal("foreign user read own sessions")
	}
	// A rejected seventeenth foreground stream must not refresh application idle.
	for i := 0; i < 15; i++ {
		authorize(freshRequest, true)
	}
	if e = rdb.PExpire(ctx, appSessionKey(freshToken), 5*time.Second).Err(); e != nil {
		t.Fatal(e)
	}
	rdb.PExpire(ctx, sessionIDKey(own.ID), 5*time.Second)
	beforeDenied := rdb.PTTL(ctx, appSessionKey(freshToken)).Val()
	fullForeground := freshRequest
	fullForeground.FetchMode = "navigate"
	fullForeground.FetchDest = "document"
	fullForeground.FetchUser = "?1"
	if out, e := s.AuthorizeRequest(ctx, proxy, fullForeground, true); e == nil && out.Allowed {
		t.Fatal("stream capacity ignored")
	}
	if rdb.PTTL(ctx, appSessionKey(freshToken)).Val() > beforeDenied {
		t.Fatal("rejected foreground request refreshed idle")
	}
	if e = s.RevokeMySession(ctx, org, uuid.New(), own.ID); e == nil {
		t.Fatal("foreign user revoked session")
	}
	if e = s.RevokeMySession(ctx, uuid.New(), user, own.ID); e == nil {
		t.Fatal("foreign org revoked session")
	}
	savedRaw, e := rdb.Get(ctx, appSessionKey(freshToken)).Result()
	if e != nil {
		t.Fatal(e)
	}
	savedID, e := rdb.Get(ctx, sessionIDKey(own.ID)).Result()
	if e != nil {
		t.Fatal(e)
	}
	savedStreamID := streamIDs[len(streamIDs)-1]
	savedStream, e := rdb.Get(ctx, "aa:stream:"+savedStreamID.String()).Result()
	if e != nil {
		t.Fatal(e)
	}
	revokes := make(chan error, 2)
	startRevokes := make(chan struct{})
	for i := 0; i < 2; i++ {
		go func() { <-startRevokes; revokes <- s.RevokeMySession(ctx, org, user, own.ID) }()
	}
	close(startRevokes)
	for i := 0; i < 2; i++ {
		if e = <-revokes; e != nil {
			t.Fatal("concurrent revoke", e)
		}
	}
	var revokeAudits int
	if e = pool.QueryRow(ctx, "SELECT count(*) FROM audit_logs WHERE action='app_access.session_revoked' AND target_id=$1", own.ID.String()).Scan(&revokeAudits); e != nil || revokeAudits != 1 {
		t.Fatal("duplicate revoke audit", revokeAudits, e)
	}

	deny(freshRequest, true)
	if _, _, e = apps.Peek(ctx, freshToken); !errors.Is(e, ErrAppSessionMissing) {
		t.Fatal("own revoke retained token", e)
	}
	// Restore an authentic pre-revoke Redis snapshot. TTL is renewed only in
	// this fixture to distinguish durable denial from accidental expiry.
	rdb.Set(ctx, appSessionKey(freshToken), savedRaw, time.Minute)
	rdb.Set(ctx, sessionIDKey(own.ID), savedID, time.Minute)
	for _, index := range sessionIndexes(own) {
		rdb.ZAdd(ctx, index, redis.Z{Score: float64(own.ExpiresAt.UnixMilli()), Member: appSessionKey(freshToken)})
	}
	rdb.Set(ctx, "aa:stream:"+savedStreamID.String(), savedStream, time.Minute)
	deny(freshRequest, true)
	if out, e := s.RenewLease(ctx, proxy, LeaseInput{StreamID: savedStreamID, Binding: route.RouteBinding}, true); e == nil && out.Allowed {
		t.Fatal("restored revoked stream renewed")
	}
	// Keep separate unrevoked records to prove generation fencing independently
	// of the session tombstone. No production recovery wait is bypassed here:
	// direct child-DB completion is only a current-generation authority fixture.
	aliveToken := mint(freshParent)
	aliveRequest := freshRequest
	aliveRequest.SessionToken = aliveToken
	aliveDecision := authorize(aliveRequest, true)
	aliveRecord, _, e := apps.Peek(ctx, aliveToken)
	if e != nil {
		t.Fatal(e)
	}
	aliveRaw, e := rdb.Get(ctx, appSessionKey(aliveToken)).Result()
	if e != nil {
		t.Fatal(e)
	}
	aliveID, e := rdb.Get(ctx, sessionIDKey(aliveRecord.ID)).Result()
	if e != nil {
		t.Fatal(e)
	}
	aliveStream, e := rdb.Get(ctx, "aa:stream:"+aliveDecision.StreamID.String()).Result()
	if e != nil {
		t.Fatal(e)
	}
	adminToken := mint(freshParent)
	adminRequest := freshRequest
	adminRequest.SessionToken = adminToken
	adminDecision := authorize(adminRequest, true)
	adminRecord, _, e := apps.Peek(ctx, adminToken)
	if e != nil {
		t.Fatal(e)
	}
	adminRaw, e := rdb.Get(ctx, appSessionKey(adminToken)).Result()
	if e != nil {
		t.Fatal(e)
	}
	adminID, e := rdb.Get(ctx, sessionIDKey(adminRecord.ID)).Result()
	if e != nil {
		t.Fatal(e)
	}
	adminStream, e := rdb.Get(ctx, "aa:stream:"+adminDecision.StreamID.String()).Result()
	if e != nil {
		t.Fatal(e)
	}
	wrongDraft := app.Draft.DraftInput
	wrongDraft.Name = "Other admin app"
	wrongDraft.PublicHostname = "other-" + appFixtureHost(org) + ".apps.example.net"
	wrongApp, e := s.CreateDraft(ctx, org, user, wrongDraft, true)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.RevokeApplicationSession(ctx, org, wrongApp.ID, user, adminRecord.ID); e == nil {
		t.Fatal("foreign app admin revoke accepted")
	}
	if e = s.RevokeApplicationSession(ctx, uuid.New(), app.ID, user, adminRecord.ID); e == nil {
		t.Fatal("foreign org admin revoke accepted")
	}
	adminRevokes := make(chan error, 2)
	startAdmin := make(chan struct{})
	for i := 0; i < 2; i++ {
		go func() {
			<-startAdmin
			adminRevokes <- s.RevokeApplicationSession(ctx, org, app.ID, user, adminRecord.ID)
		}()
	}
	close(startAdmin)
	for i := 0; i < 2; i++ {
		if e = <-adminRevokes; e != nil {
			t.Fatal("concurrent admin revoke", e)
		}
	}
	var adminAudits int
	if e = pool.QueryRow(ctx, "SELECT count(*) FROM audit_logs WHERE action='app_access.session_revoked' AND target_id=$1", adminRecord.ID.String()).Scan(&adminAudits); e != nil || adminAudits != 1 {
		t.Fatal("duplicate admin revoke audit", adminAudits, e)
	}
	rdb.Set(ctx, appSessionKey(adminToken), adminRaw, time.Minute)
	rdb.Set(ctx, sessionIDKey(adminRecord.ID), adminID, time.Minute)
	rdb.Set(ctx, "aa:stream:"+adminDecision.StreamID.String(), adminStream, time.Minute)
	deny(adminRequest, true)
	if out, e := s.RenewLease(ctx, proxy, LeaseInput{StreamID: adminDecision.StreamID, Binding: route.RouteBinding}, true); e == nil && out.Allowed {
		t.Fatal("restored admin-revoked stream renewed")
	}
	oldCode, oldNonce := newCode(freshParent)
	oldCodeRaw, e := rdb.Get(ctx, launchKey(oldCode)).Result()
	if e != nil {
		t.Fatal(e)
	}
	pendingNonce, e := randomAppSecret("")
	if e != nil {
		t.Fatal(e)
	}
	nonces = append(nonces, pendingNonce)
	if _, e = s.RegisterPendingLaunch(ctx, proxy, route.RouteBinding, secretHash(pendingNonce), "/form?q=1", true); e != nil {
		t.Fatal(e)
	}
	oldPendingRaw, e := rdb.Get(ctx, pendingKey(secretHash(pendingNonce))).Result()
	if e != nil {
		t.Fatal(e)
	}
	q := sqlc.New(pool)
	beforeRotation, e := q.GetAppAccessInstallationAuthority(ctx)
	if e != nil {
		t.Fatal(e)
	}
	rotated, e := q.RotateAppAccessInstallationAuthority(ctx, beforeRotation.Version)
	if e != nil {
		t.Fatal(e)
	}
	deny(aliveRequest, true)
	if _, e = s.RedeemApp(ctx, proxy, oldCode, oldNonce, route.Hostname, true); e == nil {
		t.Fatal("incomplete recovery redeemed code")
	}
	if _, e = q.ConfirmAppAccessInstallationRecovery(ctx, sqlc.ConfirmAppAccessInstallationRecoveryParams{ExpectedGeneration: rotated.Generation, ExpectedVersion: rotated.Version}); e != nil {
		t.Fatal(e)
	}
	rdb.Set(ctx, appSessionKey(aliveToken), aliveRaw, time.Minute)
	rdb.Set(ctx, sessionIDKey(aliveRecord.ID), aliveID, time.Minute)
	rdb.Set(ctx, "aa:stream:"+aliveDecision.StreamID.String(), aliveStream, time.Minute)
	rdb.Set(ctx, launchKey(oldCode), oldCodeRaw, time.Minute)
	rdb.Set(ctx, pendingKey(secretHash(pendingNonce)), oldPendingRaw, time.Minute)
	deny(aliveRequest, true)
	if out, e := s.RenewLease(ctx, proxy, LeaseInput{StreamID: aliveDecision.StreamID, Binding: route.RouteBinding}, true); e == nil && out.Allowed {
		t.Fatal("restored old-generation stream renewed")
	}
	if _, e = s.RedeemApp(ctx, proxy, oldCode, oldNonce, route.Hostname, true); e == nil {
		t.Fatal("restored old-generation code redeemed")
	}
	if _, e = s.LaunchApp(ctx, org, app.ID, user, freshParent.ID, secretHash(pendingNonce), "/form?q=1", true); e == nil {
		t.Fatal("restored old-generation pending consumed")
	}

}
func appFixtureHost(id uuid.UUID) string { return id.String()[:8] }
