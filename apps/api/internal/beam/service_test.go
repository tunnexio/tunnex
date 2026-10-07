package beam

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/agentca"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/appaccess"
	"github.com/tunnexio/tunnex/apps/api/internal/beamreadiness"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/session"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestBeamTargetAndDomainBoundaries(t *testing.T) {
	for _, target := range []Target{{Protocol: "http", Address: "127.0.0.1", Port: 80}, {Protocol: "https", Address: "::1", Port: 443}} {
		if e := ValidateTarget(target); e != nil {
			t.Fatal(e)
		}
	}
	for _, target := range []Target{{Protocol: "http", Address: "127.0.0.2", Port: 80}, {Protocol: "http", Address: "localhost", Port: 80}, {Protocol: "ftp", Address: "127.0.0.1", Port: 80}, {Protocol: "http", Address: "127.0.0.1", Port: 0}, {Protocol: "http", Address: "169.254.169.254", Port: 80}, {Protocol: "http", Address: "::ffff:127.0.0.1", Port: 80}} {
		if ValidateTarget(target) == nil {
			t.Fatal("accepted unsafe target", target)
		}
	}
	for _, target := range []string{"//evil.test/x", "http://evil.test/x", "/\\evil", "/bad\npath"} {
		if relative(target) {
			t.Fatal("accepted unsafe return", target)
		}
	}
	s := New(nil, Config{BaseDomain: "beam.tunnex.io", PortalURL: "https://console.tunnex.io", ProxyURL: "https://proxy.tunnex.io", DomainReady: true}, nil, nil)
	if s.domainReady() {
		t.Fatal("accepted sibling domain")
	}
	s.config.BaseDomain = "beam.other.net"
	if !s.domainReady() {
		t.Fatal("independent domain refused")
	}
	s.config.ProxyURL = "http://proxy.other.net"
	if s.domainReady() {
		t.Fatal("accepted insecure connector")
	}
	s.config.ProxyURL = "https://proxy.other.net"
	s.config.BaseDomain = strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 22) + ".net"
	if !s.domainReady() {
		t.Fatal("refused the maximum valid Beam hostname length")
	}
	s.config.BaseDomain = strings.Replace(s.config.BaseDomain, strings.Repeat("d", 22), strings.Repeat("d", 23), 1)
	if s.domainReady() {
		t.Fatal("accepted a domain that makes generated hostnames too long")
	}
	s.config.BaseDomain = "beam.other.net"
	s.config.DomainReady = false
	if _, _, e := s.Domains(); e == nil {
		t.Fatal("advertised unqualified serving domains")
	}
	s.config.DomainReady = true
	s.config.RestoreMarker = filepath.Join(t.TempDir(), "restore-pending")
	if e := os.WriteFile(s.config.RestoreMarker, []byte("pending"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, _, e := s.Domains(); e == nil {
		t.Fatal("advertised domains across the restore barrier")
	}
}

type fixture struct {
	t                                     *testing.T
	ctx                                   context.Context
	pool                                  *pgxpool.Pool
	s                                     *Service
	org, owner, reviewer, outsider, group uuid.UUID
	a                                     Actor
	store                                 *session.Store
}

func newFixture(t *testing.T) *fixture {
	ctx, pool := testpostgres.New(t)
	f := &fixture{t: t, ctx: ctx, pool: pool, org: uuid.New(), owner: uuid.New(), reviewer: uuid.New(), outsider: uuid.New(), group: uuid.New()}
	f.exec(`INSERT INTO organizations(id,name,slug) VALUES($1,'Beam fixture',$2)`, f.org, f.org.String())
	for _, user := range []uuid.UUID{f.owner, f.reviewer, f.outsider} {
		f.exec(`INSERT INTO users(id,email,name,email_verified_at)VALUES($1,$2,'Beam fixture',now())`, user, user.String()+"@beam.test")
		role := "member"
		if user == f.owner {
			role = "owner"
		}
		f.exec(`INSERT INTO memberships(org_id,user_id,role)VALUES($1,$2,$3)`, f.org, user, role)
	}
	f.exec(`INSERT INTO user_groups(id,org_id,name)VALUES($1,$2,'Beam publishers')`, f.group, f.org)
	f.exec(`INSERT INTO group_members(org_id,group_id,user_id)VALUES($1,$2,$3)`, f.org, f.group, f.owner)
	credential := uuid.New()
	f.exec(`INSERT INTO cli_credentials(id,user_id,token_hash,fingerprint,expires_at)VALUES($1,$2,$3,'fixture',now()+interval '1 day')`, credential, f.owner, hash("tnx_fixture"))
	f.a = Actor{ID: f.owner, CredentialID: credential, ManageAll: true, ManagePolicy: true}
	key := make([]byte, crypto.KeySize)
	_, _ = rand.Read(key)
	seal, e := crypto.NewSealer(key)
	if e != nil {
		t.Fatal(e)
	}
	ca, _, e := agentca.LoadOrCreate(ctx, sqlc.New(pool), seal)
	if e != nil {
		t.Fatal(e)
	}
	r := miniredis.RunT(t)
	f.store = session.NewWithClient(redis.NewClient(&redis.Options{Addr: r.Addr()}), time.Hour, 24*time.Hour)
	barrierDir, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(barrierDir, 0700); e != nil {
		t.Fatal(e)
	}
	f.s = New(pool, Config{BaseDomain: "beam.other.net", PortalURL: "https://console.fixture.org", ProxyURL: "https://connector.beam.other.net", DomainReady: true, RestoreMarker: filepath.Join(barrierDir, "restore.pending")}, ca, f.store)
	f.exec(`UPDATE users SET cp_admin=true WHERE id=$1`, f.owner)
	if _, e = f.s.UpdateDomainSettings(ctx, f.owner, DomainSettingsInput{ExpectedVersion: 1, OperatorEnabled: true, BaseDomain: f.s.config.BaseDomain, ProxyURL: f.s.config.ProxyURL}); e != nil {
		t.Fatal(e)
	}
	rsettings, e := f.s.installation(ctx, pool)
	if e != nil {
		t.Fatal(e)
	}
	view := beamreadiness.Snapshot(f.s.probeConfig(rsettings))
	checked, expires := time.Now(), time.Now().Add(5*time.Minute)
	view.CheckedAt, view.ExpiresAt, view.Passed = &checked, &expires, true
	// Service-level authority fixtures seed trusted measurement evidence in
	// their disposable database; native and readiness suites qualify network I/O.
	if _, e = f.s.persistReadiness(ctx, rsettings, view); e != nil {
		t.Fatal(e)
	}
	browser := f.a
	browser.CredentialID = uuid.Nil
	browser.SessionID = "fixture-policy"
	_, e = f.s.UpdatePolicy(ctx, f.org, browser, PolicyInput{Enabled: true, ExpectedVersion: 1, PublisherGroups: []uuid.UUID{f.group}, ReviewerUsers: []uuid.UUID{f.reviewer}, MaxDuration: 3600, MaxShares: 5})
	if e != nil {
		t.Fatal(e)
	}
	return f
}
func (f *fixture) exec(q string, args ...any) {
	f.t.Helper()
	if _, e := f.pool.Exec(f.ctx, q, args...); e != nil {
		f.t.Fatal(e)
	}
}
func (f *fixture) create() Share {
	f.t.Helper()
	r, e := f.s.Create(f.ctx, f.org, f.a, CreateInput{Name: "Fixture app", Target: Target{Protocol: "http", Address: "127.0.0.1", Port: 3000}, Duration: 1800, Grants: []Grant{{"user", f.reviewer}}, IdempotencyKey: uuid.New()})
	if e != nil {
		f.t.Fatal(e)
	}
	return r
}
func (f *fixture) connect(r Share) (Share, Connector) {
	f.t.Helper()
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		f.t.Fatal(e)
	}
	der, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "fixture"}}, key)
	if e != nil {
		f.t.Fatal(e)
	}
	out, e := f.s.IssueConnector(f.ctx, f.org, r.ID, f.a, ConnectorInput{ExpectedVersion: r.Version, CSR: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))})
	if e != nil {
		f.t.Fatal(e)
	}
	if _, e = f.s.Channel(f.ctx, out.Binding, issuedSerial(tFromPEM(out.CertificatePEM))); e != nil {
		f.t.Fatal(e)
	}
	r, e = f.s.Heartbeat(f.ctx, f.org, r.ID, f.a, Heartbeat{out.Binding.Generation, true})
	if e != nil {
		f.t.Fatal(e)
	}
	return r, out
}
func (f *fixture) login(user uuid.UUID) Actor {
	f.t.Helper()
	sess, e := f.store.CreateWithAuthority(f.ctx, user, "local_password", 1)
	if e != nil {
		f.t.Fatal(e)
	}
	return Actor{ID: user, SessionID: sess.ID}
}
func (f *fixture) browser(r Share, a Actor) string {
	f.t.Helper()
	nonce, _ := secret("")
	nh := f.s.NonceHash(nonce)
	if _, e := f.s.Pending(f.ctx, r.Binding(), nh, "/"); e != nil {
		f.t.Fatal(e)
	}
	launch, e := f.s.Launch(f.ctx, f.org, r.ID, a, LaunchInput{"/", nh})
	if e != nil {
		f.t.Fatal(e)
	}
	u, _ := url.Parse(launch.RedirectURL)
	redeemed, e := f.s.Redeem(f.ctx, r.Hostname, u.Query().Get("code"), nonce)
	if e != nil {
		f.t.Fatal(e)
	}
	if _, e = f.s.Redeem(f.ctx, r.Hostname, u.Query().Get("code"), nonce); e == nil {
		f.t.Fatal("launch code replayed")
	}
	return redeemed.Token
}
func TestBeamPersistentIdempotencyQuotaAndTenant(t *testing.T) {
	f := newFixture(t)
	in := CreateInput{Name: "Concurrent", Target: Target{Protocol: "http", Address: "127.0.0.1", Port: 3000}, Duration: 120, IdempotencyKey: uuid.New()}
	var wg sync.WaitGroup
	ids := make(chan uuid.UUID, 8)
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); r, e := f.s.Create(f.ctx, f.org, f.a, in); ids <- r.ID; errs <- e }()
	}
	wg.Wait()
	close(ids)
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	var expected uuid.UUID
	for id := range ids {
		if expected == uuid.Nil {
			expected = id
		}
		if id != expected {
			t.Fatal("retry created another share")
		}
	}
	in.Name = "Changed"
	if _, e := f.s.Create(f.ctx, f.org, f.a, in); e == nil {
		t.Fatal("idempotency body mutation accepted")
	}
	for i := 0; i < 4; i++ {
		f.create()
	}
	if _, e := f.s.Create(f.ctx, f.org, f.a, CreateInput{Name: "Over quota", Target: in.Target, Duration: 120, IdempotencyKey: uuid.New()}); e == nil {
		t.Fatal("quota exceeded")
	}
	if _, e := f.s.Get(f.ctx, uuid.New(), expected, f.a); e == nil {
		t.Fatal("cross tenant share visible")
	}
	if _, e := f.s.Get(f.ctx, f.org, expected, Actor{ID: f.outsider}); e == nil {
		t.Fatal("ungranted outsider visible")
	}
}
func TestBeamContinuousAuthorityLeaseAndTerminal(t *testing.T) {
	f := newFixture(t)
	r, _ := f.connect(f.create())
	reviewer := f.login(f.reviewer)
	token := f.browser(r, reviewer)
	decision, e := f.s.Authorize(f.ctx, r.Binding(), token, Metadata{Method: "GET", Path: "/"})
	if e != nil || decision.ExpiresAt.After(time.Now().Add(4*time.Second)) {
		t.Fatalf("lease: %v", e)
	}
	foreign := r.Binding()
	foreign.Purpose = "browser_proxy"
	if _, e = f.s.Channel(f.ctx, foreign, *r.Serial); e == nil {
		t.Fatal("foreign audience admitted")
	}
	paused, e := f.s.Action(f.ctx, f.org, r.ID, f.a, ActionInput{Action: "pause", ExpectedVersion: r.Version})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.Renew(f.ctx, r.Binding(), decision.StreamID); e == nil {
		t.Fatal("paused stream renewed")
	}
	resumed, e := f.s.Action(f.ctx, f.org, r.ID, f.a, ActionInput{Action: "resume", ExpectedVersion: paused.Version})
	if e != nil {
		t.Fatal(e)
	}
	if resumed.Hostname != r.Hostname || !resumed.ExpiresAt.Equal(r.ExpiresAt) || resumed.State != "starting" {
		t.Fatal("resume changed locator/lifetime")
	}
	stopped, e := f.s.Action(f.ctx, f.org, r.ID, f.a, ActionInput{Action: "stop", ExpectedVersion: resumed.Version})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.Action(f.ctx, f.org, r.ID, f.a, ActionInput{Action: "resume", ExpectedVersion: stopped.Version}); e == nil {
		t.Fatal("terminal share resurrected")
	}
}
func TestBeamGrantParentAndPublisherRevocation(t *testing.T) {
	f := newFixture(t)
	r, _ := f.connect(f.create())
	a := f.login(f.reviewer)
	token := f.browser(r, a)
	decision, e := f.s.Authorize(f.ctx, r.Binding(), token, Metadata{Method: "GET", Path: "/"})
	if e != nil {
		t.Fatal(e)
	}
	if e = f.store.Delete(f.ctx, a.SessionID); e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.Renew(f.ctx, r.Binding(), decision.StreamID); e == nil {
		t.Fatal("logged out reviewer renewed")
	}
	a = f.login(f.reviewer)
	token = f.browser(r, a)
	decision, e = f.s.Authorize(f.ctx, r.Binding(), token, Metadata{Method: "GET", Path: "/"})
	if e != nil {
		t.Fatal(e)
	}
	f.exec(`DELETE FROM beam_grants WHERE org_id=$1 AND share_id=$2 AND subject_id=$3`, f.org, r.ID, f.reviewer)
	if _, e = f.s.Renew(f.ctx, r.Binding(), decision.StreamID); e == nil {
		t.Fatal("removed grant renewed")
	}
	if _, e = f.s.Launch(f.ctx, f.org, r.ID, f.login(f.outsider), LaunchInput{"/", f.s.NonceHash("invalid")}); e == nil {
		t.Fatal("ungranted outsider launched")
	}
	f.exec(`UPDATE cli_credentials SET revoked_at=now() WHERE id=$1`, f.a.CredentialID)
	if _, e = f.s.Channel(f.ctx, r.Binding(), *r.Serial); e == nil {
		t.Fatal("revoked source renewed")
	}
	if e = f.s.Sweep(f.ctx); e != nil {
		t.Fatal(e)
	}
	after, e := f.s.Get(f.ctx, f.org, r.ID, f.a)
	if e != nil || after.State != "revoked" {
		t.Fatal("sweeper did not terminalize", e)
	}
}

func tFromPEM(raw string) *x509.Certificate {
	b, _ := pem.Decode([]byte(raw))
	cert, _ := x509.ParseCertificate(b.Bytes)
	return cert
}
func issuedSerial(c *x509.Certificate) string { return c.SerialNumber.Text(16) }

func TestBeamGrantOverlapPolicyReductionAndHardExpiry(t *testing.T) {
	f := newFixture(t)
	r, _ := f.connect(f.create())
	a := f.login(f.reviewer)
	token := f.browser(r, a)
	decision, e := f.s.Authorize(f.ctx, r.Binding(), token, Metadata{Method: "GET", Path: "/"})
	if e != nil {
		t.Fatal(e)
	}
	updated, e := f.s.UpdateGrants(f.ctx, f.org, r.ID, f.a, GrantsInput{ConfirmReviewerRemoval: true, ExpectedVersion: r.Version, Grants: []Grant{{"user", f.reviewer}}})
	if e != nil {
		t.Fatal(e)
	}
	if updated.AuthorityVersion == r.AuthorityVersion || updated.Binding() != r.Binding() {
		t.Fatal("audience version must change without replacing serving identity")
	}
	if _, e = f.s.Renew(f.ctx, r.Binding(), decision.StreamID); e != nil {
		t.Fatal("remaining reviewer lost valid stream", e)
	}
	if _, e = f.s.UpdateGrants(f.ctx, f.org, r.ID, f.a, GrantsInput{ConfirmReviewerRemoval: true, ExpectedVersion: updated.Version, Grants: []Grant{{"user", f.outsider}}}); e == nil {
		t.Fatal("expanded audience outsidepolicy")
	}
	f.exec(`UPDATE beam_policies SET reviewer_user_ids='{}' WHERE org_id=$1`, f.org)
	if _, e = f.s.Renew(f.ctx, r.Binding(), decision.StreamID); e == nil {
		t.Fatal("policyreduced reviewer renewed")
	}
	f.exec(`UPDATE beam_policies SET reviewer_user_ids=$2 WHERE org_id=$1`, f.org, []uuid.UUID{f.reviewer})
	f.exec(`UPDATE beam_shares SET expires_at=now()-interval '1 second',created_at=now()-interval '2 seconds' WHERE org_id=$1 AND id=$2`, f.org, r.ID)
	if _, e = f.s.Channel(f.ctx, r.Binding(), *r.Serial); e == nil {
		t.Fatal("expired connector admitted without sweeper")
	}
	if _, e = f.s.Renew(f.ctx, r.Binding(), decision.StreamID); e == nil {
		t.Fatal("expired stream renewed without sweeper")
	}
	if e = f.s.Sweep(f.ctx); e != nil {
		t.Fatal(e)
	}
	after, e := f.s.Get(f.ctx, f.org, r.ID, f.a)
	if e != nil || after.State != "expired" {
		t.Fatal("hardexpiry notdurable", e)
	}
}

// A first-time mobile sign-in must not lose its browser handoff after one minute.
func TestBeamSlowSignInAndExpiredLaunchRecovery(t *testing.T) {
	f := newFixture(t)
	r, _ := f.connect(f.create())
	a := f.login(f.reviewer)
	nonce, _ := secret("")
	nh := f.s.NonceHash(nonce)
	until, e := f.s.Pending(f.ctx, r.Binding(), nh, "/design?mobile=1")
	if e != nil {
		t.Fatal(e)
	}
	if time.Until(until) < 2*time.Minute {
		t.Fatalf("first-login window too short: %s", time.Until(until))
	}
	// Model elapsed login time without sleeping or changing the workstation clock.
	f.exec(`UPDATE beam_pending_launches SET expires_at=now()-interval '1 second' WHERE nonce_hash=decode($1,'hex')`, nh)
	_, e = f.s.Launch(f.ctx, f.org, r.ID, a, LaunchInput{"/design?mobile=1", nh})
	var failure *apierr.Error
	if !errors.As(e, &failure) || failure.Code != "beam_launch_expired" {
		t.Fatalf("expired launch not actionable: %v", e)
	}
	if e = f.s.Sweep(f.ctx); e != nil {
		t.Fatal(e)
	}
	_, e = f.s.Launch(f.ctx, f.org, r.ID, a, LaunchInput{"/design?mobile=1", nh})
	if !errors.As(e, &failure) || failure.Code != "beam_launch_expired" {
		t.Fatalf("swept launch not actionable: %v", e)
	}
	// Re-entering the original public URL creates a new browser-bound nonce.
	fresh, _ := secret("")
	freshHash := f.s.NonceHash(fresh)
	if _, e = f.s.Pending(f.ctx, r.Binding(), freshHash, "/design?mobile=1"); e != nil {
		t.Fatal(e)
	}
	launch, e := f.s.Launch(f.ctx, f.org, r.ID, a, LaunchInput{"/design?mobile=1", freshHash})
	if e != nil {
		t.Fatal("fresh handoff failed", e)
	}
	if time.Until(launch.ExpiresAt) > 30*time.Second {
		t.Fatal("redeem code lifetime increased")
	}
	u, _ := url.Parse(launch.RedirectURL)
	if _, e = f.s.Redeem(f.ctx, r.Hostname, u.Query().Get("code"), nonce); e == nil {
		t.Fatal("old browser nonce redeemed fresh code")
	}
	if _, e = f.s.Redeem(f.ctx, r.Hostname, u.Query().Get("code"), fresh); e != nil {
		t.Fatal("fresh nonce failed", e)
	}
	f.exec(`DELETE FROM beam_grants WHERE org_id=$1 AND share_id=$2`, f.org, r.ID)
	_, e = f.s.Launch(f.ctx, f.org, r.ID, a, LaunchInput{"/design?mobile=1", nh})
	if !errors.As(e, &failure) || failure.Code != "beam_authority_unavailable" {
		t.Fatal("expiry bypassed reviewer authority", e)
	}
}
func TestBeamNonceIdentityAndMFA(t *testing.T) {
	f := newFixture(t)
	r, _ := f.connect(f.create())
	a := f.login(f.reviewer)
	nonce, _ := secret("")
	nh := f.s.NonceHash(nonce)
	if _, e := f.s.Pending(f.ctx, r.Binding(), nh, "/"); e != nil {
		t.Fatal(e)
	}
	if _, e := f.s.Launch(f.ctx, f.org, r.ID, a, LaunchInput{"/another", nh}); e == nil {
		t.Fatal("pending target changed")
	}
	launch, e := f.s.Launch(f.ctx, f.org, r.ID, a, LaunchInput{"/", nh})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.Launch(f.ctx, f.org, r.ID, a, LaunchInput{"/", nh}); e == nil {
		t.Fatal("pending nonce replay")
	}
	u, _ := url.Parse(launch.RedirectURL)
	code := u.Query().Get("code")
	if _, e = f.s.Redeem(f.ctx, "foreign.beam.other.net", code, nonce); e == nil {
		t.Fatal("foreignhost redeemed")
	}
	wrong, _ := secret("")
	if _, e = f.s.Redeem(f.ctx, r.Hostname, code, wrong); e == nil {
		t.Fatal("wrongnonce redeemed")
	}
	if _, e = f.s.Redeem(f.ctx, r.Hostname, code, nonce); e != nil {
		t.Fatal("rightnonce failed", e)
	}
	if _, e = f.s.Channel(f.ctx, r.Binding(), "foreign-serial"); e == nil {
		t.Fatal("foreigncert admitted")
	}
	f.exec(`UPDATE beam_policies SET require_mfa=true WHERE org_id=$1`, f.org)
	nonce, _ = secret("")
	nh = f.s.NonceHash(nonce)
	_, _ = f.s.Pending(f.ctx, r.Binding(), nh, "/")
	if _, e = f.s.Launch(f.ctx, f.org, r.ID, a, LaunchInput{"/", nh}); e == nil {
		t.Fatal("unknown MFA assurance admitted")
	}
	sess, e := f.store.CreateWithMFAAuthority(f.ctx, f.reviewer, "local_password", 1, time.Now(), session.MFAAssuranceLocalTOTP)
	if e != nil {
		t.Fatal(e)
	}
	a.SessionID = sess.ID
	if _, e = f.s.Launch(f.ctx, f.org, r.ID, a, LaunchInput{"/", nh}); e != nil {
		t.Fatal("verified fresh MFA denied", e)
	}
}
func TestBeamStartupQuotaCleanupAndMemberLoss(t *testing.T) {
	f := newFixture(t)
	r := f.create()
	f.exec(`UPDATE beam_shares SET created_at=now()-interval '3 minutes' WHERE org_id=$1 AND id=$2`, f.org, r.ID)
	if e := f.s.Sweep(f.ctx); e != nil {
		t.Fatal(e)
	}
	after, e := f.s.Get(f.ctx, f.org, r.ID, f.a)
	if e != nil || after.State != "stopped" {
		t.Fatal("failed startup notcleaned", e)
	}
	r, _ = f.connect(f.create())
	f.exec(`DELETE FROM group_members WHERE org_id=$1 AND group_id=$2 AND user_id=$3`, f.org, f.group, f.owner)
	if _, e = f.s.Channel(f.ctx, r.Binding(), *r.Serial); e == nil {
		t.Fatal("removedpublisher group retainedauthority")
	}
	if e = f.s.Sweep(f.ctx); e != nil {
		t.Fatal(e)
	}
	after, e = f.s.Get(f.ctx, f.org, r.ID, f.a)
	if e != nil || after.State != "revoked" {
		t.Fatal("memberloss notdurable", e)
	}
}

func TestBeamDomainWithdrawalAndSupportedRestore(t *testing.T) {
	f := newFixture(t)
	r, _ := f.connect(f.create())
	a := f.login(f.reviewer)
	token := f.browser(r, a)
	decision, e := f.s.Authorize(f.ctx, r.Binding(), token, Metadata{Method: "GET", Path: "/"})
	if e != nil {
		t.Fatal(e)
	}
	f.exec(`UPDATE beam_installation_settings SET base_domain='beam.changed.net' WHERE singleton`)
	if _, e = f.s.Renew(f.ctx, r.Binding(), decision.StreamID); e == nil {
		t.Fatal("old domain silently retained serving")
	}
	if e = f.s.Sweep(f.ctx); e != nil {
		t.Fatal(e)
	}
	f.exec(`UPDATE beam_installation_settings SET base_domain='beam.other.net' WHERE singleton`)
	if _, e = f.s.Channel(f.ctx, r.Binding(), *r.Serial); e == nil {
		t.Fatal("withdrawn olddomain resurrected")
	}
	after, e := f.s.Get(f.ctx, f.org, r.ID, f.a)
	if e != nil || after.State != "revoked" {
		t.Fatal("domainwithdrawal notdurable", e)
	}
	r, _ = f.connect(f.create())
	a = f.login(f.reviewer)
	token = f.browser(r, a)
	result, e := appaccess.NewRecoveryService(f.pool).RecoverAuthority(f.ctx, "beam-test-operator")
	if e != nil || result.BeamShares != 1 {
		t.Fatal("recovery failed", e)
	}
	if _, e = f.s.Channel(f.ctx, r.Binding(), *r.Serial); e == nil {
		t.Fatal("restored oldconnector resurrected")
	}
	if _, e = f.s.Authorize(f.ctx, r.Binding(), token, Metadata{Method: "GET", Path: "/"}); e == nil {
		t.Fatal("restored oldbrowserauthority resurrected")
	}
	after, e = f.s.Get(f.ctx, f.org, r.ID, f.a)
	if e != nil || after.State != "revoked" {
		t.Fatal("restore nonterminal remained", e)
	}
}
func TestBeamHeartbeatCannotAssertServingAndCertificateGeneration(t *testing.T) {
	f := newFixture(t)
	r := f.create()
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "fixture"}}, key)
	if e != nil {
		t.Fatal(e)
	}
	in := ConnectorInput{ExpectedVersion: r.Version, CSR: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}))}
	connector, e := f.s.IssueConnector(f.ctx, f.org, r.ID, f.a, in)
	if e != nil {
		t.Fatal(e)
	}
	if connector.ShareVersion != r.Version+1 {
		t.Fatal("connector response lost the current mutation version")
	}
	r, e = f.s.Heartbeat(f.ctx, f.org, r.ID, f.a, Heartbeat{connector.Binding.Generation, true})
	if e != nil {
		t.Fatal(e)
	}
	if r.State == "active" || r.CanOpen || r.Connectivity == "online" {
		t.Fatal("heartbeat without verifiedchannel claimedLive")
	}
	if _, e = f.s.IssueConnector(f.ctx, f.org, r.ID, f.a, in); e == nil {
		t.Fatal("bootstrap staleversion replayed")
	}
	serial := issuedSerial(tFromPEM(connector.CertificatePEM))
	if _, e = f.s.Channel(f.ctx, connector.Binding, serial); e != nil {
		t.Fatal(e)
	}
	r, e = f.s.Heartbeat(f.ctx, f.org, r.ID, f.a, Heartbeat{connector.Binding.Generation, true})
	if e != nil {
		t.Fatal(e)
	}
	fresh, e := f.s.IssueConnector(f.ctx, f.org, r.ID, f.a, ConnectorInput{ExpectedVersion: r.Version, CSR: in.CSR})
	if e != nil {
		t.Fatal(e)
	}
	if fresh.Binding.Generation == connector.Binding.Generation {
		t.Fatal("replacementgeneration reused")
	}
	if _, e = f.s.Channel(f.ctx, connector.Binding, serial); e == nil {
		t.Fatal("retiredgeneration stilladmitted")
	}
	if _, e = f.s.Heartbeat(f.ctx, f.org, r.ID, f.a, Heartbeat{connector.Binding.Generation, true}); e == nil {
		t.Fatal("lateoldheartbeat resurrected")
	}
}
func TestBeamExtensionPreservesCurrentServing(t *testing.T) {
	f := newFixture(t)
	r, _ := f.connect(f.create())
	a := f.login(f.reviewer)
	token := f.browser(r, a)
	decision, e := f.s.Authorize(f.ctx, r.Binding(), token, Metadata{Method: "GET", Path: "/"})
	if e != nil {
		t.Fatal(e)
	}
	expiry := r.CreatedAt.Add(3500 * time.Second)
	extended, e := f.s.Action(f.ctx, f.org, r.ID, f.a, ActionInput{Action: "extend", ExpectedVersion: r.Version, ExpiresAt: &expiry})
	if e != nil {
		t.Fatal(e)
	}
	if extended.Binding() != r.Binding() || extended.Serial == nil || *extended.Serial != *r.Serial || extended.State != "active" || extended.Connectivity != "online" {
		t.Fatal("extension replacedcurrentservingidentity")
	}
	if _, e = f.s.Renew(f.ctx, r.Binding(), decision.StreamID); e != nil {
		t.Fatal("explicitextension invalidatedeligiblecurrentstream", e)
	}
	if _, e = f.s.Channel(f.ctx, r.Binding(), *r.Serial); e != nil {
		t.Fatal("extension invalidatedcurrentchannel", e)
	}
}
func TestBeamAccessEvidenceIsBoundedAndRedacted(t *testing.T) {
	f := newFixture(t)
	r, _ := f.connect(f.create())
	token := f.browser(r, f.login(f.reviewer))
	if _, e := f.s.Authorize(f.ctx, r.Binding(), token, Metadata{Method: "GET", Path: "/private?password=neverpersist"}); e != nil {
		t.Fatal(e)
	}
	f.exec(`DELETE FROM beam_grants WHERE org_id=$1 AND share_id=$2 AND subject_id=$3`, f.org, r.ID, f.reviewer)
	for i := 0; i < 5; i++ {
		if _, e := f.s.Authorize(f.ctx, r.Binding(), token, Metadata{Method: "GET", Path: "/private?password=neverpersist"}); e == nil {
			t.Fatal("removedreviewer admitted")
		}
	}
	var allowed, denied int
	var data string
	e := f.pool.QueryRow(f.ctx, `SELECT count(*) FILTER(WHERE action='beam.access.allowed'),count(*) FILTER(WHERE action='beam.access.denied'),COALESCE(string_agg(metadata::text,''),'') FROM audit_logs WHERE org_id=$1 AND action LIKE 'beam.access.%'`, f.org).Scan(&allowed, &denied, &data)
	if e != nil {
		t.Fatal(e)
	}
	if allowed != 1 || denied != 1 {
		t.Fatal("auditdidnotboundrepeatdenials", allowed, denied)
	}
	for _, secret := range []string{token, "neverpersist", "private?", "certificate"} {
		if strings.Contains(data, secret) {
			t.Fatal("accessauditpersistedrequestsecret")
		}
	}
}
