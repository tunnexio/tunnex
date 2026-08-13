package mfa

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	apierr "github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
)

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

type fx struct {
	org, userA, userB uuid.UUID
}

func seed(t *testing.T, pool *pgxpool.Pool) fx {
	t.Helper()
	ctx := context.Background()
	f := fx{org: uuid.New(), userA: uuid.New(), userB: uuid.New()}
	exec := func(sql string, args ...any) {
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("seed %q: %v", sql, err)
		}
	}
	exec(`INSERT INTO organizations (id, name, slug) VALUES ($1,$2,$3)`, f.org, "MFA Org", "mfa-"+f.org.String()[:8])
	exec(`INSERT INTO users (id, email) VALUES ($1,$2)`, f.userA, "a-"+f.userA.String()[:8]+"@ex.com")
	exec(`INSERT INTO users (id, email) VALUES ($1,$2)`, f.userB, "b-"+f.userB.String()[:8]+"@ex.com")
	exec(`INSERT INTO memberships (org_id, user_id, role) VALUES ($1,$2,'owner')`, f.org, f.userA)
	exec(`INSERT INTO memberships (org_id, user_id, role) VALUES ($1,$2,'member')`, f.org, f.userB)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM organizations WHERE id=$1`, f.org) })
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE id IN ($1,$2)`, f.userA, f.userB)
	})
	return f
}

// newSvc returns a service whose clock the test controls (TOTP timesteps + challenge expiry).
func newSvc(t *testing.T, pool *pgxpool.Pool) (*Service, *time.Time) {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	sealer, err := crypto.NewSealer(key)
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}
	s := NewService(pool, sealer, nil, nil)
	// Base on real now: challenge expiry is filtered against the DB's now(), so the injected
	// clock must track it. TOTP is absolute-time-agnostic (only step deltas matter).
	clock := time.Now()
	s.now = func() time.Time { return clock }
	return s, &clock
}

// enroll runs the full open-side ceremony and returns the secret + recovery codes.
func enroll(t *testing.T, s *Service, clock *time.Time, user uuid.UUID) (secret string, recovery []string) {
	t.Helper()
	ctx := context.Background()
	_, secret, err := s.StartEnrollment(ctx, user)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	recovery, err = s.ConfirmEnrollment(ctx, user, codeAt(t, secret, clock.Unix()))
	if err != nil {
		t.Fatalf("confirm: %v", err)
	}
	return secret, recovery
}

// TestUnconfirmedDoesNotCountEnrolled — an unconfirmed (abandoned-mid-ceremony) enrollment must NOT
// challenge at login and must NOT count as enrolled (the seam between slice 1 and slice 2).
func TestUnconfirmedDoesNotCountEnrolled(t *testing.T) {
	pool := testPool(t)
	f := seed(t, pool)
	s, _ := newSvc(t, pool)
	if _, _, err := s.StartEnrollment(context.Background(), f.userA); err != nil {
		t.Fatalf("start: %v", err)
	}
	ok, err := s.HasConfirmedTOTP(context.Background(), f.userA)
	if err != nil || ok {
		t.Fatalf("unconfirmed enrollment must NOT count as enrolled, got ok=%v err=%v", ok, err)
	}
}

func TestEnrollConfirmVerifyHappy(t *testing.T) {
	pool := testPool(t)
	f := seed(t, pool)
	s, clock := newSvc(t, pool)
	secret, _ := enroll(t, s, clock, f.userA)
	if ok, _ := s.HasConfirmedTOTP(context.Background(), f.userA); !ok {
		t.Fatal("confirmed enrollment must count as enrolled")
	}
	// A later timestep so the confirm code isn't replayed.
	*clock = clock.Add(60 * time.Second)
	tok, _, err := s.CreateChallenge(context.Background(), f.userA)
	if err != nil {
		t.Fatalf("challenge: %v", err)
	}
	user, viaRecovery, err := s.VerifyChallenge(context.Background(), tok, codeAt(t, secret, clock.Unix()))
	if err != nil || user.ID != f.userA || viaRecovery {
		t.Fatalf("verify happy: user=%v viaRecovery=%v err=%v", user.ID, viaRecovery, err)
	}
}

// TestReplayRefusedAtVerify — the confirm code (whose timestep is stamped as last-used) can't be
// replayed at the login challenge; a code at a NEW timestep works.
func TestReplayRefusedAtVerify(t *testing.T) {
	pool := testPool(t)
	f := seed(t, pool)
	s, clock := newSvc(t, pool)
	secret, _ := enroll(t, s, clock, f.userA)
	confirmCode := codeAt(t, secret, clock.Unix())
	tok, _, _ := s.CreateChallenge(context.Background(), f.userA)
	if _, _, err := s.VerifyChallenge(context.Background(), tok, confirmCode); code(err) != "invalid_code" {
		t.Fatalf("REPLAY of the confirm code must be refused, got %v", err)
	}
	// Fresh challenge + a code at a later timestep -> accepted.
	*clock = clock.Add(60 * time.Second)
	tok2, _, _ := s.CreateChallenge(context.Background(), f.userA)
	if _, _, err := s.VerifyChallenge(context.Background(), tok2, codeAt(t, secret, clock.Unix())); err != nil {
		t.Fatalf("a fresh-timestep code must be accepted: %v", err)
	}
}

// TestConsumedRecoveryRefused — a recovery code is single-use.
func TestConsumedRecoveryRefused(t *testing.T) {
	pool := testPool(t)
	f := seed(t, pool)
	s, clock := newSvc(t, pool)
	_, recovery := enroll(t, s, clock, f.userA)

	tok, _, _ := s.CreateChallenge(context.Background(), f.userA)
	user, viaRecovery, err := s.VerifyChallenge(context.Background(), tok, recovery[0])
	if err != nil || user.ID != f.userA || !viaRecovery {
		t.Fatalf("recovery login must succeed via recovery: user=%v via=%v err=%v", user.ID, viaRecovery, err)
	}
	tok2, _, _ := s.CreateChallenge(context.Background(), f.userA)
	if _, _, err := s.VerifyChallenge(context.Background(), tok2, recovery[0]); err == nil {
		t.Fatal("a CONSUMED recovery code must be refused")
	}
}

// TestBurnedAndExpiredChallengeRefused — a challenge is burned on success, and an expired one is gone.
func TestBurnedAndExpiredChallengeRefused(t *testing.T) {
	pool := testPool(t)
	f := seed(t, pool)
	s, clock := newSvc(t, pool)
	secret, _ := enroll(t, s, clock, f.userA)
	*clock = clock.Add(60 * time.Second)

	tok, _, _ := s.CreateChallenge(context.Background(), f.userA)
	if _, _, err := s.VerifyChallenge(context.Background(), tok, codeAt(t, secret, clock.Unix())); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	if _, _, err := s.VerifyChallenge(context.Background(), tok, codeAt(t, secret, clock.Unix())); code(err) != "mfa_challenge_invalid" {
		t.Fatalf("a BURNED challenge must be refused, got %v", err)
	}

	// Expired: mint, then age the row past its TTL against the DB clock (the expiry filter uses now()).
	tok2, _, _ := s.CreateChallenge(context.Background(), f.userA)
	if _, err := pool.Exec(context.Background(), `UPDATE mfa_challenges SET expires_at = now() - interval '1 minute' WHERE user_id=$1`, f.userA); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.VerifyChallenge(context.Background(), tok2, codeAt(t, secret, clock.Unix())); code(err) != "mfa_challenge_invalid" {
		t.Fatalf("an EXPIRED challenge must be refused, got %v", err)
	}
}

// TestChallengeCrossUserBinding — a challenge minted for A must not resolve with B's code/context
// (the pending state is identity-bound; verify keys off the challenge's user, not the code's owner).
func TestChallengeCrossUserBinding(t *testing.T) {
	pool := testPool(t)
	f := seed(t, pool)
	s, clock := newSvc(t, pool)
	enroll(t, s, clock, f.userA)
	secretB, recoveryB := enroll(t, s, clock, f.userB)
	*clock = clock.Add(60 * time.Second)

	tokA, _, _ := s.CreateChallenge(context.Background(), f.userA)
	// B's live TOTP code must NOT satisfy A's challenge.
	if _, _, err := s.VerifyChallenge(context.Background(), tokA, codeAt(t, secretB, clock.Unix())); err == nil {
		t.Fatal("A's challenge must NOT accept B's TOTP code")
	}
	// B's recovery code must NOT satisfy A's challenge either.
	tokA2, _, _ := s.CreateChallenge(context.Background(), f.userA)
	if _, _, err := s.VerifyChallenge(context.Background(), tokA2, recoveryB[0]); err == nil {
		t.Fatal("A's challenge must NOT accept B's recovery code")
	}
}

// TestCapThenFreshLogin — the terminal cap is PER-CHALLENGE (D7), not per-account: after N wrong
// attempts burn a challenge, a fresh login mints a fresh challenge that works.
func TestCapThenFreshLogin(t *testing.T) {
	pool := testPool(t)
	f := seed(t, pool)
	s, clock := newSvc(t, pool)
	secret, _ := enroll(t, s, clock, f.userA)
	*clock = clock.Add(60 * time.Second)

	tok, _, _ := s.CreateChallenge(context.Background(), f.userA)
	var lastErr error
	for i := 0; i < maxAttempts; i++ {
		_, _, lastErr = s.VerifyChallenge(context.Background(), tok, "000000")
	}
	if code(lastErr) != "mfa_challenge_exhausted" {
		t.Fatalf("the %dth wrong attempt must exhaust the challenge, got %v", maxAttempts, lastErr)
	}
	// A FRESH challenge (as a fresh password login would mint) works — the cap didn't lock the account.
	tok2, _, _ := s.CreateChallenge(context.Background(), f.userA)
	if _, _, err := s.VerifyChallenge(context.Background(), tok2, codeAt(t, secret, clock.Unix())); err != nil {
		t.Fatalf("a fresh challenge after cap-exhaustion must work: %v", err)
	}
}

// TestEnforceKeysOnConfirmed — the gate keys on CONFIRMED enrollment: an unconfirmed/abandoned
// ceremony counts as UNENROLLED (the slice-1/slice-2 seam), and confirming flips the gate off.
func TestEnforceKeysOnConfirmed(t *testing.T) {
	pool := testPool(t)
	f := seed(t, pool)
	s, clock := newSvc(t, pool)
	setEnforce(t, pool, f.org, true)

	// Unconfirmed enrollment -> still gated.
	if _, _, err := s.StartEnrollment(context.Background(), f.userA); err != nil {
		t.Fatalf("start: %v", err)
	}
	if gated, err := s.IsEnrollmentGated(context.Background(), f.userA); err != nil || !gated {
		t.Fatalf("unconfirmed enrollment must remain GATED, gated=%v err=%v", gated, err)
	}
	// Confirm -> gate lifts.
	enrollConfirmOnly(t, s, clock, f.userA)
	if gated, err := s.IsEnrollmentGated(context.Background(), f.userA); err != nil || gated {
		t.Fatalf("confirmed enrollment must lift the gate, gated=%v err=%v", gated, err)
	}
}

// TestFlipOnGrandfather — an existing UNENROLLED user is not gated until the org flips enforce ON;
// then their next login is gated (enroll-on-next-login, no prior lockout event).
func TestFlipOnGrandfather(t *testing.T) {
	pool := testPool(t)
	f := seed(t, pool)
	s, _ := newSvc(t, pool)
	if gated, _ := s.IsEnrollmentGated(context.Background(), f.userA); gated {
		t.Fatal("unenrolled user in a non-enforcing org must NOT be gated")
	}
	if err := s.SetOrgEnforce(context.Background(), f.org, f.userA, true); err != nil {
		t.Fatalf("enforce on: %v", err)
	}
	if gated, _ := s.IsEnrollmentGated(context.Background(), f.userA); !gated {
		t.Fatal("after flip-on, the unenrolled user must be gated")
	}
	if auditCount(t, pool, f.org, "mfa.enforce_enabled") != 1 {
		t.Fatal("enforce-on must audit mfa.enforce_enabled")
	}
}

// TestAdminResetDisenrollsAndAudits — admin-reset clears the target's factor (disenroll-only) and
// audits mfa.admin_reset org-scoped.
func TestAdminResetDisenrollsAndAudits(t *testing.T) {
	pool := testPool(t)
	f := seed(t, pool)
	s, clock := newSvc(t, pool)
	enroll(t, s, clock, f.userB)
	if ok, _ := s.HasConfirmedTOTP(context.Background(), f.userB); !ok {
		t.Fatal("precondition: userB enrolled")
	}
	if err := s.AdminReset(context.Background(), f.org, f.userA, f.userB); err != nil {
		t.Fatalf("admin reset: %v", err)
	}
	if ok, _ := s.HasConfirmedTOTP(context.Background(), f.userB); ok {
		t.Fatal("admin-reset must disenroll the target")
	}
	if auditCount(t, pool, f.org, "mfa.admin_reset") != 1 {
		t.Fatal("admin-reset must audit mfa.admin_reset")
	}
}

func setEnforce(t *testing.T, pool *pgxpool.Pool, org uuid.UUID, on bool) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO org_mfa (org_id, enforce) VALUES ($1,$2) ON CONFLICT (org_id) DO UPDATE SET enforce=$2`, org, on); err != nil {
		t.Fatal(err)
	}
}

func enrollConfirmOnly(t *testing.T, s *Service, clock *time.Time, user uuid.UUID) {
	t.Helper()
	if _, err := s.ConfirmEnrollment(context.Background(), user, codeAt(t, mustSecret(t, s, user), clock.Unix())); err != nil {
		t.Fatalf("confirm: %v", err)
	}
}

// mustSecret re-reads the pending secret for a user (test-only, unseals via the same sealer).
func mustSecret(t *testing.T, s *Service, user uuid.UUID) string {
	t.Helper()
	row, err := s.q.GetTOTP(context.Background(), user)
	if err != nil {
		t.Fatalf("get totp: %v", err)
	}
	sec, err := s.sealer.Open(string(row.SecretEnc))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return string(sec)
}

func auditCount(t *testing.T, pool *pgxpool.Pool, org uuid.UUID, action string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action=$2`, org, action).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestStartEnrollmentRefusesOverConfirmed — finding #3: re-starting over a CONFIRMED factor is
// refused (would silently wipe it); re-starting over an UNCONFIRMED one still works (restartable).
func TestStartEnrollmentRefusesOverConfirmed(t *testing.T) {
	pool := testPool(t)
	f := seed(t, pool)
	s, clock := newSvc(t, pool)
	enroll(t, s, clock, f.userA) // confirmed
	if _, _, err := s.StartEnrollment(context.Background(), f.userA); code(err) != "already_enrolled" {
		t.Fatalf("start over a CONFIRMED factor must be refused (already_enrolled), got %v", err)
	}
	// Restartable-ceremony property survives: over an UNCONFIRMED row, start-again is allowed.
	if _, _, e := s.StartEnrollment(context.Background(), f.userB); e != nil {
		t.Fatalf("first start: %v", e)
	}
	if _, _, e := s.StartEnrollment(context.Background(), f.userB); e != nil {
		t.Fatalf("restart over an unconfirmed enrollment must be allowed: %v", e)
	}
}

// TestAdminResetClearsInflightChallenge — finding #6: admin-reset burns the target's outstanding
// challenge, so a mid-login target gets a clean "sign in again", not attempts-to-exhaustion.
func TestAdminResetClearsInflightChallenge(t *testing.T) {
	pool := testPool(t)
	f := seed(t, pool)
	s, clock := newSvc(t, pool)
	enroll(t, s, clock, f.userB)
	tok, _, _ := s.CreateChallenge(context.Background(), f.userB) // mid-login
	if err := s.AdminReset(context.Background(), f.org, f.userA, f.userB); err != nil {
		t.Fatalf("admin reset: %v", err)
	}
	if _, _, err := s.VerifyChallenge(context.Background(), tok, "000000"); code(err) != "mfa_challenge_invalid" {
		t.Fatalf("admin-reset must burn the in-flight challenge (clean re-login), got %v", err)
	}
}

// TestAuditLandsWithNullOrgWhenUnresolvable — finding #7, made EXECUTABLE (not comment-asserted): a
// self-service MFA event for a user whose org can't be resolved (no membership) must still write a
// first-class audit row — unscoped (null org_id), never dropped to slog only.
func TestAuditLandsWithNullOrgWhenUnresolvable(t *testing.T) {
	pool := testPool(t)
	s, clock := newSvc(t, pool)
	ctx := context.Background()
	user := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, email) VALUES ($1,$2)`, user, "noorg-"+user.String()[:8]+"@ex.com"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, user) })

	enroll(t, s, clock, user) // start + confirm -> mfa.enrolled audit, primaryOrg fails (no membership)

	var n int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_logs WHERE target_id=$1 AND action='mfa.enrolled' AND org_id IS NULL`,
		user.String()).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("a membership-less user's mfa.enrolled audit must land UNSCOPED (null org), got %d null-org rows", n)
	}
}

func code(err error) string {
	var a *apierr.Error
	if err != nil && errors.As(err, &a) {
		return a.Code
	}
	return ""
}
