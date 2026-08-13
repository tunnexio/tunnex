package cliauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
)

func codeOf(err error) string {
	var a *apierr.Error
	if err != nil && errors.As(err, &a) {
		return a.Code
	}
	return ""
}

// pkcePair returns a verifier and its S256 challenge.
func pkcePair(t *testing.T) (verifier, challenge string) {
	t.Helper()
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	verifier = base64.RawURLEncoding.EncodeToString(b) // 43 chars
	h := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(h[:])
}

// harness: tx-scoped service (pool==nil → withTx runs on the tx queries), so
// every test rolls back cleanly.
func setup(t *testing.T) (context.Context, *Service, *sqlc.Queries, pgx.Tx, uuid.UUID) {
	t.Helper()
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(ctx) })
	q := sqlc.New(tx)

	key := make([]byte, crypto.KeySize)
	_, _ = rand.Read(key)
	sealer, _ := crypto.NewSealer(key)

	user := uuid.New()
	if _, err := tx.Exec(ctx, "INSERT INTO users (id,email,name) VALUES ($1,$2,$3)", user, user.String()+"@t", "U"); err != nil {
		t.Fatalf("user: %v", err)
	}
	return ctx, &Service{q: q, sealer: sealer}, q, tx, user
}

func TestLoopbackRedirectAllowlist(t *testing.T) {
	ok := []string{"http://127.0.0.1:8123/callback", "http://[::1]:9999/callback"}
	for _, u := range ok {
		if err := ValidateLoopbackRedirect(u); err != nil {
			t.Fatalf("%s: want ok, got %v", u, err)
		}
	}
	bad := []string{
		"http://localhost:8123/callback", // hostname — DNS-spoofable
		"https://127.0.0.1:8123/callback",
		"http://127.0.0.1/callback",               // no explicit port
		"http://127.0.0.1:8123/other",             // wrong path
		"http://127.0.0.1:8123/callback?x=1",      // query
		"http://evil.example:80/callback",         // non-loopback
		"http://user@127.0.0.1:8123/callback",     // userinfo
		"http://127.0.0.2:8123/callback",          // not EXACTLY 127.0.0.1
		"http://127.0.0.1:8123/callback#fragment", // fragment
	}
	for _, u := range bad {
		if err := ValidateLoopbackRedirect(u); codeOf(err) != "invalid_redirect" {
			t.Fatalf("%s: want invalid_redirect, got %v", u, err)
		}
	}
}

func TestLoopbackExchangeLifecycle(t *testing.T) {
	ctx, svc, q, tx, user := setup(t)
	redirect := "http://127.0.0.1:4242/callback"
	verifier, challenge := pkcePair(t)

	code, expiresIn, err := svc.MintAuthCode(ctx, user, redirect, challenge)
	if err != nil || expiresIn != 60 {
		t.Fatalf("mint: code=%q expires=%d err=%v", code, expiresIn, err)
	}
	if !strings.HasPrefix(code, "tnxc_") {
		t.Fatalf("code prefix: %q", code)
	}

	// Wrong verifier, wrong redirect: both the SAME generic invalid_grant (no
	// oracle for which check failed) — and neither may consume... (the code IS
	// consumed on first touch by design; so test order matters: bad attempts
	// against their own freshly-minted codes).
	badVerifier, _ := pkcePair(t)
	if _, err := svc.ExchangeCode(ctx, code, badVerifier, redirect); codeOf(err) != "invalid_grant" {
		t.Fatalf("wrong verifier: want invalid_grant, got %v", err)
	}
	// The bad attempt consumed the code (atomic single-use): a subsequent CORRECT
	// exchange must also fail — a stolen-code race can't win after any touch.
	if _, err := svc.ExchangeCode(ctx, code, verifier, redirect); codeOf(err) != "invalid_grant" {
		t.Fatalf("post-touch exchange: want invalid_grant, got %v", err)
	}

	// Fresh code: wrong redirect refused.
	code2, _, _ := svc.MintAuthCode(ctx, user, redirect, challenge)
	if _, err := svc.ExchangeCode(ctx, code2, verifier, "http://127.0.0.1:9999/callback"); codeOf(err) != "invalid_grant" {
		t.Fatalf("wrong redirect: want invalid_grant, got %v", err)
	}

	// Fresh code: the happy path.
	code3, _, _ := svc.MintAuthCode(ctx, user, redirect, challenge)
	cred, err := svc.ExchangeCode(ctx, code3, verifier, redirect)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if !strings.HasPrefix(cred.Token, TokenPrefix) || cred.Fingerprint == "" {
		t.Fatalf("credential shape: %+v", cred)
	}
	// Replay of a consumed code is refused.
	if _, err := svc.ExchangeCode(ctx, code3, verifier, redirect); codeOf(err) != "invalid_grant" {
		t.Fatalf("code replay: want invalid_grant, got %v", err)
	}

	// The credential row is live and hashed (raw token nowhere in the DB row).
	h := sha256.Sum256([]byte(cred.Token))
	row, err := q.GetActiveCliCredentialByHash(ctx, h[:])
	if err != nil || row.UserID != user {
		t.Fatalf("stored credential: %+v err=%v", row, err)
	}
	if row.Fingerprint != cred.Fingerprint {
		t.Fatalf("fingerprint mismatch: %s vs %s", row.Fingerprint, cred.Fingerprint)
	}

	// Audit: cli.credential_issued carries the fingerprint, never the token, and
	// has a NULL org (user-scoped, spans orgs).
	var meta string
	var orgIsNull bool
	if err := tx.QueryRow(ctx,
		"SELECT metadata::text, org_id IS NULL FROM audit_logs WHERE actor_user_id=$1 AND action='cli.credential_issued' ORDER BY created_at DESC LIMIT 1",
		user).Scan(&meta, &orgIsNull); err != nil {
		t.Fatalf("audit row: %v", err)
	}
	if !orgIsNull {
		t.Fatal("cli.credential_issued must be org-NULL (user-scoped)")
	}
	if !strings.Contains(meta, cred.Fingerprint) || strings.Contains(meta, cred.Token) {
		t.Fatalf("audit metadata: want fingerprint, never the token — got %s", meta)
	}

	// List → revoke → auth-dead.
	list, err := svc.List(ctx, user)
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %d err=%v", len(list), err)
	}
	if err := svc.Revoke(ctx, user, list[0].ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := q.GetActiveCliCredentialByHash(ctx, h[:]); err == nil {
		t.Fatal("revoked credential still resolves as active")
	}
	// Idempotent + no-leak: re-revoking and revoking with a WRONG user both 204.
	if err := svc.Revoke(ctx, user, list[0].ID); err != nil {
		t.Fatalf("re-revoke: %v", err)
	}
	if err := svc.Revoke(ctx, uuid.New(), list[0].ID); err != nil {
		t.Fatalf("foreign revoke must be silent: %v", err)
	}
}

func TestDeviceFlow(t *testing.T) {
	ctx, svc, _, _, user := setup(t)
	d, err := svc.StartDevice(ctx)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if len(d.UserCode) != 9 || d.UserCode[4] != '-' {
		t.Fatalf("user code shape: %q", d.UserCode)
	}
	// Pending until approved.
	if _, err := svc.PollDevice(ctx, d.DeviceCode); codeOf(err) != "authorization_pending" {
		t.Fatalf("pending poll: want authorization_pending, got %v", err)
	}
	// A wrong user code is refused generically.
	if err := svc.ApproveDevice(ctx, user, "XXXX-XXXX"); codeOf(err) != "invalid_grant" {
		t.Fatalf("bad user code: want invalid_grant, got %v", err)
	}
	// Approve (case/dash-forgiving) and collect.
	if err := svc.ApproveDevice(ctx, user, strings.ToLower(strings.ReplaceAll(d.UserCode, "-", ""))); err != nil {
		t.Fatalf("approve: %v", err)
	}
	cred, err := svc.PollDevice(ctx, d.DeviceCode)
	if err != nil || !strings.HasPrefix(cred.Token, TokenPrefix) {
		t.Fatalf("collect: %+v err=%v", cred, err)
	}
	// Consumed: further polling is refused; re-approval impossible.
	if _, err := svc.PollDevice(ctx, d.DeviceCode); codeOf(err) != "invalid_grant" {
		t.Fatalf("post-consume poll: want invalid_grant, got %v", err)
	}
	if err := svc.ApproveDevice(ctx, user, d.UserCode); codeOf(err) != "invalid_grant" {
		t.Fatalf("re-approve consumed: want invalid_grant, got %v", err)
	}
}

// TestExpiredCodesAreRefused pins that the expires_at guard in the consume
// queries actually gates redemption — a dropped "expires_at > now()" would make
// the 60s/15m codes redeemable forever.
func TestExpiredCodesAreRefused(t *testing.T) {
	ctx, svc, q, tx, user := setup(t)
	verifier, challenge := pkcePair(t)

	// Loopback: mint, then force the row past expiry → exchange refused.
	code, _, err := svc.MintAuthCode(ctx, user, "http://127.0.0.1:1/callback", challenge)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if _, err := tx.Exec(ctx, "UPDATE cli_auth_codes SET expires_at = now() - interval '1 second'"); err != nil {
		t.Fatalf("age code: %v", err)
	}
	if _, err := svc.ExchangeCode(ctx, code, verifier, "http://127.0.0.1:1/callback"); codeOf(err) != "invalid_grant" {
		t.Fatalf("expired auth code: want invalid_grant, got %v", err)
	}
	_ = q

	// Device: start + approve, then expire before poll → refused.
	d, err := svc.StartDevice(ctx)
	if err != nil {
		t.Fatalf("device start: %v", err)
	}
	if err := svc.ApproveDevice(ctx, user, d.UserCode); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if _, err := tx.Exec(ctx, "UPDATE cli_device_codes SET expires_at = now() - interval '1 second'"); err != nil {
		t.Fatalf("age device: %v", err)
	}
	if _, err := svc.PollDevice(ctx, d.DeviceCode); codeOf(err) != "invalid_grant" {
		t.Fatalf("expired device code: want invalid_grant, got %v", err)
	}
}

// TestChallengeValidation pins the PKCE-in-effect check at mint time.
func TestChallengeValidation(t *testing.T) {
	ctx, svc, _, _, user := setup(t)
	for _, bad := range []string{"", "short", strings.Repeat("a", 42), strings.Repeat("!", 43)} {
		if _, _, err := svc.MintAuthCode(ctx, user, "http://127.0.0.1:1/callback", bad); codeOf(err) != "invalid_challenge" {
			t.Fatalf("challenge %q: want invalid_challenge, got %v", bad, err)
		}
	}
	_, valid := pkcePair(t)
	if _, _, err := svc.MintAuthCode(ctx, user, "http://127.0.0.1:1/callback", valid); err != nil {
		t.Fatalf("valid challenge rejected: %v", err)
	}
}

// TestUserCodeUniform sanity-checks the rejection-sampled alphabet: every symbol
// is reachable and the dash is fixed at position 4 (no bias assertion — just
// that the generator uses the full set and shape).
func TestUserCodeUniform(t *testing.T) {
	seen := map[rune]bool{}
	for range 400 {
		c, err := newUserCode()
		if err != nil {
			t.Fatalf("gen: %v", err)
		}
		if len(c) != 9 || c[4] != '-' {
			t.Fatalf("shape: %q", c)
		}
		for _, r := range c {
			if r != '-' {
				seen[r] = true
			}
		}
	}
	if len(seen) != 28 {
		t.Fatalf("alphabet coverage: %d/28 symbols seen", len(seen))
	}
}

// TestSweep pins the sweep semantics the reset/deactivation paths rely on.
func TestSweep(t *testing.T) {
	ctx, svc, q, _, user := setup(t)
	verifier, challenge := pkcePair(t)
	for range 2 {
		code, _, _ := svc.MintAuthCode(ctx, user, "http://127.0.0.1:1/callback", challenge)
		if _, err := svc.ExchangeCode(ctx, code, verifier, "http://127.0.0.1:1/callback"); err != nil {
			t.Fatalf("mint credential: %v", err)
		}
	}
	if list, _ := svc.List(ctx, user); len(list) != 2 {
		t.Fatalf("want 2 live credentials, got %d", len(list))
	}
	if err := SweepUser(ctx, q, user); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if list, _ := svc.List(ctx, user); len(list) != 0 {
		t.Fatalf("sweep left %d credentials live", len(list))
	}
}
