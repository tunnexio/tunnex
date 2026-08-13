package auth

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/mail"
	"github.com/tunnexio/tunnex/apps/api/internal/password"
)

type captureMailer struct{ msgs []mail.Message }

func (m *captureMailer) Kind() string { return "capture" }
func (m *captureMailer) Send(_ context.Context, msg mail.Message) error {
	m.msgs = append(m.msgs, msg)
	return nil
}
func (m *captureMailer) last() mail.Message { return m.msgs[len(m.msgs)-1] }

// lastToken lifts a token out of the PLAINTEXT body, the way a person copying a link does.
//
// ⛔ A TOKEN ENDS AT WHITESPACE. This used to take everything to the end of the body, which worked only
// while the link happened to be the last thing in it. The identical version in invites_test.go went red the
// moment S12.14 added a closing sentence after the link — this one survived by luck, on bodies where the
// order happened to still suit it. Fixed as the CLASS rather than the instance that failed: an extractor
// whose correctness depends on the copy around it is a trap waiting for the next copy change.
func (m *captureMailer) lastToken() string {
	body := m.last().Text
	i := strings.Index(body, "token=")
	if i < 0 {
		return ""
	}
	tok := body[i+len("token="):]
	if end := strings.IndexAny(tok, " \t\r\n"); end >= 0 {
		tok = tok[:end]
	}
	return strings.TrimSpace(tok)
}

func newTestAuth(t *testing.T) (*Service, *captureMailer, func()) {
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
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	mailer := &captureMailer{}
	// pool nil -> withTx and direct queries all run on the rolled-back tx.
	svc := &Service{q: sqlc.New(tx), mailer: mailer, baseURL: "http://x", logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	cleanup := func() { _ = tx.Rollback(ctx); pool.Close() }
	return svc, mailer, cleanup
}

func codeOf(err error) string {
	var a *apierr.Error
	if err != nil && errors.As(err, &a) {
		return a.Code
	}
	return ""
}

func TestRejectPasswordReuse(t *testing.T) {
	hash, err := password.Hash("emailed-one-time-password")
	if err != nil {
		t.Fatal(err)
	}
	if got := codeOf(rejectPasswordReuse(hash, "emailed-one-time-password")); got != "password_reuse" {
		t.Fatalf("reusing the one-time password: code = %q, want password_reuse", got)
	}
	if err := rejectPasswordReuse(hash, "different permanent password"); err != nil {
		t.Fatalf("different password rejected: %v", err)
	}
}

func TestSignupVerifyLoginResetFlow(t *testing.T) {
	svc, mailer, cleanup := newTestAuth(t)
	defer cleanup()
	ctx := context.Background()
	email := "user-" + time.Now().Format("150405.000000") + "@t.local"
	const pw = "correct horse battery"

	// Signup sends a verification email.
	if err := svc.Signup(ctx, email, "User", pw); err != nil {
		t.Fatalf("signup: %v", err)
	}
	verifyToken := mailer.lastToken()
	if verifyToken == "" {
		t.Fatal("no verification token emailed")
	}

	// Unverified login is allowed (decision: login yes, verified gates actions).
	u, err := svc.Authenticate(ctx, email, pw)
	if err != nil {
		t.Fatalf("login before verify: %v", err)
	}
	if u.EmailVerifiedAt.Valid {
		t.Fatal("user should be unverified before verification")
	}

	// Wrong password -> generic invalid_credentials.
	if _, err := svc.Authenticate(ctx, email, "wrong password!!"); codeOf(err) != "invalid_credentials" {
		t.Fatalf("wrong password: want invalid_credentials, got %v", err)
	}
	// Unknown user -> same generic error.
	if _, err := svc.Authenticate(ctx, "nobody@t.local", pw); codeOf(err) != "invalid_credentials" {
		t.Fatalf("unknown user: want invalid_credentials, got %v", err)
	}

	// A reset token must NOT verify an email (purpose binding).
	if err := svc.Signup(ctx, email, "User", pw); err != nil { // existing email -> generic, no error
		t.Fatalf("re-signup existing email should be generic success, got %v", err)
	}

	// Verify with the wrong purpose token fails.
	if err := svc.VerifyEmail(ctx, "not-a-real-token"); codeOf(err) != "invalid_token" {
		t.Fatalf("verify bad token: want invalid_token, got %v", err)
	}
	// Verify with the correct token succeeds.
	if err := svc.VerifyEmail(ctx, verifyToken); err != nil {
		t.Fatalf("verify: %v", err)
	}
	// Single-use: second verify fails.
	if err := svc.VerifyEmail(ctx, verifyToken); codeOf(err) != "invalid_token" {
		t.Fatalf("second verify: want invalid_token, got %v", err)
	}

	// Password reset flow.
	if err := svc.RequestPasswordReset(ctx, email); err != nil {
		t.Fatalf("reset request: %v", err)
	}
	resetToken := mailer.lastToken()
	if resetToken == "" || resetToken == verifyToken {
		t.Fatal("reset token missing or reused verification token")
	}
	// Purpose binding: a reset token cannot be used to verify email.
	if err := svc.VerifyEmail(ctx, resetToken); codeOf(err) != "invalid_token" {
		t.Fatalf("reset token as verify: want invalid_token, got %v", err)
	}
	// Reset request for unknown email is a no-op (no enumeration), no error.
	before := len(mailer.msgs)
	if err := svc.RequestPasswordReset(ctx, "nobody@t.local"); err != nil {
		t.Fatalf("reset unknown email: %v", err)
	}
	if len(mailer.msgs) != before {
		t.Fatal("reset for unknown email should not send mail")
	}

	// Confirm reset with the token; new password works, old does not.
	const newPw = "brand new passphrase"
	if err := svc.ResetPassword(ctx, resetToken, newPw); err != nil {
		t.Fatalf("reset confirm: %v", err)
	}
	if _, err := svc.Authenticate(ctx, email, newPw); err != nil {
		t.Fatalf("login new password: %v", err)
	}
	if _, err := svc.Authenticate(ctx, email, pw); codeOf(err) != "invalid_credentials" {
		t.Fatalf("old password still works after reset: %v", err)
	}
}

func TestAuthenticateRejectsDeactivated(t *testing.T) {
	svc, _, cleanup := newTestAuth(t)
	defer cleanup()
	ctx := context.Background()
	email := "deact-" + time.Now().Format("150405.000000") + "@t.local"
	const pw = "correct horse battery"

	if err := svc.Signup(ctx, email, "D", pw); err != nil {
		t.Fatalf("signup: %v", err)
	}
	u, err := svc.q.GetUserByEmail(ctx, email)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if err := svc.q.SetUserStatus(ctx, sqlc.SetUserStatusParams{ID: u.ID, Status: "deactivated"}); err != nil {
		t.Fatalf("deactivate: %v", err)
	}

	// Correct password + deactivated -> account_deactivated (owner learns it).
	if _, err := svc.Authenticate(ctx, email, pw); codeOf(err) != "account_deactivated" {
		t.Fatalf("deactivated login: want account_deactivated, got %v", err)
	}
	// Wrong password stays generic (no state leak to an attacker).
	if _, err := svc.Authenticate(ctx, email, "totally wrong pw"); codeOf(err) != "invalid_credentials" {
		t.Fatalf("wrong pw on deactivated: want invalid_credentials, got %v", err)
	}
}

func TestSignupRejectsWeakPassword(t *testing.T) {
	svc, _, cleanup := newTestAuth(t)
	defer cleanup()
	if err := svc.Signup(context.Background(), "weak@t.local", "W", "short"); codeOf(err) != "weak_password" {
		t.Fatalf("want weak_password, got %v", err)
	}
}
