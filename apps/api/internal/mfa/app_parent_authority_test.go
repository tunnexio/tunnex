package mfa

import (
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

func TestAppParentMFAEpochBoundaries(t *testing.T) {
	if os.Getenv("APP_ACCESS_LOCAL_INTEGRATION") == "1" {
		pw := os.Getenv("AA0_DB_PASSWORD")
		if pw == "" {
			t.Fatal("owned fixture password required")
		}
		u := url.URL{Scheme: "postgres", User: url.UserPassword("aa0", pw), Host: "postgres:5432", Path: "/aa0", RawQuery: "sslmode=disable"}
		t.Setenv("TUNNEX_TEST_DATABASE_URL", u.String())
	}
	ctx, pool := testpostgres.New(t)
	q := sqlc.New(pool)
	user, e := q.CreateUser(ctx, sqlc.CreateUserParams{Email: "mfa-epoch@app.test", Name: "MFA"})
	if e != nil {
		t.Fatal(e)
	}
	svc, clock := newSvc(t, pool)
	_, recovery := enroll(t, svc, clock, user.ID)
	pending, _, e := svc.CreateChallengeWithAuthority(ctx, user.ID, user.AppAuthEpoch)
	if e != nil {
		t.Fatal(e)
	}
	updated, e := q.SetUserPasswordAndBumpAppAuthEpoch(ctx, sqlc.SetUserPasswordAndBumpAppAuthEpochParams{UserID: user.ID})
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = svc.CreateChallengeWithAuthority(ctx, user.ID, user.AppAuthEpoch); code(e) != "mfa_challenge_invalid" {
		t.Fatalf("stale verified snapshot acquired a new challenge: %v", e)
	}
	if _, _, e = svc.VerifyChallenge(ctx, pending, recovery[0]); code(e) != "mfa_challenge_invalid" {
		t.Fatalf("pre-reset challenge survived: %v", e)
	}
	n, e := q.CountUnusedRecoveryCodes(ctx, user.ID)
	if e != nil || n != int64(len(recovery)) {
		t.Fatal("epoch refusal consumed a recovery factor")
	}
	// A historical pending challenge has no proven password-authority snapshot.
	legacy, hash, e := newToken()
	if e != nil {
		t.Fatal(e)
	}
	if e = q.CreateMfaChallenge(ctx, sqlc.CreateMfaChallengeParams{UserID: user.ID, TokenHash: hash, ExpiresAt: time.Now().Add(time.Minute)}); e != nil {
		t.Fatal(e)
	}
	if _, _, e = svc.VerifyChallenge(ctx, legacy, recovery[0]); code(e) != "mfa_challenge_invalid" {
		t.Fatalf("legacy challenge inferred current authority: %v", e)
	}
	fresh, _, e := svc.CreateChallengeWithAuthority(ctx, user.ID, updated.AppAuthEpoch)
	if e != nil {
		t.Fatal(e)
	}
	got, viaRecovery, e := svc.VerifyChallenge(ctx, fresh, recovery[0])
	if e != nil || !viaRecovery || got.AppAuthEpoch != updated.AppAuthEpoch {
		t.Fatalf("fresh verified challenge failed: %v", e)
	}
}
