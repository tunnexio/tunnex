package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/password"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
	"golang.org/x/crypto/argon2"
)

type failedAppParentCleanup struct{ called bool }

func (f *failedAppParentCleanup) DeleteAllForUser(context.Context, uuid.UUID) error {
	f.called = true
	return errors.New("injected Redis cleanup failure")
}

type pausedAppRehash struct {
	sqlc.DBTX
	reached chan struct{}
	resume  chan struct{}
}

func (p *pausedAppRehash) Exec(ctx context.Context, query string, args ...interface{}) (pgconn.CommandTag, error) {
	if strings.Contains(query, "-- name: CASUserPasswordRehash") {
		close(p.reached)
		select {
		case <-p.resume:
		case <-ctx.Done():
			return pgconn.CommandTag{}, ctx.Err()
		}
	}
	return p.DBTX.Exec(ctx, query, args...)
}

func TestAppParentPasswordResetRehashRace(t *testing.T) {
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
	const oldPassword = "old-login-password-123"
	const newPassword = "new-reset-password-456"
	salt := []byte("owned-test-salt!!")
	key := argon2.IDKey([]byte(oldPassword), salt, 1, 8, 1, 32)
	oldHash := fmt.Sprintf("$argon2id$v=19$m=8,t=1,p=1$%s$%s", base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
	user, err := q.CreateUser(ctx, sqlc.CreateUserParams{Email: "rehash-race@app.test", Name: "Race", PasswordHash: &oldHash})
	if err != nil {
		t.Fatal(err)
	}
	raw, hash, err := newToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = q.CreateAuthToken(ctx, sqlc.CreateAuthTokenParams{UserID: user.ID, Purpose: purposeReset, TokenHash: hash, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	cleanup := &failedAppParentCleanup{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	reset := NewService(pool, &captureMailer{}, "https://console.example.com", cleanup, logger)
	paused := &pausedAppRehash{DBTX: pool, reached: make(chan struct{}), resume: make(chan struct{})}
	login := NewService(pool, &captureMailer{}, "https://console.example.com", nil, logger)
	login.q = sqlc.New(paused)
	result := make(chan error, 1)
	go func() { _, e := login.Authenticate(ctx, user.Email, oldPassword); result <- e }()
	select {
	case <-paused.reached:
	case <-ctx.Done():
		t.Fatal("login never reached rehash boundary")
	}
	defer func() {
		select {
		case <-paused.resume:
		default:
			close(paused.resume)
		}
	}()
	if err = reset.ResetPassword(ctx, raw, newPassword); err != nil {
		t.Fatal(err)
	}
	if !cleanup.called {
		t.Fatal("Redis cleanup fault was not exercised")
	}
	current, err := q.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.AppAuthEpoch != user.AppAuthEpoch+1 {
		t.Fatal("reset did not durably increment captured authority")
	}
	close(paused.resume)
	if e := <-result; codeOf(e) != "invalid_credentials" {
		t.Fatalf("stale verified login was admitted: %v", e)
	}
	current, err = q.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, e := password.Verify(newPassword, *current.PasswordHash); e != nil {
		t.Fatal("late login overwrote reset password")
	}
	if _, e := password.Verify(oldPassword, *current.PasswordHash); e == nil {
		t.Fatal("old password survived reset")
	}
	// The same previously verified snapshot cannot race a self-password change.
	replacement, err := password.Hash("another-permanent-password")
	if err != nil {
		t.Fatal(err)
	}
	if _, e := q.ChangePasswordCASAndBumpAppAuthEpoch(ctx, sqlc.ChangePasswordCASAndBumpAppAuthEpochParams{UserID: user.ID, ExpectedHash: &oldHash, ExpectedEpoch: user.AppAuthEpoch, NewHash: &replacement}); e == nil {
		t.Fatal("stale password-change snapshot replaced reset credentials")
	}
}
