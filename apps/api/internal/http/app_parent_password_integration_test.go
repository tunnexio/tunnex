package http

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http/httptest"
	"net/url"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/auth"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/password"
	"github.com/tunnexio/tunnex/apps/api/internal/session"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

type passwordParentRedisFault struct{ fail atomic.Bool }

func (h *passwordParentRedisFault) DialHook(next redis.DialHook) redis.DialHook {
	return func(c context.Context, n, a string) (net.Conn, error) { return next(c, n, a) }
}
func (h *passwordParentRedisFault) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(c context.Context, cmd redis.Cmder) error {
		return next(c, cmd)
	}
}
func (h *passwordParentRedisFault) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(c context.Context, cmds []redis.Cmder) error {
		if h.fail.Load() {
			return errors.New("owned replacement parent fault")
		}
		return next(c, cmds)
	}
}

func TestAppParentPasswordReplacementLocalIntegration(t *testing.T) {
	if os.Getenv("APP_ACCESS_LOCAL_INTEGRATION") != "1" {
		t.Skip("owned local DB/Redis qualification")
	}
	secret := os.Getenv("AA0_DB_PASSWORD")
	if secret == "" {
		t.Fatal("owned DB credential missing")
	}
	u := url.URL{Scheme: "postgres", User: url.UserPassword("aa0", secret), Host: "postgres:5432", Path: "/aa0", RawQuery: "sslmode=disable"}
	t.Setenv("TUNNEX_TEST_DATABASE_URL", u.String())
	ctx, pool := testpostgres.New(t)
	q := sqlc.New(pool)
	rdb := redis.NewClient(&redis.Options{Addr: "redis:6379", DB: 0})
	defer rdb.Close()
	fault := &passwordParentRedisFault{}
	rdb.AddHook(fault)
	parents := session.NewWithClient(rdb, time.Hour, time.Hour)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := auth.NewService(pool, nil, "https://console.example.com", parents, logger)
	for _, method := range []string{authctx.AuthLocalPassword, authctx.AuthSSO} {
		t.Run(method, func(t *testing.T) {
			hash, err := password.Hash("initial-password-123")
			if err != nil {
				t.Fatal(err)
			}
			user, err := q.CreateUser(ctx, sqlc.CreateUserParams{Email: method + "@replace.test", Name: "Replacement", PasswordHash: &hash})
			if err != nil {
				t.Fatal(err)
			}
			old, err := parents.CreateWithAuthority(ctx, user.ID, method, user.AppAuthEpoch)
			if err != nil {
				t.Fatal(err)
			}
			defer parents.Delete(ctx, old.ID)
			p := &authctx.Principal{UserID: user.ID, EmailVerified: true, SessionID: old.ID, AuthMethod: method}
			callCtx := authctx.WithPrincipal(ctx, p)
			server := apiServer{auth: svc, sessions: parents, system: q, cookieSecure: true}
			result, err := server.ChangePassword(callCtx, api.ChangePasswordRequestObject{Body: &api.ChangePasswordJSONRequestBody{CurrentPassword: "initial-password-123", NewPassword: "changed-password-456"}})
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			if err = result.VisitChangePasswordResponse(w); err != nil {
				t.Fatal(err)
			}
			if w.Code != 204 {
				t.Fatal("password change did not succeed")
			}
			cookies := w.Result().Cookies()
			if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].Value == old.ID {
				t.Fatal("replacement cookie missing or reused")
			}
			fresh, _, err := parents.GetNoTouch(ctx, cookies[0].Value)
			if err != nil {
				t.Fatal(err)
			}
			defer parents.Delete(ctx, fresh.ID)
			if fresh.AuthMethod != method || fresh.AppAuthEpoch != user.AppAuthEpoch+1 || !fresh.ExpiresAt.Equal(old.ExpiresAt) {
				t.Fatal("replacement changed login method or adopted wrong epoch")
			}
			// A second change commits while Redis writes are unavailable: return its true outcome.
			fault.fail.Store(true)
			_, err = server.ChangePassword(authctx.WithPrincipal(ctx, &authctx.Principal{UserID: user.ID, EmailVerified: true, SessionID: fresh.ID, AuthMethod: method}), api.ChangePasswordRequestObject{Body: &api.ChangePasswordJSONRequestBody{CurrentPassword: "changed-password-456", NewPassword: "final-password-789"}})
			fault.fail.Store(false)
			var ae *apierr.Error
			if !errors.As(err, &ae) || ae.Code != "password_changed_login_required" {
				t.Fatalf("committed-change outcome lost: %v", err)
			}
			current, err := q.GetUserByID(ctx, user.ID)
			if err != nil {
				t.Fatal(err)
			}
			if current.AppAuthEpoch != user.AppAuthEpoch+2 {
				t.Fatal("failed parent mint rolled back or hid committed epoch")
			}
			if _, err = password.Verify("final-password-789", *current.PasswordHash); err != nil {
				t.Fatal("new password did not commit")
			}
			r := httptest.NewRequest("GET", "https://console.example.com/api/v1/auth/me", nil)
			r.AddCookie(cookies[0])
			if SessionAuth(parents, q)(r) != nil {
				t.Fatal("old parent admitted after password commit and failed remint")
			}
		})
	}
}
