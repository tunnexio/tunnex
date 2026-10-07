package http

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/beam"
	"github.com/tunnexio/tunnex/apps/api/internal/session"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

func TestBeamRoomScreenshotHTTPUsesCurrentAuthorityAndNoStore(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	org, owner, reviewer, share, feedback := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, e := pool.Exec(ctx, q, args...); e != nil {
			t.Fatal(e)
		}
	}
	exec(`INSERT INTO organizations(id,name,slug)VALUES($1,'Screenshot fixture',$2)`, org, org.String())
	for _, user := range []uuid.UUID{owner, reviewer} {
		exec(`INSERT INTO users(id,email,name,email_verified_at)VALUES($1,$2,'Screenshot user',now())`, user, user.String()+"@beam.test")
		exec(`INSERT INTO memberships(org_id,user_id,role)VALUES($1,$2,'member')`, org, user)
	}
	target, _ := json.Marshal(beam.Target{Protocol: "http", Address: "127.0.0.1", Port: 3000})
	exec(`INSERT INTO beam_shares(id,org_id,publisher_id,name,hostname,target,digest,idempotency_key,request_digest,state,expires_at)VALUES($1,$2,$3,'Historical app','p-stopped.beam.test',$4,$5,$6,$5,'stopped',now()+interval '1 hour')`, share, org, owner, target, strings.Repeat("a", 64), uuid.New())
	shot := []byte("owned sanitized screenshot bytes")
	exec(`INSERT INTO beam_feedback(id,org_id,share_id,author_id,body,status,screenshot)VALUES($1,$2,$3,$4,'Review','comment',$5)`, feedback, org, share, owner, shot)
	redisFixture := miniredis.RunT(t)
	store := session.NewWithClient(redis.NewClient(&redis.Options{Addr: redisFixture.Addr()}), time.Hour, time.Hour)
	browser, e := store.CreateWithAuthority(ctx, owner, "local_password", 1)
	if e != nil {
		t.Fatal(e)
	}
	principal := &authctx.Principal{UserID: owner, SessionID: browser.ID, AuthMethod: authctx.AuthLocalPassword, EmailVerified: true, Roles: map[uuid.UUID]string{org: "member"}}
	h, e := NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{Beam: beam.New(pool, beam.Config{}, nil, store), AuthFn: func(*http.Request) *authctx.Principal { return principal }})
	if e != nil {
		t.Fatal(e)
	}
	path := "/api/v1/organizations/" + org.String() + "/beam/shares/" + share.String() + "/feedback/" + feedback.String() + "/screenshot"
	get := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec
	}
	rec := get()
	if rec.Code != 200 || rec.Body.String() != string(shot) || rec.Header().Get("Content-Type") != "image/png" || rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("Image response incorrect", rec.Code, rec.Header(), rec.Body.String())
	}
	if e = store.Delete(ctx, browser.ID); e != nil {
		t.Fatal(e)
	}
	rec = get()
	if rec.Code != 403 || strings.Contains(rec.Body.String(), string(shot)) {
		t.Fatal("Logged-out parent read bytes", rec.Code)
	}
	outsider, e := store.CreateWithAuthority(ctx, reviewer, "local_password", 1)
	if e != nil {
		t.Fatal(e)
	}
	principal.UserID = reviewer
	principal.SessionID = outsider.ID
	rec = get()
	if rec.Code != 404 || strings.Contains(rec.Body.String(), string(shot)) {
		t.Fatal("Reviewer read stopped screenshot", rec.Code, rec.Body.String())
	}
	principal = nil
	rec = get()
	if rec.Code != 401 {
		t.Fatal("Unauthenticated screenshot accessible", rec.Code)
	}
}
