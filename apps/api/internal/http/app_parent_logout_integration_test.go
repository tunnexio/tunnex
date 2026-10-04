package http

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/session"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

type logoutRedisFault struct {
	cleanup, outage atomic.Bool
	beforeDelete    func()
}

func (h *logoutRedisFault) DialHook(next redis.DialHook) redis.DialHook {
	return func(c context.Context, n, a string) (net.Conn, error) { return next(c, n, a) }
}
func (h *logoutRedisFault) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(c context.Context, cmd redis.Cmder) error {
		if cmd.Name() == "del" && h.cleanup.Load() && h.beforeDelete != nil {
			h.beforeDelete()
		}
		if h.outage.Load() || (h.cleanup.Load() && cmd.Name() == "del") {
			return errors.New("isolated logout Redis fault")
		}
		return next(c, cmd)
	}
}
func (h *logoutRedisFault) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

func TestAppParentLogoutLocalIntegration(t *testing.T) {
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
	uid := uuid.New()
	if _, e := pool.Exec(ctx, "INSERT INTO users(id,email,name)VALUES($1,$2,'Logout')", uid, uid.String()+"@fixture.test"); e != nil {
		t.Fatal(e)
	}
	rdb := redis.NewClient(&redis.Options{Addr: "redis:6379", DB: 0})
	defer rdb.Close()
	fault := &logoutRedisFault{}
	rdb.AddHook(fault)
	sessions := session.NewWithClient(rdb, time.Hour, time.Hour)
	parent, e := sessions.CreateWithAuthority(ctx, uid, "sso", 1)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { fault.cleanup.Store(false); fault.outage.Store(false); _ = sessions.Delete(ctx, parent.ID) }()
	handler, e := NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{Sessions: sessions, System: q})
	if e != nil {
		t.Fatal(e)
	}
	call := func(cookie string, want int, clear bool) {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, "http://localhost/api/v1/auth/logout", nil)
		r.Header.Set("Cookie", cookie)
		r.Header.Set("X-Tunnex-CSRF", "1")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("logout status%d wanted%d body%s", w.Code, want, w.Body.String())
		}
		if (w.Header().Get("Set-Cookie") != "") != clear {
			t.Fatal("cookie clearance contradicts durable outcome")
		}
	}
	hash := sha256.Sum256([]byte(parent.ID))
	var durableBeforeDelete atomic.Bool
	fault.beforeDelete = func() {
		denied, err := q.IsAppParentLogoutRevoked(ctx, hash[:])
		durableBeforeDelete.Store(err == nil && denied)
	}
	missing, e := sessions.CreateWithAuthority(ctx, uid, "sso", 1)
	if e != nil {
		t.Fatal(e)
	}
	if e = sessions.Delete(ctx, missing.ID); e != nil {
		t.Fatal(e)
	}
	call(session.CookieName+"="+missing.ID, http.StatusServiceUnavailable, false)
	snapshotMissing, e := json.Marshal(missing)
	if e != nil {
		t.Fatal(e)
	}
	if e = rdb.Set(ctx, "sess:"+missing.ID, snapshotMissing, time.Hour).Err(); e != nil {
		t.Fatal(e)
	}
	defer func() { fault.cleanup.Store(false); fault.outage.Store(false); _ = sessions.Delete(ctx, missing.ID) }()
	nativeAuth := SessionAuth(sessions, q)
	authenticated := func(id string) bool {
		r := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/auth/me", nil)
		r.AddCookie(&http.Cookie{Name: session.CookieName, Value: id})
		return nativeAuth(r) != nil
	}
	if !authenticated(parent.ID) {
		t.Fatal("current stamped parent unavailable")
	}
	legacy, e := sessions.Create(ctx, uid, "sso")
	if e != nil {
		t.Fatal(e)
	}
	defer func() { fault.cleanup.Store(false); fault.outage.Store(false); _ = sessions.Delete(ctx, legacy.ID) }()
	if !authenticated(legacy.ID) {
		t.Fatal("epoch1 legacy native compatibility lost")
	}
	mismatched, e := sessions.CreateWithAuthority(ctx, uid, "sso", 2)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { fault.cleanup.Store(false); fault.outage.Store(false); _ = sessions.Delete(ctx, mismatched.ID) }()
	if authenticated(mismatched.ID) {
		t.Fatal("stamped epoch mismatch authenticated")
	}
	fault.cleanup.Store(true)
	call(session.CookieName+"="+parent.ID, http.StatusNoContent, true)
	if !durableBeforeDelete.Load() {
		t.Fatal("cleanup attempted before durable logout commit")
	}
	revoked, e := q.IsAppParentLogoutRevoked(ctx, hash[:])
	if e != nil || !revoked {
		t.Fatal("logout failed durable denial", e)
	}
	retained, _, e := sessions.GetNoTouch(ctx, parent.ID)
	if e != nil || retained.ID != parent.ID {
		t.Fatal("cleanup fault did not retain parent", e)
	}
	// Restore a retained snapshot under the exact parent key, modeling stale Redis recovery.
	snapshot, e := json.Marshal(retained)
	if e != nil {
		t.Fatal(e)
	}
	if e = rdb.Set(ctx, "sess:"+parent.ID, snapshot, time.Hour).Err(); e != nil {
		t.Fatal(e)
	}
	// A restored/retained Redis record cannot undo exact durable token denial.
	if authenticated(parent.ID) {
		t.Fatal("restored durably revoked parent authenticated")
	}
	revoked, e = q.IsAppParentLogoutRevoked(ctx, hash[:])
	if e != nil || !revoked {
		t.Fatal("retained token resurrected", e)
	}
	call(session.CookieName+"=; "+session.CookieName+"="+parent.ID, http.StatusBadRequest, false)
	call(session.CookieName+"="+parent.ID+"; "+session.CookieName+"="+parent.ID, http.StatusBadRequest, false)
	fault.outage.Store(true)
	call(session.CookieName+"="+parent.ID, http.StatusNoContent, true) // Durable denial permits safe retry despite Redis outage.
	call(session.CookieName+"=unknown", http.StatusServiceUnavailable, false)
	fault.outage.Store(false)
	if _, e = pool.Exec(ctx, "UPDATE users SET app_auth_epoch=2 WHERE id=$1", uid); e != nil {
		t.Fatal(e)
	}
	if authenticated(legacy.ID) {
		t.Fatal("legacy parent resumed after epoch bump")
	}
	if !authenticated(mismatched.ID) {
		t.Fatal("current epoch parent refused")
	}
	// A failing durable database boundary must not report successful logout or clear its cookie.
	pool.Close()
	call(session.CookieName+"="+parent.ID, http.StatusServiceUnavailable, false)
}
