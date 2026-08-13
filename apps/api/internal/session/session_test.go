package session

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

func newTestStore(t *testing.T, idle, absolute time.Duration) (*Store, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	return NewWithClient(rdb, idle, absolute), mr
}

func TestCreateGetDelete(t *testing.T) {
	store, _ := newTestStore(t, time.Hour, 24*time.Hour)
	ctx := context.Background()
	uid := uuid.New()

	s1, err := store.Create(ctx, uid, "")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	s2, err := store.Create(ctx, uid, "")
	if err != nil {
		t.Fatalf("create2: %v", err)
	}
	if s1.ID == s2.ID {
		t.Fatal("session ids not unique — fixation risk")
	}

	got, err := store.Get(ctx, s1.ID)
	if err != nil || got.UserID != uid {
		t.Fatalf("get: %v (user %v)", err, got.UserID)
	}

	if err := store.Delete(ctx, s1.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := store.Get(ctx, s1.ID); err != ErrNotFound {
		t.Fatalf("get after delete: want ErrNotFound, got %v", err)
	}
	// s2 survives.
	if _, err := store.Get(ctx, s2.ID); err != nil {
		t.Fatalf("s2 should survive: %v", err)
	}
}

func TestDeleteAllForUser(t *testing.T) {
	store, _ := newTestStore(t, time.Hour, 24*time.Hour)
	ctx := context.Background()
	uid := uuid.New()
	other := uuid.New()

	a, _ := store.Create(ctx, uid, "")
	b, _ := store.Create(ctx, uid, "")
	c, _ := store.Create(ctx, other, "")

	if err := store.DeleteAllForUser(ctx, uid); err != nil {
		t.Fatalf("delete all: %v", err)
	}
	for _, id := range []string{a.ID, b.ID} {
		if _, err := store.Get(ctx, id); err != ErrNotFound {
			t.Fatalf("session %s should be revoked", id)
		}
	}
	if _, err := store.Get(ctx, c.ID); err != nil {
		t.Fatal("other user's session should survive")
	}
}

func TestAbsoluteExpiry(t *testing.T) {
	store, _ := newTestStore(t, time.Hour, 30*time.Minute)
	ctx := context.Background()
	cur := time.Now()
	store.now = func() time.Time { return cur } // controllable clock

	s, _ := store.Create(ctx, uuid.New(), "") // ExpiresAt = cur + 30m
	cur = cur.Add(31 * time.Minute)           // advance past the absolute lifetime
	if _, err := store.Get(ctx, s.ID); err != ErrNotFound {
		t.Fatalf("expired session: want ErrNotFound, got %v", err)
	}
}

func TestCookieFlagsContract(t *testing.T) {
	rec := httptest.NewRecorder()
	SetCookie(rec, Session{ID: "abc", ExpiresAt: time.Now().Add(time.Hour)}, true)
	c := rec.Result().Cookies()[0]
	if c.Name != CookieName {
		t.Fatalf("name = %q", c.Name)
	}
	if !c.HttpOnly {
		t.Error("cookie must be HttpOnly")
	}
	if !c.Secure {
		t.Error("cookie must be Secure when secure=true")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Error("cookie must be SameSite=Lax")
	}
	if c.Path != "/" {
		t.Errorf("cookie Path = %q, want /", c.Path)
	}
}
