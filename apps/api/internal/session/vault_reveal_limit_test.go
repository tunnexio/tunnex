package session

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// VAULT-UX-1 V4: a per-person, per-organization reveal budget.
func TestVaultRevealBudget(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	s := NewWithClient(rdb, time.Hour, 24*time.Hour)
	ctx := context.Background()
	org, user, other := uuid.New(), uuid.New(), uuid.New()
	for i := 0; i < VaultRevealLimit; i++ {
		if ok, err := s.VaultRevealAllowed(ctx, org, user); err != nil || !ok {
			t.Fatalf("reveal %d refused: %v", i+1, err)
		}
	}
	if ok, err := s.VaultRevealAllowed(ctx, org, user); err != nil || ok {
		t.Fatal("reveal past the budget was allowed")
	}
	if ok, _ := s.VaultRevealAllowed(ctx, org, other); !ok {
		t.Fatal("another person's budget was charged")
	}
	if ok, _ := s.VaultRevealAllowed(ctx, uuid.New(), user); !ok {
		t.Fatal("another organization's budget was charged")
	}
	mr.FastForward(VaultRevealWindow + time.Second)
	if ok, _ := s.VaultRevealAllowed(ctx, org, user); !ok {
		t.Fatal("budget did not reset after the window")
	}
	if _, err := s.VaultRevealAllowed(ctx, uuid.Nil, user); err == nil {
		t.Fatal("nil organization accepted")
	}
}
