package session

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

func TestMFAAuthorityMintIsExplicitAndSSOTimeIsRetained(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t, time.Hour, 24*time.Hour)
	now := time.Now().UTC()
	s.now = func() time.Time { return now }
	user := uuid.New()
	legacy, err := s.CreateWithAuthority(ctx, user, "sso", 2)
	if err != nil || !legacy.MFAVerifiedAt.IsZero() || legacy.MFAAssuranceSource != "" {
		t.Fatal("ordinary login acquired MFA proof", err)
	}
	at := now.Add(-5 * time.Minute)
	parent, err := s.CreateWithMFAAuthority(ctx, user, "sso", 2, at, MFAAssuranceSSO)
	if err != nil || !parent.MFAVerifiedAt.Equal(at) || !parent.CreatedAt.After(at) {
		t.Fatal("verified SSO auth_time lost", err)
	}
	got, _, err := s.GetNoTouch(ctx, parent.ID)
	if err != nil || got.MFAAssuranceSource != MFAAssuranceSSO || !got.MFAVerifiedAt.Equal(at) {
		t.Fatal(got, err)
	}
	for _, tc := range []struct {
		at     time.Time
		source string
		epoch  int64
	}{
		{time.Time{}, MFAAssuranceSSO, 2}, {now.Add(time.Second), MFAAssuranceSSO, 2},
		{now, "password", 2}, {now, MFAAssuranceSSO, 0},
	} {
		if _, err = s.CreateWithMFAAuthority(ctx, user, "sso", tc.epoch, tc.at, tc.source); err == nil {
			t.Fatal("invalid assurance accepted", tc)
		}
	}
}

func TestPromoteMFAKeepsParentBindingsAndBothExpiries(t *testing.T) {
	ctx := context.Background()
	s, mr := newTestStore(t, time.Minute, time.Hour)
	now := time.Now().UTC()
	s.now = func() time.Time { return now }
	parent, err := s.CreateWithAuthority(ctx, uuid.New(), "sso", 4)
	if err != nil {
		t.Fatal(err)
	}
	mr.FastForward(45 * time.Second)
	now = now.Add(45 * time.Second)
	before := mr.TTL(sessKey(parent.ID))
	got, err := s.PromoteMFA(ctx, parent, now, MFAAssuranceLocalTOTP)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != parent.ID || got.AuthMethod != parent.AuthMethod || got.AppAuthEpoch != parent.AppAuthEpoch || !got.CreatedAt.Equal(parent.CreatedAt) || !got.ExpiresAt.Equal(parent.ExpiresAt) {
		t.Fatal("parent authority changed")
	}
	if mr.TTL(sessKey(parent.ID)) != before {
		t.Fatal("promotion extended idle lifetime")
	}
	ids, err := s.Client().SMembers(ctx, userKey(parent.UserID)).Result()
	if err != nil || len(ids) != 1 || ids[0] != parent.ID {
		t.Fatal("new parent created", err)
	}
	mr.FastForward(16 * time.Second)
	if _, err = s.PromoteMFA(ctx, parent, now, MFAAssuranceLocalTOTP); !errors.Is(err, ErrNotFound) {
		t.Fatal("expired parent revived", err)
	}
}

type beforePromotionHook struct{ run func() }

func (h beforePromotionHook) DialHook(next redis.DialHook) redis.DialHook { return next }
func (h beforePromotionHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}
func (h beforePromotionHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if cmd.Name() == "eval" && len(cmd.Args()) > 1 && strings.Contains(cmd.Args()[1].(string), "KEEPTTL") {
			h.run()
		}
		return next(ctx, cmd)
	}
}

func TestPromoteMFALogoutOrConcurrentMutationWinsCAS(t *testing.T) {
	for _, mode := range []string{"logout", "epoch", "no-expiry"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			s, mr := newTestStore(t, time.Minute, time.Hour)
			parent, err := s.CreateWithAuthority(ctx, uuid.New(), "local_password", 1)
			if err != nil {
				t.Fatal(err)
			}
			s.Client().AddHook(beforePromotionHook{run: func() {
				if mode == "logout" {
					mr.Del(sessKey(parent.ID))
					return
				}
				changed := parent
				if mode == "epoch" {
					changed.AppAuthEpoch++
				}
				raw, _ := json.Marshal(changed)
				mr.Set(sessKey(parent.ID), string(raw))
				if mode == "epoch" {
					mr.SetTTL(sessKey(parent.ID), 30*time.Second)
				}
			}})
			if _, err = s.PromoteMFA(ctx, parent, time.Now(), MFAAssuranceLocalRecovery); !errors.Is(err, ErrNotFound) {
				t.Fatalf("%s did not win: %v", mode, err)
			}
			if mode == "logout" && mr.Exists(sessKey(parent.ID)) {
				t.Fatal("logout resurrected")
			}
		})
	}
}

func TestMFAStepUpBudgetIsAtomicSharedAndBounded(t *testing.T) {
	ctx := context.Background()
	s, mr := newTestStore(t, time.Hour, 24*time.Hour)
	user := uuid.New()
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := s.AllowMFAStepUp(ctx, user, uuid.NewString())
			if err != nil {
				t.Error(err)
			}
			if ok {
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 5 {
		t.Fatalf("accepted %d attempts", accepted.Load())
	}
	if ok, err := s.AllowMFAStepUp(ctx, user, "fresh-login"); err != nil || ok {
		t.Fatal("fresh parent reset user budget", ok, err)
	}
	if ok, err := s.AllowMFAStepUp(ctx, uuid.New(), "other-user"); err != nil || !ok {
		t.Fatal("unrelated user throttled", err)
	}
	mr.FastForward(5 * time.Minute)
	if ok, err := s.AllowMFAStepUp(ctx, user, "new-window"); err != nil || !ok {
		t.Fatal("budget did not expire", err)
	}
}
