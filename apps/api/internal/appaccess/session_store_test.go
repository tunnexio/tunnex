package appaccess

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestAppSessionStreamAdmissionUsesCapturedAuthority(t *testing.T) {
	s, _, r := appStoreFixture(t)
	ctx := context.Background()
	code, raw := appStoreCode(t, s, r)
	token, err := s.Redeem(ctx, code, raw, r)
	if err != nil {
		t.Fatal(err)
	}
	captured, _, err := s.Peek(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	changed := captured
	changed.InstallationGeneration = uuid.New()
	encoded, _ := json.Marshal(changed)
	if err := s.rdb.Set(ctx, appSessionKey(token), encoded, time.Minute).Err(); err != nil {
		t.Fatal(err)
	}
	proxy := AuthenticatedProxy{CredentialID: uuid.New(), CredentialVersion: 1}
	if _, err := s.createStream(ctx, token, proxy, r.Binding, s.now().Add(time.Second), captured); !errors.Is(err, ErrAppSessionMissing) {
		t.Fatalf("changed installation admitted captured authority: %v", err)
	}
}

func TestAppSessionLegacyGenerationCannotMint(t *testing.T) {
	s, _, r := appStoreFixture(t)
	r.InstallationGeneration = uuid.Nil
	if err := s.RegisterPending(context.Background(), PendingLaunch{Binding: r.Binding, ExpiresAt: s.now().Add(time.Minute)}); !errors.Is(err, ErrAppSessionMissing) {
		t.Fatalf("legacy pending accepted: %v", err)
	}
}

func appStoreFixture(t *testing.T) (*AppSessionStore, *miniredis.Miniredis, AppSessionRecord) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1})
	t.Cleanup(func() { _ = rdb.Close() })
	store := NewAppSessionStore(rdb)
	now := time.Now()
	record := AppSessionRecord{InstallationGeneration: uuid.New(), UserID: uuid.New(), Binding: RouteBinding{OrgID: uuid.New(), AppID: uuid.New(), GatewayID: uuid.New(), Generation: uuid.New(), Revision: 1, AuthorityVersion: 1, Digest: strings.Repeat("a", 64), Hostname: "a.apps.example.net", Purpose: "browser_proxy"}, ParentHash: strings.Repeat("b", 64), ParentSealed: "sealed-only", ParentEpoch: 1, AuthMethod: "local_password", CreatedAt: now, ExpiresAt: now.Add(time.Hour), IdleMillis: 60000}
	return store, mr, record
}
func appStoreCode(t *testing.T, s *AppSessionStore, r AppSessionRecord) (string, string) {
	t.Helper()
	ctx := context.Background()
	nonce, _ := randomAppSecret("")
	pending := PendingLaunch{InstallationGeneration: r.InstallationGeneration, Binding: r.Binding, NonceHash: secretHash(nonce), RelativeTarget: "/a?b=c", ProxyID: uuid.New(), ProxyVersion: 1, ExpiresAt: s.now().Add(10 * time.Minute)}
	if e := s.RegisterPending(ctx, pending); e != nil {
		t.Fatal(e)
	}
	_, raw, e := s.LoadPending(ctx, pending.NonceHash)
	if e != nil {
		t.Fatal(e)
	}
	code, e := s.CreateLaunch(ctx, LaunchRecord{AppSessionRecord: r, NonceHash: pending.NonceHash, RelativeTarget: pending.RelativeTarget, CodeExpiresAt: s.now().Add(time.Minute)}, raw)
	if e != nil {
		t.Fatal(e)
	}
	_, launchRaw, e := s.LoadLaunch(ctx, code)
	if e != nil {
		t.Fatal(e)
	}
	return code, launchRaw
}
func TestAppSessionAtomicPendingAndCodeRedemption(t *testing.T) {
	s, mr, r := appStoreFixture(t)
	ctx := context.Background()
	nonce, _ := randomAppSecret("")
	pending := PendingLaunch{InstallationGeneration: r.InstallationGeneration, Binding: r.Binding, NonceHash: secretHash(nonce), RelativeTarget: "/", ProxyID: uuid.New(), ProxyVersion: 1, ExpiresAt: s.now().Add(10 * time.Minute)}
	if e := s.RegisterPending(ctx, pending); e != nil {
		t.Fatal(e)
	}
	_, raw, e := s.LoadPending(ctx, pending.NonceHash)
	if e != nil {
		t.Fatal(e)
	}
	launch := LaunchRecord{AppSessionRecord: r, NonceHash: pending.NonceHash, RelativeTarget: "/", CodeExpiresAt: s.now().Add(time.Minute)}
	if _, e = s.CreateLaunch(ctx, launch, raw+" "); !errors.Is(e, ErrAppSessionMissing) {
		t.Fatalf("modified pending accepted: %v", e)
	}
	code, e := s.CreateLaunch(ctx, launch, raw)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.CreateLaunch(ctx, launch, raw); !errors.Is(e, ErrAppSessionMissing) {
		t.Fatalf("pending replay accepted: %v", e)
	}
	_, launchRaw, e := s.LoadLaunch(ctx, code)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Redeem(ctx, code, launchRaw+" ", r); !errors.Is(e, ErrAppSessionMissing) {
		t.Fatalf("modified code accepted: %v", e)
	}
	var successes atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, e := s.Redeem(ctx, code, launchRaw, r); e == nil {
				successes.Add(1)
			} else if !errors.Is(e, ErrAppSessionMissing) {
				t.Errorf("redeem: %v", e)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("redeemed %d times", successes.Load())
	}
	for _, key := range mr.Keys() {
		if strings.Contains(key, code) || strings.Contains(key, nonce) {
			t.Fatal("plaintext browser secret in key")
		}
		if raw, e := mr.Get(key); e == nil && (strings.Contains(raw, code) || strings.Contains(raw, nonce)) {
			t.Fatal("plaintext browser secret in record")
		}
	}
}
func TestAppSessionNoTouchForegroundRevocationAndExpiry(t *testing.T) {
	s, mr, r := appStoreFixture(t)
	ctx := context.Background()
	code, raw := appStoreCode(t, s, r)
	token, e := s.Redeem(ctx, code, raw, r)
	if e != nil {
		t.Fatal(e)
	}
	record, _, e := s.Peek(ctx, token)
	if e != nil {
		t.Fatal(e)
	}
	mr.FastForward(20 * time.Second)
	before := mr.TTL(appSessionKey(token))
	if _, _, e = s.Peek(ctx, token); e != nil {
		t.Fatal(e)
	}
	if mr.TTL(appSessionKey(token)) != before {
		t.Fatal("peek refreshed idle")
	}
	if _, e = s.List(ctx, r.Binding.OrgID, r.UserID, 100, 0, r.InstallationGeneration); e != nil {
		t.Fatal(e)
	}
	if mr.TTL(appSessionKey(token)) != before {
		t.Fatal("list refreshed idle")
	}
	if _, e = s.TouchForeground(ctx, token, record); e != nil {
		t.Fatal(e)
	}
	if got := mr.TTL(appSessionKey(token)); got <= before {
		t.Fatalf("foreground did not refresh idle: %v", got)
	}
	if e = s.RevokeOwn(ctx, r.Binding.OrgID, uuid.New(), record.ID); !errors.Is(e, ErrAppSessionMissing) {
		t.Fatal("foreign user revoked")
	}
	if e = s.RevokeOwn(ctx, r.Binding.OrgID, r.UserID, record.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = s.TouchForeground(ctx, token, record); !errors.Is(e, ErrAppSessionMissing) {
		t.Fatal("touch resurrected revoked session")
	}
	code, raw = appStoreCode(t, s, r)
	token, e = s.Redeem(ctx, code, raw, r)
	if e != nil {
		t.Fatal(e)
	}
	mr.FastForward(time.Minute)
	if _, _, e = s.Peek(ctx, token); !errors.Is(e, ErrAppSessionMissing) {
		t.Fatal("expired session accepted")
	}
	if got, _ := s.List(ctx, r.Binding.OrgID, r.UserID, 100, 0, r.InstallationGeneration); len(got) != 0 {
		t.Fatal("expired sessions listed")
	}
}
func TestAppSessionStreamBoundAndRenewNoTouch(t *testing.T) {
	s, mr, r := appStoreFixture(t)
	ctx := context.Background()
	code, raw := appStoreCode(t, s, r)
	token, e := s.Redeem(ctx, code, raw, r)
	if e != nil {
		t.Fatal(e)
	}
	proxy := AuthenticatedProxy{CredentialID: uuid.New(), CredentialVersion: 1}
	var first uuid.UUID
	for i := 0; i < 16; i++ {
		id, e := s.createStream(ctx, token, proxy, r.Binding, s.now().Add(4*time.Second))
		if e != nil {
			t.Fatal(e)
		}
		if i == 0 {
			first = id
		}
	}
	before := mr.TTL(appSessionKey(token))
	if _, e = s.createStream(ctx, token, proxy, r.Binding, s.now().Add(4*time.Second)); !errors.Is(e, ErrAppSessionCapacity) {
		t.Fatalf("17th stream accepted: %v", e)
	}
	stream, expected, e := s.loadStream(ctx, first)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.renewStream(ctx, first, expected, stream, s.now().Add(4*time.Second)); e != nil {
		t.Fatal(e)
	}
	if mr.TTL(appSessionKey(token)) != before {
		t.Fatal("lease renewed idle")
	}
	mr.FastForward(4 * time.Second)
	if e = s.renewStream(ctx, first, expected, stream, s.now().Add(4*time.Second)); !errors.Is(e, ErrAppSessionMissing) {
		t.Fatal("expired stream resurrected")
	}
}
func TestAppSessionRevocationPreventsStreamAdmissionAndRenewal(t *testing.T) {
	s, _, r := appStoreFixture(t)
	ctx := context.Background()
	code, raw := appStoreCode(t, s, r)
	token, e := s.Redeem(ctx, code, raw, r)
	if e != nil {
		t.Fatal(e)
	}
	record, _, e := s.Peek(ctx, token)
	if e != nil {
		t.Fatal(e)
	}
	proxy := AuthenticatedProxy{CredentialID: uuid.New(), CredentialVersion: 1}
	id, e := s.createStream(ctx, token, proxy, r.Binding, s.now().Add(4*time.Second))
	if e != nil {
		t.Fatal(e)
	}
	stream, expected, e := s.loadStream(ctx, id)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.RevokeOwn(ctx, r.Binding.OrgID, r.UserID, record.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = s.createStream(ctx, token, proxy, r.Binding, s.now().Add(4*time.Second)); !errors.Is(e, ErrAppSessionMissing) {
		t.Fatal("revoked app session admitted stream")
	}
	if e = s.renewStream(ctx, id, expected, stream, s.now().Add(4*time.Second)); !errors.Is(e, ErrAppSessionMissing) {
		t.Fatal("revoked app session renewed stream")
	}
}

func TestAppSessionPendingTTLAndRedisOutage(t *testing.T) {
	s, mr, r := appStoreFixture(t)
	ctx := context.Background()
	nonce, _ := randomAppSecret("")
	pending := PendingLaunch{InstallationGeneration: r.InstallationGeneration, Binding: r.Binding, NonceHash: secretHash(nonce), RelativeTarget: "/", ProxyID: uuid.New(), ProxyVersion: 1, ExpiresAt: s.now().Add(10 * time.Minute)}
	if e := s.RegisterPending(ctx, pending); e != nil {
		t.Fatal(e)
	}
	mr.FastForward(10 * time.Minute)
	if _, _, e := s.LoadPending(ctx, pending.NonceHash); !errors.Is(e, ErrAppSessionMissing) {
		t.Fatal("expired pending accepted")
	}
	mr.Close()
	if _, _, e := s.LoadPending(ctx, pending.NonceHash); e == nil || errors.Is(e, ErrAppSessionMissing) {
		t.Fatal("outage presented as absence")
	}
}
