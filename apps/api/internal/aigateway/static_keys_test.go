package aigateway

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

func TestStaticKeyFormat(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 64; i++ {
		raw, hash, hint, err := newStaticKey()
		if err != nil || len(raw) != 56 || !strings.HasPrefix(raw, "tnx_sk_") || len(hash) != 32 || hint != raw[52:] || !validStaticKeyFormat(raw) {
			t.Fatalf("bad key %d: len=%d hint=%q err=%v", i, len(raw), hint, err)
		}
		if strings.ContainsAny(raw[7:], "-_") || seen[raw] {
			t.Fatal("key body must be unique base62")
		}
		seen[raw] = true
	}
	raw, _, _, _ := newStaticKey()
	flip := []byte(raw)
	if flip[20] == 'a' {
		flip[20] = 'b'
	} else {
		flip[20] = 'a'
	}
	for _, bad := range []string{"", "tnx_sk_", raw[:55], raw + "A", "tnx_wai_" + raw[7:], string(flip), strings.Replace(raw, raw[10:11], "-", 1)} {
		if validStaticKeyFormat(bad) {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestStaticKeyCIDRs(t *testing.T) {
	for _, c := range []struct {
		scope string
		in    []string
		ok    bool
	}{
		{"internal", []string{"10.20.0.0/16", "192.168.1.0/24"}, true},
		{"internal", []string{"10.20.0.1/16"}, false},             // not canonical
		{"internal", []string{"8.8.8.0/24"}, false},               // public
		{"internal", []string{"0.0.0.0/0"}, false},                // spans everything
		{"internal", []string{"fd00::/8"}, false},                 // IPv4 only
		{"internal", []string{"10.0.0.0/8", "10.0.0.0/8"}, false}, // duplicate
		{"public", []string{"8.8.8.0/24", "2001:4860::/32"}, true},
		{"public", []string{"0.0.0.0/0"}, false},
		{"public", []string{"::/0"}, false},
		{"public", []string{"10.0.0.0/8"}, false},
		{"public", []string{"8.0.0.0/4"}, false}, // overlaps 10/8
		{"public", []string{"100.64.0.0/10"}, false},
		{"public", []string{"203.0.113.0/24"}, false},
		{"public", []string{"fc00::/7"}, false},
		{"other", []string{}, true},
	} {
		_, ok := canonicalStaticKeyCIDRs(c.in, c.scope)
		if c.scope == "other" {
			continue
		}
		if ok != c.ok {
			t.Errorf("%s %v: ok=%v want %v", c.scope, c.in, ok, c.ok)
		}
	}
	if _, ok := canonicalStaticKeyCIDRs(make([]string, 33), "internal"); ok {
		t.Fatal("33 ranges accepted")
	}
	now := time.Now()
	if validStaticKeyExpiry(now, now) || validStaticKeyExpiry(now.Add(91*24*time.Hour), now) || !validStaticKeyExpiry(now.Add(90*24*time.Hour), now) || !validStaticKeyExpiry(now.Add(time.Minute), now) {
		t.Fatal("expiry bounds")
	}
}

func TestStaticKeyIngressZeroValueRefused(t *testing.T) {
	s := &StaticKeys{}
	if _, err := s.Authorize(context.Background(), "tnx_sk_x", "m", StaticKeyIngress{}); err == nil {
		t.Fatal("zero ingress accepted")
	}
}

// staticUsageEngine reports cost per engine key id so per-key and
// per-workload thresholds can be told apart.
type staticUsageEngine struct {
	*providerFixtureEngine
	mu    sync.Mutex
	cost  map[string]float64
	calls [][]string
}

func (e *staticUsageEngine) Usage(_ context.Context, ids []string, _, _ time.Time) (Usage, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(ids) > 64 {
		return Usage{}, errors.New("engine refuses more than 64 ids")
	}
	e.calls = append(e.calls, append([]string(nil), ids...))
	var u Usage
	for _, id := range ids {
		u.TotalCost += e.cost[id]
	}
	return u, nil
}

type fakeLimiter struct {
	mu     sync.Mutex
	counts map[string]int
	err    error
}

func (l *fakeLimiter) Allow(_ context.Context, key string, limit int, _ time.Duration) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return false, l.err
	}
	l.counts[key]++
	return l.counts[key] <= limit, nil
}

type staticKeyFixture struct {
	*workloadLifecycleFixture
	keys    *StaticKeys
	engine  *staticUsageEngine
	limiter *fakeLimiter
	node    uuid.UUID
	ep      uuid.UUID
}

func newStaticKeyFixture(t *testing.T, ctx context.Context, f *workloadLifecycleFixture) *staticKeyFixture {
	t.Helper()
	engine := &staticUsageEngine{providerFixtureEngine: f.provider, cost: map[string]float64{}}
	f.policies.engine = engine
	limiter := &fakeLimiter{counts: map[string]int{}}
	s := &staticKeyFixture{workloadLifecycleFixture: f, keys: NewStaticKeys(f.workloads, limiter), engine: engine, limiter: limiter}
	if err := f.pool.QueryRow(ctx, `SELECT id FROM nodes WHERE org_id=$1 LIMIT 1`, f.org).Scan(&s.node); err != nil {
		t.Fatal(err)
	}
	s.ep = uuid.New()
	f.exec(`INSERT INTO ai_internal_endpoints(id,org_id,node_id,enabled,listen_addresses,source_cidrs) VALUES($1,$2,$3,true,'{10.9.0.1}','{10.20.0.0/16}')`, s.ep, f.org, s.node)
	return s
}

func (s *staticKeyFixture) create(scope string, mutate func(*api.AIWorkloadStaticKeyInput)) api.AIWorkloadStaticKeySecret {
	s.t.Helper()
	in := api.AIWorkloadStaticKeyInput{Name: "lambda-" + scope, Scope: api.AIWorkloadStaticKeyScope(scope), ExpiresAt: time.Now().Add(30 * 24 * time.Hour)}
	if mutate != nil {
		mutate(&in)
	}
	out, err := s.keys.Create(s.ctx, s.org, s.owner, s.workload.Id, in)
	if err != nil {
		s.t.Fatalf("create %s key: %v", scope, err)
	}
	if out.Key.Status != "applied" || !validStaticKeyFormat(out.Secret) || out.Key.Hint != out.Secret[52:] {
		s.t.Fatalf("created key not usable: status=%s", out.Key.Status)
	}
	return out
}

func (s *staticKeyFixture) internal(peer string) StaticKeyIngress {
	return InternalIngress(s.org, s.node, s.ep, netip.MustParseAddr(peer))
}

func (s *staticKeyFixture) refusedReason(key uuid.UUID) string {
	s.t.Helper()
	var reason *string
	if err := s.pool.QueryRow(s.ctx, `SELECT last_refused_reason FROM ai_workload_static_keys WHERE id=$1`, key).Scan(&reason); err != nil {
		s.t.Fatal(err)
	}
	if reason == nil {
		return ""
	}
	return *reason
}

func (s *staticKeyFixture) count(q string, args ...any) int {
	s.t.Helper()
	var n int
	if err := s.pool.QueryRow(s.ctx, q, args...).Scan(&n); err != nil {
		s.t.Fatal(err)
	}
	return n
}

func status(err error) int {
	var domain *apierr.Error
	if errors.Is(err, ErrRequestLimited) {
		return 429
	}
	if errors.As(err, &domain) {
		return domain.Status
	}
	if err == nil {
		return 200
	}
	return -1
}

func TestStaticKeysPostgres(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	allowPublic := func(s *staticKeyFixture) {
		if _, err := s.keys.SetPublicAllowed(ctx, s.org, s.owner, true); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("internal_key_admitted_only_on_internal_ingress", func(t *testing.T) {
		s := newStaticKeyFixture(t, ctx, newWorkloadLifecycleFixture(t, ctx, pool, []string{"openrouter/a"}, nil))
		k := s.create("internal", nil)
		g, err := s.keys.Authorize(ctx, k.Secret, "openrouter/a", s.internal("10.20.1.5"))
		if err != nil || g.SubjectKind != "workload_key" || g.Agent != k.Key.Id.String() || g.Instance != "" || g.Tenant != s.org.String() || g.VirtualKey == "" || time.Until(g.Expires) > 31*time.Second {
			t.Fatalf("internal admission: %+v %v", g, err)
		}
		var ingress, source string
		if err := pool.QueryRow(ctx, `SELECT last_used_ingress,host(last_used_source) FROM ai_workload_static_keys WHERE id=$1`, k.Key.Id).Scan(&ingress, &source); err != nil || ingress != "internal" || source != "10.20.1.5" {
			t.Fatalf("last used not recorded: %s %s %v", ingress, source, err)
		}
		// The same valid key on the public endpoint: generic 403, exact reason recorded, audit once.
		allowPublic(s)
		for i := 0; i < 3; i++ {
			if _, err := s.keys.Authorize(ctx, k.Secret, "openrouter/a", PublicIngress(netip.MustParseAddr("8.8.8.8"))); status(err) != 403 {
				t.Fatalf("internal key on public ingress: %v", err)
			}
		}
		if s.refusedReason(k.Key.Id) != "wrong_ingress" {
			t.Fatal("wrong_ingress not recorded")
		}
		if s.count(`SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='ai_workload.static_key_refused' AND target_id=$2`, s.org, k.Key.Id.String()) != 1 {
			t.Fatal("refusal audit must be written once per hour")
		}
		// Peer outside the endpoint ranges, disabled endpoint, other organization's gateway.
		if _, err := s.keys.Authorize(ctx, k.Secret, "openrouter/a", s.internal("10.30.0.1")); status(err) != 403 || s.refusedReason(k.Key.Id) != "source_not_allowed" {
			t.Fatalf("peer outside endpoint ranges: %v", err)
		}
		other := newStaticKeyFixture(t, ctx, newWorkloadLifecycleFixture(t, ctx, pool, []string{"openrouter/a"}, nil))
		if _, err := s.keys.Authorize(ctx, k.Secret, "openrouter/a", other.internal("10.20.1.5")); status(err) != 401 {
			t.Fatalf("other organization's gateway: %v", err)
		}
		s.exec(`UPDATE ai_internal_endpoints SET enabled=false WHERE id=$1`, s.ep)
		if _, err := s.keys.Authorize(ctx, k.Secret, "openrouter/a", s.internal("10.20.1.5")); status(err) != 403 {
			t.Fatalf("disabled endpoint: %v", err)
		}
		s.exec(`UPDATE ai_internal_endpoints SET enabled=true WHERE id=$1`, s.ep)
		// Unknown key, bad checksum, model not on the list.
		raw, _, _, _ := newStaticKey()
		if _, err := s.keys.Authorize(ctx, raw, "openrouter/a", s.internal("10.20.1.5")); status(err) != 401 {
			t.Fatal("unknown key admitted")
		}
		if _, err := s.keys.Authorize(ctx, k.Secret, "openrouter/b", s.internal("10.20.1.5")); status(err) != 403 {
			t.Fatal("model off the list admitted")
		}
	})

	t.Run("key_source_ranges_and_public_rules", func(t *testing.T) {
		s := newStaticKeyFixture(t, ctx, newWorkloadLifecycleFixture(t, ctx, pool, []string{"openrouter/a"}, nil))
		narrow := s.create("internal", func(in *api.AIWorkloadStaticKeyInput) { in.SourceCidrs = &[]string{"10.20.5.0/24"} })
		if _, err := s.keys.Authorize(ctx, narrow.Secret, "openrouter/a", s.internal("10.20.1.5")); status(err) != 403 || s.refusedReason(narrow.Key.Id) != "source_not_allowed" {
			t.Fatalf("key ranges ignored: %v", err)
		}
		if _, err := s.keys.Authorize(ctx, narrow.Secret, "openrouter/a", s.internal("10.20.5.9")); err != nil {
			t.Fatal(err)
		}
		// Public keys are off by default.
		_, err := s.keys.Create(ctx, s.org, s.owner, s.workload.Id, api.AIWorkloadStaticKeyInput{Name: "saas", Scope: "public", ExpiresAt: time.Now().Add(time.Hour), AllowAnySource: ptr(true)})
		if status(err) != 403 {
			t.Fatalf("public key with the switch off: %v", err)
		}
		allowPublic(s)
		if _, err = s.keys.Create(ctx, s.org, s.owner, s.workload.Id, api.AIWorkloadStaticKeyInput{Name: "saas", Scope: "public", ExpiresAt: time.Now().Add(time.Hour)}); status(err) != 400 {
			t.Fatal("public key without ranges needs the any-address confirmation")
		}
		pub := s.create("public", func(in *api.AIWorkloadStaticKeyInput) { in.SourceCidrs = &[]string{"8.8.8.0/24"} })
		if _, err = s.keys.Authorize(ctx, pub.Secret, "openrouter/a", PublicIngress(netip.MustParseAddr("8.8.8.8"))); err != nil {
			t.Fatal(err)
		}
		if _, err = s.keys.Authorize(ctx, pub.Secret, "openrouter/a", PublicIngress(netip.MustParseAddr("1.1.1.1"))); status(err) != 403 {
			t.Fatal("address outside the allowlist admitted")
		}
		if _, err = s.keys.Authorize(ctx, pub.Secret, "openrouter/a", PublicIngress(netip.Addr{})); status(err) != 403 || s.refusedReason(pub.Key.Id) != "source_not_allowed" {
			t.Fatal("unknown client address admitted with an allowlist")
		}
		if _, err = s.keys.Authorize(ctx, pub.Secret, "openrouter/a", s.internal("10.20.1.5")); status(err) != 403 || s.refusedReason(pub.Key.Id) != "wrong_ingress" {
			t.Fatal("public key admitted on the internal endpoint")
		}
		any := s.create("public", func(in *api.AIWorkloadStaticKeyInput) { in.AllowAnySource = ptr(true) })
		if _, err = s.keys.Authorize(ctx, any.Secret, "openrouter/a", PublicIngress(netip.Addr{})); err != nil {
			t.Fatalf("any-address public key: %v", err)
		}
		if _, err = s.keys.SetPublicAllowed(ctx, s.org, s.owner, false); err != nil {
			t.Fatal(err)
		}
		if _, err = s.keys.Authorize(ctx, any.Secret, "openrouter/a", PublicIngress(netip.Addr{})); status(err) != 403 || s.refusedReason(any.Key.Id) != "public_keys_disabled" {
			t.Fatal("public key admitted with the switch off")
		}
	})

	t.Run("lifecycle_rotate_revoke_update_and_audit", func(t *testing.T) {
		s := newStaticKeyFixture(t, ctx, newWorkloadLifecycleFixture(t, ctx, pool, []string{"openrouter/a"}, nil))
		k := s.create("internal", nil)
		page, err := s.keys.List(ctx, s.org, s.workload.Id, uuid.Nil, 50)
		if err != nil || len(page.Items) != 1 || page.Items[0].Id != k.Key.Id {
			t.Fatalf("list: %v", err)
		}
		up, err := s.keys.Update(ctx, s.org, s.owner, s.workload.Id, k.Key.Id, api.AIWorkloadStaticKeyUpdate{Name: "renamed", ExpectedUpdatedAt: k.Key.UpdatedAt, RateLimitPerMinute: ptr(100)})
		if err != nil || up.Name != "renamed" || up.Scope != "internal" || !up.ExpiresAt.Equal(k.Key.ExpiresAt) {
			t.Fatalf("update: %v", err)
		}
		if _, err = s.keys.Update(ctx, s.org, s.owner, s.workload.Id, k.Key.Id, api.AIWorkloadStaticKeyUpdate{Name: "stale", ExpectedUpdatedAt: k.Key.UpdatedAt}); status(err) != 409 {
			t.Fatalf("stale update: %v", err)
		}
		rotated, err := s.keys.Rotate(ctx, s.org, s.owner, s.workload.Id, k.Key.Id, api.AIWorkloadStaticKeyRotate{OverlapHours: ptr(1), ExpiresAt: time.Now().Add(7 * 24 * time.Hour)})
		if err != nil || rotated.Previous == nil || rotated.Previous.ExpiresAt.After(time.Now().Add(61*time.Minute)) || *rotated.Key.RotatedFromId != k.Key.Id || rotated.Key.Name != "renamed" || *rotated.Key.RateLimitPerMinute != 100 {
			t.Fatalf("rotate: %v", err)
		}
		for _, raw := range []string{k.Secret, rotated.Secret} {
			if _, err = s.keys.Authorize(ctx, raw, "openrouter/a", s.internal("10.20.1.5")); err != nil {
				t.Fatalf("overlap: %v", err)
			}
		}
		if err = s.keys.Revoke(ctx, s.org, s.owner, s.workload.Id, k.Key.Id); err != nil {
			t.Fatal(err)
		}
		if _, err = s.keys.Authorize(ctx, k.Secret, "openrouter/a", s.internal("10.20.1.5")); status(err) != 401 || s.refusedReason(k.Key.Id) != "revoked" {
			t.Fatalf("revoked key admitted: %v", err)
		}
		if _, err = s.keys.Authorize(ctx, rotated.Secret, "openrouter/a", s.internal("10.20.1.5")); err != nil {
			t.Fatal(err)
		}
		var native string
		var disabled bool
		if err = pool.QueryRow(ctx, `SELECT native_key_id,engine_disabled_at IS NOT NULL FROM ai_workload_static_keys WHERE id=$1`, k.Key.Id).Scan(&native, &disabled); err != nil || native == "" || !disabled || s.engine.active[native] {
			t.Fatal("revoked key's engine key must be disabled and its id kept")
		}
		for _, action := range []string{"created", "updated", "rotated", "revoked"} {
			if s.count(`SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action=$2 AND actor_user_id=$3`, s.org, "ai_workload.static_key_"+action, s.owner) == 0 {
				t.Fatalf("missing audit %s", action)
			}
		}
		if s.count(`SELECT count(*) FROM audit_logs WHERE org_id=$1 AND metadata::text LIKE '%tnx_sk_%'`, s.org) != 0 {
			t.Fatal("secret leaked into audit")
		}
		// Expired keys are refused (no minimum expiry).
		s.exec(`UPDATE ai_workload_static_keys SET expires_at=now()-interval '1 second' WHERE id=$1`, rotated.Key.Id)
		if _, err = s.keys.Authorize(ctx, rotated.Secret, "openrouter/a", s.internal("10.20.1.5")); status(err) != 401 || s.refusedReason(rotated.Key.Id) != "expired" {
			t.Fatal("expired key admitted")
		}
	})

	t.Run("capacity_eight_per_workload_and_binding_cap", func(t *testing.T) {
		s := newStaticKeyFixture(t, ctx, newWorkloadLifecycleFixture(t, ctx, pool, []string{"openrouter/a"}, nil))
		for i := 0; i < 8; i++ {
			s.create("internal", func(in *api.AIWorkloadStaticKeyInput) { in.Name = fmt.Sprintf("k%d", i) })
		}
		_, err := s.keys.Create(ctx, s.org, s.owner, s.workload.Id, api.AIWorkloadStaticKeyInput{Name: "ninth", Scope: "internal", ExpiresAt: time.Now().Add(time.Hour)})
		var domain *apierr.Error
		if !errors.As(err, &domain) || domain.Code != "static_key_capacity" {
			t.Fatalf("ninth key: %v", err)
		}
		if _, err = s.keys.Create(ctx, s.org, s.owner, s.workload.Id, api.AIWorkloadStaticKeyInput{Name: "long", Scope: "internal", ExpiresAt: time.Now().Add(91 * 24 * time.Hour)}); status(err) != 400 {
			t.Fatal("expiry past 90 days accepted")
		}
	})

	t.Run("disable_workload_revokes_and_reenable_does_not_revive", func(t *testing.T) {
		s := newStaticKeyFixture(t, ctx, newWorkloadLifecycleFixture(t, ctx, pool, []string{"openrouter/a"}, nil))
		k := s.create("internal", nil)
		grants := s.workload.Models
		w, err := s.workloads.Put(ctx, s.org, s.owner, s.workload.Id, api.AIWorkloadInput{Name: s.workload.Name, Enabled: false, Models: grants, ExpectedRevision: s.workload.Revision})
		if err != nil {
			t.Fatal(err)
		}
		if s.count(`SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='ai_workload.static_key_revoked' AND metadata->>'cause'='workload_disabled'`, s.org) != 1 {
			t.Fatal("system revoke audit missing")
		}
		if _, err = s.workloads.Put(ctx, s.org, s.owner, s.workload.Id, api.AIWorkloadInput{Name: s.workload.Name, Enabled: true, Models: grants, ExpectedRevision: w.Revision}); err != nil {
			t.Fatal(err)
		}
		if _, err = s.keys.Authorize(ctx, k.Secret, "openrouter/a", s.internal("10.20.1.5")); status(err) != 401 {
			t.Fatal("re-enabling the workload revived a key")
		}
		// Epoch is a second guard even if revoked_at were missing.
		s.exec(`UPDATE ai_workload_static_keys SET revoked_at=NULL,status='applied' WHERE id=$1`, k.Key.Id)
		if _, err = s.keys.Authorize(ctx, k.Secret, "openrouter/a", s.internal("10.20.1.5")); status(err) != 401 || s.refusedReason(k.Key.Id) != "workload_disabled" {
			t.Fatal("epoch mismatch admitted")
		}
	})

	t.Run("rate_limit_and_limiter_failure", func(t *testing.T) {
		s := newStaticKeyFixture(t, ctx, newWorkloadLifecycleFixture(t, ctx, pool, []string{"openrouter/a"}, nil))
		k := s.create("internal", func(in *api.AIWorkloadStaticKeyInput) { in.RateLimitPerMinute = ptr(2) })
		for i := 0; i < 2; i++ {
			if _, err := s.keys.Authorize(ctx, k.Secret, "openrouter/a", s.internal("10.20.1.5")); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := s.keys.Authorize(ctx, k.Secret, "openrouter/a", s.internal("10.20.1.5")); !errors.Is(err, ErrRequestLimited) || s.refusedReason(k.Key.Id) != "rate_limited" {
			t.Fatalf("third request: %v", err)
		}
		s.limiter.err = errors.New("redis down")
		if _, err := s.keys.Authorize(ctx, k.Secret, "openrouter/a", s.internal("10.20.1.5")); status(err) != 503 {
			t.Fatalf("limiter failure must refuse: %v", err)
		}
		nolimiter := NewStaticKeys(s.workloads, nil)
		if _, err := nolimiter.Authorize(ctx, k.Secret, "openrouter/a", s.internal("10.20.1.5")); status(err) != 503 {
			t.Fatal("missing limiter must refuse a rate-limited key")
		}
	})

	t.Run("key_and_workload_thresholds_count_keys_revoked_today", func(t *testing.T) {
		limit := 5.0
		s := newStaticKeyFixture(t, ctx, newWorkloadLifecycleFixture(t, ctx, pool, []string{"openrouter/a"}, &limit))
		if _, err := s.keys.Create(ctx, s.org, s.owner, s.workload.Id, api.AIWorkloadStaticKeyInput{Name: "too-high", Scope: "internal", ExpiresAt: time.Now().Add(time.Hour), DailyUsdThreshold: ptr(6.0)}); status(err) != 400 {
			t.Fatal("key threshold above the workload's accepted")
		}
		a := s.create("internal", func(in *api.AIWorkloadStaticKeyInput) { in.Name = "a"; in.DailyUsdThreshold = ptr(1.0) })
		b := s.create("internal", func(in *api.AIWorkloadStaticKeyInput) { in.Name = "b" })
		native := func(id uuid.UUID) string {
			var v string
			if err := pool.QueryRow(ctx, `SELECT native_key_id FROM ai_workload_static_keys WHERE id=$1`, id).Scan(&v); err != nil {
				t.Fatal(err)
			}
			return v
		}
		s.engine.cost[native(a.Key.Id)] = 1
		if _, err := s.keys.Authorize(ctx, a.Secret, "openrouter/a", s.internal("10.20.1.5")); status(err) != 403 || s.refusedReason(a.Key.Id) != "threshold_reached" {
			t.Fatalf("key threshold: %v", err)
		}
		if _, err := s.keys.Authorize(ctx, b.Secret, "openrouter/a", s.internal("10.20.1.5")); err != nil {
			t.Fatalf("other key under the workload threshold: %v", err)
		}
		// Spend on a key revoked today still counts toward the workload.
		if err := s.keys.Revoke(ctx, s.org, s.owner, s.workload.Id, a.Key.Id); err != nil {
			t.Fatal(err)
		}
		s.engine.cost[native(a.Key.Id)] = 4
		s.engine.cost[native(b.Key.Id)] = 1
		if _, err := s.keys.Authorize(ctx, b.Secret, "openrouter/a", s.internal("10.20.1.5")); status(err) != 403 || s.refusedReason(b.Key.Id) != "threshold_reached" {
			t.Fatalf("workload threshold with a key revoked today: %v", err)
		}
	})

	t.Run("usage_batches_more_than_64_ids", func(t *testing.T) {
		s := newStaticKeyFixture(t, ctx, newWorkloadLifecycleFixture(t, ctx, pool, []string{"openrouter/a"}, nil))
		// 70 retired keys still in the window plus the workload's own key.
		for i := 0; i < 70; i++ {
			id := uuid.New()
			s.exec(`INSERT INTO ai_workload_static_keys(id,org_id,workload_id,name,secret_hash,hint,scope,workload_epoch,expires_at,revoked_at,native_key_id,status,created_by) VALUES($1,$2,$3,'old',$4,'abcd','internal',1,now()+interval '1 day',now(),$5,'revoked',$6)`,
				id, s.org, s.workload.Id, sha256Bytes(id.String()), "native-"+id.String(), s.owner)
			s.engine.cost["native-"+id.String()] = 0.5
		}
		u, err := s.policies.Usage(ctx, s.org, nil, nil, time.Time{}, time.Time{})
		if err != nil || u.TotalCost != 35 {
			t.Fatalf("batched usage: %+v %v", u, err)
		}
		team, err := s.policies.Usage(ctx, s.org, &s.team, nil, time.Time{}, time.Time{})
		if err != nil || team.TotalCost != 0 {
			t.Fatalf("team usage must not include static keys: %+v %v", team, err)
		}
		// The active binding cap counts only active keys.
		var total int
		if err = pool.QueryRow(ctx, `SELECT `+activeBindingCountSQL, s.org).Scan(&total); err != nil || total > 8 {
			t.Fatalf("retired keys counted toward the binding cap: %d %v", total, err)
		}
	})

	t.Run("models_lists_workload_models", func(t *testing.T) {
		s := newStaticKeyFixture(t, ctx, newWorkloadLifecycleFixture(t, ctx, pool, []string{"openrouter/a", "openrouter/b"}, nil))
		k := s.create("internal", nil)
		models, err := s.keys.Models(ctx, k.Secret, s.internal("10.20.1.5"))
		if err != nil || len(models) != 2 {
			t.Fatalf("models: %v %v", models, err)
		}
		if _, err = s.keys.Models(ctx, k.Secret, PublicIngress(netip.MustParseAddr("8.8.8.8"))); status(err) != 403 {
			t.Fatal("internal key listed models on the public ingress")
		}
	})

	t.Run("expiry_reminders_once", func(t *testing.T) {
		s := newStaticKeyFixture(t, ctx, newWorkloadLifecycleFixture(t, ctx, pool, []string{"openrouter/a"}, nil))
		soon := s.create("internal", func(in *api.AIWorkloadStaticKeyInput) {
			in.Name = "soon"
			in.ExpiresAt = time.Now().Add(2 * 24 * time.Hour)
		})
		mid := s.create("internal", func(in *api.AIWorkloadStaticKeyInput) {
			in.Name = "mid"
			in.ExpiresAt = time.Now().Add(10 * 24 * time.Hour)
		})
		s.create("internal", func(in *api.AIWorkloadStaticKeyInput) { in.Name = "far" })
		var mu sync.Mutex
		got := map[uuid.UUID][]int{}
		notify := func(_ context.Context, e StaticKeyExpiry) error {
			mu.Lock()
			defer mu.Unlock()
			if e.Org == s.org {
				got[e.Key] = append(got[e.Key], e.DaysLeft)
			}
			return nil
		}
		for i := 0; i < 2; i++ {
			if err := s.keys.Maintain(ctx, 100, notify); err != nil {
				t.Fatal(err)
			}
		}
		if len(got) != 2 || len(got[soon.Key.Id]) != 1 || got[soon.Key.Id][0] != 3 || len(got[mid.Key.Id]) != 1 || got[mid.Key.Id][0] != 14 {
			t.Fatalf("reminders: %v", got)
		}
	})
}

func ptr[T any](v T) *T { return &v }

func sha256Bytes(v string) []byte {
	h := sha256.Sum256([]byte(v))
	return h[:]
}

type recordingAuthorizer struct{ calls int }

func (r *recordingAuthorizer) Authorize(context.Context, string, string) (Grant, error) {
	r.calls++
	return Grant{}, nil
}

func TestDefaultAuthorizeRefusesStaticKeys(t *testing.T) {
	w, c := &recordingAuthorizer{}, &recordingAuthorizer{}
	authorize := DefaultAuthorize(w, c)
	raw, _, _, _ := newStaticKey()
	if _, err := authorize(context.Background(), raw, "m"); status(err) != 401 || w.calls+c.calls != 0 {
		t.Fatal("default closure must refuse a static key without asking anyone")
	}
	if _, err := authorize(context.Background(), "tnx_wai_x", "m"); err != nil || w.calls != 1 {
		t.Fatal("workload tokens unchanged")
	}
	if _, err := authorize(context.Background(), "other", "m"); err != nil || c.calls != 1 {
		t.Fatal("credentials unchanged")
	}
}

func TestAdapterMapsRequestLimitedTo429(t *testing.T) {
	a, err := NewAdapter("http://127.0.0.1:1", func(context.Context, string, string) (Grant, error) { return Grant{}, nil })
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.ServeAuthorized(w, r, func(context.Context, string, string) (Grant, error) { return Grant{}, ErrRequestLimited })
	}))
	defer srv.Close()
	res, err := http.Post(srv.URL+"/v1/chat/completions", "application/json", strings.NewReader(`{"model":"openrouter/a","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != 429 || !strings.Contains(string(body), "AI request limit reached") {
		t.Fatalf("rate limited: %d %s", res.StatusCode, body)
	}
}

// AI-COMPAT-1: lease renewal of a static-key request repeats the key, ingress
// and model checks pinned to the admitted key, without the per-request rate
// limit or cost admission.
func TestStaticKeyLeaseRenewalPostgres(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	s := newStaticKeyFixture(t, ctx, newWorkloadLifecycleFixture(t, ctx, pool, []string{"openrouter/a"}, nil))
	k := s.create("internal", func(in *api.AIWorkloadStaticKeyInput) { in.RateLimitPerMinute = ptr(1) })
	g, err := s.keys.Authorize(ctx, k.Secret, "openrouter/a", s.internal("10.20.1.5"))
	if err != nil || g.Renew == nil {
		t.Fatalf("admission: %v", err)
	}
	// The per-minute limit is used up: new requests are refused, renewal is not.
	if _, err := s.keys.Authorize(ctx, k.Secret, "openrouter/a", s.internal("10.20.1.5")); !errors.Is(err, ErrRequestLimited) {
		t.Fatalf("second request: %v", err)
	}
	next, err := g.Renew(ctx)
	if err != nil || next.Agent != g.Agent || next.VirtualKey != g.VirtualKey {
		t.Fatalf("renewal: %v", err)
	}
	for name, change := range map[string][2]string{
		"endpoint disabled": {`UPDATE ai_internal_endpoints SET enabled=false WHERE id=$1`, `UPDATE ai_internal_endpoints SET enabled=true WHERE id=$1`},
		"peer range moved":  {`UPDATE ai_internal_endpoints SET source_cidrs='{10.30.0.0/16}' WHERE id=$1`, `UPDATE ai_internal_endpoints SET source_cidrs='{10.20.0.0/16}' WHERE id=$1`},
	} {
		s.exec(change[0], s.ep)
		if _, err := g.Renew(ctx); err == nil {
			t.Fatalf("renewal survived: %s", name)
		}
		s.exec(change[1], s.ep)
	}
	if _, err := g.Renew(ctx); err != nil {
		t.Fatalf("renewal after restore: %v", err)
	}
	s.exec(`UPDATE ai_workload_static_keys SET expires_at=now()-interval '1 second' WHERE id=$1`, k.Key.Id)
	if _, err := g.Renew(ctx); err == nil {
		t.Fatal("renewal survived key expiry")
	}
}
