package aigateway

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// ConcurrencyLeases admits active inference requests against per-key limits.
// Each request holds one lease id across all of its keys (organization and
// subject). Acquire is all-or-nothing.
type ConcurrencyLeases interface {
	Acquire(ctx context.Context, keys []string, limits []int) (lease string, ok bool, err error)
	// Renew extends a held lease. ok=false means the lease is no longer held.
	Renew(ctx context.Context, keys []string, lease string) (ok bool, err error)
	Release(ctx context.Context, keys []string, lease string) error
	// RenewEvery is how often a holder renews (zero: never needed).
	RenewEvery() time.Duration
	// TTL is how long a lease survives without renewal (zero: until released).
	TTL() time.Duration
}

func newLeaseID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// memoryLeases is the in-process limiter, used when no shared store is
// configured. Leases live until released; the adapter always releases.
type memoryLeases struct {
	mu     sync.Mutex
	active map[string]map[string]struct{}
}

func newMemoryLeases() *memoryLeases { return &memoryLeases{active: map[string]map[string]struct{}{}} }

func (m *memoryLeases) Acquire(_ context.Context, keys []string, limits []int) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, k := range keys {
		if len(m.active[k]) >= limits[i] {
			return "", false, nil
		}
	}
	lease := newLeaseID()
	for _, k := range keys {
		if m.active[k] == nil {
			m.active[k] = map[string]struct{}{}
		}
		m.active[k][lease] = struct{}{}
	}
	return lease, true, nil
}

func (m *memoryLeases) Renew(_ context.Context, keys []string, lease string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, k := range keys {
		if _, ok := m.active[k][lease]; !ok {
			return false, nil
		}
	}
	return true, nil
}

func (m *memoryLeases) Release(_ context.Context, keys []string, lease string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, k := range keys {
		delete(m.active[k], lease)
		if len(m.active[k]) == 0 {
			delete(m.active, k)
		}
	}
	return nil
}

func (m *memoryLeases) RenewEvery() time.Duration { return 0 }
func (m *memoryLeases) TTL() time.Duration        { return 0 }

// RedisLeases shares the limits across API replicas. Each key is a sorted set
// of lease ids scored by expiry in Redis server time; expired members are
// removed before counting, so a crashed replica's slots return within one TTL.
type RedisLeases struct {
	rdb   redis.Scripter
	ttl   time.Duration
	every time.Duration
}

func NewRedisLeases(rdb redis.Scripter) *RedisLeases {
	return &RedisLeases{rdb: rdb, ttl: 60 * time.Second, every: 20 * time.Second}
}

// Server time keeps replicas with skewed clocks consistent.
const leaseNow = `local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
`

var acquireLeaseScript = redis.NewScript(leaseNow + `
local ttl = tonumber(ARGV[1])
for i, key in ipairs(KEYS) do
  redis.call('ZREMRANGEBYSCORE', key, '-inf', now)
  if redis.call('ZCARD', key) >= tonumber(ARGV[i + 2]) then return 0 end
end
for _, key in ipairs(KEYS) do
  redis.call('ZADD', key, now + ttl, ARGV[2])
  redis.call('PEXPIRE', key, ttl * 2)
end
return 1`)

var renewLeaseScript = redis.NewScript(leaseNow + `
local ttl = tonumber(ARGV[1])
for _, key in ipairs(KEYS) do
  local score = redis.call('ZSCORE', key, ARGV[2])
  if not score or tonumber(score) < now then return 0 end
end
for _, key in ipairs(KEYS) do
  redis.call('ZADD', key, 'XX', now + ttl, ARGV[2])
  redis.call('PEXPIRE', key, ttl * 2)
end
return 1`)

var releaseLeaseScript = redis.NewScript(`for _, key in ipairs(KEYS) do redis.call('ZREM', key, ARGV[1]) end
return 1`)

func (l *RedisLeases) Acquire(ctx context.Context, keys []string, limits []int) (string, bool, error) {
	lease := newLeaseID()
	args := []any{l.ttl.Milliseconds(), lease}
	for _, n := range limits {
		args = append(args, n)
	}
	v, err := acquireLeaseScript.Run(ctx, l.rdb, keys, args...).Int()
	if err != nil {
		return "", false, err
	}
	return lease, v == 1, nil
}

func (l *RedisLeases) Renew(ctx context.Context, keys []string, lease string) (bool, error) {
	v, err := renewLeaseScript.Run(ctx, l.rdb, keys, l.ttl.Milliseconds(), lease).Int()
	return v == 1, err
}

func (l *RedisLeases) Release(ctx context.Context, keys []string, lease string) error {
	return releaseLeaseScript.Run(ctx, l.rdb, keys, lease).Err()
}

func (l *RedisLeases) RenewEvery() time.Duration { return l.every }
func (l *RedisLeases) TTL() time.Duration        { return l.ttl }
