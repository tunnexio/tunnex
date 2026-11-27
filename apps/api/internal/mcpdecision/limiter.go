package mcpdecision

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// RateWindow is the window a rule's per-minute limit counts in.
const RateWindow = time.Minute

// RateLimiter counts calls in a store every control-plane instance shares, so the limit holds no matter
// which instance, or which gateway, a call arrives through.
type RateLimiter interface {
	// Allow charges one call to key and reports whether it is within limit for the current window.
	Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error)
}

// RedisLimiter is the shared limiter. The window starts at the first call and the counter expires with it.
type RedisLimiter struct{ rdb redis.Scripter }

func NewRedisLimiter(rdb redis.Scripter) *RedisLimiter { return &RedisLimiter{rdb: rdb} }

func (l *RedisLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	used, err := l.rdb.Eval(ctx, `local v = redis.call('INCR', KEYS[1])
if v == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
return v`, []string{key}, window.Milliseconds()).Int()
	if err != nil {
		return false, err
	}
	return used <= limit, nil
}

// rateKey scopes a counter to one agent and one tool of one endpoint. The tool is hashed: its name is
// chosen by the MCP server.
func rateKey(deviceID uuid.UUID, endpoint, tool string) string {
	sum := sha256.Sum256([]byte(endpoint + "\x00" + tool))
	return "mcp:rl:" + deviceID.String() + ":" + hex.EncodeToString(sum[:16])
}
