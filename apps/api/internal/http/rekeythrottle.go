package http

import (
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"
)

// rekeyThrottle is THE RE-KEY ENDPOINTS' OWN throttle. It is deliberately not called `RateLimiter`, not exported,
// and not in a shared middleware package — the name and the placement are the guard.
//
// WHY THAT MATTERS. A well-placed forty-line limiter is exactly what a future story reaches for when it needs
// general rate limiting, and this one is sized for a narrow surface and would be wrong as the general mechanism: it
// keys on remote IP only, keeps unbounded per-IP state until swept, and has no per-account or per-route
// configuration. Rate limiting for login, enrolment, the agent channel and the wider API remains OWED
// (docs/S13.1-decisions.md records it honestly). If you are here because you need that, do not import this.
//
// WHY IT EXISTS AT ALL. The re-key routes are UNAUTHENTICATED by construction — the caller's certificate is the
// thing that has failed — and one of them performs RSA verification, which is CPU-amplifying, while the other
// writes a database row per call.
//
// AND WHY IT IS SMALL. The gate runs before any cryptographic work, so the cheap path is the common one: a random
// certificate serial is refused by a field comparison, and reaching RSA verification requires knowing a REAL serial
// for a genuinely expired node. So this defends a narrow surface and is sized for that rather than over-built.
type rekeyThrottle struct {
	mu      sync.Mutex
	seen    map[string]*bucket
	perMin  int
	sweepAt time.Time
}

type bucket struct {
	count int
	reset time.Time
}

func newRekeyThrottle(perMin int) *rekeyThrottle {
	return &rekeyThrottle{seen: map[string]*bucket{}, perMin: perMin}
}

// allow reports whether this caller may proceed, and counts the attempt.
//
// Fixed window rather than a token bucket: the quantity being protected is CPU and rows per minute, and a fixed
// window is trivially auditable by reading it. A burst at a window boundary is worth twice the budget, which for
// this surface is not a meaningful difference.
func (t *rekeyThrottle) allow(remoteAddr string) bool {
	key := clientIP(remoteAddr)
	now := time.Now()

	t.mu.Lock()
	defer t.mu.Unlock()

	// Sweep occasionally so an unauthenticated endpoint cannot grow this map without bound. Done inline rather
	// than on a goroutine: no lifecycle to own, and the cost is proportional to what was actually admitted.
	if now.After(t.sweepAt) {
		for k, b := range t.seen {
			if now.After(b.reset) {
				delete(t.seen, k)
			}
		}
		t.sweepAt = now.Add(time.Minute)
	}

	b, ok := t.seen[key]
	if !ok || now.After(b.reset) {
		t.seen[key] = &bucket{count: 1, reset: now.Add(time.Minute)}
		return true
	}
	if b.count >= t.perMin {
		return false
	}
	b.count++
	return true
}

// clientIP strips the port from r.RemoteAddr.
//
// THIS IS ONLY SAFE BECAUSE OF WHERE THE MIDDLEWARE IS REGISTERED. `middleware.RealIP` overwrites RemoteAddr from
// client-supplied headers, so a throttle running after it keys on a value the caller chooses. This one is
// registered BEFORE RealIP (router.go) and therefore sees the raw peer address. Review finding #1 was exactly this
// defect: the code ignored X-Forwarded-For, and the middleware above it had already laundered that header into the
// field being read.
//
// A deployment behind a proxy therefore throttles per-proxy, which is a real limitation and the honest one —
// resolving it needs trusted-proxy configuration, which belongs to the general mechanism rather than to this.
func clientIP(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}

// throttled wraps a handler. On refusal it answers 429 with no detail — the same uniform-response discipline as the
// re-key refusal itself, so the throttle cannot be used to learn anything the endpoint would not otherwise tell.
func (t *rekeyThrottle) throttled(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !t.allow(r.RemoteAddr) {
			// LOGGED HERE, because nothing downstream will (review pass 1 #13). This middleware is registered
			// ABOVE the access logger — deliberately, so the throttle keys on the raw peer address before
			// middleware.RealIP rewrites it from client-supplied headers — and the cost of that ordering is that a
			// 429 leaves no server-side trace at all: no log line, no request id, no source address.
			//
			// The one endpoint pair that is unauthenticated by construction was therefore the only one whose
			// refusals were invisible, and its budget is a per-DEPLOYMENT one (rekeyAttemptsPerMinute). Fleet-wide
			// recovery starvation was undiagnosable from the control plane's own logs — an operator could not even
			// confirm it was happening. A bound nobody can see is not a bound.
			slog.Warn("rekey_throttled",
				"peer", clientIP(r.RemoteAddr),
				"path", r.URL.Path,
				"limit_per_minute", t.perMin,
				"note", "the re-key throttle keys on the RAW peer address, which behind a proxy or ingress is the "+
					"proxy — so this budget is shared by every caller behind it. Sustained entries here mean "+
					"gateway self-recovery is being denied fleet-wide (docs/S13.1-decisions.md, finding #4)")
			w.Header().Set("Retry-After", "60")
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

// rekeyAttemptsPerMinute is DERIVED from the worst legitimate case, not chosen for feeling strict.
//
// The binding constraint is a whole fleet recovering at once after an outage longer than the 48h certificate TTL.
// Because the throttle keys on the RAW PEER address (it must, or the key is forgeable), every gateway behind an
// ingress or NAT shares ONE bucket — so the budget has to cover the fleet, not one host.
//
// Worked through: an un-recovered agent retries on a 30s floor, so in any 60s window it makes at most 2 attempts,
// and each attempt is 2 requests (challenge + submit) = 4 requests/min per gateway. For a 100-gateway fleet all
// expiring together that is 400 requests/min through a single shared bucket. 600 leaves headroom for jitter and
// clock spread without the tail: at 10/min a 100-gateway recovery would have taken over three hours, which is a
// self-inflicted outage dressed as a security control.
//
// And 600/min is still a real bound on what it protects: ~10 RSA-2048 verifications per second, low single-digit
// percent of one core, and only for requests that already named a real certificate serial for a genuinely expired
// node — everything else is refused by a field comparison before any cryptographic work.
//
// SHARED-BUCKET LIMITATION, stated in the same register as the per-proxy one below: behind a proxy or NAT this is
// a per-DEPLOYMENT budget, not a per-caller one, so one misbehaving client there can consume a recovering fleet's
// allowance. Fixing that needs trusted-proxy configuration, which belongs to the general rate-limiting mechanism
// (still owed — see docs/S13.1-decisions.md), not to this file.
const rekeyAttemptsPerMinute = 600

// maxRekeyBodyBytes caps the request body on the re-key routes.
//
// There is NO body-size limit anywhere else in apps/api — a fact worth having written down rather than
// rediscovered (registered in docs/S13.1-decisions.md). These two routes get one now because they are
// unauthenticated, and an unbounded body was being fully decoded and schema-validated before the throttle was
// consulted. A CSR plus a base64 signature and nonce is a few kilobytes; 64 KiB is generous for that and still
// refuses a megabyte.
const maxRekeyBodyBytes = 64 << 10

// rekeyOnly applies the throttle to the re-key paths and leaves every other route untouched.
//
// Scoped by PATH deliberately. A global limiter is what the general rate-limiting story will need, and quietly
// becoming that story is the failure mode this file is written to avoid — so this one refuses to cover anything it
// was not reasoned about.
func rekeyOnly(t *rekeyThrottle) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/v1/agent/rekey", "/api/v1/agent/rekey/challenge":
				// Cap the body BEFORE anything reads it. Registered ahead of the OpenAPI validator, so this is the
				// first code that touches the request at all.
				r.Body = http.MaxBytesReader(w, r.Body, maxRekeyBodyBytes)
				t.throttled(next.ServeHTTP)(w, r)
			default:
				next.ServeHTTP(w, r)
			}
		})
	}
}
