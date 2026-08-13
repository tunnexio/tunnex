package http

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// TestThrottleRefusesBeyondTheWindowBudget — the throttle actually throttles. Trivial to assert and the whole reason
// the file exists, since the endpoints it protects are unauthenticated and one of them performs RSA verification.
func TestThrottleRefusesBeyondTheWindowBudget(t *testing.T) {
	th := newRekeyThrottle(3)
	for i := 1; i <= 3; i++ {
		if !th.allow("203.0.113.7:44321") {
			t.Fatalf("attempt %d must be allowed within a budget of 3", i)
		}
	}
	if th.allow("203.0.113.7:44321") {
		t.Error("the fourth attempt in one window must be refused — an unauthenticated endpoint that performs " +
			"RSA verification is a CPU-amplification surface without this")
	}
	// A DIFFERENT caller is unaffected: throttling one address must not deny the fleet.
	if !th.allow("198.51.100.9:1234") {
		t.Error("a different client IP must have its own budget — otherwise one attacker denies every recovering gateway")
	}
}

// TestThrottleIgnoresCallerControlledHeaders — the identity must not be spoofable.
//
// X-Forwarded-For is set by the caller unless a trusted proxy overwrites it. Keying on it would let one attacker
// present as a million distinct clients, which is worse than having no throttle: it would look protected.
func TestThrottleIgnoresCallerControlledHeaders(t *testing.T) {
	th := newRekeyThrottle(2)
	h := th.throttled(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })

	codes := []int{}
	for i := 0; i < 4; i++ {
		req := httptest.NewRequest("POST", "/api/v1/agent/rekey", nil)
		req.RemoteAddr = "203.0.113.7:44321"
		// A rotating forged forwarding header, which must buy the caller nothing.
		req.Header.Set("X-Forwarded-For", []string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"}[i])
		rec := httptest.NewRecorder()
		h(rec, req)
		codes = append(codes, rec.Code)
	}
	if codes[2] != http.StatusTooManyRequests || codes[3] != http.StatusTooManyRequests {
		t.Errorf("a rotating X-Forwarded-For must not extend the budget — a header the caller controls is not an "+
			"identity. Got codes %v", codes)
	}
}

// TestThrottleRefusalLeaksNothing — same discipline as the re-key refusal itself: 429 with no detail. A throttle
// that explained itself would answer questions the endpoint deliberately refuses to answer.
func TestThrottleRefusalLeaksNothing(t *testing.T) {
	th := newRekeyThrottle(1)
	h := th.throttled(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("POST", "/api/v1/agent/rekey", nil)
		req.RemoteAddr = "203.0.113.7:1"
		rec := httptest.NewRecorder()
		h(rec, req)
		if i == 1 {
			if rec.Code != http.StatusTooManyRequests {
				t.Fatalf("want 429, got %d", rec.Code)
			}
			if rec.Header().Get("Retry-After") == "" {
				t.Error("a refusal should tell a legitimate agent when to come back — that is not a leak, it is the " +
					"one thing the caller needs")
			}
			if body := rec.Body.String(); len(body) > 32 {
				t.Errorf("the refusal body must carry no detail; got %q", body)
			}
		}
	}
}

// TestThrottleIsRegisteredBeforeRealIP — the guard that would have caught review finding #1, and did not exist.
//
// WHY THE OTHER TESTS IN THIS FILE COULD NOT. They call `th.throttled(...)` directly on a bare httptest request, so
// they prove the throttle ignores X-Forwarded-For *in isolation*. The defect was not in the throttle: it was in the
// CHAIN. `middleware.RealIP` overwrites r.RemoteAddr from client-supplied True-Client-IP / X-Real-IP / leftmost
// X-Forwarded-For, so a throttle registered after it keys on a value the caller chooses — and a unit test that never
// runs RealIP cannot see that. The guard asserted a property the production path did not have, and passed.
//
// So this asserts the REGISTRATION ORDER, which is where the property actually lives. chi runs r.Use middleware in
// registration order, so rekeyOnly must appear before middleware.RealIP for the raw peer address to survive — and
// before the OpenAPI validator, so a refused request does not pay a full body decode first (finding #4).
//
// Source-order assertion, scoped to NewRouter per the census law: matching these calls anywhere in the file would be
// matching a coincidence of the text, and the comments above them name both symbols while explaining the ordering.
func TestThrottleIsRegisteredBeforeRealIP(t *testing.T) {
	raw, err := os.ReadFile("router.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	start := strings.Index(src, "func NewRouter(")
	if start < 0 {
		t.Fatal("NewRouter not found — the guard would vouch for nothing")
	}
	var code strings.Builder
	for _, line := range strings.Split(src[start:], "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		code.WriteString(line + "\n")
	}
	body := code.String()

	throttle := strings.Index(body, "rekeyOnly(")
	realIP := strings.Index(body, "middleware.RealIP")
	validator := strings.Index(body, "OapiRequestValidator")

	if throttle < 0 {
		t.Fatal("the re-key throttle must be registered — two unauthenticated routes depend on it")
	}
	if realIP >= 0 && throttle > realIP {
		t.Error("rekeyOnly MUST be registered before middleware.RealIP. RealIP rewrites r.RemoteAddr from " +
			"client-supplied headers, so a throttle running after it keys on a value the attacker chooses: varying " +
			"one header gives every request a fresh bucket and the cap never engages, on an unauthenticated route " +
			"that performs RSA verification (review #1)")
	}
	if validator >= 0 && throttle > validator {
		t.Error("rekeyOnly MUST be registered before the OpenAPI request validator, or every refused request still " +
			"pays a full body decode and schema validation before the 429 — spending exactly the CPU and memory " +
			"the throttle exists to protect (review #4)")
	}
}

// TestChallengeSweeperIsWired — review #5, and a producer-without-consumer guard.
//
// `DeleteExpiredRekeyChallenges` was generated and called from nowhere, so node_rekey_challenges — written by an
// UNAUTHENTICATED endpoint, one row per request for any serial asked about — was never pruned. Migration 0058's own
// comment and its expires_at index described pruning that no code performed: the artifact existed and the behaviour
// did not.
//
// This asserts the sweeper is actually WIRED, in main.go, and leader-gated like every other tick. A query with no
// caller is the shape this epic keeps finding, and grep is the only thing that catches it.
func TestChallengeSweeperIsWired(t *testing.T) {
	raw, err := os.ReadFile("../../cmd/server/main.go")
	if err != nil {
		t.Fatal(err)
	}
	var code strings.Builder
	for _, line := range strings.Split(string(raw), "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		code.WriteString(line + "\n")
	}
	body := code.String()

	call := strings.Index(body, "DeleteExpiredRekeyChallenges(")
	if call < 0 {
		t.Fatal("node_rekey_challenges must be swept: the table is written by an UNAUTHENTICATED endpoint, one row " +
			"per challenge request for any serial asked about, so without a sweeper it grows until the database " +
			"volume fills. A generated query with no caller is not pruning.")
	}
	// Leader-gated, so "exactly one replica ticks" stays true of the whole tick set rather than most of it.
	gate := strings.LastIndex(body[:call], "elector.IsLeader()")
	if gate < 0 {
		t.Error("the challenge sweep must be leader-gated like every other scheduler tick (S11 D4)")
	}
}

// TestAThrottled429IsLOGGED — review pass 1 #13.
//
// The throttle is registered ABOVE the access logger, deliberately: it must key on the RAW peer address before
// middleware.RealIP rewrites it from client-supplied headers. The cost of that ordering was that a 429 left NO
// server-side trace — no log line, no request id, no source address — so the one endpoint pair that is
// unauthenticated by construction was the only one whose refusals were invisible.
//
// That matters more than tidiness because the budget is a per-DEPLOYMENT one: fleet-wide recovery starvation
// (finding #4, accepted as a bounded limitation) was undiagnosable from the control plane's own logs. A bound
// nobody can observe is not a bound.
func TestAThrottled429IsLOGGED(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	th := newRekeyThrottle(1)
	h := th.throttled(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })

	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/api/v1/agent/rekey", nil)
		req.RemoteAddr = "203.0.113.9:5555"
		h(rec, req)
		if i == 1 && rec.Code != http.StatusTooManyRequests {
			t.Fatalf("second request must be throttled, got %d", rec.Code)
		}
	}
	out := buf.String()
	if !strings.Contains(out, "rekey_throttled") {
		t.Fatal("a throttled re-key must leave a server-side log line — it is registered above the access logger, " +
			"so nothing downstream will record it, and fleet-wide starvation would be undiagnosable")
	}
	if !strings.Contains(out, "203.0.113.9") {
		t.Fatalf("the log must name the peer the budget was spent by, or an operator cannot tell a flood from a "+
			"recovering fleet; got %s", out)
	}
}
