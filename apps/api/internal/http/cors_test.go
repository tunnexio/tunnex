package http

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// S6.2 CORS: cross-origin BEARER access for the exact desktop origin, WITHOUT
// ever allowing credentials (so the same-origin cookie/CSRF posture can't be
// weakened). These are the properties the security review depends on.
func TestCorsBearer(t *testing.T) {
	allowed := []string{"app://tunnex"}
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := corsBearer(allowed)(inner)

	do := func(method, origin string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/api/v1/auth/me", nil)
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// Allowlisted origin, real GET → ACAO echoes the origin; NEVER Allow-Credentials.
	rec := do("GET", "app://tunnex")
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "app://tunnex" {
		t.Fatalf("allowed GET ACAO: want app://tunnex, got %q", got)
	}
	if rec.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Fatal("Allow-Credentials must NEVER be set (bearer only, no cookies cross-origin)")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("allowed GET reached handler: want 200, got %d", rec.Code)
	}

	// Allowlisted preflight → 204 with methods + the custom CSRF header allowed,
	// handled HERE (the generated handlers define no OPTIONS).
	pre := do("OPTIONS", "app://tunnex")
	if pre.Code != http.StatusNoContent {
		t.Fatalf("allowed preflight: want 204, got %d", pre.Code)
	}
	if h := pre.Header().Get("Access-Control-Allow-Headers"); h == "" || !hdrHas(h, "X-Tunnex-CSRF") {
		t.Fatalf("preflight Allow-Headers must include X-Tunnex-CSRF, got %q", h)
	}
	if pre.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Fatal("preflight Allow-Credentials must NEVER be set")
	}

	// A DISALLOWED origin (a web attacker) gets NO CORS headers — the browser blocks it.
	evil := do("GET", "https://evil.example")
	if evil.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("a non-allowlisted origin must receive NO Access-Control-Allow-Origin")
	}

	// Same-origin web requests carry no (or a non-listed) Origin and are unaffected
	// — no CORS headers, handler runs normally.
	same := do("GET", "")
	if same.Header().Get("Access-Control-Allow-Origin") != "" || same.Code != http.StatusOK {
		t.Fatalf("same-origin (no Origin) must be untouched: acao=%q code=%d",
			same.Header().Get("Access-Control-Allow-Origin"), same.Code)
	}
}

func hdrHas(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
