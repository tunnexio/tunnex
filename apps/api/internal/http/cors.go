package http

import (
	"net/http"
	"strings"
)

// corsBearer enables CROSS-ORIGIN, BEARER-authenticated requests from an EXACT
// allowlist of origins — for the S6.2 desktop client, whose renderer origin is
// app://tunnex. It is deliberately narrow and does NOT weaken the cookie/CSRF
// posture that csrfGuard depends on:
//
//   - only EXACT-match allowlisted origins get any CORS headers (a web attacker's
//     https://evil.example is never allowlisted; the same-origin web SPA never
//     triggers CORS at all);
//   - Access-Control-Allow-Credentials is NEVER sent, so cookies can never be
//     used cross-origin — the desktop authenticates with a bearer header, and the
//     browser's same-origin cookie flow is untouched;
//   - the custom X-Tunnex-CSRF header is only accepted from the allowlisted
//     origin, so it cannot become a cross-site CSRF vector for cookie sessions.
//
// A preflight (OPTIONS) from an allowlisted origin is answered 204 here, before
// routing (the generated handlers define no OPTIONS).
func corsBearer(allowed []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" && isAllowedOrigin(allowed, origin) {
				h := w.Header()
				h.Set("Access-Control-Allow-Origin", origin)
				h.Add("Vary", "Origin")
				// NOTE: no Access-Control-Allow-Credentials — bearer only, never cookies.
				if r.Method == http.MethodOptions {
					h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
					h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Tunnex-CSRF")
					h.Set("Access-Control-Max-Age", "600")
					w.WriteHeader(http.StatusNoContent)
					return
				}
			} else if r.Method == http.MethodOptions {
				// A preflight from a non-allowlisted origin: no CORS headers → the
				// browser blocks it. Answer 204 (nothing to route).
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// isAllowedOrigin is exported-for-test visibility into the allowlist decision.
func isAllowedOrigin(allowed []string, origin string) bool {
	for _, o := range allowed {
		if strings.EqualFold(o, origin) {
			return true
		}
	}
	return false
}
