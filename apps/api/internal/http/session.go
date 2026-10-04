package http

import (
	"crypto/sha256"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/session"
)

// SessionAuth builds the AuthFunc that resolves the session cookie into a
// Principal (user + memberships + verified state). Returns nil (unauthenticated)
// for any missing/invalid session, so gated endpoints fail closed.
func SessionAuth(store *session.Store, q *sqlc.Queries) AuthFunc {
	return func(r *http.Request) *authctx.Principal {
		if state, _ := r.Context().Value(requestTransportKey{}).(requestTransportState); state.ambiguousSession {
			return nil
		}
		c, err := r.Cookie(sessionCookieName(r.Context()))
		if err != nil {
			return nil
		}
		sess, _, err := store.GetNoTouch(r.Context(), c.Value)
		if err != nil {
			return nil
		}
		user, err := q.GetUserByID(r.Context(), sess.UserID)
		if err != nil {
			return nil
		}
		// A deactivated user's live session is invalid on its very next request —
		// not merely blocked from future logins.
		if user.Status != "active" {
			return nil
		}
		hash := sha256.Sum256([]byte(sess.ID))
		revoked, err := q.IsAppParentLogoutRevoked(r.Context(), hash[:])
		if err != nil || revoked {
			return nil
		}
		// Legacy parents remain usable only before the first credential epoch change.
		// Never promote a parent's authority by reading the current user epoch.
		if (sess.AppAuthEpoch == 0 && user.AppAuthEpoch != 1) || (sess.AppAuthEpoch != 0 && sess.AppAuthEpoch != user.AppAuthEpoch) {
			return nil
		}
		// Assurance verification must not extend the first-factor session. Other
		// validated native console requests retain their ordinary idle behavior.
		assuranceOnly := r.Method == http.MethodPost && (r.URL.Path == "/api/v1/auth/mfa/step-up" || r.URL.Path == "/api/v1/auth/mfa/enroll/confirm")
		if !assuranceOnly {
			if _, err := store.Get(r.Context(), c.Value); err != nil {
				return nil
			}
		}
		memberships, err := q.ListMembershipsByUser(r.Context(), sess.UserID)
		if err != nil {
			return nil
		}
		roles := make(map[uuid.UUID]string, len(memberships))
		roleSets := make(map[uuid.UUID][]string, len(memberships))
		for _, m := range memberships {
			roles[m.OrgID] = m.Role
			roleSets[m.OrgID] = m.Roles
		}
		return &authctx.Principal{
			UserID:        user.ID,
			SessionID:     sess.ID,
			Email:         user.Email,
			EmailVerified: user.EmailVerifiedAt.Valid,
			AuthMethod:    sess.AuthMethod, // rides the session's mint-time method (immutable)
			Roles:         roles,
			RoleSets:      roleSets,
			// ⛔ ONLY ACCOUNTS THAT HAVE A LOCAL PASSWORD CAN BE ASKED TO CHANGE ONE.
			//
			// An SSO user has no password_hash at all — they authenticate through their IdP. If the flag
			// were ever set on such an account they would be walled out of every route with
			// `password_change_required` and sent to a screen whose only action is "enter your CURRENT
			// password", which does not exist. A trap with no exit.
			//
			// ⚠ It is not reachable today (only bootstrap sets the flag, and that account has a password),
			// which is exactly why it is guarded HERE rather than left to the setter: the next thing that
			// sets it — a password-rotation policy, an admin-forced reset — will not remember this.
			MustChangePassword: user.MustChangePassword && user.PasswordHash != nil,
			CPAdmin:            user.CpAdmin,
		}
	}
}

// csrfGuard protects cookie-authenticated state changes. For an unsafe method
// carrying the session cookie, it requires a custom header that a cross-site
// form post cannot set (browsers block custom headers cross-origin absent CORS,
// which we do not grant). Combined with SameSite=Lax cookies, this is defense in
// depth. Browser login/signup also enforce the console origin to prevent login
// CSRF from a private app on the same registrable site.
func csrfGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isUnsafeMethod(r.Method) {
			// Subdomains are same-site, but not the console's origin. Check the
			// browser's exact origin even for unauthenticated login requests.
			// Credential-free bearer API calls retain their existing CORS flow.
			_, cookieErr := r.Cookie(sessionCookieName(r.Context()))
			if cookieErr == nil || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
				origins := r.Header.Values("Origin")
				secure, known := requestHTTPS(r.Context())
				scheme := "http"
				if secure || !known && r.TLS != nil {
					scheme = "https"
				}
				originMatches := len(origins) == 1 && origins[0] == scheme+"://"+originAuthority(r.Host, scheme == "https")
				if len(origins) > 1 || len(origins) == 1 && !originMatches || len(origins) == 0 && (r.Header.Get("Sec-Fetch-Site") == "cross-site" || r.Header.Get("Sec-Fetch-Site") == "same-site") {
					apierr.Write(w, r, apierr.New(http.StatusForbidden, "csrf", "State-changing browser requests must originate from this console."))
					return
				}
			}
			if _, err := r.Cookie(sessionCookieName(r.Context())); err == nil {
				if r.Header.Get("X-Tunnex-CSRF") == "" {
					apierr.Write(w, r, apierr.New(http.StatusForbidden, "csrf",
						"missing X-Tunnex-CSRF header on a state-changing request"))
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func isUnsafeMethod(m string) bool {
	switch m {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}
