package http

import (
	"net/http"

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
		c, err := r.Cookie(session.CookieName)
		if err != nil {
			return nil
		}
		sess, err := store.Get(r.Context(), c.Value)
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
		memberships, err := q.ListMembershipsByUser(r.Context(), sess.UserID)
		if err != nil {
			return nil
		}
		roles := make(map[uuid.UUID]string, len(memberships))
		for _, m := range memberships {
			roles[m.OrgID] = m.Role
		}
		return &authctx.Principal{
			UserID:        user.ID,
			SessionID:     sess.ID,
			Email:         user.Email,
			EmailVerified: user.EmailVerifiedAt.Valid,
			AuthMethod:    sess.AuthMethod, // rides the session's mint-time method (immutable)
			Roles:         roles,
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
// depth. Requests without the session cookie (e.g. login/signup) are unaffected.
func csrfGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isUnsafeMethod(r.Method) {
			if _, err := r.Cookie(session.CookieName); err == nil {
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
