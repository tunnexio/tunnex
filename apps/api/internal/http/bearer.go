package http

import (
	"crypto/sha256"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/cliauth"
)

// BearerAuthFunc resolves an Authorization: Bearer CLI credential.
// Returns (principal, nil) for a valid credential; (nil, nil) for ANY failure —
// no/unknown/revoked/EXPIRED bearer are all deliberately indistinguishable
// (no oracle), failing closed at the handlers' generic 401. Expiry is surfaced
// to the CLI from its locally-stored expires_at, not a server-side code. The
// error return is retained for a future auth path that needs a distinct refusal.
type BearerAuthFunc func(r *http.Request) (*authctx.Principal, error)

// BearerAuth builds the bearer resolver. bearer ≡ cookie (S5.1 decision 2): the
// principal is constructed EXACTLY like SessionAuth's (user status check,
// memberships, verified state) so every downstream authorization rule applies
// identically to both credential types.
func BearerAuth(q *sqlc.Queries) BearerAuthFunc {
	return func(r *http.Request) (*authctx.Principal, error) {
		raw, ok := bearerToken(r)
		if !ok {
			return nil, nil
		}
		h := sha256.Sum256([]byte(raw))
		cred, err := q.GetCliCredentialByHash(r.Context(), h[:])
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil // unknown token — generic 401 downstream
		}
		if err != nil {
			return nil, nil // fail closed, no oracle
		}
		// NO-ORACLE: revoked, expired, and unknown are ALL indistinguishable at
		// the wire — a generic 401 (nil,nil → falls through to the generic
		// per-op unauthenticated response). The CLI recognizes an expired
		// credential from its LOCALLY-stored expires_at and prints the re-login
		// line itself, so the UX needs no server-side expiry oracle.
		if cred.RevokedAt.Valid || !cred.ExpiresAt.After(time.Now()) {
			return nil, nil
		}
		user, err := q.GetUserByID(r.Context(), cred.UserID)
		if err != nil {
			return nil, nil
		}
		// A deactivated user's credential dies on its very next request
		// (SessionAuth parity), independent of the deactivation sweep.
		if user.Status != "active" {
			return nil, nil
		}
		memberships, err := q.ListMembershipsByUser(r.Context(), cred.UserID)
		if err != nil {
			return nil, nil
		}
		roles := make(map[uuid.UUID]string, len(memberships))
		for _, m := range memberships {
			roles[m.OrgID] = m.Role
		}
		_ = q.TouchCliCredentialUsed(r.Context(), cred.ID) // best-effort telemetry
		return &authctx.Principal{
			UserID:        user.ID,
			Email:         user.Email,
			EmailVerified: user.EmailVerifiedAt.Valid,
			AuthMethod:    authctx.AuthBearer, // a CLI/automation credential — exempt from the MFA-enrollment gate (D5)
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
		}, nil
	}
}

// bearerToken extracts a tnx_-prefixed bearer token, if present.
func bearerToken(r *http.Request) (string, bool) {
	const scheme = "Bearer "
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, scheme) {
		return "", false
	}
	tok := strings.TrimSpace(strings.TrimPrefix(h, scheme))
	if !strings.HasPrefix(tok, cliauth.TokenPrefix) {
		return "", false
	}
	return tok, true
}
