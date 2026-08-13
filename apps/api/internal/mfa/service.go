package mfa

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/mail"
)

const (
	challengeTTL = 5 * time.Minute
	maxAttempts  = 5 // D7 terminal per-challenge cap (TOTP + recovery share it)
)

// Service orchestrates TOTP enrollment + the login-time challenge. Enrollment is OPEN;
// org enforce (slice 2) layers on top. `now` is injectable for tests.
type Service struct {
	pool   *pgxpool.Pool
	q      *sqlc.Queries
	sealer *crypto.Sealer
	mailer mail.Mailer // best-effort notifications (admin-reset); nil-safe
	logger *slog.Logger
	now    func() time.Time
}

func NewService(pool *pgxpool.Pool, sealer *crypto.Sealer, mailer mail.Mailer, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{pool: pool, q: sqlc.New(pool), sealer: sealer, mailer: mailer, logger: logger, now: time.Now}
}

// OrgEnforcesForUser reports whether ANY org the user belongs to enforces MFA (the D8/D5 predicate;
// caller gates it to local-auth logins in the enterprise edition — SSO + open edition are exempt).
func (s *Service) OrgEnforcesForUser(ctx context.Context, userID uuid.UUID) (bool, error) {
	return s.q.UserInEnforcingOrg(ctx, userID)
}

// IsEnrollmentGated reports whether the user must enroll before proceeding (D8): their org enforces
// MFA AND they have no CONFIRMED TOTP. An unconfirmed/abandoned ceremony counts as unenrolled. The
// caller applies this only in the enterprise edition (downgrade-release: open never gates).
func (s *Service) IsEnrollmentGated(ctx context.Context, userID uuid.UUID) (bool, error) {
	enforced, err := s.q.UserInEnforcingOrg(ctx, userID)
	if err != nil || !enforced {
		return false, err
	}
	confirmed, err := s.HasConfirmedTOTP(ctx, userID)
	if err != nil {
		return false, err
	}
	return !confirmed, nil
}

// SetOrgEnforce toggles org-level MFA enforcement (enterprise; PermMfaManage-gated at the handler),
// audited org-scoped with the acting admin.
func (s *Service) SetOrgEnforce(ctx context.Context, orgID, actor uuid.UUID, enforce bool) error {
	return s.withTx(ctx, func(q *sqlc.Queries) error {
		if e := q.UpsertOrgMfaEnforce(ctx, sqlc.UpsertOrgMfaEnforceParams{OrgID: orgID, Enforce: enforce}); e != nil {
			return e
		}
		action := "mfa.enforce_disabled"
		if enforce {
			action = "mfa.enforce_enabled"
		}
		return s.auditOrg(ctx, q, orgID, actor, action, "organization", orgID.String(), nil)
	})
}

// OrgEnforces reports the org's current enforce flag (for the settings UI).
func (s *Service) OrgEnforces(ctx context.Context, orgID uuid.UUID) (bool, error) {
	row, err := s.q.GetOrgMfa(ctx, orgID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil // no row = OFF (unlock-then-opt-in)
	}
	if err != nil {
		return false, err
	}
	return row.Enforce, nil
}

// AdminReset DISENROLLS another user's MFA (enterprise; PermMfaManage). It only clears the factor —
// it never authenticates as the user. Audited org-scoped (actor=admin, target=user) and the target
// is NOTIFIED best-effort (a silently-reset factor by a compromised admin must surface to the owner).
func (s *Service) AdminReset(ctx context.Context, orgID, actorAdmin, targetUser uuid.UUID) error {
	if err := s.withTx(ctx, func(q *sqlc.Queries) error {
		if e := revokeAllMfa(ctx, q, targetUser); e != nil {
			return e
		}
		return s.auditOrg(ctx, q, orgID, actorAdmin, "mfa.admin_reset", "user", targetUser.String(),
			map[string]any{"target_user": targetUser.String()})
	}); err != nil {
		return err
	}
	// Notify the target (best-effort — never fail the reset on a mail error).
	if s.mailer != nil {
		if u, e := s.q.GetUserByID(ctx, targetUser); e == nil {
			_ = s.mailer.Send(ctx, mail.MFAResetMessage(u.Email))
		}
	}
	return nil
}

func (s *Service) withTx(ctx context.Context, fn func(*sqlc.Queries) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := fn(s.q.WithTx(tx)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// StartEnrollment (OPEN) generates a fresh secret, stores it SEALED + unconfirmed (replacing any
// prior unconfirmed attempt), and returns the otpauth URI (QR) + the base32 manual key ONCE. The
// account label on the URI is the user's email (resolved here so the handler needn't thread it).
func (s *Service) StartEnrollment(ctx context.Context, userID uuid.UUID) (uri, manualKey string, err error) {
	// Refuse over a CONFIRMED factor (finding #3): UpsertUnconfirmedTOTP would silently set
	// confirmed=false and replace the secret, destroying a working second factor without the
	// deliberate disable step. Re-enrollment = disenroll first (the UI's "turn off 2FA"). An
	// UNCONFIRMED row is NOT confirmed, so starting over mid-ceremony still works (restartable).
	if existing, e := s.q.GetTOTP(ctx, userID); e == nil && existing.Confirmed {
		return "", "", apierr.Conflict("already_enrolled", "Two-factor authentication is already on. Turn it off first to set it up again.")
	} else if e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return "", "", e
	}
	user, err := s.q.GetUserByID(ctx, userID)
	if err != nil {
		return "", "", err
	}
	account := user.Email
	secret, err := GenerateSecret()
	if err != nil {
		return "", "", err
	}
	sealed, err := s.sealer.Seal([]byte(secret))
	if err != nil {
		return "", "", err
	}
	if err := s.q.UpsertUnconfirmedTOTP(ctx, sqlc.UpsertUnconfirmedTOTPParams{
		UserID: userID, SecretEnc: []byte(sealed),
	}); err != nil {
		return "", "", err
	}
	return OtpauthURI(secret, account), secret, nil
}

// ConfirmEnrollment (OPEN) arms MFA: a VALID code flips confirmed=true (verify-before-arm),
// stamps the replay clock, issues + stores single-use recovery codes (hashed), and audits
// mfa.enrolled. Returns the plaintext recovery codes ONCE.
func (s *Service) ConfirmEnrollment(ctx context.Context, userID uuid.UUID, code string) ([]string, error) {
	row, err := s.q.GetTOTP(ctx, userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apierr.BadRequest("no_pending_enrollment", "start an enrollment first")
	}
	if err != nil {
		return nil, err
	}
	if row.Confirmed {
		return nil, apierr.Conflict("already_enrolled", "MFA is already enrolled; disenroll to re-enroll")
	}
	secret, err := s.sealer.Open(string(row.SecretEnc))
	if err != nil {
		return nil, err
	}
	ts, ok := Validate(string(secret), code, s.now().Unix(), -1)
	if !ok {
		return nil, apierr.BadRequest("invalid_code", "that code is not valid")
	}

	codes, err := GenerateRecoveryCodes()
	if err != nil {
		return nil, err
	}
	if err := s.withTx(ctx, func(q *sqlc.Queries) error {
		n, e := q.ConfirmTOTP(ctx, sqlc.ConfirmTOTPParams{UserID: userID, LastUsedTimestep: &ts})
		if e != nil {
			return e
		}
		if n == 0 {
			return apierr.Conflict("already_enrolled", "MFA is already enrolled")
		}
		if e := q.DeleteRecoveryCodesForUser(ctx, userID); e != nil { // clear any stale set
			return e
		}
		for _, c := range codes {
			if e := q.InsertRecoveryCode(ctx, sqlc.InsertRecoveryCodeParams{UserID: userID, CodeHash: HashCode(c)}); e != nil {
				return e
			}
		}
		return s.audit(ctx, q, userID, userID, "mfa.enrolled", nil)
	}); err != nil {
		return nil, err
	}
	return codes, nil
}

// HasConfirmedTOTP reports whether the user has an armed TOTP (self-enrolled users are always
// challenged at login — D1). Unconfirmed enrollments do NOT count.
func (s *Service) HasConfirmedTOTP(ctx context.Context, userID uuid.UUID) (bool, error) {
	row, err := s.q.GetTOTP(ctx, userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return row.Confirmed, nil
}

// CreateChallenge mints the login second-step token (NOT a session — D6): a short-lived,
// hashed, attempt-capped challenge. Returns the RAW token + its TTL in seconds.
func (s *Service) CreateChallenge(ctx context.Context, userID uuid.UUID) (string, int, error) {
	raw, hash, err := newToken()
	if err != nil {
		return "", 0, err
	}
	if err := s.q.CreateMfaChallenge(ctx, sqlc.CreateMfaChallengeParams{
		UserID: userID, TokenHash: hash, ExpiresAt: s.now().Add(challengeTTL),
	}); err != nil {
		return "", 0, err
	}
	return raw, int(challengeTTL.Seconds()), nil
}

// VerifyChallenge resolves the login second step. It accepts a TOTP code (replay-guarded) OR a
// single-use recovery code, burns the challenge on SUCCESS or on cap exhaustion, and returns the
// authenticated user id (the handler then mints the full session). viaRecovery flags a
// recovery-code login (a security signal). The challenge + TOTP rows are locked so the
// attempt-count, replay clock, and burn all serialize.
type verifyOutcome int

const (
	outOK verifyOutcome = iota
	outChallengeGone
	outInvalid
	outExhausted
)

func (s *Service) VerifyChallenge(ctx context.Context, rawToken, code string) (sqlc.User, bool, error) {
	var userID uuid.UUID
	var viaRecovery bool
	var outcome verifyOutcome
	// The tx COMMITS regardless of the code being right or wrong — the attempt-count increment
	// and the burn-on-exhaustion MUST persist. A wrong code is signalled by an outcome value,
	// NOT by returning an error (which would roll back the increment — the terminal cap would
	// then never fire). Only a genuine infra error rolls back.
	err := s.withTx(ctx, func(q *sqlc.Queries) error {
		ch, e := q.GetMfaChallengeForUpdate(ctx, hashToken(rawToken))
		if errors.Is(e, pgx.ErrNoRows) {
			outcome = outChallengeGone
			return nil
		}
		if e != nil {
			return e
		}
		userID = ch.UserID

		// TOTP first (replay-guarded), then recovery.
		if totp, e := q.GetConfirmedTOTPForUpdate(ctx, ch.UserID); e == nil {
			last := int64(-1)
			if totp.LastUsedTimestep != nil {
				last = *totp.LastUsedTimestep
			}
			secret, oe := s.sealer.Open(string(totp.SecretEnc))
			if oe != nil {
				return oe
			}
			if ts, ok := Validate(string(secret), code, s.now().Unix(), last); ok {
				if e := q.SetTOTPLastTimestep(ctx, sqlc.SetTOTPLastTimestepParams{UserID: ch.UserID, LastUsedTimestep: &ts}); e != nil {
					return e
				}
				outcome = outOK
				return q.DeleteMfaChallenge(ctx, ch.ID) // burn on success
			}
		} else if !errors.Is(e, pgx.ErrNoRows) {
			return e
		}

		// Recovery code (atomic single-use).
		if _, e := q.ConsumeRecoveryCode(ctx, sqlc.ConsumeRecoveryCodeParams{UserID: ch.UserID, CodeHash: HashCode(code)}); e == nil {
			viaRecovery = true
			outcome = outOK
			if e := q.DeleteMfaChallenge(ctx, ch.ID); e != nil { // burn on success
				return e
			}
			return s.audit(ctx, q, ch.UserID, ch.UserID, "mfa.recovery_code_used", map[string]any{"fingerprint": s.sealer.Fingerprint([]byte(normalizeCode(code)))})
		} else if !errors.Is(e, pgx.ErrNoRows) {
			return e
		}

		// Wrong. Count against the terminal cap; burn on exhaustion. Committed either way.
		n, e := q.IncrementMfaChallengeAttempts(ctx, ch.ID)
		if e != nil {
			return e
		}
		if int(n) >= maxAttempts {
			outcome = outExhausted
			return q.DeleteMfaChallenge(ctx, ch.ID)
		}
		outcome = outInvalid
		return nil
	})
	if err != nil {
		return sqlc.User{}, false, err
	}
	switch outcome {
	case outChallengeGone:
		return sqlc.User{}, false, apierr.New(401, "mfa_challenge_invalid", "this login challenge is invalid or has expired — sign in again")
	case outExhausted:
		return sqlc.User{}, false, apierr.New(401, "mfa_challenge_exhausted", "too many attempts — sign in again")
	case outInvalid:
		return sqlc.User{}, false, apierr.New(401, "invalid_code", "that code is not valid")
	}
	user, err := s.q.GetUserByID(ctx, userID)
	if err != nil {
		return sqlc.User{}, false, err
	}
	return user, viaRecovery, nil
}

// Disenroll removes the user's TOTP + recovery codes (self re-enroll / admin reset), audited.
func (s *Service) Disenroll(ctx context.Context, actor, target uuid.UUID, action string) error {
	return s.withTx(ctx, func(q *sqlc.Queries) error {
		if e := revokeAllMfa(ctx, q, target); e != nil {
			return e
		}
		return s.audit(ctx, q, target, actor, action, nil)
	})
}

// revokeAllMfa clears a user's ENTIRE MFA state in one place — TOTP, recovery codes, AND outstanding
// login challenges (findings #6 + #10). Both Disenroll (self) and AdminReset share it, so a future
// change to "what a full revocation clears" can't drift between the two paths. A challenge is claimed
// state; revocation releases it, so a mid-login target gets a clean re-login, not attempts-to-exhaustion.
func revokeAllMfa(ctx context.Context, q *sqlc.Queries, userID uuid.UUID) error {
	if _, e := q.DeleteTOTP(ctx, userID); e != nil {
		return e
	}
	if e := q.DeleteRecoveryCodesForUser(ctx, userID); e != nil {
		return e
	}
	return q.DeleteMfaChallengesForUser(ctx, userID)
}

// CountRecoveryRemaining returns the user's unused recovery-code count (low-remaining warnings).
func (s *Service) CountRecoveryRemaining(ctx context.Context, userID uuid.UUID) (int, error) {
	n, err := s.q.CountUnusedRecoveryCodes(ctx, userID)
	return int(n), err
}

// audit scopes a user-global MFA event to the user's PRIMARY (earliest) membership org — a
// single-org user (the common case) is exact; a multi-org user gets a deterministic primary.
func (s *Service) audit(ctx context.Context, q *sqlc.Queries, subjectUser, actor uuid.UUID, action string, meta map[string]any) error {
	// Never DROP a security-relevant audit (finding #7). If the user's org can't be resolved (no
	// membership / transient query error), write the row with a NULL org_id — the schema allows it
	// (org_id is nullable, ON DELETE SET NULL) — rather than leaving only a slog line. Same law as
	// the S7.5.4 sweeper: a factor-change audit must land, org-scoped when it can be, unscoped when
	// it can't, never nowhere.
	orgParam := pgtype.UUID{}
	if orgID, err := s.primaryOrg(ctx, q, subjectUser); err == nil {
		orgParam = pgtype.UUID{Bytes: [16]byte(orgID), Valid: true}
	} else {
		s.logger.Warn("mfa_audit_org_unresolved", slog.String("user_id", subjectUser.String()), slog.String("action", action))
	}
	b := []byte("{}")
	if meta != nil {
		b, _ = json.Marshal(meta)
	}
	tt, tid := "user", subjectUser.String()
	_, err := q.InsertAuditLog(ctx, sqlc.InsertAuditLogParams{
		OrgID:       orgParam,
		ActorUserID: pgtype.UUID{Bytes: [16]byte(actor), Valid: true},
		Action:      action, TargetType: &tt, TargetID: &tid, Metadata: b,
	})
	return err
}

// auditOrg writes an ORG-scoped audit (enterprise enforce/admin-reset actions have a clear org
// context — the acting admin's org), unlike the user-primary-org scoping of self-service events.
func (s *Service) auditOrg(ctx context.Context, q *sqlc.Queries, orgID, actor uuid.UUID, action, targetType, targetID string, meta map[string]any) error {
	b := []byte("{}")
	if meta != nil {
		b, _ = json.Marshal(meta)
	}
	_, err := q.InsertAuditLog(ctx, sqlc.InsertAuditLogParams{
		OrgID:       pgtype.UUID{Bytes: [16]byte(orgID), Valid: true},
		ActorUserID: pgtype.UUID{Bytes: [16]byte(actor), Valid: true},
		Action:      action, TargetType: &targetType, TargetID: &targetID, Metadata: b,
	})
	return err
}

func (s *Service) primaryOrg(ctx context.Context, q *sqlc.Queries, userID uuid.UUID) (uuid.UUID, error) {
	ms, err := q.ListMembershipsByUser(ctx, userID)
	if err != nil {
		return uuid.Nil, err
	}
	if len(ms) == 0 {
		return uuid.Nil, errors.New("no membership")
	}
	return ms[0].OrgID, nil
}

// newToken returns a random raw challenge token + its sha256 hash (join-token hygiene).
func newToken() (raw string, hash []byte, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", nil, err
	}
	raw = base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(raw))
	return raw, h[:], nil
}

func hashToken(raw string) []byte { h := sha256.Sum256([]byte(raw)); return h[:] }
