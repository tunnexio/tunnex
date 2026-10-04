package mfa

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

func mfaParentInvalid() error {
	return apierr.New(401, "mfa_session_invalid", "sign in again before verifying a second factor")
}

// lockMFAUser serializes new ceremonies with factor reset and verifies the
// epoch of the authenticated parent. Zero is only for the legacy internal
// enrollment API; HTTP always supplies the verified parent's positive epoch.
func lockMFAUser(ctx context.Context, q *sqlc.Queries, userID uuid.UUID, epoch int64) (sqlc.User, error) {
	user, err := q.GetMFAUserForUpdate(ctx, userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return sqlc.User{}, mfaParentInvalid()
	}
	if err != nil {
		return sqlc.User{}, err
	}
	if user.Status != "active" || (epoch != 0 && user.AppAuthEpoch != epoch) {
		return sqlc.User{}, mfaParentInvalid()
	}
	return user, nil
}

// StartEnrollmentWithAuthority refuses stale parents before replacing a pending
// ceremony. The user lock also prevents replacing a concurrently confirmed factor.
func (s *Service) StartEnrollmentWithAuthority(ctx context.Context, userID uuid.UUID, epoch int64) (uri, manualKey string, err error) {
	if epoch <= 0 {
		return "", "", mfaParentInvalid()
	}
	return s.startEnrollment(ctx, userID, epoch)
}

func (s *Service) startEnrollment(ctx context.Context, userID uuid.UUID, epoch int64) (uri, manualKey string, err error) {
	err = s.withTx(ctx, func(q *sqlc.Queries) error {
		user, e := lockMFAUser(ctx, q, userID, epoch)
		if e != nil {
			return e
		}
		existing, e := q.GetTOTPForUpdate(ctx, userID)
		if e == nil && existing.Confirmed {
			return apierr.Conflict("already_enrolled", "Two-factor authentication is already on. Turn it off first to set it up again.")
		}
		if e != nil && !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		secret, e := GenerateSecret()
		if e != nil {
			return e
		}
		sealed, e := s.sealer.Seal([]byte(secret))
		if e != nil {
			return e
		}
		if e = q.UpsertUnconfirmedTOTP(ctx, sqlc.UpsertUnconfirmedTOTPParams{UserID: userID, SecretEnc: []byte(sealed)}); e != nil {
			return e
		}
		uri, manualKey = OtpauthURI(secret, user.Email), secret
		return nil
	})
	if err != nil {
		return "", "", err
	}
	return uri, manualKey, nil
}

// ConfirmEnrollmentWithAuthority verifies the actual locked secret before
// arming it and returns recovery codes exactly once. No org enforcement changes.
func (s *Service) ConfirmEnrollmentWithAuthority(ctx context.Context, userID uuid.UUID, epoch int64, code string) ([]string, time.Time, error) {
	if epoch <= 0 {
		return nil, time.Time{}, mfaParentInvalid()
	}
	return s.confirmEnrollment(ctx, userID, epoch, code)
}

func (s *Service) confirmEnrollment(ctx context.Context, userID uuid.UUID, epoch int64, code string) ([]string, time.Time, error) {
	var codes []string
	var verifiedAt time.Time
	err := s.withTx(ctx, func(q *sqlc.Queries) error {
		if _, e := lockMFAUser(ctx, q, userID, epoch); e != nil {
			return e
		}
		row, e := q.GetTOTPForUpdate(ctx, userID)
		if errors.Is(e, pgx.ErrNoRows) {
			return apierr.BadRequest("no_pending_enrollment", "start an enrollment first")
		}
		if e != nil {
			return e
		}
		if row.Confirmed {
			return apierr.Conflict("already_enrolled", "MFA is already enrolled; disenroll to re-enroll")
		}
		secret, e := s.sealer.Open(string(row.SecretEnc))
		if e != nil {
			return e
		}
		now := s.now().UTC()
		ts, ok := Validate(string(secret), code, now.Unix(), -1)
		if !ok {
			return apierr.BadRequest("invalid_code", "that code is not valid")
		}
		codes, e = GenerateRecoveryCodes()
		if e != nil {
			return e
		}
		n, e := q.ConfirmTOTP(ctx, sqlc.ConfirmTOTPParams{UserID: userID, LastUsedTimestep: &ts})
		if e != nil {
			return e
		}
		if n != 1 {
			return apierr.Conflict("already_enrolled", "MFA is already enrolled")
		}
		if e = q.DeleteRecoveryCodesForUser(ctx, userID); e != nil {
			return e
		}
		for _, code := range codes {
			if e = q.InsertRecoveryCode(ctx, sqlc.InsertRecoveryCodeParams{UserID: userID, CodeHash: HashCode(code)}); e != nil {
				return e
			}
		}
		verifiedAt = now
		return s.audit(ctx, q, userID, userID, "mfa.enrolled", nil)
	})
	if err != nil {
		return nil, time.Time{}, err
	}
	return codes, verifiedAt, nil
}

// VerifyStepUp consumes a factor for an existing authenticated parent, never a
// login challenge. The HTTP layer applies the Redis attempt budget first.
func (s *Service) VerifyStepUp(ctx context.Context, userID uuid.UUID, epoch int64, code string) (time.Time, bool, error) {
	if epoch <= 0 {
		return time.Time{}, false, mfaParentInvalid()
	}
	var verifiedAt time.Time
	var recovery bool
	err := s.withTx(ctx, func(q *sqlc.Queries) error {
		if _, e := lockMFAUser(ctx, q, userID, epoch); e != nil {
			return e
		}
		factor, e := q.GetConfirmedTOTPForUpdate(ctx, userID)
		if errors.Is(e, pgx.ErrNoRows) {
			return apierr.New(403, "mfa_setup_required", "set up two-factor authentication first")
		}
		if e != nil {
			return e
		}
		secret, e := s.sealer.Open(string(factor.SecretEnc))
		if e != nil {
			return e
		}
		last := int64(-1)
		if factor.LastUsedTimestep != nil {
			last = *factor.LastUsedTimestep
		}
		now := s.now().UTC()
		if ts, valid := Validate(string(secret), code, now.Unix(), last); valid {
			if e = q.SetTOTPLastTimestep(ctx, sqlc.SetTOTPLastTimestepParams{UserID: userID, LastUsedTimestep: &ts}); e != nil {
				return e
			}
		} else {
			if _, e = q.ConsumeRecoveryCode(ctx, sqlc.ConsumeRecoveryCodeParams{UserID: userID, CodeHash: HashCode(code)}); errors.Is(e, pgx.ErrNoRows) {
				return apierr.New(401, "invalid_code", "that code is not valid")
			} else if e != nil {
				return e
			}
			recovery = true
			if e = s.audit(ctx, q, userID, userID, "mfa.recovery_code_used", map[string]any{"fingerprint": s.sealer.Fingerprint([]byte(normalizeCode(code)))}); e != nil {
				return e
			}
		}
		verifiedAt = now
		return s.audit(ctx, q, userID, userID, "mfa.step_up", map[string]any{"via_recovery": recovery})
	})
	if err != nil {
		return time.Time{}, false, err
	}
	user, err := s.q.GetUserByID(ctx, userID)
	if err != nil {
		return time.Time{}, false, err
	}
	if user.Status != "active" || user.AppAuthEpoch != epoch {
		return time.Time{}, false, mfaParentInvalid()
	}
	return verifiedAt, recovery, nil
}
