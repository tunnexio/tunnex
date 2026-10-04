package session

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

const (
	MFAAssuranceLocalTOTP     = "local_totp"
	MFAAssuranceLocalRecovery = "local_recovery"
	MFAAssuranceSSO           = "sso_mfa"
)

// ValidMFAAssurance accepts only proof stamped by a trusted verification path.
// Freshness is checked by the application policy, independently of parent login.
func ValidMFAAssurance(at time.Time, source string, now time.Time) bool {
	if at.IsZero() || at.After(now) {
		return false
	}
	switch source {
	case MFAAssuranceLocalTOTP, MFAAssuranceLocalRecovery, MFAAssuranceSSO:
		return true
	default:
		return false
	}
}

// CreateWithMFAAuthority is for successful factor verification or validated,
// signed IdP MFA claims. Callers must never pass client-selected assurance.
func (s *Store) CreateWithMFAAuthority(ctx context.Context, userID uuid.UUID, authMethod string, epoch int64, verifiedAt time.Time, source string) (Session, error) {
	if userID == uuid.Nil || epoch <= 0 || !ValidMFAAssurance(verifiedAt, source, s.now()) {
		return Session{}, errors.New("invalid MFA session authority")
	}
	return s.createUntilWithMFA(ctx, userID, authMethod, epoch, time.Time{}, verifiedAt.UTC(), source)
}

// PromoteMFA updates only the existing parent's assurance. The compare-and-set
// cannot recreate a logged-out parent or extend either its Redis TTL or absolute
// lifetime. The caller must additionally verify durable user/logout authority.
func (s *Store) PromoteMFA(ctx context.Context, parent Session, at time.Time, source string) (Session, error) {
	if parent.ID == "" || parent.UserID == uuid.Nil || parent.AppAuthEpoch <= 0 || !ValidMFAAssurance(at, source, s.now()) {
		return Session{}, ErrNotFound
	}
	raw, err := s.rdb.Get(ctx, sessKey(parent.ID)).Bytes()
	if errors.Is(err, redis.Nil) {
		return Session{}, ErrNotFound
	}
	if err != nil {
		return Session{}, err
	}
	var current Session
	if json.Unmarshal(raw, &current) != nil || current.ID != parent.ID || current.UserID != parent.UserID ||
		current.AppAuthEpoch != parent.AppAuthEpoch || current.AuthMethod != parent.AuthMethod ||
		!current.CreatedAt.Equal(parent.CreatedAt) || !current.ExpiresAt.Equal(parent.ExpiresAt) ||
		!current.ExpiresAt.After(s.now()) || current.MFAVerifiedAt.After(at) {
		return Session{}, ErrNotFound
	}
	current.MFAVerifiedAt, current.MFAAssuranceSource = at.UTC(), source
	updated, err := json.Marshal(current)
	if err != nil {
		return Session{}, err
	}
	changed, err := s.rdb.Eval(ctx, `if redis.call('GET', KEYS[1]) ~= ARGV[1] or redis.call('PTTL', KEYS[1]) <= 0 then return 0 end
 redis.call('SET', KEYS[1], ARGV[2], 'KEEPTTL')
 return 1`, []string{sessKey(parent.ID)}, string(raw), string(updated)).Int()
	if err != nil {
		return Session{}, err
	}
	if changed != 1 || !current.ExpiresAt.After(s.now()) {
		return Session{}, ErrNotFound
	}
	return current, nil
}

// AllowMFAStepUp enforces one shared five-attempt/five-minute user budget as
// well as a parent budget. Re-login cannot reset the user cap. Keys expire and
// contain only a user UUID and a one-way hash of the parent token.
func (s *Store) AllowMFAStepUp(ctx context.Context, userID uuid.UUID, parentID string) (bool, error) {
	if userID == uuid.Nil || parentID == "" {
		return false, ErrNotFound
	}
	hash := sha256.Sum256([]byte(parentID))
	keys := []string{"mfa:attempt:user:" + userID.String(), "mfa:attempt:parent:" + hex.EncodeToString(hash[:])}
	n, err := s.rdb.Eval(ctx, `for _, key in ipairs(KEYS) do
  local value = tonumber(redis.call('GET', key) or '0')
  if value >= 5 then return 0 end
 end
 for _, key in ipairs(KEYS) do
  local value = redis.call('INCR', key)
  if value == 1 then redis.call('PEXPIRE', key, 300000) end
 end
 return 1`, keys).Int()
	return n == 1, err
}
