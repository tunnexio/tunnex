package session

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// Password re-authentication budget (SA-UI-1). Separate from the MFA step-up budget and charged only by
// FAILED password checks, so an administrator who re-enters the right password is never limited.
const (
	ReauthPasswordFailureLimit  = 5
	ReauthPasswordFailureWindow = 5 * time.Minute
)

func reauthPasswordKey(scope string, user uuid.UUID) string {
	return "reauth:password:fail:" + scope + ":" + user.String()
}

// ReauthPasswordAllowed reports whether the user still has failure budget for scope.
func (s *Store) ReauthPasswordAllowed(ctx context.Context, scope string, user uuid.UUID) (bool, error) {
	if user == uuid.Nil || scope == "" {
		return false, ErrNotFound
	}
	n, err := s.rdb.Get(ctx, reauthPasswordKey(scope, user)).Int()
	if err != nil && !errors.Is(err, redis.Nil) {
		return false, err
	}
	return n < ReauthPasswordFailureLimit, nil
}

// RecordReauthPasswordFailure charges one failed attempt; the window starts at the first failure.
func (s *Store) RecordReauthPasswordFailure(ctx context.Context, scope string, user uuid.UUID) error {
	if user == uuid.Nil || scope == "" {
		return ErrNotFound
	}
	key := reauthPasswordKey(scope, user)
	_, err := s.rdb.Eval(ctx, `local v = redis.call('INCR', KEYS[1])
if v == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
return v`, []string{key}, ReauthPasswordFailureWindow.Milliseconds()).Int()
	return err
}
