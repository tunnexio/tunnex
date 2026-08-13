// Package session implements Redis-backed cookie sessions.
//
// Design (S2.2):
//   - Fixation-safe: Create always mints a fresh random id; login never adopts a
//     pre-login id.
//   - Revocation index: alongside sess:{id} -> data we keep usess:{userID} -> set
//     of ids, so "revoke all sessions for a user" (password reset, deactivate,
//     log-out-everywhere) is a single sweep.
//   - Two expiries: an absolute lifetime (stored in the record) and an idle
//     timeout (the Redis TTL, refreshed on each Get).
package session

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// CookieName is the session cookie name.
const CookieName = "tunnex_session"

// ErrNotFound indicates a missing, expired, or revoked session.
var ErrNotFound = errors.New("session not found")

// Session is the stored session record.
type Session struct {
	ID        string    `json:"id"`
	UserID    uuid.UUID `json:"user_id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"` // absolute lifetime
	// AuthMethod is how this session was minted (authctx.AuthLocalPassword | AuthSSO). Immutable for
	// the session's life (fixation rule). Empty on legacy sessions minted before the marker existed.
	// No Redis migration needed: legacy sessions decode with "" and age out; the MFA gate reads "" as
	// non-local (exempt), consistent with D8 (enforce governs new logins, not live sessions).
	AuthMethod string `json:"auth_method,omitempty"`
}

// Store persists sessions in Redis.
type Store struct {
	rdb      *redis.Client
	idle     time.Duration
	absolute time.Duration
	now      func() time.Time
}

// New connects to Redis and returns a Store. idle is the sliding inactivity
// timeout; absolute is the hard maximum lifetime.
func New(redisURL string, idle, absolute time.Duration) (*Store, error) {
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("parse redis url: %w", err)
	}
	return &Store{rdb: redis.NewClient(opt), idle: idle, absolute: absolute, now: time.Now}, nil
}

// NewWithClient builds a Store over an existing client (used in tests).
func NewWithClient(rdb *redis.Client, idle, absolute time.Duration) *Store {
	return &Store{rdb: rdb, idle: idle, absolute: absolute, now: time.Now}
}

// Client exposes the underlying Redis client (reused by the SSO flow store).
func (s *Store) Client() *redis.Client { return s.rdb }

func sessKey(id string) string   { return "sess:" + id }
func userKey(u uuid.UUID) string { return "usess:" + u.String() }

// Create mints a brand-new session for userID (fresh id => fixation-safe). authMethod records HOW
// the user authenticated (authctx.AuthLocalPassword | AuthSSO) — stamped once, immutable thereafter.
func (s *Store) Create(ctx context.Context, userID uuid.UUID, authMethod string) (Session, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return Session{}, err
	}
	now := s.now()
	sess := Session{
		ID:         base64.RawURLEncoding.EncodeToString(b),
		UserID:     userID,
		CreatedAt:  now,
		ExpiresAt:  now.Add(s.absolute),
		AuthMethod: authMethod,
	}
	data, err := json.Marshal(sess)
	if err != nil {
		return Session{}, err
	}
	pipe := s.rdb.TxPipeline()
	pipe.Set(ctx, sessKey(sess.ID), data, s.idle)
	pipe.SAdd(ctx, userKey(userID), sess.ID)
	pipe.Expire(ctx, userKey(userID), s.absolute)
	if _, err := pipe.Exec(ctx); err != nil {
		return Session{}, err
	}
	return sess, nil
}

// Get returns a live session, refreshing its idle TTL (sliding). Expired or
// missing sessions return ErrNotFound (and expired ones are cleaned up).
func (s *Store) Get(ctx context.Context, id string) (Session, error) {
	data, err := s.rdb.Get(ctx, sessKey(id)).Bytes()
	if errors.Is(err, redis.Nil) {
		return Session{}, ErrNotFound
	}
	if err != nil {
		return Session{}, err
	}
	var sess Session
	if err := json.Unmarshal(data, &sess); err != nil {
		return Session{}, ErrNotFound
	}
	if s.now().After(sess.ExpiresAt) {
		_ = s.Delete(ctx, id)
		return Session{}, ErrNotFound
	}
	// Slide the idle window, but never beyond the absolute expiry.
	ttl := s.idle
	if remaining := time.Until(sess.ExpiresAt); remaining < ttl {
		ttl = remaining
	}
	s.rdb.Expire(ctx, sessKey(id), ttl)
	return sess, nil
}

// Delete removes a single session and de-indexes it.
func (s *Store) Delete(ctx context.Context, id string) error {
	if data, err := s.rdb.Get(ctx, sessKey(id)).Bytes(); err == nil {
		var sess Session
		if json.Unmarshal(data, &sess) == nil {
			s.rdb.SRem(ctx, userKey(sess.UserID), id)
		}
	}
	return s.rdb.Del(ctx, sessKey(id)).Err()
}

// DeleteAllForUser revokes every session belonging to a user (password reset,
// deactivate, log-out-everywhere).
func (s *Store) DeleteAllForUser(ctx context.Context, userID uuid.UUID) error {
	ids, err := s.rdb.SMembers(ctx, userKey(userID)).Result()
	if err != nil {
		return err
	}
	pipe := s.rdb.TxPipeline()
	for _, id := range ids {
		pipe.Del(ctx, sessKey(id))
	}
	pipe.Del(ctx, userKey(userID))
	_, err = pipe.Exec(ctx)
	return err
}

// SetCookie writes the session cookie. secure MUST be true in production; the
// caller logs loudly when it is false.
func SetCookie(w http.ResponseWriter, sess Session, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    sess.ID,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode, // Lax (not Strict): Strict would drop the cookie on the SSO redirect return (S2.3/2.4).
		Expires:  sess.ExpiresAt,
	})
}

// ClearCookie expires the session cookie.
func ClearCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}
