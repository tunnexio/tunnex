// Package cliauth is the server side of the S5.1 CLI credential flow: one-time
// loopback authorization codes (browser consent leg), the device-code fallback,
// and the dedicated header-borne CLI credentials they mint.
//
// Hygiene class (join tokens / auth_tokens): every secret is random, stored
// hashed, single-use where applicable, expiring, and identity-bound. Audit rows
// carry the KEYED fingerprint only (proof-of-secret convention) with a NULL
// org_id — CLI credentials are user-scoped, not org-scoped.
package cliauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
)

const (
	// TokenPrefix makes leaked credentials pattern-matchable by secret scanners.
	TokenPrefix = "tnx_"

	// CredentialTTL is the absolute credential lifetime (decision 1: 90 days, no
	// refresh machinery in S5.1 — `tunnex login` again is the refresh).
	CredentialTTL = 90 * 24 * time.Hour

	// AuthCodeTTL bounds the loopback code (decision 3).
	AuthCodeTTL = 60 * time.Second

	// DeviceCodeTTL / DevicePollInterval bound the device-code fallback.
	DeviceCodeTTL      = 15 * time.Minute
	DevicePollInterval = 5 * time.Second
)

// Service implements the CLI credential flow.
type Service struct {
	pool   *pgxpool.Pool
	q      *sqlc.Queries
	sealer *crypto.Sealer
}

// NewService builds the CLI auth service.
func NewService(pool *pgxpool.Pool, sealer *crypto.Sealer) *Service {
	return &Service{pool: pool, q: sqlc.New(pool), sealer: sealer}
}

// MintForUser mints a CLI bearer credential for a user OUT OF BAND (no browser/device flow) —
// for privileged bootstrap tooling only (the S7.5.2 box-walk drives the enterprise endpoints with
// it). Not wired to any HTTP handler.
func (s *Service) MintForUser(ctx context.Context, userID uuid.UUID) (Credential, error) {
	var cred Credential
	err := s.withTx(ctx, func(q *sqlc.Queries) error {
		var e error
		cred, e = s.mintCredential(ctx, q, userID, "walk-bootstrap")
		return e
	})
	return cred, err
}

func (s *Service) withTx(ctx context.Context, fn func(*sqlc.Queries) error) error {
	if s.pool == nil {
		return fn(s.q)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit
	if err := fn(sqlc.New(tx)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ValidateLoopbackRedirect enforces decision 3's allowlist: http, host EXACTLY
// 127.0.0.1 or ::1 (never a hostname — "localhost" is DNS-spoofable), an
// explicit port, path exactly /callback, nothing else on the URL.
func ValidateLoopbackRedirect(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return apierr.BadRequest("invalid_redirect", "redirect_uri is not a valid URL")
	}
	host := u.Hostname()
	switch {
	case u.Scheme != "http",
		host != "127.0.0.1" && host != "::1",
		u.Port() == "",
		u.Path != "/callback",
		u.RawQuery != "" || u.Fragment != "" || u.User != nil:
		return apierr.BadRequest("invalid_redirect",
			"redirect_uri must be http://127.0.0.1:<port>/callback (or [::1]) — loopback IP literal, explicit port, exactly /callback")
	}
	return nil
}

// MintAuthCode mints the one-time loopback authorization code (consent leg).
// The code is bound to the exact redirect and the PKCE S256 challenge.
func (s *Service) MintAuthCode(ctx context.Context, userID uuid.UUID, redirectURI, codeChallenge string) (code string, expiresIn int, err error) {
	if err := ValidateLoopbackRedirect(redirectURI); err != nil {
		return "", 0, err
	}
	// PKCE must actually be in effect: reject a challenge that is not a 43-char
	// base64url S256 digest at MINT time (loud failure), rather than silently
	// minting a code that can never be redeemed (a self-DoS a broken client
	// wouldn't understand).
	if !isS256Challenge(codeChallenge) {
		return "", 0, apierr.BadRequest("invalid_challenge",
			"code_challenge must be a base64url-encoded SHA-256 (S256) PKCE challenge")
	}
	raw, hash, err := newSecret("tnxc_")
	if err != nil {
		return "", 0, err
	}
	_, err = s.q.CreateCliAuthCode(ctx, sqlc.CreateCliAuthCodeParams{
		UserID: userID, CodeHash: hash, RedirectUri: redirectURI,
		CodeChallenge: codeChallenge, ExpiresAt: time.Now().Add(AuthCodeTTL),
	})
	if err != nil {
		return "", 0, err
	}
	return raw, int(AuthCodeTTL.Seconds()), nil
}

// Credential is the mint result. Token appears here EXACTLY ONCE.
type Credential struct {
	Token       string
	Fingerprint string
	ExpiresAt   time.Time
}

// ExchangeCode redeems a one-time code (+ PKCE verifier + exact redirect) for a
// CLI credential. Any mismatch, reuse, or expiry is the same generic
// invalid_grant — no oracle for which check failed.
func (s *Service) ExchangeCode(ctx context.Context, code, codeVerifier, redirectURI string) (Credential, error) {
	invalid := apierr.BadRequest("invalid_grant", "the authorization code is invalid, used, or expired")
	var cred Credential
	err := s.withTx(ctx, func(q *sqlc.Queries) error {
		row, e := q.ConsumeCliAuthCode(ctx, hash(code))
		if errors.Is(e, pgx.ErrNoRows) {
			return invalid
		}
		if e != nil {
			return e
		}
		// PKCE S256: challenge must equal base64url(sha256(verifier)).
		want := base64.RawURLEncoding.EncodeToString(func() []byte { h := sha256.Sum256([]byte(codeVerifier)); return h[:] }())
		if subtle.ConstantTimeCompare([]byte(want), []byte(row.CodeChallenge)) != 1 {
			return invalid
		}
		// Exact redirect binding (host+port+path, decision 3).
		if redirectURI != row.RedirectUri {
			return invalid
		}
		var e2 error
		cred, e2 = s.mintCredential(ctx, q, row.UserID, "loopback")
		return e2
	})
	if err != nil {
		return Credential{}, err
	}
	return cred, nil
}

// mintCredential creates the credential and its audit row in the SAME tx.
func (s *Service) mintCredential(ctx context.Context, q *sqlc.Queries, userID uuid.UUID, via string) (Credential, error) {
	raw, h, err := newSecret(TokenPrefix)
	if err != nil {
		return Credential{}, err
	}
	fp := s.sealer.Fingerprint([]byte(raw))
	row, err := q.CreateCliCredential(ctx, sqlc.CreateCliCredentialParams{
		UserID: userID, Name: "tunnex-cli", TokenHash: h, Fingerprint: fp,
		ExpiresAt: time.Now().Add(CredentialTTL),
	})
	if err != nil {
		return Credential{}, err
	}
	// User-scoped audit: org_id NULL (CLI credentials span orgs); fingerprint
	// only — never the token (proof-of-secret convention).
	if err := auditUserScoped(ctx, q, userID, "cli.credential_issued",
		map[string]any{"fingerprint": fp, "via": via, "credential_id": row.ID.String()}); err != nil {
		return Credential{}, err
	}
	return Credential{Token: raw, Fingerprint: fp, ExpiresAt: row.ExpiresAt}, nil
}

// List returns the caller's live credentials (metadata only).
func (s *Service) List(ctx context.Context, userID uuid.UUID) ([]sqlc.CliCredential, error) {
	return s.q.ListCliCredentialsForUser(ctx, userID)
}

// Revoke revokes one of the CALLER'S credentials. Idempotent; another user's
// credential id is indistinguishable from an already-revoked one (no leak).
func (s *Service) Revoke(ctx context.Context, userID, credentialID uuid.UUID) error {
	return s.withTx(ctx, func(q *sqlc.Queries) error {
		n, err := q.RevokeCliCredential(ctx, sqlc.RevokeCliCredentialParams{ID: credentialID, UserID: userID})
		if err != nil {
			return err
		}
		if n == 0 {
			return nil // idempotent: already revoked / not yours — same 204
		}
		return auditUserScoped(ctx, q, userID, "cli.credential_revoked",
			map[string]any{"credential_id": credentialID.String()})
	})
}

// DeviceStart begins the device-code fallback.
type DeviceStart struct {
	DeviceCode string
	UserCode   string
	ExpiresIn  int
	Interval   int
}

// StartDevice mints the device_code/user_code pair (both stored hashed).
func (s *Service) StartDevice(ctx context.Context) (DeviceStart, error) {
	device, dh, err := newSecret("tnxd_")
	if err != nil {
		return DeviceStart{}, err
	}
	user, err := newUserCode()
	if err != nil {
		return DeviceStart{}, err
	}
	if _, err := s.q.CreateCliDeviceCode(ctx, sqlc.CreateCliDeviceCodeParams{
		DeviceCodeHash: dh, UserCodeHash: hash(user), ExpiresAt: time.Now().Add(DeviceCodeTTL),
	}); err != nil {
		return DeviceStart{}, err
	}
	return DeviceStart{
		DeviceCode: device, UserCode: user,
		ExpiresIn: int(DeviceCodeTTL.Seconds()), Interval: int(DevicePollInterval.Seconds()),
	}, nil
}

// ApproveDevice is the browser leg's human checkpoint: it binds the verified
// user to the pending code. Unknown/expired/already-approved codes are one
// generic refusal (no oracle).
func (s *Service) ApproveDevice(ctx context.Context, userID uuid.UUID, userCode string) error {
	n, err := s.q.ApproveCliDeviceCode(ctx, sqlc.ApproveCliDeviceCodeParams{
		UserCodeHash: hash(normalizeUserCode(userCode)),
		UserID:       pgtype.UUID{Bytes: [16]byte(userID), Valid: true},
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return apierr.BadRequest("invalid_grant", "the code is invalid, used, or expired")
	}
	return nil
}

// PollDevice is the CLI's polling exchange: pending until approved, then the
// credential exactly once.
func (s *Service) PollDevice(ctx context.Context, deviceCode string) (Credential, error) {
	invalid := apierr.BadRequest("invalid_grant", "the device code is invalid, used, or expired")
	var cred Credential
	err := s.withTx(ctx, func(q *sqlc.Queries) error {
		row, e := q.GetCliDeviceCodeByDeviceHash(ctx, hash(deviceCode))
		if errors.Is(e, pgx.ErrNoRows) {
			return invalid
		}
		if e != nil {
			return e
		}
		if !row.ApprovedAt.Valid || !row.UserID.Valid {
			return apierr.BadRequest("authorization_pending", "the code has not been approved yet")
		}
		if _, e := q.ConsumeCliDeviceCode(ctx, hash(deviceCode)); e != nil {
			if errors.Is(e, pgx.ErrNoRows) {
				return invalid // consumed concurrently
			}
			return e
		}
		var e2 error
		cred, e2 = s.mintCredential(ctx, q, uuid.UUID(row.UserID.Bytes), "device")
		return e2
	})
	if err != nil {
		return Credential{}, err
	}
	return cred, nil
}

// SweepUser revokes ALL of a user's live CLI credentials — called by password
// reset and account deactivation with the same-tx queries handle, so the sweep
// commits or fails WITH the triggering mutation.
func SweepUser(ctx context.Context, q *sqlc.Queries, userID uuid.UUID) error {
	return q.RevokeAllCliCredentialsForUser(ctx, userID)
}

// ---- helpers ----------------------------------------------------------------

// newSecret returns (raw with prefix, sha256 of raw).
func newSecret(prefix string) (string, []byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	raw := prefix + base64.RawURLEncoding.EncodeToString(b)
	return raw, hash(raw), nil
}

func hash(raw string) []byte { h := sha256.Sum256([]byte(raw)); return h[:] }

// newUserCode returns a short human-typable code (XXXX-XXXX, unambiguous set).
// Rejection sampling keeps the distribution UNIFORM — a plain byte%28 would bias
// toward the first four symbols (256 mod 28 = 4) and shave entropy.
func newUserCode() (string, error) {
	const alphabet = "BCDFGHJKLMNPQRSTVWXZ23456789" // no vowels (no words), no 0/O/1/I
	out := make([]byte, 0, 9)
	for len(out) < 9 {
		if len(out) == 4 {
			out = append(out, '-')
			continue
		}
		i, err := uniformIndex(len(alphabet))
		if err != nil {
			return "", err
		}
		out = append(out, alphabet[i])
	}
	return string(out), nil
}

// uniformIndex returns a uniform int in [0,n) via rejection sampling.
func uniformIndex(n int) (int, error) {
	max := 256 - (256 % n) // reject bytes at/above this to remove modulo bias
	b := make([]byte, 1)
	for {
		if _, err := rand.Read(b); err != nil {
			return 0, err
		}
		if int(b[0]) < max {
			return int(b[0]) % n, nil
		}
	}
}

// isS256Challenge reports whether s is a 43-char base64url (no padding) string —
// the exact shape of a base64url(SHA-256) PKCE challenge.
func isS256Challenge(s string) bool {
	if len(s) != 43 {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil
}

// normalizeUserCode is forgiving about case and a missing dash.
func normalizeUserCode(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, " ", "")
	if len(s) == 8 && !strings.Contains(s, "-") {
		s = s[:4] + "-" + s[4:]
	}
	return s
}

func auditUserScoped(ctx context.Context, q *sqlc.Queries, actor uuid.UUID, action string, meta map[string]any) error {
	b, _ := json.Marshal(meta)
	targetType := "cli_credential"
	targetID := ""
	if v, ok := meta["credential_id"].(string); ok {
		targetID = v
	}
	_, err := q.InsertAuditLog(ctx, sqlc.InsertAuditLogParams{
		OrgID:       pgtype.UUID{}, // NULL: user-scoped, spans orgs
		ActorUserID: pgtype.UUID{Bytes: [16]byte(actor), Valid: true},
		Action:      action, TargetType: &targetType, TargetID: &targetID, Metadata: b,
	})
	return err
}
