package sso

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"log/slog"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
)

// flowHarness wires a real Service against a rolled-back tx, miniredis flow
// store, and a fake IdP — the assembled flow, end to end.
type flowHarness struct {
	svc *Service
	idp *fakeIdP
	org uuid.UUID
	tx  pgx.Tx
	q   *sqlc.Queries
	ctx context.Context
}

func newFlowHarness(t *testing.T) *flowHarness {
	t.Helper()
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(ctx) })

	org := uuid.New()
	if _, err := tx.Exec(ctx, "INSERT INTO organizations (id,name,slug) VALUES ($1,$2,$3)", org, "O", "sso-"+org.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	// An actor user for the config-write audit row's FK (audit_logs.actor_user_id).
	actor := uuid.New()
	if _, err := tx.Exec(ctx, "INSERT INTO users (id,email,name) VALUES ($1,$2,'Actor')", actor, actor.String()+"@t.local"); err != nil {
		t.Fatalf("actor: %v", err)
	}

	key := make([]byte, crypto.KeySize)
	_, _ = rand.Read(key)
	sealer, _ := crypto.NewSealer(key)

	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	idp := newFakeIdP(t, "test-client")
	q := sqlc.New(tx)
	svc := &Service{
		q:       q,
		configs: newConfigService(q, sealer),
		flows:   NewFlowStore(rdb, time.Hour),
		factory: idp.factory(),
		baseURL: "http://app",
		logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if err := svc.configs.Set(ctx, actor, org, "google", "test-client", "secret", "", true); err != nil {
		t.Fatalf("set config: %v", err)
	}
	return &flowHarness{svc: svc, idp: idp, org: org, tx: tx, q: q, ctx: ctx}
}

// start runs StartLogin and returns (state, nonce).
func (h *flowHarness) start(t *testing.T) (string, string) {
	t.Helper()
	authURL, err := h.svc.StartLogin(h.ctx, h.org, "google")
	if err != nil {
		t.Fatalf("StartLogin: %v", err)
	}
	u, _ := url.Parse(authURL)
	return u.Query().Get("state"), u.Query().Get("nonce")
}

func code(err error) string {
	var a *apierr.Error
	if err != nil && errors.As(err, &a) {
		return a.Code
	}
	return ""
}

func TestSSOFlowHappyPathCreatesUserAndMembership(t *testing.T) {
	h := newFlowHarness(t)
	state, nonce := h.start(t)
	h.idp.mint(h.idp.key, map[string]any{
		"sub": "google-123", "email": "newsso@example.com", "email_verified": true, "name": "SSO User", "nonce": nonce,
	})

	userID, err := h.svc.HandleCallback(h.ctx, "google", "any-code", state)
	if err != nil {
		t.Fatalf("HandleCallback: %v", err)
	}
	if userID == uuid.Nil {
		t.Fatal("no user id returned")
	}
	// The user exists, is verified, and is a member of the org.
	got, err := h.svc.q.GetUserByEmail(h.ctx, "newsso@example.com")
	if err != nil || got.ID != userID || !got.EmailVerifiedAt.Valid {
		t.Fatalf("user not provisioned correctly: %+v err=%v", got, err)
	}
	if _, err := h.svc.q.GetMembership(h.ctx, sqlc.GetMembershipParams{OrgID: h.org, UserID: userID}); err != nil {
		t.Fatalf("membership not created: %v", err)
	}
}

func TestSSOFlowRejectsBadState(t *testing.T) {
	h := newFlowHarness(t)
	if _, err := h.svc.HandleCallback(h.ctx, "google", "code", "not-a-real-state"); code(err) != "invalid_state" {
		t.Fatalf("bad state: want invalid_state, got %v", err)
	}
}

func TestSSOFlowStateIsSingleUse(t *testing.T) {
	h := newFlowHarness(t)
	state, nonce := h.start(t)
	h.idp.mint(h.idp.key, map[string]any{"sub": "s", "email": "once@example.com", "email_verified": true, "nonce": nonce})
	if _, err := h.svc.HandleCallback(h.ctx, "google", "code", state); err != nil {
		t.Fatalf("first callback: %v", err)
	}
	// Replaying the same state must fail (flow consumed).
	if _, err := h.svc.HandleCallback(h.ctx, "google", "code", state); code(err) != "invalid_state" {
		t.Fatalf("replayed state: want invalid_state, got %v", err)
	}
}

func TestSSOFlowRejectsTamperedSignature(t *testing.T) {
	h := newFlowHarness(t)
	state, nonce := h.start(t)
	// Sign with a DIFFERENT key than the published JWKS.
	wrongKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	h.idp.mint(wrongKey, map[string]any{"sub": "s", "email": "tamper@example.com", "email_verified": true, "nonce": nonce})
	if _, err := h.svc.HandleCallback(h.ctx, "google", "code", state); code(err) != "sso_verification_failed" {
		t.Fatalf("tampered signature: want sso_verification_failed, got %v", err)
	}
}

func TestSSOFlowRejectsNonceMismatch(t *testing.T) {
	h := newFlowHarness(t)
	state, _ := h.start(t)
	// Mint a token with the wrong nonce (replay of a different login).
	h.idp.mint(h.idp.key, map[string]any{"sub": "s", "email": "nonce@example.com", "email_verified": true, "nonce": "attacker-nonce"})
	if _, err := h.svc.HandleCallback(h.ctx, "google", "code", state); code(err) != "sso_verification_failed" {
		t.Fatalf("nonce mismatch: want sso_verification_failed, got %v", err)
	}
}
