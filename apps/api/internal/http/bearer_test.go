package http

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/cliauth"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/tenancy"
)

// S5.1 bearer-credential semantics at the FULL router (middleware chain incl.
// csrfGuard + spec validator):
//   - a valid bearer authenticates exactly like a cookie (bearer ≡ cookie);
//   - a bearer MUTATION needs no cookie and no X-Tunnex-CSRF header (csrfGuard
//     is cookie-keyed and therefore inert for the CLI — D3's point);
//   - a REVOKED bearer is a generic 401 (no revocation oracle);
//   - an EXPIRED bearer is a DISTINCT 401 credential_expired (the CLI's
//     "run 'tunnex login'" UX hangs off this code).
func TestBearerCredentialSemantics(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	// A real (non-tx) user: the router's queries run on the pool. Cleanup cascades.
	userID := uuid.New()
	email := "bearer-" + userID.String() + "@walk.local"
	if _, err := pool.Exec(ctx,
		"INSERT INTO users (id,email,name,email_verified_at) VALUES ($1,$2,$3,now())", userID, email, "Bearer T"); err != nil {
		t.Fatalf("user: %v", err)
	}
	defer pool.Exec(context.Background(), "DELETE FROM audit_logs WHERE actor_user_id=$1", userID) //nolint:errcheck
	defer pool.Exec(context.Background(), "DELETE FROM users WHERE id=$1", userID)                 //nolint:errcheck

	key := make([]byte, crypto.KeySize)
	_, _ = rand.Read(key)
	sealer, _ := crypto.NewSealer(key)
	svc := cliauth.NewService(pool, sealer)

	router, err := NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{
		Orgs:     tenancy.NewService(pool),
		CliAuth:  svc,
		BearerFn: BearerAuth(sqlc.New(pool)),
	})
	if err != nil {
		t.Fatalf("router: %v", err)
	}
	srv := httptest.NewServer(router)
	defer srv.Close()

	// Mint two credentials via the REAL loopback exchange.
	mint := func() cliauth.Credential {
		vb := make([]byte, 32)
		_, _ = rand.Read(vb)
		verifier := base64.RawURLEncoding.EncodeToString(vb)
		ch := sha256.Sum256([]byte(verifier))
		code, _, err := svc.MintAuthCode(ctx, userID, "http://127.0.0.1:7/callback", base64.RawURLEncoding.EncodeToString(ch[:]))
		if err != nil {
			t.Fatalf("mint code: %v", err)
		}
		cred, err := svc.ExchangeCode(ctx, code, verifier, "http://127.0.0.1:7/callback")
		if err != nil {
			t.Fatalf("exchange: %v", err)
		}
		return cred
	}
	cred1, cred2 := mint(), mint()

	do := func(method, path, bearer string) *http.Response {
		req, _ := http.NewRequest(method, srv.URL+path, nil)
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		return resp
	}

	// bearer ≡ cookie: an org-gated endpoint accepts the bearer principal.
	if resp := do("GET", "/api/v1/organizations", cred1.Token); resp.StatusCode != 200 {
		t.Fatalf("bearer on gated GET: want 200, got %d", resp.StatusCode)
	}
	// Self-scoped list works and never contains token material.
	resp := do("GET", "/api/v1/auth/cli/credentials", cred1.Token)
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(body), cred1.Fingerprint) {
		t.Fatalf("list: %d %s", resp.StatusCode, body)
	}
	if strings.Contains(string(body), cred1.Token) || strings.Contains(string(body), cred2.Token) {
		t.Fatal("credential list leaked token material")
	}

	// COOKIE-ONLY MINTING (the argued exception, decision b) — a bearer must NOT
	// be able to mint a new credential from an existing one (self-replication).
	// This is the deliberate-red guard: refused with 403 session_required.
	mintBody := strings.NewReader(`{"redirect_uri":"http://127.0.0.1:9/callback","code_challenge":"` + strings.Repeat("a", 43) + `","state":"x"}`)
	mreq, _ := http.NewRequest("POST", srv.URL+"/api/v1/auth/cli/authorize", mintBody)
	mreq.Header.Set("Content-Type", "application/json")
	mreq.Header.Set("Authorization", "Bearer "+cred1.Token)
	mresp, err := srv.Client().Do(mreq)
	if err != nil {
		t.Fatalf("mint-from-bearer: %v", err)
	}
	mrb, _ := io.ReadAll(mresp.Body)
	if mresp.StatusCode != 403 || !strings.Contains(string(mrb), "session_required") {
		t.Fatalf("bearer minting a credential: want 403 session_required, got %d — %s", mresp.StatusCode, mrb)
	}

	// Locate cred2's id by PARSING the list (not string-slicing — a field-order
	// change must not silently mis-target the revoke).
	var creds []struct {
		Id          string `json:"id"`
		Fingerprint string `json:"fingerprint"`
	}
	if err := json.Unmarshal(body, &creds); err != nil {
		t.Fatalf("parse list: %v", err)
	}
	var cred2ID string
	for _, c := range creds {
		if c.Fingerprint == cred2.Fingerprint {
			cred2ID = c.Id
		}
	}
	if cred2ID == "" {
		t.Fatal("could not locate cred2 id in list")
	}

	// THE CSRF-INERT PROOF: an unsafe-method mutation with a bearer, NO cookie,
	// NO X-Tunnex-CSRF header — csrfGuard must not interfere (it is cookie-keyed).
	if resp := do("DELETE", "/api/v1/auth/cli/credentials/"+cred2ID, cred1.Token); resp.StatusCode != 204 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("bearer DELETE without CSRF header: want 204, got %d — %s", resp.StatusCode, b)
	}

	// NO-ORACLE: REVOKED, EXPIRED, and UNKNOWN bearers must ALL be byte-identical
	// 401s — an attacker probing a stolen token learns nothing (not "was real,
	// revoked", not "was real, aged out", not "never existed"). Expiry is
	// surfaced to the CLI from its LOCAL expires_at, so the server carries no
	// distinct code. cred2 is revoked; cred1 we age out; a random tnx_ is unknown.
	h := sha256.Sum256([]byte(cred1.Token))
	if _, err := pool.Exec(ctx, "UPDATE cli_credentials SET expires_at = now() - interval '1 second' WHERE token_hash=$1", h[:]); err != nil {
		t.Fatalf("expire: %v", err)
	}
	revokedBody := get401(t, do, cred2.Token)
	expiredBody := get401(t, do, cred1.Token)
	unknownBody := get401(t, do, "tnx_"+strings.Repeat("z", 43))
	if !bytes.Equal(stripReqID(revokedBody), stripReqID(unknownBody)) {
		t.Fatalf("revoked vs unknown NOT identical (oracle):\n revoked=%s\n unknown=%s", revokedBody, unknownBody)
	}
	if !bytes.Equal(stripReqID(expiredBody), stripReqID(unknownBody)) {
		t.Fatalf("expired vs unknown NOT identical (oracle):\n expired=%s\n unknown=%s", expiredBody, unknownBody)
	}
	if strings.Contains(string(expiredBody), "credential_expired") {
		t.Fatalf("expired bearer leaked a distinct oracle code: %s", expiredBody)
	}

	// DEACTIVATED user's bearer → generic 401 (independent of the sweep — a
	// direct status flip that didn't run SweepUser must still kill the credential).
	// A freshly-minted live credential isolates the status path (cred1 is expired).
	live := mint()
	if _, err := pool.Exec(ctx, "UPDATE users SET status='deactivated' WHERE id=$1", userID); err != nil {
		t.Fatalf("deactivate: %v", err)
	}
	if resp := do("GET", "/api/v1/auth/cli/credentials", live.Token); resp.StatusCode != 401 {
		t.Fatalf("deactivated user's bearer: want 401, got %d", resp.StatusCode)
	}
	if _, err := pool.Exec(ctx, "UPDATE users SET status='active' WHERE id=$1", userID); err != nil {
		t.Fatalf("reactivate: %v", err)
	}

	// No bearer at all → generic 401 (the walk covers this per-op already).
	if resp := do("GET", "/api/v1/auth/cli/credentials", ""); resp.StatusCode != 401 {
		t.Fatalf("no auth: want 401, got %d", resp.StatusCode)
	}
}

// get401 does a GET expecting a 401 and returns its body.
func get401(t *testing.T, do func(string, string, string) *http.Response, bearer string) []byte {
	t.Helper()
	resp := do("GET", "/api/v1/auth/cli/credentials", bearer)
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 401 {
		t.Fatalf("want 401, got %d — %s", resp.StatusCode, body)
	}
	return body
}

// stripReqID removes the per-request request_id so two error envelopes can be
// compared for the no-oracle property (only request_id legitimately differs).
func stripReqID(b []byte) []byte {
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return b
	}
	if e, ok := m["error"].(map[string]any); ok {
		delete(e, "request_id")
	}
	out, _ := json.Marshal(m)
	return out
}
