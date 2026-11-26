package http

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/mfa"
	"github.com/tunnexio/tunnex/apps/api/internal/password"
	"github.com/tunnexio/tunnex/apps/api/internal/session"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
	"github.com/tunnexio/tunnex/apps/api/internal/vault"
)

// VAULT-UX-1 V17: the body limit admits the largest valid secret, worst-case escaped.
func TestVaultBodyLimitMatchesSecretLimit(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	org, user := uuid.New(), uuid.New()
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Vault limits',$2)`, []any{org, "vault-limits-" + org.String()}},
		{`INSERT INTO users(id,email,name,email_verified_at) VALUES($1,$2,'Limit user',now())`, []any{user, user.String() + "@example.test"}},
		{`INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'member')`, []any{org, user}},
	} {
		if _, err := pool.Exec(ctx, q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	sealer, err := crypto.NewSealer(bytes.Repeat([]byte{19}, crypto.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	h := vaultSecurityRouter(t, Deps{Vault: vault.New(pool, sealer), AuthFn: func(*http.Request) *authctx.Principal { return vaultSecurityPrincipal(org, user, "member") }})
	base := "/api/v1/organizations/" + org.String() + "/vault/entries"
	// Each astral character is escaped by JSON encoders as a surrogate pair: 12 bytes.
	escaped := func(n int) string { return strings.Repeat(`🔑`, n) }
	body := func(secret string) string {
		return `{"title":"Largest key","kind":"api_key","visibility":"personal","service_name":"Limits","secret":"` + secret + `"}`
	}
	if w := vaultSecurityRequest(h, "POST", base, body(escaped(16384)), true); w.Code != 201 {
		t.Fatalf("maximum secret refused: %d %s", w.Code, w.Body.String())
	}
	if w := vaultSecurityRequest(h, "POST", base, body(escaped(16385)), true); w.Code != 400 {
		t.Fatalf("one past the maximum: %d", w.Code)
	}
	w := vaultSecurityRequest(h, "POST", base, body(strings.Repeat("a", 300<<10)), true)
	if w.Code != 413 || !strings.Contains(w.Body.String(), "16,384 characters") {
		t.Fatalf("oversized body: %d %s", w.Code, w.Body.String())
	}
}

// VAULT-UX-1 V4: shared reveals re-authenticate through requireRecentReauthentication; personal ones do not;
// every reveal is budgeted.
func TestVaultRevealStepUpAndRateLimit(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	q := sqlc.New(pool)
	org := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Vault step-up',$2)`, org, "vault-stepup-"+org.String()); err != nil {
		t.Fatal(err)
	}
	hash, err := password.Hash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	mkUser := func(email, role string) sqlc.User {
		u, e := q.CreateUser(ctx, sqlc.CreateUserParams{Email: email, Name: role + " user"})
		if e != nil {
			t.Fatal(e)
		}
		if _, e = pool.Exec(ctx, `UPDATE users SET email_verified_at=now(), password_hash=$2 WHERE id=$1`, u.ID, hash); e != nil {
			t.Fatal(e)
		}
		if _, e = pool.Exec(ctx, `INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,$3)`, org, u.ID, role); e != nil {
			t.Fatal(e)
		}
		return u
	}
	admin, alice := mkUser("vault-stepup-admin@app.test", "admin"), mkUser("vault-stepup-alice@app.test", "member")
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1})
	t.Cleanup(func() { _ = rdb.Close() })
	store := session.NewWithClient(rdb, time.Hour, 24*time.Hour)
	sealer, err := crypto.NewSealer(bytes.Repeat([]byte{23}, crypto.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	vs := vault.New(pool, sealer)
	server := apiServer{system: q, sessions: store, mfa: mfa.NewService(pool, sealer, nil, nil), vault: vs}
	svc, err := vs.AddService(ctx, org, admin.ID, "Step-up service")
	if err != nil {
		t.Fatal(err)
	}
	kind := api.VaultCreateInputSubjectKind("user")
	secret := "vault-stepup-shared-secret"
	shared, err := vs.Create(ctx, org, admin.ID, api.VaultCreateInput{Title: "Shared", Kind: "password", Visibility: "assigned", ServiceId: &svc.Id, Secret: &secret, SubjectKind: &kind, SubjectId: &alice.ID})
	if err != nil {
		t.Fatal(err)
	}
	personalSecret, privateService := "vault-stepup-personal-secret", "Private"
	mine, err := vs.Create(ctx, org, alice.ID, api.VaultCreateInput{Title: "Mine", Kind: "password", Visibility: "personal", ServiceName: &privateService, Secret: &personalSecret})
	if err != nil {
		t.Fatal(err)
	}
	parent, err := store.CreateWithAuthority(ctx, alice.ID, authctx.AuthLocalPassword, alice.AppAuthEpoch)
	if err != nil {
		t.Fatal(err)
	}
	as := func() context.Context {
		c := mfaHandlerContext(ctx, parent)
		p, _ := authctx.PrincipalFrom(c)
		p.Roles = map[uuid.UUID]string{org: "member"}
		return c
	}
	str := func(v string) *string { return &v }
	reveal := func(id uuid.UUID, pw *string, purpose api.VaultRevealInputPurpose) (api.VaultSecret, error) {
		out, e := server.RevealVaultEntry(as(), api.RevealVaultEntryRequestObject{OrgId: org, EntryId: id, Body: &api.VaultRevealInput{CurrentPassword: pw, Purpose: &purpose}})
		if e != nil {
			return api.VaultSecret{}, e
		}
		return api.VaultSecret(out.(api.RevealVaultEntry200JSONResponse)), nil
	}

	listed, err := server.ListVaultEntries(as(), api.ListVaultEntriesRequestObject{OrgId: org})
	if err != nil {
		t.Fatal(err)
	}
	ws := listed.(api.ListVaultEntries200JSONResponse)
	if ws.Reauthentication == nil || !ws.Reauthentication.Password || ws.Reauthentication.Mfa || !ws.Reauthentication.Available {
		t.Fatalf("workspace must say what a shared reveal will ask for: %+v", ws.Reauthentication)
	}
	if _, err = reveal(shared.Id, nil, "reveal"); mfaHandlerErrorCode(err) != "current_password_required" {
		t.Fatalf("missing password: %v", err)
	}
	if _, err = reveal(shared.Id, str("wrong"), "reveal"); mfaHandlerErrorCode(err) != "invalid_credentials" {
		t.Fatalf("wrong password: %v", err)
	}
	got, err := reveal(shared.Id, str("correct horse battery staple"), "copy")
	if err != nil || got.Value != secret {
		t.Fatalf("re-authenticated shared copy: %v", err)
	}
	if got, err = reveal(mine.Id, nil, "reveal"); err != nil || got.Value != personalSecret {
		t.Fatalf("personal reveal must not need re-authentication: %v", err)
	}
	var copied, revealed int
	if err = pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE action='vault.copied'), count(*) FILTER (WHERE action='vault.revealed') FROM audit_logs WHERE org_id=$1`, org).Scan(&copied, &revealed); err != nil || copied != 1 || revealed != 1 {
		t.Fatalf("audit copied=%d revealed=%d %v", copied, revealed, err)
	}

	// With an authenticator enrolled, a fresh MFA within five minutes is also required.
	mfaHandlerEnroll(t, ctx, server, parent)
	if _, err = reveal(shared.Id, str("correct horse battery staple"), "reveal"); mfaHandlerErrorCode(err) != "mfa_step_up_required" {
		t.Fatalf("stale MFA: %v", err)
	}
	if got, err = reveal(mine.Id, nil, "reveal"); err != nil {
		t.Fatalf("personal reveal must not need MFA: %v", err)
	}
	parent, err = store.CreateWithMFAAuthority(ctx, alice.ID, authctx.AuthLocalPassword, alice.AppAuthEpoch, time.Now(), session.MFAAssuranceLocalTOTP)
	if err != nil {
		t.Fatal(err)
	}
	if got, err = reveal(shared.Id, str("correct horse battery staple"), "reveal"); err != nil || got.Value != secret {
		t.Fatalf("fresh MFA reveal: %v", err)
	}

	// The budget: personal and shared alike, per person and organization.
	// Every attempt is charged, refused ones included, so loop until the store says no.
	for i := 0; i < session.VaultRevealLimit+1; i++ {
		_, err = reveal(mine.Id, nil, "reveal")
		if err != nil {
			break
		}
	}
	if mfaHandlerErrorCode(err) != "vault_reveal_rate_limited" {
		t.Fatalf("rate limit: %v", err)
	}
	mr.FastForward(session.VaultRevealWindow + time.Second)
	if _, err = reveal(mine.Id, nil, "reveal"); err != nil {
		t.Fatalf("budget did not reset: %v", err)
	}
	raw, _ := json.Marshal(ws)
	if strings.Contains(string(raw), secret) {
		t.Fatal("workspace leaked a secret")
	}
}
