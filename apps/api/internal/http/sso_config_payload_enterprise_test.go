//go:build enterprise

package http

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	tcrypto "github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/licence"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

// TestGetSsoConfigPayloadCarriesNoSecret is the BLOCKING security assertion
// (gates job, `make test-editions`) that SATISFIES the twice-deferred S4.5
// secret-payload claim: the SSO config READ endpoint returns the keyed
// fingerprint but NEVER the client secret (plaintext or sealed). It exercises
// the REAL read handler against a live DB in the enterprise build — the
// substitute (settings.spec.ts:25) only checked the open-edition 403 gate, which
// proves the endpoint is hidden, NOT that its payload is secret-free when served.
//
// The config is written through the REAL audited ConfigService.Set (via the SSO
// port) — NOT a shortcut upsert — so the sealing + the secret-free audit-metadata
// path (the exact S4.5 concern family: secret must not leak into audit_logs
// either) stays under coverage. Cleanup can't cascade-delete the org because the
// audit_logs row is APPEND-ONLY (its trigger REFUSES the SET NULL the FK cascade
// attempts), so the cleanup deletes children explicitly under a test-only
// `session_replication_role = replica` trigger bypass — no product-code change,
// no shared-DB leak.
func TestGetSsoConfigPayloadCarriesNoSecret(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	org := uuid.New()
	actor := uuid.New()
	// Cleanup DELETEs the rows THEN closes the pool (own-defers would unwind before
	// t.Cleanup, hitting a closed pool → a silent leak inflating countRealOrgs).
	// The audited write leaves an append-only audit_logs row that blocks the normal
	// org-delete cascade, so we drop triggers for the cleanup connection only
	// (session_replication_role=replica), delete children + org + actor explicitly,
	// then restore — on ITS OWN acquired conn so the setting never escapes to a
	// pooled connection, and the pool is closed right after regardless.
	t.Cleanup(func() {
		c, cc := context.WithTimeout(context.Background(), 10*time.Second)
		defer cc()
		defer pool.Close()
		conn, err := pool.Acquire(c)
		if err != nil {
			return
		}
		defer conn.Release()
		if _, err := conn.Exec(c, "SET session_replication_role = replica"); err != nil {
			return
		}
		_, _ = conn.Exec(c, "DELETE FROM audit_logs WHERE org_id=$1", org)
		_, _ = conn.Exec(c, "DELETE FROM sso_configs WHERE org_id=$1", org)
		_, _ = conn.Exec(c, "DELETE FROM organizations WHERE id=$1", org)
		_, _ = conn.Exec(c, "DELETE FROM users WHERE id=$1", actor)
		_, _ = conn.Exec(c, "SET session_replication_role = default")
	})

	// A real org + actor to satisfy FKs (Set writes an audit row referencing both).
	if _, err := pool.Exec(ctx, "INSERT INTO organizations (id,name,slug) VALUES ($1,$2,$3)",
		org, "O", "s45-"+org.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, "INSERT INTO users (id,email,name) VALUES ($1,$2,'Actor')",
		actor, actor.String()+"@t.local"); err != nil {
		t.Fatalf("actor: %v", err)
	}

	masterKey := make([]byte, tcrypto.KeySize)
	if _, err := rand.Read(masterKey); err != nil {
		t.Fatal(err)
	}
	sealer, err := tcrypto.NewSealer(masterKey)
	if err != nil {
		t.Fatal(err)
	}
	const secret = "super-secret-google-client-secret-payload-guard"
	const clientID = "client-id-abc.apps.googleusercontent.com"

	// Write through the REAL audited path (seals the secret, records a secret-free
	// audit event), then read back through the REAL handler.
	port := NewSSOPort(pool, sealer, nil, "", nil, slog.Default())
	if err := port.SetConfig(ctx, actor, org, "google", clientID, secret, "", true); err != nil {
		t.Fatalf("set config: %v", err)
	}

	// ⚠ A LICENCE IS REQUIRED TO REACH THIS HANDLER AS OF S12.1 SLICE 8, and supplying one here is
	// deliberate rather than incidental: this test's subject is the PAYLOAD, not the entitlement. Leaving
	// it unlicensed would turn a blocking secret-leak assertion into a 403 check that passes for the wrong
	// reason — the strongest possible version of a test that no longer tests what it says it does.
	s := apiServer{sso: port, licence: licence.NewTestManager("starter", time.Now().Add(time.Hour))}
	authed := principalWithRole(org, rbac.RoleOwner)
	resp, err := s.GetSsoConfig(authed, api.GetSsoConfigRequestObject{OrgId: org, Provider: "google"})
	if err != nil {
		t.Fatalf("GetSsoConfig: %v", err)
	}
	ok, isOK := resp.(api.GetSsoConfig200JSONResponse)
	if !isOK {
		t.Fatalf("want 200 JSON response, got %T", resp)
	}

	raw, err := json.Marshal(ok.Body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	blob := string(raw)

	// (1) The secret must not appear anywhere in the wire payload.
	if strings.Contains(blob, secret) {
		t.Fatalf("payload leaked the client secret: %s", blob)
	}
	// (2) No field named client_secret is serialized.
	if strings.Contains(strings.ToLower(blob), "client_secret") {
		t.Fatalf("payload exposes a client_secret field: %s", blob)
	}
	// (3) The keyed fingerprint IS present — proves which secret is stored without
	//     ever revealing it (the positive half of the S4.5 assertion).
	wantFP := sealer.Fingerprint([]byte(secret))
	if !strings.Contains(blob, wantFP) {
		t.Fatalf("payload missing secret_fingerprint %q: %s", wantFP, blob)
	}
	// (4) The client id IS surfaced — the View is functional, not an empty stub.
	if !strings.Contains(blob, clientID) {
		t.Fatalf("payload missing client_id: %s", blob)
	}

	// (5) The audited write must not leak the secret into audit_logs metadata
	//     either — the same S4.5 concern, one table over. Set records a
	//     sso.config_updated event; its metadata carries the fingerprint, not the
	//     secret. (Only reachable now that the write goes through the real Set.)
	var auditMeta string
	if err := pool.QueryRow(ctx,
		`SELECT metadata::text FROM audit_logs
		   WHERE org_id=$1 AND action='sso.config_updated'
		   ORDER BY created_at DESC LIMIT 1`, org).Scan(&auditMeta); err != nil {
		t.Fatalf("audit row: %v", err)
	}
	if strings.Contains(auditMeta, secret) {
		t.Fatalf("audit metadata leaked the client secret: %s", auditMeta)
	}
	if strings.Contains(strings.ToLower(auditMeta), "client_secret") {
		t.Fatalf("audit metadata exposes a client_secret field: %s", auditMeta)
	}
	if !strings.Contains(auditMeta, wantFP) {
		t.Fatalf("audit metadata missing the secret fingerprint proof: %s", auditMeta)
	}
}
