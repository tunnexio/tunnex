package http

import (
	"context"
	"crypto/ed25519"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/devices"
	"github.com/tunnexio/tunnex/apps/api/internal/licence"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"github.com/tunnexio/tunnex/apps/api/internal/release"
)

func TestAgentBootstrapReleaseFailureIsAtomicAndOrdered(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL for release-metadata atomicity proof")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	org := uuid.New()
	_, err = pool.Exec(ctx, `INSERT INTO organizations (id,name,slug,pool_cidr) VALUES ($1,'F3 release atomicity',$2,'10.111.0.0/24')`, org, "f3-release-"+org.String()[:8])
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, org) })

	countAndHashes := func() (int64, string) {
		t.Helper()
		var count int64
		var hashes string
		if err := pool.QueryRow(ctx, `
			SELECT count(*), coalesce(string_agg(encode(token_hash,'hex'), ',' ORDER BY encode(token_hash,'hex')), '')
			FROM agent_bootstrap_tokens WHERE org_id=$1`, org).Scan(&count, &hashes); err != nil {
			t.Fatal(err)
		}
		return count, hashes
	}
	beforeCount, beforeHashes := countAndHashes()

	req := api.IssueAgentBootstrapTokenRequestObject{
		OrgId: org,
		Body:  &api.AgentBootstrapTokenRequest{GatewayId: uuid.New(), Name: "f3-atomicity"},
	}
	ownerCtx := principalWithRole(org, rbac.RoleOwner)
	enterpriseUnavailable := apiServer{
		devices: devices.NewService(pool, nil, nil),
		licence: licence.NewTestManager("scale", time.Now().Add(time.Hour)),
		policy:  NewPolicyPort(pool, nil),
		// A failed release.Load/Verify leaves this projection unavailable.
		releaseBootstrap: nil,
	}
	_, missingErr := enterpriseUnavailable.IssueAgentBootstrapToken(ownerCtx, req)
	if !hasCode(missingErr, 503, "bootstrap_unavailable") {
		t.Fatalf("missing authoritative descriptor: want generic 503, got %v", missingErr)
	}
	if strings.Contains(errString(missingErr), "bootstrap_token") || strings.Contains(errString(missingErr), "release.json") || strings.Contains(errString(missingErr), "source_sha") {
		t.Fatalf("descriptor failure leaked token/provenance metadata: %v", missingErr)
	}

	// An invalid signed descriptor is rejected before it can become the server
	// projection; the handler sees the same unavailable state and must remain
	// atomic. This keeps the test on the authoritative failure boundary without
	// inventing an invalid BootstrapRelease value.
	if err := release.Verify(release.SignedManifest{}, ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))); err == nil {
		t.Fatal("invalid signed descriptor unexpectedly verified")
	}
	if _, err := enterpriseUnavailable.IssueAgentBootstrapToken(ownerCtx, req); !hasCode(err, 503, "bootstrap_unavailable") {
		t.Fatalf("invalid authoritative descriptor: want generic 503, got %v", err)
	}
	afterCount, afterHashes := countAndHashes()
	if afterCount != beforeCount || afterHashes != beforeHashes {
		t.Fatalf("descriptor failure mutated bootstrap tokens: before=%d/%q after=%d/%q", beforeCount, beforeHashes, afterCount, afterHashes)
	}

	if _, err := enterpriseUnavailable.IssueAgentBootstrapToken(ctx, req); !hasCode(err, 401, "unauthenticated") {
		t.Fatalf("unauthenticated request: want 401 before descriptor lookup, got %v", err)
	}
	communityUnavailable := enterpriseUnavailable
	communityUnavailable.licence = licence.NewTestManager("community", time.Now().Add(time.Hour))
	if _, err := communityUnavailable.IssueAgentBootstrapToken(ownerCtx, req); !hasCode(err, 503, "bootstrap_unavailable") {
		t.Fatalf("community request: base enrollment must reach the real descriptor guard, got %v", err)
	}
	finalCount, finalHashes := countAndHashes()
	if finalCount != beforeCount || finalHashes != beforeHashes {
		t.Fatalf("ordering refusals mutated bootstrap tokens: before=%d/%q after=%d/%q", beforeCount, beforeHashes, finalCount, finalHashes)
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
