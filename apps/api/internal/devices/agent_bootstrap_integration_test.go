//go:build enterprise

package devices

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/internal/nodepush"
)

func TestManagedAgentBootstrapIsHashedSingleUseAndClientKeyed(t *testing.T) {
	f := agentBootstrapFixture(t)
	tok, err := f.svc.IssueAgentBootstrapToken(f.ctx, f.owner, f.org, f.node, "managed-agent")
	if err != nil {
		t.Fatal(err)
	}
	if tok == "" {
		t.Fatal("issue must return the one-time token")
	}
	h := sha256.Sum256([]byte(tok))
	var stored []byte
	if err := f.pool.QueryRow(f.ctx, "SELECT token_hash FROM agent_bootstrap_tokens WHERE org_id=$1", f.org).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if string(stored) == tok || string(stored) == string([]byte(tok)) {
		t.Fatal("raw bootstrap token persisted")
	}
	if string(stored) != string(h[:]) {
		t.Fatalf("stored token is not SHA-256: %x", stored)
	}

	pub := testAgentPublicKey(f.deviceSeed)
	res, err := f.svc.Create(f.ctx, CreateInput{BootstrapToken: tok, PublicKey: pub})
	if err != nil {
		t.Fatal(err)
	}
	if res.PrivateKeyOneTime != "" || res.RuntimeCredential == "" {
		t.Fatal("bootstrap must use client key and return runtime credential once")
	}
	if !contains(res.Config, "__TUNNEX_PRIVATE_KEY__") {
		t.Fatal("bootstrap config must contain only a private-key placeholder")
	}
	var rawKey string
	if err := f.pool.QueryRow(f.ctx, "SELECT public_key FROM devices WHERE id=$1", res.Device.ID).Scan(&rawKey); err != nil {
		t.Fatal(err)
	}
	if rawKey != pub {
		t.Fatalf("stored public key = %q, want client key", rawKey)
	}
	rh := sha256.Sum256([]byte(res.RuntimeCredential))
	var storedRuntime []byte
	if err := f.pool.QueryRow(f.ctx, "SELECT token_hash FROM agent_runtime_credentials WHERE device_id=$1", res.Device.ID).Scan(&storedRuntime); err != nil {
		t.Fatal(err)
	}
	if string(storedRuntime) != string(rh[:]) || string(storedRuntime) == res.RuntimeCredential {
		t.Fatal("runtime credential was not stored as a hash")
	}

	if _, err := f.svc.Create(f.ctx, CreateInput{BootstrapToken: tok, PublicKey: testAgentPublicKey(f.deviceSeed + 1)}); err == nil || !contains(err.Error(), "invalid_bootstrap_token") {
		t.Fatalf("consumed token must be rejected uniformly, got %v", err)
	}

	expired := "expired-f03-token"
	eh := sha256.Sum256([]byte(expired))
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO agent_bootstrap_tokens (org_id,gateway_node_id,agent_name,token_hash,expires_at,created_at,issued_by) VALUES ($1,$2,'expired',$3,now()-interval '1 hour',now()-interval '2 hours',$4)`, f.org, f.node, eh[:], f.owner); err != nil {
		t.Fatal(err)
	}
	_, err = f.svc.Create(f.ctx, CreateInput{BootstrapToken: "not-a-token", PublicKey: testAgentPublicKey(30)})
	if err == nil {
		t.Fatal("wrong token must be rejected")
	}
	_, expiredErr := f.svc.Create(f.ctx, CreateInput{BootstrapToken: expired, PublicKey: testAgentPublicKey(31)})
	if expiredErr == nil || err.Error() != expiredErr.Error() {
		t.Fatalf("wrong and expired tokens must have identical refusal: wrong=%v expired=%v", err, expiredErr)
	}
}

func TestManagedAgentBootstrapConcurrentRedemptionCreatesOneDevice(t *testing.T) {
	f := agentBootstrapFixture(t)
	tok, err := f.svc.IssueAgentBootstrapToken(f.ctx, f.owner, f.org, f.node, "race-agent")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, e := f.svc.Create(f.ctx, CreateInput{BootstrapToken: tok, PublicKey: testAgentPublicKey(f.deviceSeed + i + 3)})
			results <- e
		}(i)
	}
	wg.Wait()
	close(results)
	var success, failure int
	for err := range results {
		if err == nil {
			success++
		} else if contains(err.Error(), "invalid_bootstrap_token") {
			failure++
		}
	}
	if success != 1 || failure != 1 {
		t.Fatalf("concurrent redemption results: success=%d invalid=%d", success, failure)
	}
	var devices, credentials int
	if err := f.pool.QueryRow(f.ctx, "SELECT count(*) FROM devices WHERE org_id=$1 AND kind='agent'", f.org).Scan(&devices); err != nil {
		t.Fatal(err)
	}
	if err := f.pool.QueryRow(f.ctx, "SELECT count(*) FROM agent_runtime_credentials WHERE org_id=$1", f.org).Scan(&credentials); err != nil {
		t.Fatal(err)
	}
	if devices != 1 || credentials != 1 {
		t.Fatalf("created devices=%d credentials=%d, want one each", devices, credentials)
	}
}

func TestManagedAgentBootstrapConcurrentQuotaEnforcementIsAtomic(t *testing.T) {
	f := agentBootstrapFixture(t)
	if _, err := f.pool.Exec(f.ctx, `UPDATE organizations SET max_agent_identities=1 WHERE id=$1`, f.org); err != nil {
		t.Fatal(err)
	}
	tokA, err := f.svc.IssueAgentBootstrapToken(f.ctx, f.owner, f.org, f.node, "quota-a")
	if err != nil {
		t.Fatal(err)
	}
	tokB, err := f.svc.IssueAgentBootstrapToken(f.ctx, f.owner, f.org, f.node, "quota-b")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i, token := range []string{tokA, tokB} {
		wg.Add(1)
		go func(i int, token string) {
			defer wg.Done()
			_, e := f.svc.Create(f.ctx, CreateInput{BootstrapToken: token, PublicKey: testAgentPublicKey(80 + i)})
			results <- e
		}(i, token)
	}
	wg.Wait()
	close(results)
	var success, quotaRefusal int
	for err := range results {
		if err == nil {
			success++
		} else if contains(err.Error(), "agent_quota_exceeded") {
			quotaRefusal++
		} else {
			t.Fatalf("unexpected concurrent quota result: %v", err)
		}
	}
	if success != 1 || quotaRefusal != 1 {
		t.Fatalf("quota race results: success=%d quota_refusal=%d, want 1/1", success, quotaRefusal)
	}
	var count int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM devices WHERE org_id=$1 AND kind='agent' AND status IN ('pending','active','suspended') AND deleted_at IS NULL`, f.org).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("counted agent identities=%d, want 1", count)
	}
	var existing uuid.UUID
	if err := f.pool.QueryRow(f.ctx, `SELECT id FROM devices WHERE org_id=$1 AND kind='agent' ORDER BY created_at LIMIT 1`, f.org).Scan(&existing); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE devices SET status='suspended' WHERE id=$1`, existing); err != nil {
		t.Fatal(err)
	}
	pausedToken, err := f.svc.IssueAgentBootstrapToken(f.ctx, f.owner, f.org, f.node, "quota-paused")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Create(f.ctx, CreateInput{BootstrapToken: pausedToken, PublicKey: testAgentPublicKey(90)}); err == nil || !contains(err.Error(), "agent_quota_exceeded") {
		t.Fatalf("suspended identity must count toward quota, got %v", err)
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE devices SET status='revoked', revoked_at=now() WHERE id=$1`, existing); err != nil {
		t.Fatal(err)
	}
	revokedToken, err := f.svc.IssueAgentBootstrapToken(f.ctx, f.owner, f.org, f.node, "quota-revoked")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Create(f.ctx, CreateInput{BootstrapToken: revokedToken, PublicKey: testAgentPublicKey(91)}); err != nil {
		t.Fatalf("revoked identity must not count toward quota: %v", err)
	}
}

func TestManagedAgentBootstrapBindsRedemptionToTokenOrganizationAndGateway(t *testing.T) {
	f := agentBootstrapFixture(t)
	tok, err := f.svc.IssueAgentBootstrapToken(f.ctx, f.owner, f.org, f.node, "bound-agent")
	if err != nil {
		t.Fatal(err)
	}

	forgedOrg, forgedNode, forgedOwner := uuid.New(), uuid.New(), uuid.New()
	res, err := f.svc.Create(f.ctx, CreateInput{
		BootstrapToken: tok,
		PublicKey:      testAgentPublicKey(44),
		OrgID:          forgedOrg,
		NodeID:         forgedNode,
		OwnerID:        forgedOwner,
		ActorID:        forgedOwner,
		Name:           "caller-controlled-name",
		Kind:           "agent",
	})
	if err != nil {
		t.Fatalf("token-bound redemption should use the token row rather than caller scope: %v", err)
	}
	if res.Device.OrgID != f.org || res.Device.NodeID != f.node {
		t.Fatalf("device escaped token binding: org=%s node=%s want org=%s node=%s", res.Device.OrgID, res.Device.NodeID, f.org, f.node)
	}

	var forgedDevices, forgedCredentials int
	if err := f.pool.QueryRow(f.ctx, "SELECT count(*) FROM devices WHERE org_id=$1 OR node_id=$2", forgedOrg, forgedNode).Scan(&forgedDevices); err != nil {
		t.Fatal(err)
	}
	if err := f.pool.QueryRow(f.ctx, "SELECT count(*) FROM agent_runtime_credentials WHERE org_id=$1", forgedOrg).Scan(&forgedCredentials); err != nil {
		t.Fatal(err)
	}
	if forgedDevices != 0 || forgedCredentials != 0 {
		t.Fatalf("forged caller scope created rows: devices=%d credentials=%d", forgedDevices, forgedCredentials)
	}

	var boundCredentials int
	if err := f.pool.QueryRow(f.ctx, "SELECT count(*) FROM agent_runtime_credentials WHERE org_id=$1 AND device_id=$2", f.org, res.Device.ID).Scan(&boundCredentials); err != nil {
		t.Fatal(err)
	}
	if boundCredentials != 1 {
		t.Fatalf("token-bound runtime credential count=%d, want 1", boundCredentials)
	}
}

type agentBootstrapTestFixture struct {
	ctx              context.Context
	pool             *pgxpool.Pool
	svc              *Service
	org, owner, node uuid.UUID
	deviceSeed       int
}

func agentBootstrapFixture(t *testing.T) *agentBootstrapTestFixture {
	t.Helper()
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	f := &agentBootstrapTestFixture{ctx: ctx, pool: pool, org: uuid.New(), owner: uuid.New(), node: uuid.New(), deviceSeed: 10}
	t.Cleanup(pool.Close)
	ex := func(q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	ex("INSERT INTO organizations (id,name,slug,pool_cidr,max_devices_per_user) VALUES ($1,'F03',$2,'10.99.0.0/24',0)", f.org, "f03-"+f.org.String())
	ex("INSERT INTO users (id,email,name,status) VALUES ($1,$2,'F03','active')", f.owner, f.owner.String()+"@f03.test")
	ex("INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'owner')", f.org, f.owner)
	ex("INSERT INTO nodes (id,org_id,name,cert_serial,wg_public_key,endpoint,status) VALUES ($1,$2,'f03-gw',$3,$4,'gw.example:51820','active')", f.node, f.org, "f03-"+f.node.String(), "c2VydmVycHVia2V5MDAwMDAwMDAwMDAwMDAwMDAwMD0=")
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), "DELETE FROM organizations WHERE id=$1", f.org) })
	f.svc = NewService(pool, nodepush.New(), nil)
	return f
}

func testAgentPublicKey(n int) string {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(n + i)
	}
	return base64.StdEncoding.EncodeToString(b)
}
func contains(s, sub string) bool { return strings.Contains(s, sub) }
