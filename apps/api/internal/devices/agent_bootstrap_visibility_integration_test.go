package devices

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/internal/nodepush"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

// AI-SEC-1 item 6: a bootstrap token is a live credential, so issuing one is
// audited, a pending one can be listed and revoked, and a revoked one is
// refused exactly like an expired one. No test here may ever read the raw
// token or its hash back out of the audit trail or the listing.

type bootstrapVisibilityFixture struct {
	ctx              context.Context
	pool             *pgxpool.Pool
	svc              *Service
	org, owner, node uuid.UUID
}

func newBootstrapVisibilityFixture(t *testing.T) *bootstrapVisibilityFixture {
	t.Helper()
	ctx, pool := testpostgres.New(t)
	f := &bootstrapVisibilityFixture{ctx: ctx, pool: pool}
	f.org, f.owner, f.node = f.seedOrg(t, "10.98.0.0/24")
	f.svc = NewService(pool, nodepush.New(), nil)
	return f
}

func (f *bootstrapVisibilityFixture) exec(t *testing.T, query string, args ...any) {
	t.Helper()
	if _, err := f.pool.Exec(f.ctx, query, args...); err != nil {
		t.Fatal(err)
	}
}

func (f *bootstrapVisibilityFixture) seedOrg(t *testing.T, cidr string) (org, owner, node uuid.UUID) {
	t.Helper()
	org, owner, node = uuid.New(), uuid.New(), uuid.New()
	f.exec(t, `INSERT INTO organizations (id,name,slug,pool_cidr,max_devices_per_user) VALUES ($1,'AI-SEC-1',$2,$3,0)`, org, "aisec1-"+org.String(), cidr)
	f.exec(t, `INSERT INTO users (id,email,name,status) VALUES ($1,$2,'Token Issuer','active')`, owner, owner.String()+"@aisec1.test")
	f.exec(t, `INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'owner')`, org, owner)
	key := make([]byte, 32)
	copy(key, node[:])
	f.exec(t, `INSERT INTO nodes (id,org_id,name,cert_serial,wg_public_key,endpoint,status) VALUES ($1,$2,'aisec1-gateway',$3,$4,'gw.example:51820','active')`, node, org, "aisec1-"+node.String(), base64.StdEncoding.EncodeToString(key))
	return org, owner, node
}

type bootstrapAuditRow struct {
	actor    *uuid.UUID
	targetID string
	metadata string
}

func (f *bootstrapVisibilityFixture) auditRows(t *testing.T, org uuid.UUID, action string) []bootstrapAuditRow {
	t.Helper()
	rows, err := f.pool.Query(f.ctx, `SELECT actor_user_id, coalesce(target_type,''), coalesce(target_id,''), metadata::text FROM audit_logs WHERE org_id=$1 AND action=$2 ORDER BY created_at, id`, org, action)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []bootstrapAuditRow
	for rows.Next() {
		var row bootstrapAuditRow
		var targetType string
		if err := rows.Scan(&row.actor, &targetType, &row.targetID, &row.metadata); err != nil {
			t.Fatal(err)
		}
		if targetType != "agent_bootstrap_token" {
			t.Fatalf("%s target_type = %q, want agent_bootstrap_token", action, targetType)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func assertNoTokenMaterial(t *testing.T, where, text, raw string) {
	t.Helper()
	hash := sha256.Sum256([]byte(raw))
	for _, secret := range []string{raw, strings.TrimPrefix(raw, "tnx_agent_"), hex.EncodeToString(hash[:]), base64.StdEncoding.EncodeToString(hash[:]), base64.RawURLEncoding.EncodeToString(hash[:])} {
		if strings.Contains(text, secret) {
			t.Fatalf("%s contains bootstrap token material", where)
		}
	}
}

func TestIssuingAgentBootstrapTokenIsAudited(t *testing.T) {
	f := newBootstrapVisibilityFixture(t)
	before := time.Now()
	raw, err := f.svc.IssueAgentBootstrapToken(f.ctx, f.owner, f.org, f.node, "audited-agent")
	if err != nil {
		t.Fatal(err)
	}
	var tokenID uuid.UUID
	var expiresAt time.Time
	if err := f.pool.QueryRow(f.ctx, `SELECT id, expires_at FROM agent_bootstrap_tokens WHERE org_id=$1`, f.org).Scan(&tokenID, &expiresAt); err != nil {
		t.Fatal(err)
	}
	rows := f.auditRows(t, f.org, "agent.bootstrap_token_issued")
	if len(rows) != 1 {
		t.Fatalf("issued audit rows = %d, want 1", len(rows))
	}
	row := rows[0]
	if row.actor == nil || *row.actor != f.owner {
		t.Fatalf("issued audit actor = %v, want the issuing user", row.actor)
	}
	if row.targetID != tokenID.String() {
		t.Fatalf("issued audit target = %q, want token row id %s", row.targetID, tokenID)
	}
	var meta map[string]any
	if err := json.Unmarshal([]byte(row.metadata), &meta); err != nil {
		t.Fatal(err)
	}
	if meta["agent_name"] != "audited-agent" || meta["gateway_id"] != f.node.String() {
		t.Fatalf("issued audit metadata = %v", meta)
	}
	recorded, err := time.Parse(time.RFC3339, meta["expires_at"].(string))
	if err != nil {
		t.Fatalf("expires_at is not RFC 3339: %v", meta["expires_at"])
	}
	if recorded.Before(before.Add(59*time.Minute)) || recorded.Sub(expiresAt).Abs() > time.Second {
		t.Fatalf("audited expiry %s does not match stored expiry %s", recorded, expiresAt)
	}
	if len(meta) != 3 {
		t.Fatalf("issued audit metadata carries unexpected keys: %v", meta)
	}
	assertNoTokenMaterial(t, "issued audit row", row.metadata+row.targetID, raw)
}

func TestRefusedAgentBootstrapTokenIssueLeavesNoTokenAndNoAudit(t *testing.T) {
	f := newBootstrapVisibilityFixture(t)
	f.exec(t, `UPDATE nodes SET status='revoked' WHERE id=$1`, f.node)
	if _, err := f.svc.IssueAgentBootstrapToken(f.ctx, f.owner, f.org, f.node, "refused-agent"); err == nil {
		t.Fatal("an inactive gateway must refuse issuance")
	}
	if _, err := f.svc.IssueAgentBootstrapToken(f.ctx, f.owner, f.org, uuid.New(), "refused-agent"); err == nil {
		t.Fatal("an unknown gateway must refuse issuance")
	}
	var tokens int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM agent_bootstrap_tokens WHERE org_id=$1`, f.org).Scan(&tokens); err != nil {
		t.Fatal(err)
	}
	if tokens != 0 || len(f.auditRows(t, f.org, "agent.bootstrap_token_issued")) != 0 {
		t.Fatalf("refused issuance left state: tokens=%d", tokens)
	}
}

func TestPendingAgentBootstrapTokensListOnlyLiveTokensOfTheOrganization(t *testing.T) {
	f := newBootstrapVisibilityFixture(t)
	issue := func(name string) string {
		t.Helper()
		raw, err := f.svc.IssueAgentBootstrapToken(f.ctx, f.owner, f.org, f.node, name)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	idOf := func(raw string) uuid.UUID {
		t.Helper()
		var id uuid.UUID
		if err := f.pool.QueryRow(f.ctx, `SELECT id FROM agent_bootstrap_tokens WHERE token_hash=$1`, hashBootstrapToken(raw)).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	pendingRaw := issue("pending-agent")
	consumedRaw := issue("consumed-agent")
	revokedRaw := issue("revoked-agent")
	if _, err := f.svc.Create(f.ctx, CreateInput{BootstrapToken: consumedRaw, PublicKey: testVisibilityPublicKey(1)}); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.RevokeAgentBootstrapToken(f.ctx, f.owner, f.org, idOf(revokedRaw)); err != nil {
		t.Fatal(err)
	}
	expiredHash := sha256.Sum256([]byte("expired-" + uuid.NewString()))
	f.exec(t, `INSERT INTO agent_bootstrap_tokens (org_id,gateway_node_id,agent_name,token_hash,expires_at,created_at,issued_by) VALUES ($1,$2,'expired-agent',$3,now()-interval '1 minute',now()-interval '2 hours',$4)`, f.org, f.node, expiredHash[:], f.owner)

	otherOrg, otherOwner, otherNode := f.seedOrg(t, "10.97.0.0/24")
	if _, err := f.svc.IssueAgentBootstrapToken(f.ctx, otherOwner, otherOrg, otherNode, "other-org-agent"); err != nil {
		t.Fatal(err)
	}

	list, err := f.svc.ListPendingAgentBootstrapTokens(f.ctx, f.org)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("pending tokens = %d, want only the live one: %+v", len(list), list)
	}
	got := list[0]
	if got.ID != idOf(pendingRaw) || got.AgentName != "pending-agent" || got.GatewayID != f.node || got.GatewayName != "aisec1-gateway" {
		t.Fatalf("pending token row = %+v", got)
	}
	if got.IssuedBy == nil || *got.IssuedBy != f.owner || got.IssuedByEmail == nil || *got.IssuedByEmail != f.owner.String()+"@aisec1.test" {
		t.Fatalf("pending token issuer = %v / %v", got.IssuedBy, got.IssuedByEmail)
	}
	if !got.ExpiresAt.After(time.Now()) || !got.IssuedAt.Before(got.ExpiresAt) {
		t.Fatalf("pending token times: issued=%s expires=%s", got.IssuedAt, got.ExpiresAt)
	}
	encoded, err := json.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	assertNoTokenMaterial(t, "pending token listing", string(encoded), pendingRaw)
}

func TestRevokedAgentBootstrapTokenIsRefusedLikeAnExpiredOne(t *testing.T) {
	f := newBootstrapVisibilityFixture(t)
	raw, err := f.svc.IssueAgentBootstrapToken(f.ctx, f.owner, f.org, f.node, "revoked-agent")
	if err != nil {
		t.Fatal(err)
	}
	var tokenID uuid.UUID
	if err := f.pool.QueryRow(f.ctx, `SELECT id FROM agent_bootstrap_tokens WHERE org_id=$1`, f.org).Scan(&tokenID); err != nil {
		t.Fatal(err)
	}

	// Another organization can neither see nor revoke it.
	otherOrg, otherOwner, _ := f.seedOrg(t, "10.97.0.0/24")
	if err := f.svc.RevokeAgentBootstrapToken(f.ctx, otherOwner, otherOrg, tokenID); err == nil || !strings.Contains(err.Error(), "bootstrap_token_not_found") {
		t.Fatalf("cross-organization revoke: want bootstrap_token_not_found, got %v", err)
	}
	if rows := f.auditRows(t, otherOrg, "agent.bootstrap_token_revoked"); len(rows) != 0 {
		t.Fatal("a refused revoke must not be audited as a revoke")
	}

	revoker := uuid.New()
	f.exec(t, `INSERT INTO users (id,email,name,status) VALUES ($1,$2,'Revoker','active')`, revoker, revoker.String()+"@aisec1.test")
	f.exec(t, `INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'admin')`, f.org, revoker)
	if err := f.svc.RevokeAgentBootstrapToken(f.ctx, revoker, f.org, tokenID); err != nil {
		t.Fatal(err)
	}
	rows := f.auditRows(t, f.org, "agent.bootstrap_token_revoked")
	if len(rows) != 1 {
		t.Fatalf("revoked audit rows = %d, want 1", len(rows))
	}
	if rows[0].actor == nil || *rows[0].actor != revoker || rows[0].targetID != tokenID.String() {
		t.Fatalf("revoked audit row = %+v", rows[0])
	}
	var meta map[string]any
	if err := json.Unmarshal([]byte(rows[0].metadata), &meta); err != nil {
		t.Fatal(err)
	}
	if meta["agent_name"] != "revoked-agent" || meta["gateway_id"] != f.node.String() || meta["expires_at"] == nil || len(meta) != 3 {
		t.Fatalf("revoked audit metadata = %v", meta)
	}
	assertNoTokenMaterial(t, "revoked audit row", rows[0].metadata, raw)

	expired := "expired-" + uuid.NewString()
	expiredHash := sha256.Sum256([]byte(expired))
	f.exec(t, `INSERT INTO agent_bootstrap_tokens (org_id,gateway_node_id,agent_name,token_hash,expires_at,created_at,issued_by) VALUES ($1,$2,'expired-agent',$3,now()-interval '1 minute',now()-interval '2 hours',$4)`, f.org, f.node, expiredHash[:], f.owner)
	_, expiredErr := f.svc.Create(f.ctx, CreateInput{BootstrapToken: expired, PublicKey: testVisibilityPublicKey(2)})
	_, revokedErr := f.svc.Create(f.ctx, CreateInput{BootstrapToken: raw, PublicKey: testVisibilityPublicKey(3)})
	if expiredErr == nil || revokedErr == nil || expiredErr.Error() != revokedErr.Error() {
		t.Fatalf("revoked and expired tokens must be refused identically: expired=%v revoked=%v", expiredErr, revokedErr)
	}
	if !strings.Contains(revokedErr.Error(), "invalid_bootstrap_token") {
		t.Fatalf("revoked token refusal = %v", revokedErr)
	}
	var devices int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM devices WHERE org_id=$1`, f.org).Scan(&devices); err != nil {
		t.Fatal(err)
	}
	if devices != 0 {
		t.Fatalf("a revoked token created %d device(s)", devices)
	}

	// Revoking again, or revoking something that is no longer pending, changes
	// nothing and is not recorded as a second revoke.
	if err := f.svc.RevokeAgentBootstrapToken(f.ctx, revoker, f.org, tokenID); err == nil || !strings.Contains(err.Error(), "bootstrap_token_not_found") {
		t.Fatalf("second revoke: want bootstrap_token_not_found, got %v", err)
	}
	consumedRaw, err := f.svc.IssueAgentBootstrapToken(f.ctx, f.owner, f.org, f.node, "consumed-agent")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Create(f.ctx, CreateInput{BootstrapToken: consumedRaw, PublicKey: testVisibilityPublicKey(4)}); err != nil {
		t.Fatal(err)
	}
	var consumedID uuid.UUID
	if err := f.pool.QueryRow(f.ctx, `SELECT id FROM agent_bootstrap_tokens WHERE token_hash=$1`, hashBootstrapToken(consumedRaw)).Scan(&consumedID); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.RevokeAgentBootstrapToken(f.ctx, revoker, f.org, consumedID); err == nil || !strings.Contains(err.Error(), "bootstrap_token_not_found") {
		t.Fatalf("revoking a used token: want bootstrap_token_not_found, got %v", err)
	}
	if rows := f.auditRows(t, f.org, "agent.bootstrap_token_revoked"); len(rows) != 1 {
		t.Fatalf("revoked audit rows after no-op revokes = %d, want 1", len(rows))
	}
}

func testVisibilityPublicKey(n int) string {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(100 + n + i)
	}
	return base64.StdEncoding.EncodeToString(b)
}
