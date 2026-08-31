package nodes

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/licence"
)

func TestOpenLifecycleRemintResponseBindsCiphertextToCredentialRow(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	sealer, err := crypto.NewSealer(key)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := sealer.Seal([]byte("claim-a-token"))
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{sealer: sealer}
	token := sqlc.NodeJoinToken{LifecycleTokenSealed: &sealed, TokenHash: hashToken("claim-a-token"), ExpiresAt: time.Now().Add(time.Hour)}
	if got, err := service.openLifecycleRemintResponse(token, time.Now()); err != nil || got != "claim-a-token" {
		t.Fatalf("matching sealed response = %q, %v", got, err)
	}
	token.TokenHash = hashToken("claim-b-token")
	if _, err := service.openLifecycleRemintResponse(token, time.Now()); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("cross-row sealed response error = %v", err)
	}
	token.TokenHash = hashToken("claim-a-token")
	token.ExpiresAt = time.Now().Add(-time.Second)
	if raw, err := service.openLifecycleRemintResponse(token, time.Now()); raw != "" || code(err) != "lifecycle_claim_response_expired" {
		t.Fatalf("expired sealed response = raw:%q err:%v", raw, err)
	}
}

func TestLifecycleStatusUnconsumedExpiryOutranksAcknowledgement(t *testing.T) {
	claim, requestID := uuid.New(), uuid.New()
	nodeName := "gateway-a"
	acknowledged := time.Now().Add(-2 * time.Hour)
	token := sqlc.NodeJoinToken{
		NodeName: &nodeName, LifecycleClaim: requiredPGUUID(claim), LifecycleGeneration: 1,
		LifecycleRequestID: requiredPGUUID(requestID), ExpiresAt: time.Now().Add(-time.Hour),
		LifecycleAcknowledgedAt: pgtype.Timestamptz{Time: acknowledged, Valid: true},
	}
	status, err := lifecycleStatus(token, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if status.State != LifecycleClaimExpired || status.AcknowledgedAt == nil {
		t.Fatalf("expired acknowledged token status = %+v", status)
	}
}

func TestLifecycleClaimRawTokenReturnsAreAuditedAndIdempotentAcrossLicenceChange(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run lifecycle claim audit integration")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	q := sqlc.New(tx)
	orgID, actorID, claim, request1, request2 := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	if _, err := tx.Exec(ctx, "INSERT INTO organizations (id,name,slug) VALUES ($1,$2,$3)", orgID, "Lifecycle Audit", "lifecycle-"+orgID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, "INSERT INTO users (id,email,name) VALUES ($1,$2,$3)", actorID, actorID.String()+"@test", "Lifecycle Actor"); err != nil {
		t.Fatal(err)
	}
	key := make([]byte, crypto.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	sealer, err := crypto.NewSealer(key)
	if err != nil {
		t.Fatal(err)
	}
	svc := (&Service{q: q, sealer: sealer}).WithLicence(licence.NewTestManager("scale", time.Now().Add(time.Hour)))
	actor := LifecycleActor{IssuerUserID: actorID, AuditUserID: actorID}
	input := LifecycleClaimRemint{Claim: claim, NodeName: "gateway-a", ExpectedGeneration: 0, RequestID: request1}
	first, err := svc.RemintLifecycleClaim(ctx, actor, orgID, input)
	if err != nil {
		t.Fatal(err)
	}
	wrongIdentity := input
	wrongIdentity.NodeName = "gateway-b"
	if _, err := svc.RemintLifecycleClaim(ctx, actor, orgID, wrongIdentity); code(err) != "lifecycle_claim_identity_mismatch" {
		t.Fatalf("initial replay under altered node-name error = %v", err)
	}
	var wrongReplayAudits int
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='node.lifecycle_claim_redelivered'", orgID).Scan(&wrongReplayAudits); err != nil || wrongReplayAudits != 0 {
		t.Fatalf("altered node-name replay audits=%d err=%v", wrongReplayAudits, err)
	}
	// Growth gates may change after the committed response was lost. Exact
	// idempotent redelivery remains available and returns the identical secret.
	svc.WithLicence(licence.NewTestManager("scale", time.Now().Add(-time.Hour)))
	replayed, err := svc.RemintLifecycleClaim(ctx, actor, orgID, input)
	if err != nil || replayed.JoinToken != first.JoinToken {
		t.Fatalf("same-request redelivery = token_equal:%t err:%v", replayed.JoinToken == first.JoinToken, err)
	}
	if _, err := tx.Exec(ctx, "UPDATE node_join_tokens SET expires_at=now()-interval '1 minute' WHERE lifecycle_claim=$1", claim); err != nil {
		t.Fatal(err)
	}
	if expiredReplay, err := svc.RemintLifecycleClaim(ctx, actor, orgID, input); expiredReplay.JoinToken != "" || code(err) != "lifecycle_claim_response_expired" {
		t.Fatalf("expired generation-one redelivery = raw:%q err:%v", expiredReplay.JoinToken, err)
	}
	// Restore growth allowance only for the genuinely new generation.
	svc.WithLicence(licence.NewTestManager("scale", time.Now().Add(time.Hour)))
	input.ExpectedGeneration, input.RequestID = 1, request2
	rotated, err := svc.RemintLifecycleClaim(ctx, actor, orgID, input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, "UPDATE node_join_tokens SET expires_at=now()-interval '1 minute' WHERE lifecycle_claim=$1", claim); err != nil {
		t.Fatal(err)
	}
	if expiredReplay, err := svc.RemintLifecycleClaim(ctx, actor, orgID, input); expiredReplay.JoinToken != "" || code(err) != "lifecycle_claim_response_expired" {
		t.Fatalf("expired later-generation redelivery = raw:%q err:%v", expiredReplay.JoinToken, err)
	}
	want := map[string]string{
		"node.lifecycle_claim_minted":      first.JoinToken,
		"node.lifecycle_claim_redelivered": replayed.JoinToken,
		"node.lifecycle_claim_reminted":    rotated.JoinToken,
	}
	for action, raw := range want {
		var metadata []byte
		if err := tx.QueryRow(ctx, "SELECT metadata FROM audit_logs WHERE org_id=$1 AND action=$2 ORDER BY created_at DESC LIMIT 1", orgID, action).Scan(&metadata); err != nil {
			t.Fatalf("%s audit: %v", action, err)
		}
		var values map[string]any
		if err := json.Unmarshal(metadata, &values); err != nil {
			t.Fatal(err)
		}
		if values["token_fingerprint"] != sealer.Fingerprint([]byte(raw)) || strings.Contains(string(metadata), raw) || strings.Contains(string(metadata), string(hashToken(raw))) {
			t.Fatalf("%s unsafe/inexact audit metadata: %s", action, metadata)
		}
	}
}

func TestLifecycleClaimRemintUsesPostLockDatabaseClockPostgres(t *testing.T) {
	pool, ctx := lifecycleInstallTestPool(t)
	orgID, actorID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,$2,$3)`, orgID, "D13h Remint Clock", "d13h-remint-"+orgID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,email,name) VALUES($1,$2,$3)`, actorID, actorID.String()+"@d13h.test", "D13h Remint Actor"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, orgID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, actorID)
	})
	key := make([]byte, crypto.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	sealer, err := crypto.NewSealer(key)
	if err != nil {
		t.Fatal(err)
	}
	service := NewService(pool, nil, sealer).WithLicence(licence.NewTestManager("scale", time.Now().Add(time.Hour)))
	actor := LifecycleActor{IssuerUserID: actorID, AuditUserID: actorID}
	claim, firstRequest, secondRequest := uuid.New(), uuid.New(), uuid.New()
	first, err := service.RemintLifecycleClaim(ctx, actor, orgID, LifecycleClaimRemint{
		Claim: claim, NodeName: "d13h-remint-clock", ExpectedGeneration: 0, RequestID: firstRequest,
	})
	if err != nil {
		t.Fatal(err)
	}
	var expiresAt time.Time
	if err := pool.QueryRow(ctx, `
		UPDATE node_join_tokens
		SET expires_at=clock_timestamp()+interval '3 seconds'
		WHERE org_id=$1 AND lifecycle_claim=$2
		RETURNING expires_at`, orgID, claim).Scan(&expiresAt); err != nil {
		t.Fatal(err)
	}

	blocker, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(ctx) //nolint:errcheck
	var lockedToken uuid.UUID
	if err := blocker.QueryRow(ctx, `SELECT id FROM node_join_tokens WHERE org_id=$1 AND lifecycle_claim=$2 FOR UPDATE`, orgID, claim).Scan(&lockedToken); err != nil {
		t.Fatal(err)
	}
	type remintResult struct {
		value LifecycleClaimRemintResult
		err   error
	}
	result := make(chan remintResult, 1)
	go func() {
		value, remintErr := service.RemintLifecycleClaim(ctx, actor, orgID, LifecycleClaimRemint{
			Claim: claim, NodeName: "d13h-remint-clock", ExpectedGeneration: first.Generation, RequestID: secondRequest,
		})
		result <- remintResult{value: value, err: remintErr}
	}()

	// Observe the second transaction genuinely blocked on the token row before
	// expiry. This makes the regression discriminate clock_timestamp sampled
	// after the lock from PostgreSQL now(), which is frozen at transaction start.
	waitDeadline := time.Now().Add(2 * time.Second)
	for {
		var waiters int
		if err := pool.QueryRow(ctx, `
			SELECT count(*) FROM pg_stat_activity
			WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%FOR UPDATE%'`).Scan(&waiters); err != nil {
			t.Fatal(err)
		}
		if waiters > 0 {
			break
		}
		if time.Now().After(waitDeadline) {
			t.Fatal("remint did not block on the lifecycle token row")
		}
		time.Sleep(20 * time.Millisecond)
	}
	for {
		var serverTime time.Time
		if err := pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&serverTime); err != nil {
			t.Fatal(err)
		}
		if !serverTime.Before(expiresAt) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := blocker.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-result:
		if got.err != nil || got.value.Generation != 2 || got.value.RequestID != secondRequest || got.value.JoinToken == "" {
			t.Fatalf("post-lock DB-clock remint = %+v err=%v", got.value, got.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("remint did not resume after lifecycle token lock release")
	}
}
