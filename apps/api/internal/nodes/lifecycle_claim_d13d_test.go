package nodes

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/licence"
)

func TestLifecycleStatusAcceptsOnlyExactGenerationZeroTombstone(t *testing.T) {
	now := time.Now()
	abortedAt := pgtype.Timestamptz{Time: now.Add(-time.Minute), Valid: true}
	nodeName := "gateway-pre-mint"
	token := sqlc.NodeJoinToken{
		NodeName: &nodeName, LifecycleClaim: requiredPGUUID(uuid.New()),
		LifecycleRequestID: requiredPGUUID(uuid.New()), LifecycleGeneration: 0,
		LifecycleAbortedAt: abortedAt, ExpiresAt: time.Unix(0, 0).UTC(),
	}
	status, err := lifecycleStatus(token, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != LifecycleClaimAborted || status.Generation != 0 || status.NodeName != nodeName || status.AbortedAt == nil {
		t.Fatalf("generation-zero tombstone status = %+v", status)
	}

	sealed := "must-not-exist"
	malformed := token
	malformed.LifecycleTokenSealed = &sealed
	if _, err := lifecycleStatus(malformed, nil, now); err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Fatalf("generation-zero tombstone with sealed credential error = %v", err)
	}
	malformed = token
	malformed.LifecycleAbortedAt = pgtype.Timestamptz{}
	if _, err := lifecycleStatus(malformed, nil, now); err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Fatalf("non-aborted generation-zero claim error = %v", err)
	}
}

func TestLifecycleClaimGenerationZeroAbortIsDurableIdempotentAndClosesMintRace(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run generation-zero lifecycle abort integration")
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
	orgID, otherOrgID, actorID := uuid.New(), uuid.New(), uuid.New()
	for id, name := range map[uuid.UUID]string{orgID: "D13d Abort", otherOrgID: "D13d Other"} {
		if _, err := tx.Exec(ctx, "INSERT INTO organizations (id,name,slug) VALUES ($1,$2,$3)", id, name, "d13d-"+id.String()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tx.Exec(ctx, "INSERT INTO users (id,email,name) VALUES ($1,$2,$3)", actorID, actorID.String()+"@test", "D13d Actor"); err != nil {
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

	claim, requestID := uuid.New(), uuid.New()
	input := LifecycleClaimAbort{Claim: claim, NodeName: "gateway-pre-mint", ExpectedGeneration: 0, RequestID: requestID}
	first, err := svc.AbortLifecycleClaim(ctx, actor, orgID, input)
	if err != nil {
		t.Fatal(err)
	}
	if first.State != LifecycleClaimAborted || first.Generation != 0 || first.RequestID != requestID || first.NodeName != input.NodeName || first.NodeID != nil || !first.ExpiresAt.Equal(time.Unix(0, 0).UTC()) {
		t.Fatalf("generation-zero abort status = %+v", first)
	}
	second, err := svc.AbortLifecycleClaim(ctx, actor, orgID, input)
	if err != nil || second.Claim != first.Claim || second.State != first.State || second.Generation != first.Generation || second.RequestID != first.RequestID || second.NodeName != first.NodeName || !second.ExpiresAt.Equal(first.ExpiresAt) {
		t.Fatalf("idempotent generation-zero abort = %+v err=%v", second, err)
	}

	var generation int
	var tokenHash []byte
	var sealed *string
	var consumedAt *time.Time
	var auditCount int
	if err := tx.QueryRow(ctx, `
		SELECT lifecycle_generation,token_hash,lifecycle_token_sealed,consumed_at
		FROM node_join_tokens WHERE org_id=$1 AND lifecycle_claim=$2`, orgID, claim).
		Scan(&generation, &tokenHash, &sealed, &consumedAt); err != nil {
		t.Fatal(err)
	}
	if generation != 0 || len(tokenHash) != 32 || sealed != nil || consumedAt != nil {
		t.Fatalf("unsafe generation-zero row: generation=%d hash_len=%d sealed=%v consumed=%v", generation, len(tokenHash), sealed, consumedAt)
	}
	if _, err := q.PeekJoinToken(ctx, tokenHash); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("current enrollment peek accepted generation-zero tombstone: %v", err)
	}
	if _, err := q.ConsumeJoinToken(ctx, tokenHash); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("current enrollment consumed generation-zero tombstone: %v", err)
	}
	var nMinusOneID uuid.UUID
	if err := tx.QueryRow(ctx, `
		UPDATE node_join_tokens SET consumed_at=now()
		WHERE token_hash=$1 AND consumed_at IS NULL AND expires_at > now()
		RETURNING id`, tokenHash).Scan(&nMinusOneID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("N-1 enrollment consumed generation-zero tombstone %s: %v", nMinusOneID, err)
	}
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='node.lifecycle_claim_aborted_before_mint'`, orgID).Scan(&auditCount); err != nil || auditCount != 1 {
		t.Fatalf("pre-mint abort audits=%d err=%v", auditCount, err)
	}
	var metadata []byte
	if err := tx.QueryRow(ctx, `SELECT metadata FROM audit_logs WHERE org_id=$1 AND action='node.lifecycle_claim_aborted_before_mint'`, orgID).Scan(&metadata); err != nil {
		t.Fatal(err)
	}
	var audit map[string]any
	if err := json.Unmarshal(metadata, &audit); err != nil {
		t.Fatal(err)
	}
	if audit["generation"] != float64(0) || audit["request_id"] != requestID.String() || audit["node_name"] != input.NodeName || audit["token_fingerprint"] != nil || strings.Contains(string(metadata), string(tokenHash)) {
		t.Fatalf("unsafe/inexact pre-mint abort audit: %s", metadata)
	}

	wrongRequest := input
	wrongRequest.RequestID = uuid.New()
	if _, err := svc.AbortLifecycleClaim(ctx, actor, orgID, wrongRequest); code(err) != "lifecycle_claim_cas_failed" {
		t.Fatalf("wrong-request generation-zero retry error = %v", err)
	}
	wrongName := input
	wrongName.NodeName = "gateway-other"
	if _, err := svc.AbortLifecycleClaim(ctx, actor, orgID, wrongName); code(err) != "lifecycle_claim_identity_mismatch" {
		t.Fatalf("wrong-node generation-zero retry error = %v", err)
	}
	if _, err := svc.AbortLifecycleClaim(ctx, actor, otherOrgID, input); code(err) != "lifecycle_claim_cas_failed" {
		t.Fatalf("cross-organization generation-zero retry error = %v", err)
	}
	if _, err := svc.RemintLifecycleClaim(ctx, actor, otherOrgID, LifecycleClaimRemint{
		Claim: claim, NodeName: input.NodeName, ExpectedGeneration: 0, RequestID: requestID,
	}); code(err) != "lifecycle_claim_cas_failed" {
		t.Fatalf("cross-organization initial mint conflict error = %v", err)
	}

	raceClaim, raceRequest := uuid.New(), uuid.New()
	_, err = svc.RemintLifecycleClaim(ctx, actor, orgID, LifecycleClaimRemint{
		Claim: raceClaim, NodeName: "gateway-race", ExpectedGeneration: 0, RequestID: raceRequest,
	})
	if err != nil {
		t.Fatal(err)
	}
	traced, err := svc.AbortLifecycleClaim(ctx, actor, orgID, LifecycleClaimAbort{
		Claim: raceClaim, NodeName: "gateway-race", ExpectedGeneration: 0, RequestID: raceRequest,
	})
	if err != nil {
		t.Fatal(err)
	}
	if traced.State != LifecycleClaimAborted || traced.Generation != 1 || traced.RequestID != raceRequest || traced.NodeName != "gateway-race" || traced.NodeID != nil {
		t.Fatalf("mint-won race abort status = %+v", traced)
	}
	raceToken, err := q.GetLifecycleJoinTokenForOrg(ctx, sqlc.GetLifecycleJoinTokenForOrgParams{OrgID: orgID, LifecycleClaim: requiredPGUUID(raceClaim)})
	if err != nil {
		t.Fatal(err)
	}
	if raceToken.LifecycleTokenSealed != nil || !raceToken.LifecycleAbortedAt.Valid {
		t.Fatalf("mint-won abort retained sealed response or missed tombstone: %+v", raceToken)
	}
	if opened, err := svc.openLifecycleRemintResponse(raceToken, time.Now()); opened != "" || err == nil {
		t.Fatalf("aborted mint response remained recoverable: raw=%q err=%v", opened, err)
	}
}

func TestLifecycleClaimConcurrentGenerationZeroAbortAndMintConvergeToAborted(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run concurrent lifecycle abort integration")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	orgID, actorID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, "INSERT INTO organizations (id,name,slug) VALUES ($1,$2,$3)", orgID, "D13d Concurrent", "d13d-race-"+orgID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "INSERT INTO users (id,email,name) VALUES ($1,$2,$3)", actorID, actorID.String()+"@test", "D13d Race Actor"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM organizations WHERE id=$1", orgID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM users WHERE id=$1", actorID)
	})
	key := make([]byte, crypto.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	sealer, err := crypto.NewSealer(key)
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(pool, nil, sealer).WithLicence(licence.NewTestManager("scale", time.Now().Add(time.Hour)))
	actor := LifecycleActor{IssuerUserID: actorID, AuditUserID: actorID}

	for iteration := 0; iteration < 8; iteration++ {
		claim, requestID := uuid.New(), uuid.New()
		nodeName := "gateway-concurrent-" + uuid.NewString()[:8]
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		var minted LifecycleClaimRemintResult
		var mintErr error
		var aborted LifecycleClaimStatus
		var abortErr error
		go func() {
			defer wg.Done()
			<-start
			minted, mintErr = svc.RemintLifecycleClaim(ctx, actor, orgID, LifecycleClaimRemint{
				Claim: claim, NodeName: nodeName, ExpectedGeneration: 0, RequestID: requestID,
			})
		}()
		go func() {
			defer wg.Done()
			<-start
			aborted, abortErr = svc.AbortLifecycleClaim(ctx, actor, orgID, LifecycleClaimAbort{
				Claim: claim, NodeName: nodeName, ExpectedGeneration: 0, RequestID: requestID,
			})
		}()
		close(start)
		wg.Wait()
		if abortErr != nil {
			t.Fatalf("iteration %d concurrent abort: %v", iteration, abortErr)
		}
		if mintErr != nil && code(mintErr) != "lifecycle_claim_aborted" {
			t.Fatalf("iteration %d concurrent mint error: %v", iteration, mintErr)
		}
		if abortErr == nil && minted.JoinToken != "" && mintErr != nil {
			t.Fatalf("iteration %d returned both raw mint and error", iteration)
		}
		status, err := svc.GetLifecycleClaimStatus(ctx, orgID, claim)
		if err != nil {
			t.Fatalf("iteration %d final status: %v", iteration, err)
		}
		if status.State != LifecycleClaimAborted || status.NodeName != nodeName || status.RequestID != requestID || (status.Generation != 0 && status.Generation != 1) || aborted.State != LifecycleClaimAborted || aborted.Generation != status.Generation {
			t.Fatalf("iteration %d non-converged state: abort=%+v final=%+v", iteration, aborted, status)
		}
		row, err := sqlc.New(pool).GetLifecycleJoinTokenForOrg(ctx, sqlc.GetLifecycleJoinTokenForOrgParams{OrgID: orgID, LifecycleClaim: requiredPGUUID(claim)})
		if err != nil {
			t.Fatal(err)
		}
		if row.LifecycleTokenSealed != nil || !row.LifecycleAbortedAt.Valid || row.ConsumedAt.Valid {
			t.Fatalf("iteration %d unsafe final token row: %+v", iteration, row)
		}
		if raw, openErr := svc.openLifecycleRemintResponse(row, time.Now()); raw != "" || openErr == nil {
			t.Fatalf("iteration %d final row redelivered raw=%q err=%v", iteration, raw, openErr)
		}
	}
}
