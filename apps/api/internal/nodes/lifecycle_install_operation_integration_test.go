package nodes

import (
	"context"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

type lifecycleInstallFixture struct {
	service   *Service
	actor     LifecycleActor
	orgID     uuid.UUID
	actorID   uuid.UUID
	tokenID   uuid.UUID
	claim     uuid.UUID
	requestID uuid.UUID
	operation uuid.UUID
	status    LifecycleInstallOperationStatus
}

func seedLifecycleInstallFixture(t *testing.T, ctx context.Context, pool *pgxpool.Pool, duration int32) lifecycleInstallFixture {
	t.Helper()
	orgID, actorID, tokenID := uuid.New(), uuid.New(), uuid.New()
	claim, requestID, operation := uuid.New(), uuid.New(), uuid.New()
	nodeName := "d13h-" + uuid.NewString()[:8]
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,$2,$3)`, orgID, "D13h Test", "d13h-"+orgID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,email,name) VALUES($1,$2,$3)`, actorID, actorID.String()+"@d13h.test", "D13h Actor"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, orgID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, actorID)
	})
	if _, err := pool.Exec(ctx, `
		INSERT INTO node_join_tokens(
			id,org_id,node_name,token_hash,expires_at,issued_by,enrols_kind,
			lifecycle_claim,lifecycle_generation,lifecycle_request_id,lifecycle_acknowledged_at)
		VALUES($1,$2,$3,$4,clock_timestamp()+interval '1 hour',$5,'gateway',$6,1,$7,clock_timestamp())`,
		tokenID, orgID, nodeName, []byte(uuid.NewString()), actorID, claim, requestID); err != nil {
		t.Fatal(err)
	}
	service := NewService(pool, nil, nil)
	actor := LifecycleActor{IssuerUserID: actorID, AuditUserID: actorID}
	status, err := service.BeginLifecycleInstall(ctx, actor, orgID, LifecycleInstallBegin{
		Claim: claim, ExpectedGeneration: 1, RequestID: requestID, OperationID: operation,
		ReleaseNamespace: "tunnex", ReleaseName: "tunnex-gateway",
		InstallIntentDigest: "sha256:" + strings.Repeat("a", 64), RequestedDurationSeconds: duration,
	})
	if err != nil {
		t.Fatal(err)
	}
	return lifecycleInstallFixture{service: service, actor: actor, orgID: orgID, actorID: actorID, tokenID: tokenID, claim: claim, requestID: requestID, operation: operation, status: status}
}

func consumeAndBindLifecycleNode(t *testing.T, ctx context.Context, pool *pgxpool.Pool, fixture lifecycleInstallFixture) uuid.UUID {
	t.Helper()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var tokenID uuid.UUID
	if err := tx.QueryRow(ctx, `
		UPDATE node_join_tokens SET consumed_at=clock_timestamp()
		WHERE id=$1 AND consumed_at IS NULL RETURNING id`, fixture.tokenID).Scan(&tokenID); err != nil {
		t.Fatalf("consume active lifecycle token: %v", err)
	}
	var nodeID uuid.UUID
	if err := tx.QueryRow(ctx, `
		INSERT INTO nodes(org_id,name,cert_serial,agent_version,lifecycle_claim)
		SELECT org_id,node_name,$2,'d13h-test',lifecycle_claim
		FROM node_join_tokens WHERE id=$1
		RETURNING id`, fixture.tokenID, "d13h-"+uuid.NewString()).Scan(&nodeID); err != nil {
		t.Fatalf("bind exact lifecycle node: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit exact lifecycle enrollment: %v", err)
	}
	return nodeID
}

func lifecycleInstallTestPool(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run D13h lifecycle install integration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	t.Cleanup(cancel)
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	base, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	databaseName := "tnx_d13h_" + uuid.NewString()[:8]
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+databaseName); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+databaseName+" WITH (FORCE)")
	})
	testURL := *base
	testURL.Path = "/" + databaseName
	if err := db.MigrateTo(testURL.String(), 131); err != nil {
		t.Fatalf("migrate disposable D13h database: %v", err)
	}
	pool, err := pgxpool.New(ctx, testURL.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	var version int64
	var dirty bool
	if err := pool.QueryRow(ctx, `SELECT version, dirty FROM schema_migrations`).Scan(&version, &dirty); err != nil {
		t.Fatalf("read disposable D13h migration state: %v", err)
	}
	if version != 131 || dirty {
		t.Fatalf("disposable D13h migration state version=%d dirty=%t, want 131/false", version, dirty)
	}
	return pool, ctx
}

func TestLifecycleInstallBeginHeartbeatCompleteAndNoBothSuccessPostgres(t *testing.T) {
	pool, ctx := lifecycleInstallTestPool(t)
	fixture := seedLifecycleInstallFixture(t, ctx, pool, 120)
	first := fixture.status
	if first.State != LifecycleInstallActive || first.Epoch != 1 || !first.NotAfter.After(first.ServerTime) || first.NotAfter.Sub(first.ServerTime) > 120*time.Second {
		t.Fatalf("begin status = %+v", first)
	}
	replayed, err := fixture.service.BeginLifecycleInstall(ctx, fixture.actor, fixture.orgID, LifecycleInstallBegin{
		Claim: fixture.claim, ExpectedGeneration: 1, RequestID: fixture.requestID, OperationID: fixture.operation,
		ReleaseNamespace: "tunnex", ReleaseName: "tunnex-gateway",
		InstallIntentDigest: "sha256:" + strings.Repeat("a", 64), RequestedDurationSeconds: 120,
	})
	if err != nil || replayed.Epoch != first.Epoch || !replayed.NotAfter.Equal(first.NotAfter) {
		t.Fatalf("exact begin replay = %+v err=%v", replayed, err)
	}
	foreign := fixture
	foreign.operation = uuid.New()
	if _, err := fixture.service.BeginLifecycleInstall(ctx, fixture.actor, fixture.orgID, LifecycleInstallBegin{
		Claim: foreign.claim, ExpectedGeneration: 1, RequestID: foreign.requestID, OperationID: foreign.operation,
		ReleaseNamespace: "tunnex", ReleaseName: "tunnex-gateway",
		InstallIntentDigest: "sha256:" + strings.Repeat("a", 64), RequestedDurationSeconds: 120,
	}); code(err) != "lifecycle_install_operation_held" {
		t.Fatalf("foreign begin error = %v", err)
	}
	heartbeat, err := fixture.service.HeartbeatLifecycleInstall(ctx, fixture.actor, fixture.orgID, LifecycleInstallCAS{
		Claim: fixture.claim, ExpectedGeneration: 1, RequestID: fixture.requestID, OperationID: fixture.operation, ExpectedEpoch: 1,
	})
	if err != nil || !heartbeat.NotAfter.Equal(first.NotAfter) || heartbeat.HeartbeatAt.Before(first.HeartbeatAt) {
		t.Fatalf("heartbeat extended/regressed lease: before=%+v after=%+v err=%v", first, heartbeat, err)
	}
	nodeID := consumeAndBindLifecycleNode(t, ctx, pool, fixture)
	completed, err := fixture.service.CompleteLifecycleInstall(ctx, fixture.actor, fixture.orgID, LifecycleInstallComplete{
		LifecycleInstallCAS: LifecycleInstallCAS{Claim: fixture.claim, ExpectedGeneration: 1, RequestID: fixture.requestID, OperationID: fixture.operation, ExpectedEpoch: 1},
		ReleaseReady:        true,
	})
	if err != nil || completed.State != LifecycleInstallCompleted {
		t.Fatalf("complete = %+v err=%v", completed, err)
	}
	if _, err := fixture.service.CoordinatedAbortLifecycleClaim(ctx, fixture.actor, fixture.orgID, LifecycleInstallCAS{
		Claim: fixture.claim, ExpectedGeneration: 1, RequestID: fixture.requestID, OperationID: fixture.operation, ExpectedEpoch: 1,
	}); code(err) != "lifecycle_install_already_completed" {
		t.Fatalf("abort after successful complete error = %v", err)
	}
	var status string
	if err := pool.QueryRow(ctx, `SELECT status FROM nodes WHERE id=$1`, nodeID).Scan(&status); err != nil || status != "active" {
		t.Fatalf("completed node status=%q err=%v", status, err)
	}
}

func TestLifecycleInstallAbortTakeoverLostResponseAndFinalizePostgres(t *testing.T) {
	pool, ctx := lifecycleInstallTestPool(t)
	fixture := seedLifecycleInstallFixture(t, ctx, pool, 120)
	nodeID := consumeAndBindLifecycleNode(t, ctx, pool, fixture)
	cas := LifecycleInstallCAS{Claim: fixture.claim, ExpectedGeneration: 1, RequestID: fixture.requestID, OperationID: fixture.operation, ExpectedEpoch: 1}
	requested, err := fixture.service.CoordinatedAbortLifecycleClaim(ctx, fixture.actor, fixture.orgID, cas)
	if err != nil || !requested.Pending || requested.OperationStatus == nil || requested.OperationStatus.State != LifecycleInstallAbortRequested {
		t.Fatalf("abort request = %+v err=%v", requested, err)
	}
	heartbeat, err := fixture.service.HeartbeatLifecycleInstall(ctx, fixture.actor, fixture.orgID, cas)
	if err != nil || heartbeat.State != LifecycleInstallAbortRequested || !heartbeat.NotAfter.Equal(fixture.status.NotAfter) {
		t.Fatalf("abort-request heartbeat = %+v err=%v", heartbeat, err)
	}
	if _, err := fixture.service.ReleaseLifecycleInstall(ctx, fixture.actor, fixture.orgID, cas); err != nil {
		t.Fatal(err)
	}
	taken, err := fixture.service.CoordinatedAbortLifecycleClaim(ctx, fixture.actor, fixture.orgID, cas)
	if err != nil || taken.OperationStatus == nil || taken.OperationStatus.State != LifecycleInstallAborting || taken.OperationStatus.Epoch != 2 {
		t.Fatalf("released takeover = %+v err=%v", taken, err)
	}
	lostReplay, err := fixture.service.CoordinatedAbortLifecycleClaim(ctx, fixture.actor, fixture.orgID, cas)
	if err != nil || lostReplay.OperationStatus == nil || lostReplay.OperationStatus.Epoch != 2 || lostReplay.OperationStatus.State != LifecycleInstallAborting {
		t.Fatalf("lost takeover response replay = %+v err=%v", lostReplay, err)
	}
	if _, err := fixture.service.FinalizeLifecycleInstallAbort(ctx, fixture.actor, fixture.orgID, LifecycleInstallAbortFinalize{
		LifecycleInstallCAS: LifecycleInstallCAS{Claim: fixture.claim, ExpectedGeneration: 1, RequestID: fixture.requestID, OperationID: fixture.operation, ExpectedEpoch: 2},
	}); code(err) != "lifecycle_install_release_not_absent" {
		t.Fatalf("missing release-absence attestation error = %v", err)
	}
	finalized, err := fixture.service.FinalizeLifecycleInstallAbort(ctx, fixture.actor, fixture.orgID, LifecycleInstallAbortFinalize{
		LifecycleInstallCAS: LifecycleInstallCAS{Claim: fixture.claim, ExpectedGeneration: 1, RequestID: fixture.requestID, OperationID: fixture.operation, ExpectedEpoch: 2},
		ReleaseAbsent:       true,
	})
	if err != nil || finalized.State != LifecycleClaimAborted || finalized.NodeID == nil || *finalized.NodeID != nodeID {
		t.Fatalf("finalized abort = %+v err=%v", finalized, err)
	}
	replayed, err := fixture.service.FinalizeLifecycleInstallAbort(ctx, fixture.actor, fixture.orgID, LifecycleInstallAbortFinalize{
		LifecycleInstallCAS: LifecycleInstallCAS{Claim: fixture.claim, ExpectedGeneration: 1, RequestID: fixture.requestID, OperationID: fixture.operation, ExpectedEpoch: 2},
		ReleaseAbsent:       true,
	})
	if err != nil || replayed.NodeID == nil || *replayed.NodeID != nodeID {
		t.Fatalf("finalize lost-response replay = %+v err=%v", replayed, err)
	}
	if _, err := fixture.service.CoordinatedAbortLifecycleClaim(ctx, fixture.actor, fixture.orgID, LifecycleInstallCAS{
		Claim: fixture.claim, ExpectedGeneration: 1, RequestID: fixture.requestID, OperationID: fixture.operation, ExpectedEpoch: 0,
	}); code(err) != "invalid_lifecycle_install_operation_cas" {
		t.Fatalf("invalid stale epoch error = %v", err)
	}
	var nodeStatus string
	if err := pool.QueryRow(ctx, `SELECT status FROM nodes WHERE id=$1`, nodeID).Scan(&nodeStatus); err != nil || nodeStatus != "revoked" {
		t.Fatalf("aborted node status=%q err=%v", nodeStatus, err)
	}
	legacy, err := fixture.service.AbortLifecycleClaim(ctx, fixture.actor, fixture.orgID, LifecycleClaimAbort{Claim: fixture.claim, ExpectedGeneration: 1, RequestID: fixture.requestID})
	if err != nil || legacy.State != LifecycleClaimAborted || legacy.NodeID == nil || *legacy.NodeID != nodeID {
		t.Fatalf("legacy abort idempotency after terminal abort = %+v err=%v", legacy, err)
	}
}

func TestLifecycleInstallMixedVersionGuardsPostgres(t *testing.T) {
	pool, ctx := lifecycleInstallTestPool(t)
	fixture := seedLifecycleInstallFixture(t, ctx, pool, 120)
	legacyAbort, err := pool.Exec(ctx, `UPDATE node_join_tokens SET lifecycle_aborted_at=clock_timestamp() WHERE id=$1`, fixture.tokenID)
	if err != nil || legacyAbort.RowsAffected() != 0 {
		t.Fatalf("legacy active abort rows=%d err=%v", legacyAbort.RowsAffected(), err)
	}
	legacyRemint, err := pool.Exec(ctx, `UPDATE node_join_tokens SET lifecycle_generation=2,lifecycle_request_id=$2 WHERE id=$1`, fixture.tokenID, uuid.New())
	if err != nil || legacyRemint.RowsAffected() != 0 {
		t.Fatalf("legacy active remint rows=%d err=%v", legacyRemint.RowsAffected(), err)
	}
	abortRequested := seedLifecycleInstallFixture(t, ctx, pool, 120)
	if _, err := abortRequested.service.CoordinatedAbortLifecycleClaim(ctx, abortRequested.actor, abortRequested.orgID, LifecycleInstallCAS{
		Claim: abortRequested.claim, ExpectedGeneration: 1, RequestID: abortRequested.requestID,
		OperationID: abortRequested.operation, ExpectedEpoch: 1,
	}); err != nil {
		t.Fatal(err)
	}
	abortRequestedConsume, err := pool.Exec(ctx, `UPDATE node_join_tokens SET consumed_at=clock_timestamp() WHERE id=$1`, abortRequested.tokenID)
	if err != nil || abortRequestedConsume.RowsAffected() != 0 {
		t.Fatalf("legacy abort-requested consumption rows=%d err=%v", abortRequestedConsume.RowsAffected(), err)
	}
	var abortRequestedAuthorizations int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM node_lifecycle_enrollment_authorizations WHERE token_id=$1`, abortRequested.tokenID).Scan(&abortRequestedAuthorizations); err != nil || abortRequestedAuthorizations != 0 {
		t.Fatalf("abort-requested refusal left enrollment authorizations=%d err=%v", abortRequestedAuthorizations, err)
	}
	if _, err := fixture.service.ReleaseLifecycleInstall(ctx, fixture.actor, fixture.orgID, LifecycleInstallCAS{
		Claim: fixture.claim, ExpectedGeneration: 1, RequestID: fixture.requestID, OperationID: fixture.operation, ExpectedEpoch: 1,
	}); err != nil {
		t.Fatal(err)
	}
	legacyConsume, err := pool.Exec(ctx, `UPDATE node_join_tokens SET consumed_at=clock_timestamp() WHERE id=$1`, fixture.tokenID)
	if err != nil || legacyConsume.RowsAffected() != 0 {
		t.Fatalf("legacy released consumption rows=%d err=%v", legacyConsume.RowsAffected(), err)
	}
	legacyAbort, err = pool.Exec(ctx, `UPDATE node_join_tokens SET lifecycle_aborted_at=clock_timestamp() WHERE id=$1`, fixture.tokenID)
	if err != nil || legacyAbort.RowsAffected() != 0 {
		t.Fatalf("legacy released abort rows=%d err=%v", legacyAbort.RowsAffected(), err)
	}
	legacyRemint, err = pool.Exec(ctx, `UPDATE node_join_tokens SET lifecycle_generation=2,lifecycle_request_id=$2 WHERE id=$1`, fixture.tokenID, uuid.New())
	if err != nil || legacyRemint.RowsAffected() != 1 {
		t.Fatalf("legacy clean-release remint rows=%d err=%v", legacyRemint.RowsAffected(), err)
	}
	var generation int32
	if err := pool.QueryRow(ctx, `SELECT lifecycle_generation FROM node_join_tokens WHERE id=$1`, fixture.tokenID).Scan(&generation); err != nil || generation != 2 {
		t.Fatalf("clean-release generation=%d err=%v", generation, err)
	}

	expired := seedLifecycleInstallFixture(t, ctx, pool, 1)
	if _, err := pool.Exec(ctx, `UPDATE node_lifecycle_install_operations SET not_after=heartbeat_at WHERE operation_id=$1`, expired.operation); err != nil {
		t.Fatal(err)
	}
	consume, err := pool.Exec(ctx, `UPDATE node_join_tokens SET consumed_at=clock_timestamp() WHERE id=$1`, expired.tokenID)
	if err != nil || consume.RowsAffected() != 0 {
		t.Fatalf("legacy expired consumption rows=%d err=%v", consume.RowsAffected(), err)
	}
	var authorizations int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM node_lifecycle_enrollment_authorizations WHERE token_id=$1`, expired.tokenID).Scan(&authorizations); err != nil || authorizations != 0 {
		t.Fatalf("expired refusal left enrollment authorizations=%d err=%v", authorizations, err)
	}
	expiredRemint, err := pool.Exec(ctx, `UPDATE node_join_tokens SET lifecycle_generation=2,lifecycle_request_id=$2 WHERE id=$1`, expired.tokenID, uuid.New())
	if err != nil || expiredRemint.RowsAffected() != 0 {
		t.Fatalf("legacy expired remint rows=%d err=%v", expiredRemint.RowsAffected(), err)
	}
	if _, err := expired.service.CoordinatedAbortLifecycleClaim(ctx, expired.actor, expired.orgID, LifecycleInstallCAS{
		Claim: expired.claim, ExpectedGeneration: 1, RequestID: expired.requestID, OperationID: expired.operation, ExpectedEpoch: 1,
	}); err != nil {
		t.Fatal(err)
	}
	legacyAbort, err = pool.Exec(ctx, `UPDATE node_join_tokens SET lifecycle_aborted_at=clock_timestamp() WHERE id=$1`, expired.tokenID)
	if err != nil || legacyAbort.RowsAffected() != 0 {
		t.Fatalf("legacy taken-over abort rows=%d err=%v", legacyAbort.RowsAffected(), err)
	}
	takenOverRemint, err := pool.Exec(ctx, `UPDATE node_join_tokens SET lifecycle_generation=2,lifecycle_request_id=$2 WHERE id=$1`, expired.tokenID, uuid.New())
	if err != nil || takenOverRemint.RowsAffected() != 0 {
		t.Fatalf("legacy taken-over remint rows=%d err=%v", takenOverRemint.RowsAffected(), err)
	}
}

func TestLifecycleInstallActiveConsumptionGuardAllowsExactEnrollmentPostgres(t *testing.T) {
	pool, ctx := lifecycleInstallTestPool(t)
	fixture := seedLifecycleInstallFixture(t, ctx, pool, 120)
	nodeID := consumeAndBindLifecycleNode(t, ctx, pool, fixture)
	if nodeID == uuid.Nil {
		t.Fatal("active pre-deadline lifecycle enrollment returned nil node")
	}
	var authorizationCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM node_lifecycle_enrollment_authorizations WHERE token_id=$1`, fixture.tokenID).Scan(&authorizationCount); err != nil || authorizationCount != 0 {
		t.Fatalf("committed enrollment left authorization rows=%d err=%v", authorizationCount, err)
	}
}

func TestLifecycleInstallBeginSamplesDatabaseClockAfterTokenLockWaitPostgres(t *testing.T) {
	pool, ctx := lifecycleInstallTestPool(t)
	orgID, actorID, tokenID := uuid.New(), uuid.New(), uuid.New()
	claim, requestID, operationID := uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,$2,$3)`, orgID, "D13h Lock Wait", "d13h-lock-"+orgID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,email,name) VALUES($1,$2,$3)`, actorID, actorID.String()+"@d13h.test", "D13h Lock Actor"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, orgID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, actorID)
	})
	if _, err := pool.Exec(ctx, `
		INSERT INTO node_join_tokens(
			id,org_id,node_name,token_hash,expires_at,issued_by,enrols_kind,
			lifecycle_claim,lifecycle_generation,lifecycle_request_id,lifecycle_acknowledged_at)
		VALUES($1,$2,$3,$4,clock_timestamp()+interval '1 hour',$5,'gateway',$6,1,$7,clock_timestamp())`,
		tokenID, orgID, "d13h-lock-"+uuid.NewString()[:8], []byte(uuid.NewString()), actorID, claim, requestID); err != nil {
		t.Fatal(err)
	}

	blocker, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(ctx) //nolint:errcheck
	var lockedTokenID uuid.UUID
	if err := blocker.QueryRow(ctx, `SELECT id FROM node_join_tokens WHERE id=$1 FOR UPDATE`, tokenID).Scan(&lockedTokenID); err != nil {
		t.Fatal(err)
	}

	type beginResult struct {
		status LifecycleInstallOperationStatus
		err    error
	}
	started := make(chan struct{})
	result := make(chan beginResult, 1)
	go func() {
		close(started)
		status, beginErr := NewService(pool, nil, nil).BeginLifecycleInstall(ctx, LifecycleActor{IssuerUserID: actorID, AuditUserID: actorID}, orgID, LifecycleInstallBegin{
			Claim: claim, ExpectedGeneration: 1, RequestID: requestID, OperationID: operationID,
			ReleaseNamespace: "tunnex", ReleaseName: "tunnex-gateway",
			InstallIntentDigest: "sha256:" + strings.Repeat("b", 64), RequestedDurationSeconds: 10,
		})
		result <- beginResult{status: status, err: beginErr}
	}()
	<-started
	select {
	case got := <-result:
		t.Fatalf("begin did not wait for the token row lock: status=%+v err=%v", got.status, got.err)
	case <-time.After(2 * time.Second):
	}
	var releaseServerTime time.Time
	if err := pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&releaseServerTime); err != nil {
		t.Fatal(err)
	}
	if err := blocker.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-result:
		if got.err != nil {
			t.Fatal(got.err)
		}
		if got.status.ServerTime.Before(releaseServerTime) {
			t.Fatalf("begin server_time=%s predates DB lock release sample=%s", got.status.ServerTime, releaseServerTime)
		}
		remaining := got.status.NotAfter.Sub(got.status.ServerTime)
		if remaining <= 9*time.Second || remaining > 10*time.Second {
			t.Fatalf("lock wait consumed DB-authoritative lease budget: remaining=%s status=%+v", remaining, got.status)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("begin did not resume after token row lock release")
	}
}

func TestLifecycleInstallExpiredAbsentRecoveryAndLatestReadPostgres(t *testing.T) {
	pool, ctx := lifecycleInstallTestPool(t)

	// Exact operation replay always wins, even after both the lifecycle
	// credential and immutable install deadline have expired. A retry must not
	// retire/remint an operation that the control plane already linearized.
	existing := seedLifecycleInstallFixture(t, ctx, pool, 120)
	latest, err := existing.service.GetLatestLifecycleInstallOperation(ctx, existing.orgID, existing.claim)
	if err != nil || latest.OperationID != existing.operation || latest.Epoch != existing.status.Epoch {
		t.Fatalf("latest exact operation = %+v err=%v", latest, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE node_join_tokens SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, existing.tokenID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE node_lifecycle_install_operations SET not_after=heartbeat_at WHERE operation_id=$1`, existing.operation); err != nil {
		t.Fatal(err)
	}
	replayed, err := existing.service.BeginLifecycleInstall(ctx, existing.actor, existing.orgID, LifecycleInstallBegin{
		Claim: existing.claim, ExpectedGeneration: 1, RequestID: existing.requestID, OperationID: existing.operation,
		ReleaseNamespace: "tunnex", ReleaseName: "tunnex-gateway",
		InstallIntentDigest: "sha256:" + strings.Repeat("a", 64), RequestedDurationSeconds: 120,
	})
	if err != nil || replayed.OperationID != existing.operation || replayed.State != LifecycleInstallExpired {
		t.Fatalf("expired exact operation replay = %+v err=%v", replayed, err)
	}
	foreignActive := LifecycleInstallBegin{
		Claim: existing.claim, ExpectedGeneration: 1, RequestID: existing.requestID, OperationID: uuid.New(),
		ReleaseNamespace: "tunnex", ReleaseName: "tunnex-gateway",
		InstallIntentDigest: "sha256:" + strings.Repeat("a", 64), RequestedDurationSeconds: 120,
	}
	if _, err := existing.service.BeginLifecycleInstall(ctx, existing.actor, existing.orgID, foreignActive); code(err) != "lifecycle_install_operation_held" {
		t.Fatalf("expired foreign active predecessor error = %v", err)
	}

	// Model the D13h crash boundary: Kubernetes persisted the exact operation
	// UUID, but the process died before Begin reached the control plane. Only
	// the exact locked token tuple, clean latest-operation absence, DB expiry,
	// and absence of a bound node produce the typed recovery proof.
	absent := seedLifecycleInstallFixture(t, ctx, pool, 120)
	if _, err := pool.Exec(ctx, `DELETE FROM node_lifecycle_install_operations WHERE operation_id=$1`, absent.operation); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE node_join_tokens SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, absent.tokenID); err != nil {
		t.Fatal(err)
	}
	begin := LifecycleInstallBegin{
		Claim: absent.claim, ExpectedGeneration: 1, RequestID: absent.requestID, OperationID: absent.operation,
		ReleaseNamespace: "tunnex", ReleaseName: "tunnex-gateway",
		InstallIntentDigest: "sha256:" + strings.Repeat("a", 64), RequestedDurationSeconds: 120,
	}
	if _, err := absent.service.BeginLifecycleInstall(ctx, absent.actor, absent.orgID, begin); code(err) != "lifecycle_install_operation_absent_after_expiry" {
		t.Fatalf("expired absent operation error = %v", err)
	}
	var operationCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM node_lifecycle_install_operations WHERE lifecycle_claim=$1`, absent.claim).Scan(&operationCount); err != nil || operationCount != 0 {
		t.Fatalf("expired absent recovery mutated operations=%d err=%v", operationCount, err)
	}
	foreignTuple := begin
	foreignTuple.RequestID = uuid.New()
	if _, err := absent.service.BeginLifecycleInstall(ctx, absent.actor, absent.orgID, foreignTuple); code(err) != "lifecycle_install_operation_cas_failed" {
		t.Fatalf("foreign tuple received recovery proof: %v", err)
	}
	if _, err := absent.service.GetLatestLifecycleInstallOperation(ctx, absent.orgID, absent.claim); code(err) != "lifecycle_install_operation_not_found" {
		t.Fatalf("domain absence error = %v", err)
	}
	bound := seedLifecycleInstallFixture(t, ctx, pool, 120)
	consumeAndBindLifecycleNode(t, ctx, pool, bound)
	if _, err := pool.Exec(ctx, `DELETE FROM node_lifecycle_install_operations WHERE operation_id=$1`, bound.operation); err != nil {
		t.Fatal(err)
	}
	// Model a defensive legacy/corruption shape that the current enrollment
	// bridge cannot create: the immutable claim remains bound on the node, while
	// the token's consumed marker is missing. Begin must still never turn this
	// into an absent-operation recovery proof.
	if _, err := pool.Exec(ctx, `
		UPDATE node_join_tokens
		SET consumed_at=NULL,consumed_node_id=NULL,expires_at=clock_timestamp()-interval '1 second'
		WHERE id=$1`, bound.tokenID); err != nil {
		t.Fatal(err)
	}
	boundBegin := LifecycleInstallBegin{
		Claim: bound.claim, ExpectedGeneration: 1, RequestID: bound.requestID, OperationID: bound.operation,
		ReleaseNamespace: "tunnex", ReleaseName: "tunnex-gateway",
		InstallIntentDigest: "sha256:" + strings.Repeat("a", 64), RequestedDurationSeconds: 120,
	}
	if _, err := bound.service.BeginLifecycleInstall(ctx, bound.actor, bound.orgID, boundBegin); code(err) != "lifecycle_install_claim_terminal" {
		t.Fatalf("bound-node claim received recovery proof: %v", err)
	}

	for _, test := range []struct {
		name     string
		mutation string
		wantCode string
	}{
		{name: "unacknowledged", mutation: `UPDATE node_join_tokens SET lifecycle_acknowledged_at=NULL WHERE id=$1`, wantCode: "lifecycle_install_claim_not_acknowledged"},
		{name: "aborted", mutation: `UPDATE node_join_tokens SET lifecycle_aborted_at=clock_timestamp() WHERE id=$1`, wantCode: "lifecycle_install_claim_terminal"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := seedLifecycleInstallFixture(t, ctx, pool, 120)
			if _, err := pool.Exec(ctx, `DELETE FROM node_lifecycle_install_operations WHERE operation_id=$1`, fixture.operation); err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Exec(ctx, `UPDATE node_join_tokens SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, fixture.tokenID); err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Exec(ctx, test.mutation, fixture.tokenID); err != nil {
				t.Fatal(err)
			}
			input := LifecycleInstallBegin{
				Claim: fixture.claim, ExpectedGeneration: 1, RequestID: fixture.requestID, OperationID: fixture.operation,
				ReleaseNamespace: "tunnex", ReleaseName: "tunnex-gateway",
				InstallIntentDigest: "sha256:" + strings.Repeat("a", 64), RequestedDurationSeconds: 120,
			}
			if _, err := fixture.service.BeginLifecycleInstall(ctx, fixture.actor, fixture.orgID, input); code(err) != test.wantCode {
				t.Fatalf("fence error = %v, want code %s", err, test.wantCode)
			}
		})
	}

	consumed := seedLifecycleInstallFixture(t, ctx, pool, 120)
	consumeAndBindLifecycleNode(t, ctx, pool, consumed)
	if _, err := pool.Exec(ctx, `DELETE FROM node_lifecycle_install_operations WHERE operation_id=$1`, consumed.operation); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE node_join_tokens SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, consumed.tokenID); err != nil {
		t.Fatal(err)
	}
	consumedBegin := LifecycleInstallBegin{
		Claim: consumed.claim, ExpectedGeneration: 1, RequestID: consumed.requestID, OperationID: consumed.operation,
		ReleaseNamespace: "tunnex", ReleaseName: "tunnex-gateway",
		InstallIntentDigest: "sha256:" + strings.Repeat("a", 64), RequestedDurationSeconds: 120,
	}
	if _, err := consumed.service.BeginLifecycleInstall(ctx, consumed.actor, consumed.orgID, consumedBegin); code(err) != "lifecycle_install_claim_terminal" {
		t.Fatalf("consumed claim received recovery proof: %v", err)
	}

	cleanReleased := seedLifecycleInstallFixture(t, ctx, pool, 120)
	if _, err := cleanReleased.service.ReleaseLifecycleInstall(ctx, cleanReleased.actor, cleanReleased.orgID, LifecycleInstallCAS{
		Claim: cleanReleased.claim, ExpectedGeneration: 1, RequestID: cleanReleased.requestID,
		OperationID: cleanReleased.operation, ExpectedEpoch: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE node_join_tokens SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, cleanReleased.tokenID); err != nil {
		t.Fatal(err)
	}
	cleanReleasedBegin := LifecycleInstallBegin{
		Claim: cleanReleased.claim, ExpectedGeneration: 1, RequestID: cleanReleased.requestID, OperationID: uuid.New(),
		ReleaseNamespace: "tunnex", ReleaseName: "tunnex-gateway",
		InstallIntentDigest: "sha256:" + strings.Repeat("a", 64), RequestedDurationSeconds: 120,
	}
	if _, err := cleanReleased.service.BeginLifecycleInstall(ctx, cleanReleased.actor, cleanReleased.orgID, cleanReleasedBegin); code(err) != "lifecycle_install_operation_absent_after_expiry" {
		t.Fatalf("clean released predecessor recovery error = %v", err)
	}

	dirtyReleased := seedLifecycleInstallFixture(t, ctx, pool, 120)
	dirtyCAS := LifecycleInstallCAS{
		Claim: dirtyReleased.claim, ExpectedGeneration: 1, RequestID: dirtyReleased.requestID,
		OperationID: dirtyReleased.operation, ExpectedEpoch: 1,
	}
	if _, err := dirtyReleased.service.CoordinatedAbortLifecycleClaim(ctx, dirtyReleased.actor, dirtyReleased.orgID, dirtyCAS); err != nil {
		t.Fatal(err)
	}
	if _, err := dirtyReleased.service.ReleaseLifecycleInstall(ctx, dirtyReleased.actor, dirtyReleased.orgID, dirtyCAS); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE node_join_tokens SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, dirtyReleased.tokenID); err != nil {
		t.Fatal(err)
	}
	dirtyReleasedBegin := LifecycleInstallBegin{
		Claim: dirtyReleased.claim, ExpectedGeneration: 1, RequestID: dirtyReleased.requestID, OperationID: uuid.New(),
		ReleaseNamespace: "tunnex", ReleaseName: "tunnex-gateway",
		InstallIntentDigest: "sha256:" + strings.Repeat("a", 64), RequestedDurationSeconds: 120,
	}
	if _, err := dirtyReleased.service.BeginLifecycleInstall(ctx, dirtyReleased.actor, dirtyReleased.orgID, dirtyReleasedBegin); code(err) != "lifecycle_install_operation_held" {
		t.Fatalf("abort-marked released predecessor error = %v", err)
	}

	completed := seedLifecycleInstallFixture(t, ctx, pool, 120)
	consumeAndBindLifecycleNode(t, ctx, pool, completed)
	if _, err := completed.service.CompleteLifecycleInstall(ctx, completed.actor, completed.orgID, LifecycleInstallComplete{
		LifecycleInstallCAS: LifecycleInstallCAS{
			Claim: completed.claim, ExpectedGeneration: 1, RequestID: completed.requestID,
			OperationID: completed.operation, ExpectedEpoch: 1,
		},
		ReleaseReady: true,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE node_join_tokens SET expires_at=clock_timestamp()-interval '1 second',lifecycle_token_sealed=NULL WHERE id=$1`, completed.tokenID); err != nil {
		t.Fatal(err)
	}
	var beforeLatestRead, afterLatestRead time.Time
	if err := pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&beforeLatestRead); err != nil {
		t.Fatal(err)
	}
	completedLatest, err := completed.service.GetLatestLifecycleInstallOperation(ctx, completed.orgID, completed.claim)
	if clockErr := pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&afterLatestRead); clockErr != nil {
		t.Fatal(clockErr)
	}
	if err != nil || completedLatest.State != LifecycleInstallCompleted || completedLatest.OperationID != completed.operation {
		t.Fatalf("completed token-blind latest = %+v err=%v", completedLatest, err)
	}
	if completedLatest.ServerTime.Before(beforeLatestRead) || completedLatest.ServerTime.After(afterLatestRead) {
		t.Fatalf("latest server_time=%s is outside DB samples [%s,%s]", completedLatest.ServerTime, beforeLatestRead, afterLatestRead)
	}
	completedBegin := LifecycleInstallBegin{
		Claim: completed.claim, ExpectedGeneration: 1, RequestID: completed.requestID, OperationID: uuid.New(),
		ReleaseNamespace: "tunnex", ReleaseName: "tunnex-gateway",
		InstallIntentDigest: "sha256:" + strings.Repeat("a", 64), RequestedDurationSeconds: 120,
	}
	if _, err := completed.service.BeginLifecycleInstall(ctx, completed.actor, completed.orgID, completedBegin); code(err) != "lifecycle_install_operation_held" {
		t.Fatalf("completed predecessor error = %v", err)
	}

	otherOrg := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,$2,$3)`, otherOrg, "D13k Other", "d13k-"+otherOrg.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, otherOrg) })
	if _, err := completed.service.GetLatestLifecycleInstallOperation(ctx, otherOrg, completed.claim); code(err) != "lifecycle_install_operation_not_found" {
		t.Fatalf("cross-org latest read error = %v", err)
	}
}

func TestLifecycleInstallForeignAndGappedEpochRefuseWithoutMutation(t *testing.T) {
	now := time.Now().UTC()
	operation := sqlc.NodeLifecycleInstallOperation{
		OperationID: uuid.New(), OrgID: uuid.New(), LifecycleClaim: uuid.New(), LifecycleGeneration: 1,
		LifecycleRequestID: uuid.New(), Epoch: 4, State: "taken_over", InstallIntentDigest: "sha256:" + strings.Repeat("a", 64),
		ReleaseNamespace: "tunnex", ReleaseName: "tunnex-gateway", RequestedDurationSeconds: 120,
		NotAfter: now, HeartbeatAt: now,
	}
	base := LifecycleInstallCAS{Claim: operation.LifecycleClaim, ExpectedGeneration: 1, RequestID: operation.LifecycleRequestID, OperationID: operation.OperationID}
	base.ExpectedEpoch = 3
	if err := validateAbortAgainstOperation(base, operation); err != nil {
		t.Fatalf("exact lost takeover response was not replayable: %v", err)
	}
	base.ExpectedEpoch = 2
	if err := validateAbortAgainstOperation(base, operation); code(err) != "lifecycle_install_operation_fenced" {
		t.Fatalf("gapped epoch error = %v", err)
	}
	base.ExpectedEpoch = 3
	base.OperationID = uuid.New()
	if err := validateAbortAgainstOperation(base, operation); code(err) != "lifecycle_install_operation_fenced" {
		t.Fatalf("foreign operation error = %v", err)
	}
}
