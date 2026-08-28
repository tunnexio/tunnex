package nodes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
)

// TestPostgresPoolVIPOwnershipDeliveryStore is deliberately a real PostgreSQL
// proof. It uses an isolated database because it migrates up/down/up and races
// acknowledgement transactions; no shared test database is mutated.
func TestPostgresPoolVIPOwnershipDeliveryStore(t *testing.T) {
	admin := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run ownership delivery PostgreSQL integration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	dsn := newOwnershipDeliveryIntegrationDatabase(t, ctx, admin)

	if err := db.MigrateTo(dsn, 78); err != nil {
		t.Fatalf("migrate prerequisite baseline: %v", err)
	}
	installOwnershipDeliveryPoolPrerequisite(t, ctx, dsn)
	if err := db.MigrateTo(dsn, 81); err != nil {
		t.Fatalf("migrate through 0081: %v", err)
	}
	if err := db.DownOne(dsn); err != nil {
		t.Fatalf("0081 down: %v", err)
	}
	assertOwnershipDeliveryTable(t, ctx, dsn, false)
	if err := db.MigrateTo(dsn, 81); err != nil {
		t.Fatalf("0081 up after down: %v", err)
	}
	assertOwnershipDeliveryTable(t, ctx, dsn, true)

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	org, otherOrg, connector, target, otherTarget, scope := seedOwnershipDeliveryNodes(t, ctx, pool)
	store := NewPostgresPoolVIPOwnershipDeliveryStore(pool)
	agent := PoolVIPOwnershipAgentIdentity{NodeID: target, OrgID: org}
	expires := time.Now().Add(time.Hour).UTC()

	firstEnvelope := ownershipDeliveryStoreEnvelope(org, connector, target, scope, 7, 11, 13)
	// A P1 crash can retry the same immutable issue concurrently. Exactly one
	// row may exist, but both callers must succeed after comparing the conflict.
	issueErrs := make(chan error, 2)
	var issueWG sync.WaitGroup
	for range 2 {
		issueWG.Add(1)
		go func() {
			defer issueWG.Done()
			issueErrs <- NewPostgresPoolVIPOwnershipDeliveryStore(pool).IssuePoolVIPOwnershipDelivery(context.Background(), firstEnvelope, expires)
		}()
	}
	issueWG.Wait()
	close(issueErrs)
	for err := range issueErrs {
		if err != nil {
			t.Fatalf("concurrent identical issue: %v", err)
		}
	}
	var initialRows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pool_vip_ownership_deliveries WHERE org_id=$1 AND delivery_id=$2`, org, uuid.MustParse(firstEnvelope.DeliveryID)).Scan(&initialRows); err != nil || initialRows != 1 {
		t.Fatalf("identical reissue must retain one delivery row: rows=%d err=%v", initialRows, err)
	}
	if err := NewPostgresPoolVIPOwnershipDeliveryStore(pool).IssuePoolVIPOwnershipDelivery(ctx, firstEnvelope, expires); err != nil {
		t.Fatalf("post-restart identical issue must succeed: %v", err)
	}
	changedEnvelope := firstEnvelope
	changedEnvelope.DeliveryNonce = strings.Repeat("c", 64)
	if err := store.IssuePoolVIPOwnershipDelivery(ctx, changedEnvelope, expires); err == nil {
		t.Fatal("same delivery ID with a changed immutable envelope must fail closed")
	}
	if err := store.IssuePoolVIPOwnershipDelivery(ctx, firstEnvelope, expires.Add(time.Minute)); err == nil {
		t.Fatal("same delivery ID with a changed expiry must fail closed")
	}
	if _, err := pool.Exec(ctx, `
		UPDATE pool_vip_ownership_deliveries
		SET target_node_id=$1
		WHERE org_id=$2 AND delivery_id=$3`, otherTarget, org, uuid.MustParse(firstEnvelope.DeliveryID)); err == nil {
		t.Fatal("raw cross-org target update must violate the composite node/org FK")
	}
	if _, err := pool.Exec(ctx, `
		UPDATE pool_vip_ownership_deliveries SET pool_id=$1
		WHERE org_id=$2 AND delivery_id=$3`, uuid.New(), org, uuid.MustParse(firstEnvelope.DeliveryID)); err == nil {
		t.Fatal("raw wrong-pool delivery update must violate the exact pool scope FK")
	}
	if _, err := pool.Exec(ctx, `
		UPDATE pool_vip_ownership_deliveries SET connector_node_id=$1
		WHERE org_id=$2 AND delivery_id=$3`, otherTarget, org, uuid.MustParse(firstEnvelope.DeliveryID)); err == nil {
		t.Fatal("raw non-member connector update must violate the exact pool membership FK")
	}
	var firstDeliveryRow, firstStateID uuid.UUID
	if err := pool.QueryRow(ctx, `
		SELECT d.id, s.id
		FROM pool_vip_ownership_deliveries d
		JOIN pool_vip_ownership_delivery_states s
		  ON s.org_id=d.org_id AND s.site_id=d.site_id AND s.cluster_id=d.cluster_id
		 AND s.pool_id=d.pool_id AND s.connector_node_id=d.connector_node_id
		WHERE d.org_id=$1 AND d.delivery_id=$2`, org, uuid.MustParse(firstEnvelope.DeliveryID)).Scan(&firstDeliveryRow, &firstStateID); err != nil {
		t.Fatalf("load raw-FK fixture IDs: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO pool_vip_ownership_delivery_ack_receipts
			(org_id, delivery_row_id, state_id, fingerprint, receipt_time)
		VALUES ($1, $2, $3, 'raw-cross-org', now())`, otherOrg, firstDeliveryRow, firstStateID); err == nil {
		t.Fatal("raw cross-org acknowledgement receipt insertion must violate composite delivery/state FKs")
	}
	if _, err := pool.Exec(ctx, `
		UPDATE pool_vip_ownership_delivery_states SET cluster_id=$1 WHERE id=$2`, uuid.New(), firstStateID); err == nil {
		t.Fatal("raw state cluster update must violate the exact pool scope FK")
	}
	if _, err := pool.Exec(ctx, `
		UPDATE pool_vip_ownership_delivery_states SET connector_node_id=$1 WHERE id=$2`, otherTarget, firstStateID); err == nil {
		t.Fatal("raw state connector update must violate the exact pool membership FK")
	}
	if got, found, err := store.LoadIssuedPoolVIPOwnershipDelivery(ctx, agent); err != nil || !found || got != firstEnvelope {
		t.Fatalf("load issued: found=%v envelope=%+v err=%v", found, got, err)
	}
	if _, found, err := store.LoadIssuedPoolVIPOwnershipDelivery(ctx, PoolVIPOwnershipAgentIdentity{NodeID: otherTarget, OrgID: otherOrg}); err != nil || found {
		t.Fatalf("cross-org load found=%v err=%v", found, err)
	}
	if _, found, err := store.LoadIssuedPoolVIPOwnershipDelivery(ctx, PoolVIPOwnershipAgentIdentity{NodeID: connector, OrgID: org}); err != nil || found {
		t.Fatalf("cross-node load found=%v err=%v", found, err)
	}
	lookup := PoolVIPOwnershipDeliveryReadScope{
		OrgID: org.String(), SiteID: scope.siteID.String(), PoolID: scope.poolID.String(),
		OperationID: firstEnvelope.OperationID, ManifestIdentity: firstEnvelope.ManifestIdentity, DeliveryID: firstEnvelope.DeliveryID,
	}
	projection, found, err := store.LoadPoolVIPOwnershipDeliveryProjection(ctx, lookup)
	if err != nil || !found || projection.Envelope != firstEnvelope || !projection.ExpiresAt.Equal(canonicalPoolVIPOwnershipDeliveryExpiry(expires)) || projection.Receipt != nil {
		t.Fatalf("unacknowledged exact projection: found=%v projection=%+v err=%v", found, projection, err)
	}
	for _, mutate := range []func(*PoolVIPOwnershipDeliveryReadScope){
		func(v *PoolVIPOwnershipDeliveryReadScope) { v.OrgID = otherOrg.String() },
		func(v *PoolVIPOwnershipDeliveryReadScope) { v.SiteID = uuid.New().String() },
		func(v *PoolVIPOwnershipDeliveryReadScope) { v.PoolID = uuid.New().String() },
		func(v *PoolVIPOwnershipDeliveryReadScope) { v.OperationID = uuid.New().String() },
		func(v *PoolVIPOwnershipDeliveryReadScope) { v.ManifestIdentity = strings.Repeat("c", 64) },
	} {
		denied := lookup
		mutate(&denied)
		if _, found, err := store.LoadPoolVIPOwnershipDeliveryProjection(ctx, denied); err != nil || found {
			t.Fatalf("cross-org/scope projection must reveal no delivery: found=%v err=%v", found, err)
		}
	}

	ackFirst := ownershipAck(firstEnvelope)
	receiptTime := time.Date(2026, 8, 13, 17, 0, 0, 0, time.UTC)
	first, err := store.UpdatePoolVIPOwnershipAck(ctx, agent, ackFirst, receiptTime, validateOwnershipDeliveryAck(agent, ackFirst, receiptTime))
	if err != nil || first.Duplicate || !first.ReceiptTime.Equal(receiptTime) {
		t.Fatalf("first ack=%+v err=%v", first, err)
	}
	// A restarted owner reads the durable receipt, but the receipt remains only
	// acknowledgement evidence—not an applied or serving readiness assertion.
	restarted := NewPostgresPoolVIPOwnershipDeliveryStore(pool)
	projection, found, err = restarted.LoadPoolVIPOwnershipDeliveryProjection(ctx, lookup)
	if err != nil || !found || projection.Receipt == nil || !projection.Receipt.ReceiptTime.Equal(receiptTime) {
		t.Fatalf("restart receipt projection: found=%v projection=%+v err=%v", found, projection, err)
	}
	// P1 0079 permits a node to belong to exactly one pool. Within that valid
	// scope, an acknowledged higher row must not hide a pending delivery: polls
	// select only unacknowledged rows, not the historical highest row.
	pendingEnvelope := ownershipDeliveryStoreEnvelope(org, connector, target, scope, 7, 12, 14)
	if err := store.IssuePoolVIPOwnershipDelivery(ctx, pendingEnvelope, expires); err != nil {
		t.Fatalf("issue pending delivery: %v", err)
	}
	if got, found, err := store.LoadIssuedPoolVIPOwnershipDelivery(ctx, agent); err != nil || !found || got.DeliveryID != pendingEnvelope.DeliveryID {
		t.Fatalf("poll must select pending delivery after an acknowledged row: found=%v envelope=%+v err=%v", found, got, err)
	}
	// A second store instance proves the receipt/fence is PostgreSQL-backed, not
	// retained by the original process.
	duplicate, err := restarted.UpdatePoolVIPOwnershipAck(ctx, agent, ackFirst, receiptTime.Add(time.Hour), validateOwnershipDeliveryAck(agent, ackFirst, receiptTime.Add(time.Hour)))
	if err != nil || !duplicate.Duplicate || !duplicate.ReceiptTime.Equal(receiptTime) {
		t.Fatalf("restart duplicate=%+v err=%v", duplicate, err)
	}
	futureAck := ackFirst
	futureAck.ManifestRevision++
	if _, err := store.UpdatePoolVIPOwnershipAck(ctx, agent, futureAck, receiptTime, validateOwnershipDeliveryAck(agent, futureAck, receiptTime)); err == nil {
		t.Fatal("future acknowledgement must be rejected without changing the fence")
	}
	if _, err := store.UpdatePoolVIPOwnershipAck(ctx, PoolVIPOwnershipAgentIdentity{NodeID: otherTarget, OrgID: otherOrg}, ackFirst, receiptTime, validateOwnershipDeliveryAck(agent, ackFirst, receiptTime)); err == nil {
		t.Fatal("cross-principal acknowledgement must be denied")
	}

	successor := ownershipDeliveryStoreEnvelope(org, connector, target, scope, 8, 12, 14)
	if err := store.IssuePoolVIPOwnershipDelivery(ctx, successor, expires); err != nil {
		t.Fatalf("issue successor: %v", err)
	}
	ackSuccessor := ownershipAck(successor)
	if got, err := store.UpdatePoolVIPOwnershipAck(ctx, agent, ackSuccessor, receiptTime.Add(time.Minute), validateOwnershipDeliveryAck(agent, ackSuccessor, receiptTime.Add(time.Minute))); err != nil || got.Duplicate {
		t.Fatalf("successor ack=%+v err=%v", got, err)
	}
	stale := ownershipDeliveryStoreEnvelope(org, connector, target, scope, 7, 13, 15)
	if err := store.IssuePoolVIPOwnershipDelivery(ctx, stale, expires); err != nil {
		t.Fatalf("issue stale candidate: %v", err)
	}
	ackStale := ownershipAck(stale)
	if _, err := store.UpdatePoolVIPOwnershipAck(ctx, agent, ackStale, receiptTime.Add(2*time.Minute), validateOwnershipDeliveryAck(agent, ackStale, receiptTime.Add(2*time.Minute))); err == nil {
		t.Fatal("regressed generation must be rejected")
	}

	concurrent := ownershipDeliveryStoreEnvelope(org, connector, target, scope, 9, 14, 16)
	if err := store.IssuePoolVIPOwnershipDelivery(ctx, concurrent, expires); err != nil {
		t.Fatalf("issue concurrent: %v", err)
	}
	ackConcurrent := ownershipAck(concurrent)
	results := make(chan PoolVIPOwnershipAckValidation, 2)
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := NewPostgresPoolVIPOwnershipDeliveryStore(pool).UpdatePoolVIPOwnershipAck(context.Background(), agent, ackConcurrent, receiptTime.Add(3*time.Minute), validateOwnershipDeliveryAck(agent, ackConcurrent, receiptTime.Add(3*time.Minute)))
			results <- got
			errs <- err
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	duplicates := 0
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent acknowledgement: %v", err)
		}
	}
	for result := range results {
		if result.Duplicate {
			duplicates++
		}
	}
	if duplicates != 1 {
		t.Fatalf("concurrent acknowledgements must yield one exact duplicate, got %d", duplicates)
	}
	var receipts int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pool_vip_ownership_delivery_ack_receipts`).Scan(&receipts); err != nil || receipts != 3 {
		t.Fatalf("ack receipt count=%d err=%v", receipts, err)
	}

	deleted, err := store.CleanupExpiredPoolVIPOwnershipDeliveries(ctx, time.Now().Add(2*time.Hour))
	if err != nil || deleted != 5 {
		t.Fatalf("cleanup deleted=%d err=%v", deleted, err)
	}
	if _, found, err := store.LoadIssuedPoolVIPOwnershipDelivery(ctx, agent); err != nil || found {
		t.Fatalf("cleaned delivery found=%v err=%v", found, err)
	}
	if _, err := store.UpdatePoolVIPOwnershipAck(ctx, agent, ackConcurrent, receiptTime.Add(4*time.Minute), validateOwnershipDeliveryAck(agent, ackConcurrent, receiptTime.Add(4*time.Minute))); err == nil {
		t.Fatal("expired/cleaned acknowledgement must be rejected")
	}
	// The state fence survives cleanup, so a previously regressed generation
	// remains refused after all delivery rows have been removed.
	postCleanupStale := ownershipDeliveryStoreEnvelope(org, connector, target, scope, 8, 15, 17)
	if err := store.IssuePoolVIPOwnershipDelivery(ctx, postCleanupStale, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("issue post-cleanup stale candidate: %v", err)
	}
	ackPostCleanupStale := ownershipAck(postCleanupStale)
	if _, err := store.UpdatePoolVIPOwnershipAck(ctx, agent, ackPostCleanupStale, receiptTime.Add(5*time.Minute), validateOwnershipDeliveryAck(agent, ackPostCleanupStale, receiptTime.Add(5*time.Minute))); err == nil {
		t.Fatal("cleanup must not erase the generation fence")
	}
	if err := db.DownOne(dsn); err == nil {
		t.Fatal("0081 rollback with delivery state must refuse loudly")
	}
}

func TestPostgresPoolVIPOwnershipDeliveryStoreV3(t *testing.T) {
	admin := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run ownership delivery v3 PostgreSQL integration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	dsn := newOwnershipDeliveryIntegrationDatabase(t, ctx, admin)
	if err := db.MigrateTo(dsn, 118); err != nil {
		t.Fatalf("migrate through 0118: %v", err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	org, _, connector, target, _, scope := seedOwnershipDeliveryNodes(t, ctx, pool)
	base := ownershipDeliveryStoreEnvelope(org, connector, target, scope, 7, 11, 13)
	base.Version = PoolVIPOwnershipDeliveryHandoffVersion
	expires := time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)
	manifest := PoolVIPOwnershipManifestV3{Version: 1, OrgID: base.OrgID, SiteID: base.SiteID, ClusterID: base.ClusterID, PoolID: base.PoolID, ConnectorNodeID: base.ConnectorNodeID,
		Role: base.Role, PromotionGeneration: base.PromotionGeneration, ManifestRevision: base.ManifestRevision, LeaseEpoch: base.LeaseEpoch, LeaseExpiresAt: expires,
		DNSZone: "cluster.k8s.example", DNSVIP: "100.64.0.2", HandoffOwnerID: base.OperationID, RouteIntent: "serving", WGPeers: []PoolVIPOwnershipWGPeerV3{{PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", AllowedIPs: []string{"10.44.0.0/16"}}}, Routes: []string{"10.44.0.0/16"},
		Services: []PoolVIPOwnershipServiceV3{{ServiceID: uuid.NewString(), VIP: "100.64.0.10", Namespace: "default", Service: "api", ServiceCIDR: "10.96.0.0/12", DNSName: "api.default.cluster.k8s.example", Protocol: "tcp", Port: 443}}}
	policy := manifest.policyManifest()
	base.ManifestIdentity, err = policyspec.PoolVIPOwnershipManifestIdentity(policy)
	if err != nil {
		t.Fatal(err)
	}
	routeDigest, _ := PoolVIPOwnershipOwnedRouteDigest(manifest.Routes)
	envelope := PoolVIPOwnershipDeliveryEnvelopeV3{PoolVIPOwnershipDeliveryEnvelope: base, ExpiresAt: expires, Manifest: manifest, ExpectedRouteDigest: routeDigest, ExpectedVIPMapDigest: poolVIPOwnershipManifestVIPMapDigest(policy)}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	const lockKey int64 = 0x203a03
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, lockKey); err != nil {
		t.Fatal(err)
	}
	defer conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, lockKey) //nolint:errcheck
	var pid int32
	if err := conn.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	store := NewPostgresPoolVIPOwnershipDeliveryStore(pool)
	if err := store.IssuePoolVIPOwnershipHandoffDeliveryV3LeaderBound(ctx, PoolVIPOwnershipHandoffLeaderSession{Epoch: PoolVIPOwnershipHandoffLeadershipEpoch{BackendPID: pid, AdvisoryLockKey: lockKey}, Conn: conn}, envelope); err != nil {
		t.Fatalf("leader-bound v3 issue: %v", err)
	}
	agent := PoolVIPOwnershipAgentIdentity{NodeID: target, OrgID: org}
	loaded, found, err := store.LoadIssuedPoolVIPOwnershipDeliveryV3(ctx, agent)
	if err != nil || !found || !reflect.DeepEqual(loaded, envelope) {
		t.Fatalf("load v3 found=%t err=%v got=%+v", found, err, loaded)
	}
	ack := ownershipAckV3(envelope)
	result, err := store.UpdatePoolVIPOwnershipAckV3(ctx, agent, ack, time.Now().UTC(), func(e PoolVIPOwnershipDeliveryEnvelopeV3, state PoolVIPOwnershipAckState) (PoolVIPOwnershipAckValidation, error) {
		return ValidatePoolVIPOwnershipDeliveryAckV3(time.Now().UTC(), agent, e, ack, state)
	})
	if err != nil || result.Duplicate {
		t.Fatalf("persist v3 ACK=%+v err=%v", result, err)
	}
	var wire int
	var storedManifest, appliedManifest []byte
	if err := pool.QueryRow(ctx, `SELECT d.wire_version,d.ownership_manifest,r.applied_manifest FROM pool_vip_ownership_deliveries d JOIN pool_vip_ownership_delivery_ack_receipts r ON r.delivery_row_id=d.id WHERE d.org_id=$1 AND d.delivery_id=$2`, org, uuid.MustParse(envelope.DeliveryID)).Scan(&wire, &storedManifest, &appliedManifest); err != nil {
		t.Fatal(err)
	}
	if wire != 3 || len(storedManifest) == 0 || len(appliedManifest) == 0 {
		t.Fatalf("v3 durable payload missing wire=%d", wire)
	}
}

func TestPostgresPoolVIPOwnershipDeliveryStoreV2AppliedAttestation(t *testing.T) {
	admin := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run ownership delivery PostgreSQL integration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	dsn := newOwnershipDeliveryIntegrationDatabase(t, ctx, admin)
	if err := db.MigrateTo(dsn, 78); err != nil {
		t.Fatalf("migrate prerequisite baseline: %v", err)
	}
	installOwnershipDeliveryPoolPrerequisite(t, ctx, dsn)
	if err := db.MigrateTo(dsn, 81); err != nil {
		t.Fatalf("migrate through 0081: %v", err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	org, otherOrg, connector, target, otherTarget, scope := seedOwnershipDeliveryNodes(t, ctx, pool)
	store := NewPostgresPoolVIPOwnershipDeliveryStore(pool)
	agent := PoolVIPOwnershipAgentIdentity{NodeID: target, OrgID: org}
	expires := time.Now().Add(time.Hour).UTC()

	serving := ownershipDeliveryStoreEnvelopeV2(org, connector, target, scope, policyspec.PoolVIPOwnershipServing, 7, 11, 13)
	if err := store.IssuePoolVIPOwnershipDeliveryV2(ctx, serving, expires); err != nil {
		t.Fatalf("issue v2 serving: %v", err)
	}
	overLimitRoutes := make([]string, poolVIPOwnershipMaxOwnedRoutes+1)
	for i := range overLimitRoutes {
		overLimitRoutes[i] = fmt.Sprintf("10.%d.%d.0/24", i/256, i%256)
	}
	overLimitRoutesJSON, err := json.Marshal(overLimitRoutes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE pool_vip_ownership_deliveries SET owned_routes=$1::jsonb
		WHERE org_id=$2 AND delivery_id=$3`, string(overLimitRoutesJSON), org, uuid.MustParse(serving.DeliveryID)); err == nil {
		t.Fatal("raw oversized v2 route evidence must violate the durable cardinality check")
	}
	if _, found, err := store.LoadIssuedPoolVIPOwnershipDelivery(ctx, agent); err != nil || found {
		t.Fatalf("v1 poll must never receive v2 work: found=%v err=%v", found, err)
	}
	if loaded, found, err := store.LoadIssuedPoolVIPOwnershipDeliveryV2(ctx, agent); err != nil || !found || !samePoolVIPOwnershipDeliveryV2(loaded, expires, serving, expires) {
		t.Fatalf("v2 load found=%v loaded=%+v err=%v", found, loaded, err)
	}
	invalidRolePhase := serving
	invalidRolePhase.Role = policyspec.PoolVIPOwnershipPreparedNonServing
	if err := store.IssuePoolVIPOwnershipDeliveryV2(ctx, invalidRolePhase, expires); err == nil {
		t.Fatal("role/phase mismatch must be refused before persistence")
	}

	ackServing := ownershipAckV2(serving)
	receiptTime := time.Date(2026, 8, 13, 19, 0, 0, 0, time.UTC)
	first, err := store.UpdatePoolVIPOwnershipAckV2(ctx, agent, ackServing, receiptTime, validateOwnershipDeliveryAckV2(agent, ackServing, receiptTime))
	if err != nil || first.Duplicate || !first.ReceiptTime.Equal(receiptTime) {
		t.Fatalf("v2 first ack=%+v err=%v", first, err)
	}
	retry, err := NewPostgresPoolVIPOwnershipDeliveryStore(pool).UpdatePoolVIPOwnershipAckV2(ctx, agent, ackServing, receiptTime.Add(time.Hour), validateOwnershipDeliveryAckV2(agent, ackServing, receiptTime.Add(time.Hour)))
	if err != nil || !retry.Duplicate || !retry.ReceiptTime.Equal(receiptTime) {
		t.Fatalf("v2 exact retry=%+v err=%v", retry, err)
	}
	if _, err := store.UpdatePoolVIPOwnershipAckV2(ctx, PoolVIPOwnershipAgentIdentity{NodeID: otherTarget, OrgID: otherOrg}, ackServing, receiptTime, validateOwnershipDeliveryAckV2(agent, ackServing, receiptTime)); err == nil {
		t.Fatal("cross-org/node v2 acknowledgement must be denied")
	}
	attestationScope := ownershipAppliedAttestationScope(serving)
	attestation, found, err := store.LoadPoolVIPOwnershipAppliedAttestation(ctx, attestationScope)
	if err != nil || !found || attestation.Envelope.Version != PoolVIPOwnershipDeliveryAttestationVersion || attestation.Ack.AppliedRole != ackServing.AppliedRole || attestation.Ack.AppliedManifestIdentity != ackServing.AppliedManifestIdentity || attestation.Ack.AppliedPromotionGeneration != ackServing.AppliedPromotionGeneration || attestation.Ack.AppliedManifestRevision != ackServing.AppliedManifestRevision || attestation.Ack.AppliedLeaseEpoch != ackServing.AppliedLeaseEpoch || attestation.Ack.OwnedRouteDigest != serving.ExpectedRouteDigest || attestation.Ack.VIPMapDigest != serving.ExpectedVIPMapDigest || !attestation.ReceiptTime.Equal(receiptTime) || !attestation.ExpiresAt.Equal(canonicalPoolVIPOwnershipDeliveryExpiry(expires)) {
		t.Fatalf("exact serving attestation found=%v value=%+v err=%v", found, attestation, err)
	}
	for _, mutate := range []func(*PoolVIPOwnershipAppliedAttestationScope){
		func(v *PoolVIPOwnershipAppliedAttestationScope) { v.OrgID = otherOrg.String() },
		func(v *PoolVIPOwnershipAppliedAttestationScope) {
			v.Role, v.DeliveryPhase = policyspec.PoolVIPOwnershipWithdrawal, poolVIPOwnershipPhaseWithdraw
		},
		func(v *PoolVIPOwnershipAppliedAttestationScope) { v.OperationID = uuid.New().String() },
	} {
		denied := attestationScope
		mutate(&denied)
		if _, found, err := store.LoadPoolVIPOwnershipAppliedAttestation(ctx, denied); err != nil || found {
			t.Fatalf("reader must isolate org/artifact/phase: found=%v err=%v", found, err)
		}
	}

	// A valid v1 receipt may advance the shared replay fence, but it remains
	// receipt-only: the applied-state reader filters it out by wire version.
	v1Receipt := ownershipDeliveryStoreEnvelope(org, connector, target, scope, 8, 12, 14)
	if err := store.IssuePoolVIPOwnershipDelivery(ctx, v1Receipt, expires); err != nil {
		t.Fatalf("issue receipt-only v1: %v", err)
	}
	ackV1 := ownershipAck(v1Receipt)
	if _, err := store.UpdatePoolVIPOwnershipAck(ctx, agent, ackV1, receiptTime.Add(time.Minute), validateOwnershipDeliveryAck(agent, ackV1, receiptTime.Add(time.Minute))); err != nil {
		t.Fatalf("ack receipt-only v1: %v", err)
	}
	v1Scope := PoolVIPOwnershipAppliedAttestationScope{OrgID: v1Receipt.OrgID, SiteID: v1Receipt.SiteID, ClusterID: v1Receipt.ClusterID, PoolID: v1Receipt.PoolID, ConnectorNodeID: v1Receipt.ConnectorNodeID, TargetNodeID: v1Receipt.TargetNodeID, OperationID: v1Receipt.OperationID, ManifestIdentity: v1Receipt.ManifestIdentity, Role: v1Receipt.Role, DeliveryPhase: v1Receipt.DeliveryPhase, DeliveryID: v1Receipt.DeliveryID, PromotionGeneration: v1Receipt.PromotionGeneration, ManifestRevision: v1Receipt.ManifestRevision, LeaseEpoch: v1Receipt.LeaseEpoch}
	if _, found, err := store.LoadPoolVIPOwnershipAppliedAttestation(ctx, v1Scope); err != nil || found {
		t.Fatalf("v1 receipt must never satisfy applied-state reader: found=%v err=%v", found, err)
	}

	stale := ownershipDeliveryStoreEnvelopeV2(org, connector, target, scope, policyspec.PoolVIPOwnershipServing, 7, 13, 15)
	if err := store.IssuePoolVIPOwnershipDeliveryV2(ctx, stale, expires); err != nil {
		t.Fatalf("issue stale v2 candidate: %v", err)
	}
	ackStale := ownershipAckV2(stale)
	if _, err := store.UpdatePoolVIPOwnershipAckV2(ctx, agent, ackStale, receiptTime.Add(time.Minute), validateOwnershipDeliveryAckV2(agent, ackStale, receiptTime.Add(time.Minute))); err == nil {
		t.Fatal("stale v2 generation must be rejected")
	}

	withdrawal := ownershipDeliveryStoreEnvelopeV2(org, connector, target, scope, policyspec.PoolVIPOwnershipWithdrawal, 9, 13, 15)
	withdrawal.PriorLeaseEpoch = 14
	if err := store.IssuePoolVIPOwnershipDeliveryV2(ctx, withdrawal, expires); err != nil {
		t.Fatalf("issue withdrawal v2: %v", err)
	}
	ackWithdrawal := ownershipAckV2(withdrawal)
	if _, err := store.UpdatePoolVIPOwnershipAckV2(ctx, agent, ackWithdrawal, receiptTime.Add(2*time.Minute), validateOwnershipDeliveryAckV2(agent, ackWithdrawal, receiptTime.Add(2*time.Minute))); err != nil {
		t.Fatalf("withdrawal prior-lease evidence: %v", err)
	}
	if got, found, err := store.LoadPoolVIPOwnershipAppliedAttestation(ctx, ownershipAppliedAttestationScope(withdrawal)); err != nil || !found || got.Ack.AppliedLeaseEpoch != withdrawal.PriorLeaseEpoch || got.Ack.VIPMapDigest != "" {
		t.Fatalf("withdrawal attestation found=%v got=%+v err=%v", found, got, err)
	}

	expired := ownershipDeliveryStoreEnvelopeV2(org, connector, target, scope, policyspec.PoolVIPOwnershipServing, 10, 14, 16)
	if err := store.IssuePoolVIPOwnershipDeliveryV2(ctx, expired, expires); err != nil {
		t.Fatalf("issue expiring v2 candidate: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE pool_vip_ownership_deliveries SET expires_at=clock_timestamp()-interval '1 second' WHERE org_id=$1 AND delivery_id=$2`, org, uuid.MustParse(expired.DeliveryID)); err != nil {
		t.Fatal(err)
	}
	ackExpired := ownershipAckV2(expired)
	if _, err := store.UpdatePoolVIPOwnershipAckV2(ctx, agent, ackExpired, receiptTime.Add(3*time.Minute), validateOwnershipDeliveryAckV2(agent, ackExpired, receiptTime.Add(3*time.Minute))); err == nil {
		t.Fatal("expired v2 acknowledgement must be rejected")
	}
	if _, found, err := store.LoadPoolVIPOwnershipAppliedAttestation(ctx, ownershipAppliedAttestationScope(expired)); err != nil || found {
		t.Fatalf("expired v2 attestation must not be admissible: found=%v err=%v", found, err)
	}
}

// TestPostgresPoolVIPOwnershipHandoffDeliveryFacade proves the narrow
// coordinator seam against the real ledger. It never starts a scheduler: the
// explicit acknowledgement calls model the already-tested authenticated agent
// channel, while the HTTP/node E2E test composes that channel through this same
// facade.
func TestPostgresPoolVIPOwnershipHandoffDeliveryFacade(t *testing.T) {
	admin := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run ownership handoff PostgreSQL integration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	dsn := newOwnershipDeliveryIntegrationDatabase(t, ctx, admin)
	if err := db.MigrateTo(dsn, 118); err != nil {
		t.Fatalf("migrate through 0118: %v", err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	org, otherOrg, connector, target, _, scope := seedOwnershipDeliveryNodes(t, ctx, pool)
	store := NewPostgresPoolVIPOwnershipDeliveryStore(pool)
	leader := acquirePoolVIPOwnershipHandoffLeaderSession(t, ctx, pool, 0x5a10)
	first, err := NewPoolVIPOwnershipHandoffDeliveryFacade(store)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := NewPoolVIPOwnershipHandoffDeliveryFacade(NewPostgresPoolVIPOwnershipDeliveryStore(pool))
	if err != nil {
		t.Fatal(err)
	}
	expires := canonicalPoolVIPOwnershipDeliveryExpiry(time.Now().Add(time.Hour))
	envelope := ownershipDeliveryStoreEnvelopeV3(t, org, connector, target, scope, 7, 11, 13, expires)
	artifact := poolVIPOwnershipHandoffArtifact(envelope)

	for _, facade := range []*PoolVIPOwnershipHandoffDeliveryFacade{first, restarted} {
		got, err := facade.Issue(ctx, leader, envelope)
		if err != nil || got.Outcome != PoolVIPOwnershipHandoffPending || got.Artifact != artifact {
			t.Fatalf("leader-bound exact handoff issue=%+v err=%v", got, err)
		}
	}
	var rows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pool_vip_ownership_deliveries WHERE org_id=$1 AND delivery_id=$2`, org, uuid.MustParse(envelope.DeliveryID)).Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("concurrent issue rows=%d err=%v", rows, err)
	}
	if got, err := restarted.Issue(ctx, leader, envelope); err != nil || got.Outcome != PoolVIPOwnershipHandoffPending || got.Artifact != artifact {
		t.Fatalf("restart exact retry=%+v err=%v", got, err)
	}
	changed := envelope
	changed.DeliveryNonce = strings.Repeat("f", 64)
	if got, err := first.Issue(ctx, leader, changed); err != nil || got.Outcome != PoolVIPOwnershipHandoffConflict {
		t.Fatalf("changed immutable retry=%+v err=%v", got, err)
	}
	invalid := envelope
	invalid.Role = policyspec.PoolVIPOwnershipPreparedNonServing
	if got, err := first.Issue(ctx, leader, invalid); err != nil || got.Outcome != PoolVIPOwnershipHandoffRefused {
		t.Fatalf("invalid issue=%+v err=%v", got, err)
	}

	if got, err := first.Attestation(ctx, artifact); err != nil || got.Outcome != PoolVIPOwnershipHandoffPending {
		t.Fatalf("unacknowledged exact artifact=%+v err=%v", got, err)
	}
	agent := PoolVIPOwnershipAgentIdentity{NodeID: target, OrgID: org}
	ack := ownershipAckV3(envelope)
	// Receipt time must be before the issued artifact expires. Keep this
	// restart/idempotency fixture relative to the disposable test clock so it
	// exercises the production fail-closed invariant at every wall-clock time.
	receipt := canonicalPoolVIPOwnershipDeliveryExpiry(time.Now())
	firstAck, err := store.UpdatePoolVIPOwnershipAckV3(ctx, agent, ack, receipt, validateOwnershipDeliveryAckV3(agent, ack, receipt))
	if err != nil || firstAck.Duplicate || !firstAck.ReceiptTime.Equal(receipt) {
		t.Fatalf("first applied ack=%+v err=%v", firstAck, err)
	}
	// A lost HTTP response retries against a fresh facade/store instance and
	// returns the original CP receipt time, never agent-clock freshness.
	retryReceipt := receipt.Add(time.Minute)
	retry, err := NewPostgresPoolVIPOwnershipDeliveryStore(pool).UpdatePoolVIPOwnershipAckV3(ctx, agent, ack, retryReceipt, validateOwnershipDeliveryAckV3(agent, ack, retryReceipt))
	if err != nil || !retry.Duplicate || !retry.ReceiptTime.Equal(receipt) {
		t.Fatalf("lost-response retry=%+v err=%v", retry, err)
	}
	if reissue, err := restarted.Issue(ctx, leader, envelope); err != nil || reissue.Outcome != PoolVIPOwnershipHandoffPending || reissue.Artifact != artifact {
		t.Fatalf("post-advance exact issue retry=%+v err=%v", reissue, err)
	}
	got, err := restarted.Attestation(ctx, artifact)
	if err != nil || got.Outcome != PoolVIPOwnershipHandoffApplied || got.WireVersion != envelope.Version || got.AppliedRole != envelope.Role || got.AppliedManifestIdentity != envelope.ManifestIdentity || got.AppliedPromotionGeneration != envelope.PromotionGeneration || got.AppliedManifestRevision != envelope.ManifestRevision || got.AppliedLeaseEpoch != ack.AppliedLeaseEpoch || !got.ReceiptTime.Equal(receipt) || !got.ExpiresAt.Equal(expires) || got.OwnedRouteDigest != envelope.ExpectedRouteDigest || got.VIPMapDigest != envelope.ExpectedVIPMapDigest {
		t.Fatalf("restart exact applied result=%+v err=%v", got, err)
	}
	for name, mutate := range map[string]func(*PoolVIPOwnershipHandoffArtifact){
		"org":  func(v *PoolVIPOwnershipHandoffArtifact) { v.OrgID = otherOrg.String() },
		"site": func(v *PoolVIPOwnershipHandoffArtifact) { v.SiteID = uuid.NewString() },
		"role": func(v *PoolVIPOwnershipHandoffArtifact) {
			v.Role, v.DeliveryPhase = policyspec.PoolVIPOwnershipWithdrawal, poolVIPOwnershipPhaseWithdraw
		},
		"generation": func(v *PoolVIPOwnershipHandoffArtifact) { v.PromotionGeneration++ },
		"lease":      func(v *PoolVIPOwnershipHandoffArtifact) { v.LeaseEpoch++ },
	} {
		t.Run("wrong "+name+" cannot satisfy", func(t *testing.T) {
			wrong := artifact
			mutate(&wrong)
			outcome, err := restarted.Attestation(ctx, wrong)
			if err != nil || outcome.Outcome == PoolVIPOwnershipHandoffApplied {
				t.Fatalf("wrong %s result=%+v err=%v", name, outcome, err)
			}
		})
	}
	stale := ownershipDeliveryStoreEnvelopeV3(t, org, connector, target, scope, 6, 12, 14, expires)
	if got, err := first.Issue(ctx, leader, stale); err != nil || got.Outcome != PoolVIPOwnershipHandoffStaleGeneration {
		t.Fatalf("regressed generation issue=%+v err=%v", got, err)
	}
	read, found, err := store.ReadPoolVIPOwnershipHandoffAppliedAttestationV3(ctx, artifact)
	if err != nil || !found || read.WireVersion != envelope.Version || read.AppliedRole != envelope.Role || read.AppliedManifestIdentity != envelope.ManifestIdentity || read.AppliedPromotionGeneration != envelope.PromotionGeneration || read.AppliedManifestRevision != envelope.ManifestRevision || read.AppliedLeaseEpoch != ack.AppliedLeaseEpoch || !read.ReceiptTime.Equal(receipt) || !read.ExpiresAt.Equal(expires) || read.OwnedRouteDigest != envelope.ExpectedRouteDigest || read.VIPMapDigest != envelope.ExpectedVIPMapDigest {
		t.Fatalf("exact applied read=%+v found=%v err=%v", read, found, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE pool_vip_ownership_deliveries SET expires_at=clock_timestamp()-interval '1 second' WHERE org_id=$1 AND delivery_id=$2`, org, uuid.MustParse(envelope.DeliveryID)); err != nil {
		t.Fatal(err)
	}
	if got, err := restarted.Attestation(ctx, artifact); err != nil || got.Outcome != PoolVIPOwnershipHandoffPending {
		t.Fatalf("expired exact artifact must remain pending, got=%+v err=%v", got, err)
	}
}

func TestPostgresPoolVIPOwnershipLeaderBoundIssue(t *testing.T) {
	admin := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run leader-bound ownership PostgreSQL integration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	dsn := newOwnershipDeliveryIntegrationDatabase(t, ctx, admin)
	if err := db.MigrateTo(dsn, 78); err != nil {
		t.Fatalf("migrate prerequisite baseline: %v", err)
	}
	installOwnershipDeliveryPoolPrerequisite(t, ctx, dsn)
	if err := db.MigrateTo(dsn, 81); err != nil {
		t.Fatalf("migrate through 0081: %v", err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	org, _, connector, target, _, scope := seedOwnershipDeliveryNodes(t, ctx, pool)
	store := NewPostgresPoolVIPOwnershipDeliveryStore(pool)
	expires := time.Now().Add(time.Hour).UTC()
	leader := acquirePoolVIPOwnershipHandoffLeaderSession(t, ctx, pool, 0x5a20)

	accepted := ownershipDeliveryStoreEnvelopeV2(org, connector, target, scope, policyspec.PoolVIPOwnershipServing, 7, 11, 13)
	if err := store.IssuePoolVIPOwnershipHandoffDeliveryV2LeaderBound(ctx, leader, accepted, expires); err != nil {
		t.Fatalf("correct leader session issue: %v", err)
	}
	if err := store.IssuePoolVIPOwnershipHandoffDeliveryV2LeaderBound(ctx, leader, accepted, expires); err != nil {
		t.Fatalf("correct leader exact retry: %v", err)
	}
	assertNoLeaderBoundDelivery := func(t *testing.T, envelope PoolVIPOwnershipDeliveryEnvelopeV2) {
		t.Helper()
		var count int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM pool_vip_ownership_deliveries WHERE org_id=$1 AND delivery_id=$2`, org, uuid.MustParse(envelope.DeliveryID)).Scan(&count); err != nil || count != 0 {
			t.Fatalf("refused leader-bound issue wrote rows=%d err=%v", count, err)
		}
	}
	otherConn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer otherConn.Release()
	differentConn := ownershipDeliveryStoreEnvelopeV2(org, connector, target, scope, policyspec.PoolVIPOwnershipServing, 8, 12, 14)
	if err := store.IssuePoolVIPOwnershipHandoffDeliveryV2LeaderBound(ctx, PoolVIPOwnershipHandoffLeaderSession{Epoch: leader.Epoch, Conn: otherConn}, differentConn, expires); !errors.Is(err, ErrPoolVIPOwnershipHandoffLeaderSession) {
		t.Fatalf("different connection with claimed PID must refuse, got %v", err)
	}
	assertNoLeaderBoundDelivery(t, differentConn)
	wrongKey := ownershipDeliveryStoreEnvelopeV2(org, connector, target, scope, policyspec.PoolVIPOwnershipServing, 8, 12, 14)
	wrongKeySession := leader
	wrongKeySession.Epoch.AdvisoryLockKey++
	if err := store.IssuePoolVIPOwnershipHandoffDeliveryV2LeaderBound(ctx, wrongKeySession, wrongKey, expires); !errors.Is(err, ErrPoolVIPOwnershipHandoffLeaderSession) {
		t.Fatalf("wrong advisory key must refuse, got %v", err)
	}
	assertNoLeaderBoundDelivery(t, wrongKey)
	wrongPID := ownershipDeliveryStoreEnvelopeV2(org, connector, target, scope, policyspec.PoolVIPOwnershipServing, 8, 12, 14)
	wrongPIDSession := leader
	wrongPIDSession.Epoch.BackendPID++
	if err := store.IssuePoolVIPOwnershipHandoffDeliveryV2LeaderBound(ctx, wrongPIDSession, wrongPID, expires); !errors.Is(err, ErrPoolVIPOwnershipHandoffLeaderSession) {
		t.Fatalf("wrong backend PID must refuse, got %v", err)
	}
	assertNoLeaderBoundDelivery(t, wrongPID)
	changed := accepted
	changed.DeliveryNonce = strings.Repeat("e", 64)
	if err := store.IssuePoolVIPOwnershipHandoffDeliveryV2LeaderBound(ctx, leader, changed, expires); !errors.Is(err, ErrPoolVIPOwnershipDeliveryImmutableConflict) {
		t.Fatalf("immutable conflict=%v", err)
	}

	ack := ownershipAckV2(accepted)
	ackReceipt := time.Now().UTC()
	agent := PoolVIPOwnershipAgentIdentity{NodeID: target, OrgID: org}
	if _, err := store.UpdatePoolVIPOwnershipAckV2(ctx, agent, ack, ackReceipt, validateOwnershipDeliveryAckV2(agent, ack, ackReceipt)); err != nil {
		t.Fatalf("advance durable generation fence: %v", err)
	}
	stale := ownershipDeliveryStoreEnvelopeV2(org, connector, target, scope, policyspec.PoolVIPOwnershipServing, 6, 13, 15)
	if err := store.IssuePoolVIPOwnershipHandoffDeliveryV2LeaderBound(ctx, leader, stale, expires); !errors.Is(err, ErrPoolVIPOwnershipDeliveryStaleGeneration) {
		t.Fatalf("stale generation=%v", err)
	}
	assertNoLeaderBoundDelivery(t, stale)

	if _, err := leader.Conn.Exec(ctx, `SELECT pg_advisory_unlock($1)`, leader.Epoch.AdvisoryLockKey); err != nil {
		t.Fatalf("release leader lock before call: %v", err)
	}
	lost := ownershipDeliveryStoreEnvelopeV2(org, connector, target, scope, policyspec.PoolVIPOwnershipServing, 8, 14, 16)
	if err := store.IssuePoolVIPOwnershipHandoffDeliveryV2LeaderBound(ctx, leader, lost, expires); !errors.Is(err, ErrPoolVIPOwnershipHandoffLeaderSession) {
		t.Fatalf("lost lock before call must refuse, got %v", err)
	}
	assertNoLeaderBoundDelivery(t, lost)

	hookLeader := acquirePoolVIPOwnershipHandoffLeaderSession(t, ctx, pool, 0x5a21)
	store.leaderBoundPreWriteHook = func(ctx context.Context, conn *pgxpool.Conn) error {
		_, err := conn.Exec(ctx, `SELECT pg_advisory_unlock($1)`, hookLeader.Epoch.AdvisoryLockKey)
		return err
	}
	t.Cleanup(func() { store.leaderBoundPreWriteHook = nil })
	duringHook := ownershipDeliveryStoreEnvelopeV2(org, connector, target, scope, policyspec.PoolVIPOwnershipServing, 8, 14, 16)
	if err := store.IssuePoolVIPOwnershipHandoffDeliveryV2LeaderBound(ctx, hookLeader, duringHook, expires); !errors.Is(err, ErrPoolVIPOwnershipHandoffLeaderSession) {
		t.Fatalf("lock release during pre-write hook must refuse, got %v", err)
	}
	assertNoLeaderBoundDelivery(t, duringHook)
}

func validateOwnershipDeliveryAck(agent PoolVIPOwnershipAgentIdentity, ack PoolVIPOwnershipDeliveryAck, receiptTime time.Time) func(PoolVIPOwnershipDeliveryEnvelope, PoolVIPOwnershipAckState) (PoolVIPOwnershipAckValidation, error) {
	return func(envelope PoolVIPOwnershipDeliveryEnvelope, state PoolVIPOwnershipAckState) (PoolVIPOwnershipAckValidation, error) {
		return ValidatePoolVIPOwnershipDeliveryAck(receiptTime, agent, envelope, ack, state)
	}
}

type ownershipDeliveryStoreScope struct {
	siteID, clusterID, poolID uuid.UUID
}

func ownershipDeliveryStoreEnvelope(org, connector, target uuid.UUID, scope ownershipDeliveryStoreScope, generation, revision, epoch uint64) PoolVIPOwnershipDeliveryEnvelope {
	return PoolVIPOwnershipDeliveryEnvelope{
		Version: 1, OrgID: org.String(), SiteID: scope.siteID.String(), ClusterID: scope.clusterID.String(), PoolID: scope.poolID.String(),
		ConnectorNodeID: connector.String(), TargetNodeID: target.String(), OperationID: uuid.New().String(),
		ManifestIdentity: strings.Repeat("a", 64), Role: policyspec.PoolVIPOwnershipServing,
		PromotionGeneration: generation, ManifestRevision: revision, LeaseEpoch: epoch, DeliveryPhase: poolVIPOwnershipPhaseServe,
		DeliveryID: uuid.New().String(), DeliveryNonce: strings.Repeat("b", 64),
	}
}

func ownershipDeliveryStoreEnvelopeV2(org, connector, target uuid.UUID, scope ownershipDeliveryStoreScope, role string, generation, revision, epoch uint64) PoolVIPOwnershipDeliveryEnvelopeV2 {
	base := ownershipDeliveryStoreEnvelope(org, connector, target, scope, generation, revision, epoch)
	base.Version = PoolVIPOwnershipDeliveryAttestationVersion
	envelope := PoolVIPOwnershipDeliveryEnvelopeV2{PoolVIPOwnershipDeliveryEnvelope: base}
	switch role {
	case policyspec.PoolVIPOwnershipPreparedNonServing:
		envelope.Role, envelope.DeliveryPhase = role, poolVIPOwnershipPhasePrepare
	case policyspec.PoolVIPOwnershipWithdrawal:
		envelope.Role, envelope.DeliveryPhase, envelope.PriorLeaseEpoch = role, poolVIPOwnershipPhaseWithdraw, epoch-1
	default:
		envelope.OwnedRoutes = []string{"10.44.0.0/16"}
		envelope.ExpectedVIPMapDigest = strings.Repeat("c", 64)
	}
	envelope.ExpectedRouteDigest, _ = PoolVIPOwnershipOwnedRouteDigest(envelope.OwnedRoutes)
	return envelope
}

func ownershipDeliveryStoreEnvelopeV3(t *testing.T, org, connector, target uuid.UUID, scope ownershipDeliveryStoreScope, generation, revision, epoch uint64, expires time.Time) PoolVIPOwnershipDeliveryEnvelopeV3 {
	t.Helper()
	base := ownershipDeliveryStoreEnvelope(org, connector, target, scope, generation, revision, epoch)
	base.Version = PoolVIPOwnershipDeliveryHandoffVersion
	manifest := PoolVIPOwnershipManifestV3{
		Version: policyspec.PoolVIPOwnershipManifestVersion, OrgID: base.OrgID, SiteID: base.SiteID, ClusterID: base.ClusterID,
		PoolID: base.PoolID, ConnectorNodeID: base.ConnectorNodeID, Role: base.Role, PromotionGeneration: base.PromotionGeneration,
		ManifestRevision: base.ManifestRevision, LeaseEpoch: base.LeaseEpoch, LeaseExpiresAt: expires, DNSZone: "cluster.k8s.example",
		DNSVIP: "100.64.0.2", HandoffOwnerID: base.OperationID, RouteIntent: "serving",
		WGPeers: []PoolVIPOwnershipWGPeerV3{{PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", AllowedIPs: []string{"10.44.0.0/16"}}},
		Routes:  []string{"10.44.0.0/16"},
		Services: []PoolVIPOwnershipServiceV3{{
			ServiceID: uuid.NewString(), VIP: "100.64.0.10", Namespace: "default", Service: "api", ServiceCIDR: "10.96.0.0/12",
			DNSName: "api.default.cluster.k8s.example", Protocol: "tcp", Port: 443,
		}},
	}
	identity, err := policyspec.PoolVIPOwnershipManifestIdentity(manifest.policyManifest())
	if err != nil {
		t.Fatal(err)
	}
	base.ManifestIdentity = identity
	routeDigest, err := PoolVIPOwnershipOwnedRouteDigest(manifest.Routes)
	if err != nil {
		t.Fatal(err)
	}
	return PoolVIPOwnershipDeliveryEnvelopeV3{PoolVIPOwnershipDeliveryEnvelope: base, ExpiresAt: expires, Manifest: manifest,
		ExpectedRouteDigest: routeDigest, ExpectedVIPMapDigest: poolVIPOwnershipManifestVIPMapDigest(manifest.policyManifest())}
}

func validateOwnershipDeliveryAckV2(agent PoolVIPOwnershipAgentIdentity, ack PoolVIPOwnershipDeliveryAckV2, receiptTime time.Time) func(PoolVIPOwnershipDeliveryEnvelopeV2, PoolVIPOwnershipAckState) (PoolVIPOwnershipAckValidation, error) {
	return func(envelope PoolVIPOwnershipDeliveryEnvelopeV2, state PoolVIPOwnershipAckState) (PoolVIPOwnershipAckValidation, error) {
		return ValidatePoolVIPOwnershipDeliveryAckV2(receiptTime, agent, envelope, ack, state)
	}
}

func validateOwnershipDeliveryAckV3(agent PoolVIPOwnershipAgentIdentity, ack PoolVIPOwnershipDeliveryAckV3, receiptTime time.Time) func(PoolVIPOwnershipDeliveryEnvelopeV3, PoolVIPOwnershipAckState) (PoolVIPOwnershipAckValidation, error) {
	return func(envelope PoolVIPOwnershipDeliveryEnvelopeV3, state PoolVIPOwnershipAckState) (PoolVIPOwnershipAckValidation, error) {
		return ValidatePoolVIPOwnershipDeliveryAckV3(receiptTime, agent, envelope, ack, state)
	}
}

func ownershipAppliedAttestationScope(envelope PoolVIPOwnershipDeliveryEnvelopeV2) PoolVIPOwnershipAppliedAttestationScope {
	return PoolVIPOwnershipAppliedAttestationScope{OrgID: envelope.OrgID, SiteID: envelope.SiteID, ClusterID: envelope.ClusterID, PoolID: envelope.PoolID, ConnectorNodeID: envelope.ConnectorNodeID, TargetNodeID: envelope.TargetNodeID, OperationID: envelope.OperationID, ManifestIdentity: envelope.ManifestIdentity, Role: envelope.Role, DeliveryPhase: envelope.DeliveryPhase, DeliveryID: envelope.DeliveryID, PromotionGeneration: envelope.PromotionGeneration, ManifestRevision: envelope.ManifestRevision, LeaseEpoch: envelope.LeaseEpoch}
}

// p1ConnectorPoolPrerequisiteMigrationSQL is the test-only, byte-for-byte P1
// 0079 prerequisite for P2's isolated migration tests. It is deliberately not
// a P2 migration: a consolidated tree uses the real P1 migration below, and
// TestOwnershipDeliveryPoolPrerequisiteMatchesP1Migration prevents this copy
// from silently drifting when both worktrees are present.
const p1ConnectorPoolPrerequisiteMigrationSQL = `-- S10.3c: additive connector-pool persistence. The legacy
-- k8s_clusters.connector_node_id remains authoritative for existing clusters;
-- this optional pool reference is only a contract for the next handoff slice.
ALTER TABLE nodes
    ADD CONSTRAINT nodes_id_org_site_key UNIQUE (id, org_id, site_id);

ALTER TABLE k8s_clusters
    ADD CONSTRAINT k8s_clusters_id_org_site_key UNIQUE (id, org_id, site_id);

CREATE TABLE k8s_connector_pools (
    id                 uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    org_id             uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    site_id            uuid NOT NULL REFERENCES sites (id) ON DELETE CASCADE,
    cluster_id         uuid NOT NULL,
    preferred_node_id  uuid NOT NULL,
    active_node_id     uuid NOT NULL,
    generation         bigint NOT NULL DEFAULT 1 CHECK (generation > 0),
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, cluster_id),
    UNIQUE (id, org_id, site_id),
    UNIQUE (id, org_id, site_id, cluster_id),
    FOREIGN KEY (cluster_id, org_id, site_id) REFERENCES k8s_clusters (id, org_id, site_id) ON DELETE CASCADE,
    FOREIGN KEY (preferred_node_id, org_id, site_id) REFERENCES nodes (id, org_id, site_id) ON DELETE RESTRICT,
    FOREIGN KEY (active_node_id, org_id, site_id) REFERENCES nodes (id, org_id, site_id) ON DELETE RESTRICT
);

CREATE INDEX k8s_connector_pools_org_idx ON k8s_connector_pools (org_id);
CREATE INDEX k8s_connector_pools_site_idx ON k8s_connector_pools (site_id);
CREATE TRIGGER set_updated_at BEFORE UPDATE ON k8s_connector_pools
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE k8s_connector_pool_members (
    pool_id         uuid NOT NULL,
    org_id          uuid NOT NULL,
    site_id         uuid NOT NULL,
    node_id         uuid NOT NULL,
    admin_priority  int NOT NULL DEFAULT 0,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (pool_id, node_id),
    UNIQUE (pool_id, org_id, site_id, node_id),
    FOREIGN KEY (pool_id, org_id, site_id) REFERENCES k8s_connector_pools (id, org_id, site_id) ON DELETE CASCADE,
    FOREIGN KEY (node_id, org_id, site_id) REFERENCES nodes (id, org_id, site_id) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX k8s_connector_pool_members_node_unique
    ON k8s_connector_pool_members (node_id);

CREATE INDEX k8s_connector_pool_members_org_idx ON k8s_connector_pool_members (org_id);
CREATE TRIGGER set_updated_at BEFORE UPDATE ON k8s_connector_pool_members
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Preferred and active are not merely same-scope nodes: they must remain
-- members of THIS pool. The constraints are deferred because CreatePool inserts
-- the pool and its initial member set in one atomic statement.
ALTER TABLE k8s_connector_pools
    ADD CONSTRAINT k8s_connector_pools_preferred_member_fk
        FOREIGN KEY (id, org_id, site_id, preferred_node_id)
        REFERENCES k8s_connector_pool_members (pool_id, org_id, site_id, node_id)
        DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT k8s_connector_pools_active_member_fk
        FOREIGN KEY (id, org_id, site_id, active_node_id)
        REFERENCES k8s_connector_pool_members (pool_id, org_id, site_id, node_id)
        DEFERRABLE INITIALLY DEFERRED;

-- A cluster is either on the old one-node contract or explicitly attached to
-- the new pool contract. This prevents a future reader from silently choosing
-- between two authorities during a mixed-version rollout.
ALTER TABLE k8s_clusters
    ADD COLUMN connector_pool_id uuid,
    ADD CONSTRAINT k8s_clusters_connector_pool_fk
        FOREIGN KEY (connector_pool_id, org_id, site_id, id)
        REFERENCES k8s_connector_pools (id, org_id, site_id, cluster_id)
        DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT k8s_clusters_connector_mode_check
        CHECK (connector_node_id IS NULL OR connector_pool_id IS NULL);

CREATE INDEX k8s_clusters_connector_pool_idx ON k8s_clusters (connector_pool_id)
    WHERE connector_pool_id IS NOT NULL;
`

func TestOwnershipDeliveryPoolPrerequisiteMatchesP1Migration(t *testing.T) {
	b, err := os.ReadFile("../../db/migrations/0079_k8s_connector_pool.up.sql")
	if os.IsNotExist(err) {
		t.Skip("P1 0079 is absent in this isolated P2 worktree")
	}
	if err != nil {
		t.Fatalf("read P1 0079 migration: %v", err)
	}
	if string(b) != p1ConnectorPoolPrerequisiteMigrationSQL {
		t.Fatal("P2 standalone prerequisite drifted from real P1 0079; update this test-only fixture and re-run consolidated PostgreSQL proof")
	}
}

// installOwnershipDeliveryPoolPrerequisite uses P1's real 0079 in a
// consolidated tree. Before consolidation, it installs the exact test-only
// prerequisite above so P2's 0081 tests cannot accept a weaker pool contract.
// Consolidation order is 0079 -> 0080 -> 0081 -> 0082.
func installOwnershipDeliveryPoolPrerequisite(t *testing.T, ctx context.Context, dsn string) {
	t.Helper()
	if _, err := os.Stat("../../db/migrations/0079_k8s_connector_pool.up.sql"); err == nil {
		return
	} else if !os.IsNotExist(err) {
		t.Fatalf("stat P1 0079 migration prerequisite: %v", err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, p1ConnectorPoolPrerequisiteMigrationSQL); err != nil {
		t.Fatalf("install exact P1 0079 prerequisite: %v", err)
	}
}

func newOwnershipDeliveryIntegrationDatabase(t *testing.T, ctx context.Context, admin string) string {
	t.Helper()
	adminPool, err := pgxpool.New(ctx, admin)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	t.Cleanup(adminPool.Close)
	name := fmt.Sprintf("tnx_ownership_delivery_%d", time.Now().UnixNano())
	if _, err := adminPool.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("create isolated database: %v", err)
	}
	t.Cleanup(func() { _, _ = adminPool.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)") })
	u, err := url.Parse(admin)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	return u.String()
}

func acquirePoolVIPOwnershipHandoffLeaderSession(t *testing.T, ctx context.Context, pool *pgxpool.Pool, key int64) PoolVIPOwnershipHandoffLeaderSession {
	t.Helper()
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Release)
	var pid int32
	var granted bool
	if err := conn.QueryRow(ctx, `SELECT pg_backend_pid(), pg_try_advisory_lock($1)`, key).Scan(&pid, &granted); err != nil || !granted {
		t.Fatalf("acquire handoff leader lock: pid=%d granted=%v err=%v", pid, granted, err)
	}
	t.Cleanup(func() { _, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, key) })
	return PoolVIPOwnershipHandoffLeaderSession{Epoch: PoolVIPOwnershipHandoffLeadershipEpoch{BackendPID: pid, AdvisoryLockKey: key}, Conn: conn}
}

func assertOwnershipDeliveryTable(t *testing.T, ctx context.Context, dsn string, want bool) {
	t.Helper()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	var table *string
	if err := pool.QueryRow(ctx, `SELECT to_regclass('pool_vip_ownership_deliveries')::text`).Scan(&table); err != nil {
		t.Fatal(err)
	}
	if (table != nil) != want {
		t.Fatalf("delivery table=%v want exists=%v", table, want)
	}
}

func seedOwnershipDeliveryNodes(t *testing.T, ctx context.Context, pool *pgxpool.Pool) (uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID, ownershipDeliveryStoreScope) {
	t.Helper()
	org, otherOrg, connector, target, otherTarget := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	site, cluster, poolID := uuid.New(), uuid.New(), uuid.New()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	exec(`INSERT INTO organizations (id, name, slug, pool_cidr) VALUES ($1, 'ownership', $2, '10.99.0.0/24')`, org, "ownership-"+org.String()[:8])
	exec(`INSERT INTO organizations (id, name, slug, pool_cidr) VALUES ($1, 'other', $2, '10.98.0.0/24')`, otherOrg, "other-"+otherOrg.String()[:8])
	exec(`INSERT INTO sites (id, org_id, name) VALUES ($1, $2, 'ownership-site')`, site, org)
	for _, node := range []struct {
		id   uuid.UUID
		org  uuid.UUID
		name string
	}{
		{connector, org, "connector"}, {target, org, "target"}, {otherTarget, otherOrg, "other"},
	} {
		if node.org == org {
			exec(`INSERT INTO nodes (id, org_id, site_id, name, cert_serial, agent_version) VALUES ($1, $2, $3, $4, $5, 'test')`, node.id, node.org, site, node.name, "serial-"+node.id.String())
		} else {
			exec(`INSERT INTO nodes (id, org_id, name, cert_serial, agent_version) VALUES ($1, $2, $3, $4, 'test')`, node.id, node.org, node.name, "serial-"+node.id.String())
		}
	}
	exec(`INSERT INTO k8s_clusters (id, org_id, site_id, name, vip_range) VALUES ($1, $2, $3, $4, '100.99.0.0/24')`, cluster, org, site, "ownership-"+cluster.String()[:8])
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	execTx := func(sql string, args ...any) {
		t.Helper()
		if _, err := tx.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("seed pool membership: %v", err)
		}
	}
	execTx(`INSERT INTO k8s_connector_pools (id, org_id, site_id, cluster_id, preferred_node_id, active_node_id) VALUES ($1, $2, $3, $4, $5, $5)`, poolID, org, site, cluster, connector)
	for _, nodeID := range []uuid.UUID{connector, target} {
		execTx(`INSERT INTO k8s_connector_pool_members (pool_id, org_id, site_id, node_id) VALUES ($1, $2, $3, $4)`, poolID, org, site, nodeID)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("seed pool membership commit: %v", err)
	}
	return org, otherOrg, connector, target, otherTarget,
		ownershipDeliveryStoreScope{siteID: site, clusterID: cluster, poolID: poolID}
}
