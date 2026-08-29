package nodes

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/k8s"
)

func TestProjectConnectorPoolStatus(t *testing.T) {
	now := time.Date(2026, time.August, 13, 12, 0, 0, 0, time.UTC)
	freshness := time.Minute

	t.Run("reports only server-known healthy evidence and durable operation", func(t *testing.T) {
		pool, acks := testConnectorPoolStatusSnapshot(now)
		operationID := uuid.New()
		pool.handoff = &ConnectorPoolHandoffStatus{OperationID: operationID, Phase: k8s.HandoffAwaitWithdrawal}

		status, ok := projectConnectorPoolStatus(now, freshness, pool, acks)
		if !ok {
			t.Fatal("valid pool status must project")
		}
		if status.PoolID != pool.id || status.ClusterID != pool.cluster || status.PreferredNodeID != pool.preferred || status.ActiveNodeID != pool.active || status.Generation != uint64(pool.generation) {
			t.Fatalf("pool identity/config changed in projection: %+v", status)
		}
		if status.Handoff == nil || status.Handoff.OperationID != operationID || status.Handoff.Phase != k8s.HandoffAwaitWithdrawal {
			t.Fatalf("nonterminal handoff not projected exactly: %+v", status.Handoff)
		}
		if len(status.Members) != 2 || !status.Members[0].Health.Known || !status.Members[0].Health.Healthy || status.Members[0].Health.Reason != ConnectorPoolHealthHealthy {
			t.Fatalf("member health must be known/healthy only from complete evidence: %+v", status.Members)
		}
		if status.Members[0].AdminPriority < status.Members[1].AdminPriority {
			t.Fatalf("members must retain deterministic priority order: %+v", status.Members)
		}
	})

	t.Run("missing endpoint-view evidence is explicitly unknown", func(t *testing.T) {
		pool, acks := testConnectorPoolStatusSnapshot(now)
		pool.members[0].node.Capabilities = []byte(`{"policy_hash":"policy"}`)
		status, ok := projectConnectorPoolStatus(now, freshness, pool, acks)
		if !ok || len(status.Members) == 0 {
			t.Fatal("configured pool must remain visible when evidence is unknown")
		}
		health := status.Members[0].Health
		if health.Known || health.Healthy || health.Reason != ConnectorPoolHealthUnknownEndpointView {
			t.Fatalf("missing endpoint view must fail closed as unknown, got %+v", health)
		}
	})

	t.Run("missing CP policy acknowledgement is explicitly unknown", func(t *testing.T) {
		pool, _ := testConnectorPoolStatusSnapshot(now)
		status, ok := projectConnectorPoolStatus(now, freshness, pool, nil)
		if !ok || len(status.Members) == 0 {
			t.Fatal("configured pool must remain visible when policy evidence is unknown")
		}
		health := status.Members[0].Health
		if health.Known || health.Healthy || health.Reason != ConnectorPoolHealthUnknownPolicyAcknowledged {
			t.Fatalf("missing policy acknowledgement must fail closed as unknown, got %+v", health)
		}
	})

	t.Run("stale evidence is known unhealthy, never readiness", func(t *testing.T) {
		pool, acks := testConnectorPoolStatusSnapshot(now)
		pool.members[0].node.LastSeenAt = pgtype.Timestamptz{Time: now.Add(-freshness), Valid: true}
		status, ok := projectConnectorPoolStatus(now, freshness, pool, acks)
		if !ok {
			t.Fatal("configured pool must remain visible when heartbeat is stale")
		}
		health := status.Members[0].Health
		if !health.Known || health.Healthy || health.Reason != ConnectorPoolHealthStaleHeartbeat {
			t.Fatalf("stale heartbeat must be known unhealthy, got %+v", health)
		}
	})

	t.Run("cross-tenant member is rejected instead of projected", func(t *testing.T) {
		pool, acks := testConnectorPoolStatusSnapshot(now)
		pool.members[0].node.OrgID = uuid.New()
		if status, ok := projectConnectorPoolStatus(now, freshness, pool, acks); ok || status.PoolID != uuid.Nil {
			t.Fatalf("cross-tenant member must fail closed, status=%+v ok=%v", status, ok)
		}
	})

	t.Run("terminal or malformed operation is never projected as active handoff", func(t *testing.T) {
		pool, acks := testConnectorPoolStatusSnapshot(now)
		pool.handoff = &ConnectorPoolHandoffStatus{OperationID: uuid.New(), Phase: k8s.HandoffComplete}
		if status, ok := projectConnectorPoolStatus(now, freshness, pool, acks); ok || status.PoolID != uuid.Nil {
			t.Fatalf("terminal operation must fail closed rather than look active: status=%+v ok=%v", status, ok)
		}
	})
}

func testConnectorPoolStatusSnapshot(now time.Time) (connectorPoolStatusSnapshot, map[uuid.UUID]k8s.PolicyAcknowledgement) {
	org, site, cluster, poolID, first, second := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	member := func(id uuid.UUID, priority int32) connectorPoolStatusMemberSnapshot {
		return connectorPoolStatusMemberSnapshot{id: id, priority: priority, node: sqlc.Node{
			ID: id, OrgID: org, SiteID: pgtype.UUID{Bytes: site, Valid: true}, Status: "active",
			WgPublicKey: "/RLJQov+0n5q0hNM2/ZkqzUO/GFUcoziClpzUvI+5j4=", Endpoint: "198.51.100.2:51820",
			LastSeenAt: pgtype.Timestamptz{Time: now.Add(-time.Second), Valid: true}, PolicyReportedAt: pgtype.Timestamptz{Time: now.Add(-time.Second), Valid: true},
			Capabilities: []byte(`{"policy_hash":"policy","k8s_endpoints_unavailable":false}`),
		}}
	}
	pool := connectorPoolStatusSnapshot{id: poolID, org: org, site: site, cluster: cluster, preferred: first, active: first, generation: 7, members: []connectorPoolStatusMemberSnapshot{member(first, 10), member(second, 1)}}
	ack := k8s.PolicyAcknowledgement{ExpectedKnown: true, ExpectedHash: "policy", HealthKnown: true}
	return pool, map[uuid.UUID]k8s.PolicyAcknowledgement{first: ack, second: ack}
}
