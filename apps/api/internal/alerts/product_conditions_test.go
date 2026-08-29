package alerts

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
)

type productSource struct {
	snapshots []ProductHealthSnapshot
	err       error
}

func (s productSource) Snapshots(context.Context) ([]ProductHealthSnapshot, error) {
	return s.snapshots, s.err
}

type lifecycleRecorder struct {
	active     []Event
	published  []Event
	listedKeys []EventKey
}

func (p *lifecycleRecorder) Publish(_ context.Context, event Event) error {
	p.published = append(p.published, event.normalized())
	return event.Validate()
}

func (p *lifecycleRecorder) ListFiringOccurrences(_ context.Context, _ uuid.UUID, keys []EventKey) ([]Event, error) {
	p.listedKeys = append([]EventKey(nil), keys...)
	return append([]Event(nil), p.active...), nil
}

func TestProductScannerPublishesRecoveryAndCurrentConditions(t *testing.T) {
	t.Parallel()
	orgID := uuid.New()
	current := Event{OrgID: orgID, Key: EventGatewayOffline, Severity: SeverityCritical, DedupKey: "gateway:new:offline", Subject: "Gateway new is not reporting"}
	previous := Event{OrgID: orgID, Key: EventSiteLinkDown, Severity: SeverityCritical, DedupKey: "site:old:link-down", Subject: "Site old has no healthy gateway path"}
	publisher := &lifecycleRecorder{active: []Event{previous}}
	scanner := NewProductConditionScanner(productSource{snapshots: []ProductHealthSnapshot{{OrgID: orgID, Events: []Event{current}}}}, publisher)
	if err := scanner.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(publisher.published) != 2 {
		t.Fatalf("published=%#v", publisher.published)
	}
	if publisher.published[0].State != EventStateResolved || publisher.published[0].Fields["resolution"] == "" {
		t.Fatalf("first event=%#v, want explicit resolution", publisher.published[0])
	}
	if publisher.published[1].State != EventStateFiring || publisher.published[1].DedupKey != current.DedupKey {
		t.Fatalf("second event=%#v, want current firing condition", publisher.published[1])
	}
}

func TestProductScannerDoesNotInferRecoveryFromSourceFailure(t *testing.T) {
	t.Parallel()
	publisher := &lifecycleRecorder{active: []Event{{OrgID: uuid.New(), Key: EventGatewayOffline, Severity: SeverityCritical, DedupKey: "x", Subject: "x"}}}
	err := NewProductConditionScanner(productSource{err: errors.New("evidence unavailable")}, publisher).RunOnce(context.Background())
	if err == nil || len(publisher.published) != 0 {
		t.Fatalf("err=%v published=%#v", err, publisher.published)
	}
}

func TestProductScannerReconcilesOnlyItsEvidenceDomain(t *testing.T) {
	t.Parallel()
	orgID := uuid.New()
	publisher := &lifecycleRecorder{}
	scanner := NewScopedProductConditionScanner(productSource{snapshots: []ProductHealthSnapshot{{OrgID: orgID}}}, publisher, deviceKeys)
	if err := scanner.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(publisher.listedKeys) != 1 || publisher.listedKeys[0] != EventDevicePostureBlocked {
		t.Fatalf("listed keys=%v, want device domain only", publisher.listedKeys)
	}
}

func TestGatewaySiteEventsAreResourceScopedAndSiteDeduplicated(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 29, 10, 0, 0, 0, time.UTC)
	orgID, siteID := uuid.New(), uuid.New()
	first, second := uuid.New(), uuid.New()
	rows := []sqlc.Node{
		{ID: first, OrgID: orgID, Name: "gw-one", Status: "active", SiteID: pgtype.UUID{Bytes: siteID, Valid: true}, LastSeenAt: pgtype.Timestamptz{Time: now, Valid: true}},
		{ID: second, OrgID: orgID, Name: "gw-two", Status: "active", SiteID: pgtype.UUID{Bytes: siteID, Valid: true}, LastSeenAt: pgtype.Timestamptz{Time: now, Valid: true}},
	}
	health := map[uuid.UUID]nodes.PolicyHealth{
		first:  {Degraded: true, Kind: nodes.KindSiteLinkDown},
		second: {Degraded: true, Kind: nodes.KindSiteLinkDown},
	}
	events := gatewaySiteEvents(orgID, rows, map[uuid.UUID]string{siteID: "prod"}, health, now)
	if len(events) != 1 || events[0].Key != EventSiteLinkDown || events[0].Resource == nil || events[0].Resource.ID != siteID.String() {
		t.Fatalf("events=%#v, want one site-scoped condition", events)
	}
}

func TestGatewaySiteEventsPreferOfflineOverStalePolicy(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	orgID, gatewayID := uuid.New(), uuid.New()
	row := sqlc.Node{ID: gatewayID, OrgID: orgID, Name: "edge", Status: "active", LastSeenAt: pgtype.Timestamptz{Time: now.Add(-2 * nodes.ReportFreshnessWindow), Valid: true}}
	events := gatewaySiteEvents(orgID, []sqlc.Node{row}, nil, map[uuid.UUID]nodes.PolicyHealth{gatewayID: {Degraded: true, Kind: nodes.KindSilentDesync}}, now)
	if len(events) != 1 || events[0].Key != EventGatewayOffline {
		t.Fatalf("events=%#v, want only gateway offline", events)
	}
}

func TestDeviceEventsUseCanonicalPostureBlock(t *testing.T) {
	t.Parallel()
	orgID := uuid.New()
	blockedID, pendingID := uuid.New(), uuid.New()
	state := "noncompliant"
	events := deviceEvents(orgID, []sqlc.ListDevicesByOrgRow{
		{Device: sqlc.Device{ID: blockedID, OrgID: orgID, Name: "laptop", Status: "active", HealthBlocked: true}, EvaluatedState: &state},
		{Device: sqlc.Device{ID: pendingID, OrgID: orgID, Name: "pending", Status: "pending", HealthBlocked: true}},
	})
	if len(events) != 1 || events[0].Key != EventDevicePostureBlocked || events[0].Resource == nil || events[0].Resource.ID != blockedID.String() {
		t.Fatalf("events=%#v, want one active posture-blocked device", events)
	}
	if events[0].Fields["evaluated_state"] != state {
		t.Fatalf("fields=%#v, want canonical evaluated state", events[0].Fields)
	}
}

func TestKubernetesEventsBindConnectorInventoryAndServiceImpact(t *testing.T) {
	t.Parallel()
	orgID, clusterID, connectorID, poolID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	now := time.Date(2026, 8, 29, 10, 0, 0, 0, time.UTC)
	clusters := []sqlc.ListK8sClusterConnectorViewsForOrgRow{{
		ID: clusterID, OrgID: orgID, Name: "payments",
		ConnectorPoolID:       pgtype.UUID{Bytes: poolID, Valid: true},
		ActiveConnectorNodeID: pgtype.UUID{Bytes: connectorID, Valid: true},
	}}
	services := []sqlc.ListActiveK8sServicesForOrgRow{{
		ID: uuid.New(), ClusterID: clusterID, Name: "api",
		ConnectorPoolID: pgtype.UUID{Bytes: poolID, Valid: true}, PoolConnectorEligible: false,
	}}
	health := map[uuid.UUID]nodes.PolicyHealth{connectorID: {Degraded: true, Kind: nodes.KindK8sEndpointsUnavailable}}
	events := kubernetesEvents(orgID, clusters, services, health, map[uuid.UUID]time.Time{clusterID: now.Add(-time.Minute)}, now)
	want := map[EventKey]bool{
		EventKubernetesConnectorDegraded:  false,
		EventKubernetesInventoryStale:     false,
		EventKubernetesServiceUnavailable: false,
	}
	for _, event := range events {
		if _, ok := want[event.Key]; ok {
			want[event.Key] = true
		}
		if event.Resource == nil || event.Resource.Type != "kubernetes_cluster" || event.Resource.ID != clusterID.String() {
			t.Fatalf("event=%#v, want cluster provenance", event)
		}
	}
	for key, seen := range want {
		if !seen {
			t.Fatalf("events=%#v, missing %s", events, key)
		}
	}
}

func TestKubernetesEventsDoNotCallFreshInventoryStale(t *testing.T) {
	t.Parallel()
	orgID, clusterID, connectorID := uuid.New(), uuid.New(), uuid.New()
	now := time.Now().UTC()
	clusters := []sqlc.ListK8sClusterConnectorViewsForOrgRow{{ID: clusterID, OrgID: orgID, Name: "healthy", ConnectorNodeID: pgtype.UUID{Bytes: connectorID, Valid: true}}}
	events := kubernetesEvents(orgID, clusters, nil, map[uuid.UUID]nodes.PolicyHealth{connectorID: {Kind: nodes.KindHealthy}}, map[uuid.UUID]time.Time{clusterID: now.Add(time.Minute)}, now)
	if len(events) != 0 {
		t.Fatalf("events=%#v, want no false condition", events)
	}
}
