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
	active    []Event
	published []Event
}

func (p *lifecycleRecorder) Publish(_ context.Context, event Event) error {
	p.published = append(p.published, event.normalized())
	return event.Validate()
}

func (p *lifecycleRecorder) ListFiringOccurrences(context.Context, uuid.UUID, []EventKey) ([]Event, error) {
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
