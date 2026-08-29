package alerts

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
)

var gatewaySiteKeys = []EventKey{EventGatewayOffline, EventGatewayPolicyDegraded, EventSiteLinkDown}

type ProductHealthSnapshot struct {
	OrgID  uuid.UUID
	Events []Event
}

type ProductHealthSource interface {
	Snapshots(context.Context) ([]ProductHealthSnapshot, error)
}

type LifecyclePublisher interface {
	Publisher
	ListFiringOccurrences(context.Context, uuid.UUID, []EventKey) ([]Event, error)
}

// ProductConditionScanner reconciles a complete per-organization snapshot.
// A source failure aborts the scan before any recovery is inferred: missing
// evidence must never be presented as a resolved incident.
type ProductConditionScanner struct {
	source    ProductHealthSource
	publisher LifecyclePublisher
}

func NewProductConditionScanner(source ProductHealthSource, publisher LifecyclePublisher) *ProductConditionScanner {
	return &ProductConditionScanner{source: source, publisher: publisher}
}

func (s *ProductConditionScanner) RunOnce(ctx context.Context) error {
	if s == nil || s.source == nil || s.publisher == nil {
		return fmt.Errorf("product alert scanner is not configured")
	}
	snapshots, err := s.source.Snapshots(ctx)
	if err != nil {
		return err
	}
	for _, snapshot := range snapshots {
		current := make(map[string]struct{}, len(snapshot.Events))
		for _, event := range snapshot.Events {
			current[string(event.Key)+"\x1f"+event.DedupKey] = struct{}{}
		}
		active, err := s.publisher.ListFiringOccurrences(ctx, snapshot.OrgID, gatewaySiteKeys)
		if err != nil {
			return err
		}
		for _, previous := range active {
			if _, ok := current[string(previous.Key)+"\x1f"+previous.DedupKey]; ok {
				continue
			}
			previous.State = EventStateResolved
			previous.Subject = resolvedSubject(previous.Subject)
			if previous.Fields == nil {
				previous.Fields = map[string]string{}
			}
			previous.Fields["resolution"] = "condition no longer observed"
			if err := s.publisher.Publish(ctx, previous); err != nil {
				return err
			}
		}
		for _, event := range snapshot.Events {
			if err := s.publisher.Publish(ctx, event); err != nil {
				return err
			}
		}
	}
	return nil
}

func resolvedSubject(subject string) string {
	if strings.HasPrefix(subject, "Resolved: ") {
		return subject
	}
	return "Resolved: " + subject
}

type NodeProductHealthSource struct {
	q     *sqlc.Queries
	nodes *nodes.Service
	now   func() time.Time
}

func NewNodeProductHealthSource(pool *pgxpool.Pool, nodeService *nodes.Service) *NodeProductHealthSource {
	return &NodeProductHealthSource{q: sqlc.New(pool), nodes: nodeService, now: time.Now}
}

func (s *NodeProductHealthSource) Snapshots(ctx context.Context) ([]ProductHealthSnapshot, error) {
	if s == nil || s.q == nil || s.nodes == nil {
		return nil, fmt.Errorf("gateway and site alert source is not configured")
	}
	orgs, err := s.q.ListOrganizations(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]ProductHealthSnapshot, 0, len(orgs))
	for _, org := range orgs {
		nodeRows, err := s.nodes.ListNodes(ctx, org.ID)
		if err != nil {
			return nil, err
		}
		active := make([]sqlc.Node, 0, len(nodeRows))
		for _, node := range nodeRows {
			if node.Status == "active" {
				active = append(active, node)
			}
		}
		sites, err := s.q.ListSitesByOrg(ctx, org.ID)
		if err != nil {
			return nil, err
		}
		siteNames := make(map[uuid.UUID]string, len(sites))
		for _, site := range sites {
			siteNames[site.ID] = site.Name
		}
		health := s.nodes.PolicyHealthForNodes(ctx, org.ID, active)
		events := gatewaySiteEvents(org.ID, active, siteNames, health, s.now().UTC())
		out = append(out, ProductHealthSnapshot{OrgID: org.ID, Events: events})
	}
	return out, nil
}

func gatewaySiteEvents(orgID uuid.UUID, gatewayRows []sqlc.Node, siteNames map[uuid.UUID]string, health map[uuid.UUID]nodes.PolicyHealth, now time.Time) []Event {
	var events []Event
	seenSites := map[uuid.UUID]struct{}{}
	for _, gateway := range gatewayRows {
		isOffline := !gateway.LastSeenAt.Valid || now.Sub(gateway.LastSeenAt.Time) >= nodes.ReportFreshnessWindow
		if isOffline {
			events = append(events, Event{
				OrgID: orgID, Key: EventGatewayOffline, Severity: SeverityCritical,
				DedupKey: "gateway:" + gateway.ID.String() + ":offline",
				Subject:  "Gateway " + gateway.Name + " is not reporting",
				Fields:   map[string]string{"gateway_id": gateway.ID.String(), "gateway_name": gateway.Name, "threshold_seconds": fmt.Sprint(int(nodes.ReportFreshnessWindow.Seconds()))},
				Resource: &ResourceRef{Type: "gateway", ID: gateway.ID.String(), Name: gateway.Name},
			})
		}
		gatewayHealth := health[gateway.ID]
		if gateway.SiteID.Valid && (gatewayHealth.Kind == nodes.KindSiteLinkDown || gatewayHealth.Kind == nodes.KindSiteHubDown) {
			siteID := uuid.UUID(gateway.SiteID.Bytes)
			if _, seen := seenSites[siteID]; !seen {
				seenSites[siteID] = struct{}{}
				siteName := siteNames[siteID]
				if siteName == "" {
					siteName = siteID.String()[:8]
				}
				events = append(events, Event{
					OrgID: orgID, Key: EventSiteLinkDown, Severity: SeverityCritical,
					DedupKey: "site:" + siteID.String() + ":link-down",
					Subject:  "Site " + siteName + " has no healthy gateway path",
					Fields:   map[string]string{"site_id": siteID.String(), "site_name": siteName, "health_kind": string(gatewayHealth.Kind)},
					Resource: &ResourceRef{Type: "site", ID: siteID.String(), Name: siteName},
				})
			}
			continue
		}
		if isOffline || gatewayHealth.Kind == nodes.KindHealthy || gatewayHealth.Kind == nodes.KindConverging {
			continue
		}
		events = append(events, Event{
			OrgID: orgID, Key: EventGatewayPolicyDegraded, Severity: gatewayHealthSeverity(gatewayHealth.Kind),
			DedupKey: "gateway:" + gateway.ID.String() + ":policy:" + string(gatewayHealth.Kind),
			Subject:  "Gateway " + gateway.Name + " requires attention",
			Fields:   map[string]string{"gateway_id": gateway.ID.String(), "gateway_name": gateway.Name, "health_kind": string(gatewayHealth.Kind)},
			Resource: &ResourceRef{Type: "gateway", ID: gateway.ID.String(), Name: gateway.Name},
		})
	}
	return events
}

func gatewayHealthSeverity(kind nodes.PolicyDegradedKind) Severity {
	switch kind {
	case nodes.KindCertExpiredCannotReconnect, nodes.KindUnsupportedPolicyVersion, nodes.KindSilentDesync, nodes.KindStuckEnforcing:
		return SeverityCritical
	default:
		return SeverityWarning
	}
}
