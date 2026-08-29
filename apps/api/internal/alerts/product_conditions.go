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

var (
	gatewaySiteKeys = []EventKey{EventGatewayOffline, EventGatewayPolicyDegraded, EventSiteLinkDown}
	deviceKeys      = []EventKey{EventDevicePostureBlocked}
	kubernetesKeys  = []EventKey{EventKubernetesConnectorDegraded, EventKubernetesInventoryStale, EventKubernetesServiceUnavailable}
)

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
	keys      []EventKey
}

func NewProductConditionScanner(source ProductHealthSource, publisher LifecyclePublisher) *ProductConditionScanner {
	return NewScopedProductConditionScanner(source, publisher, gatewaySiteKeys)
}

func GatewaySiteKeys() []EventKey { return append([]EventKey(nil), gatewaySiteKeys...) }
func DeviceKeys() []EventKey      { return append([]EventKey(nil), deviceKeys...) }
func KubernetesKeys() []EventKey  { return append([]EventKey(nil), kubernetesKeys...) }

// NewScopedProductConditionScanner keeps recovery inference inside one evidence
// domain. A Kubernetes read failure must not resolve gateway conditions (or the
// reverse), so each complete snapshot is reconciled only against its own keys.
func NewScopedProductConditionScanner(source ProductHealthSource, publisher LifecyclePublisher, keys []EventKey) *ProductConditionScanner {
	return &ProductConditionScanner{source: source, publisher: publisher, keys: append([]EventKey(nil), keys...)}
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
		active, err := s.publisher.ListFiringOccurrences(ctx, snapshot.OrgID, s.keys)
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

type DeviceProductHealthSource struct{ q *sqlc.Queries }

func NewDeviceProductHealthSource(pool *pgxpool.Pool) *DeviceProductHealthSource {
	return &DeviceProductHealthSource{q: sqlc.New(pool)}
}

func (s *DeviceProductHealthSource) Snapshots(ctx context.Context) ([]ProductHealthSnapshot, error) {
	if s == nil || s.q == nil {
		return nil, fmt.Errorf("device alert source is not configured")
	}
	orgs, err := s.q.ListOrganizations(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]ProductHealthSnapshot, 0, len(orgs))
	for _, org := range orgs {
		rows, err := s.q.ListDevicesByOrg(ctx, org.ID)
		if err != nil {
			return nil, err
		}
		out = append(out, ProductHealthSnapshot{OrgID: org.ID, Events: deviceEvents(org.ID, rows)})
	}
	return out, nil
}

func deviceEvents(orgID uuid.UUID, rows []sqlc.ListDevicesByOrgRow) []Event {
	events := make([]Event, 0)
	for _, row := range rows {
		device := row.Device
		// Pending and revoked devices do not currently carry traffic. Alert only
		// when the canonical enforcement bit excludes an otherwise-active device.
		if device.Status != "active" || !device.HealthBlocked {
			continue
		}
		events = append(events, Event{
			OrgID: orgID, Key: EventDevicePostureBlocked, Severity: SeverityCritical,
			DedupKey: "device:" + device.ID.String() + ":posture-blocked",
			Subject:  "Device " + device.Name + " is blocked by posture policy",
			Fields: map[string]string{
				"device_id": device.ID.String(), "device_name": device.Name,
				"evaluated_state": stringValue(row.EvaluatedState, "blocked"),
			},
			Resource: &ResourceRef{Type: "device", ID: device.ID.String(), Name: device.Name},
		})
	}
	return events
}

func stringValue(value *string, fallback string) string {
	if value == nil || strings.TrimSpace(*value) == "" {
		return fallback
	}
	return *value
}

type KubernetesProductHealthSource struct {
	pool  *pgxpool.Pool
	q     *sqlc.Queries
	nodes *nodes.Service
	now   func() time.Time
}

func NewKubernetesProductHealthSource(pool *pgxpool.Pool, nodeService *nodes.Service) *KubernetesProductHealthSource {
	return &KubernetesProductHealthSource{pool: pool, q: sqlc.New(pool), nodes: nodeService, now: time.Now}
}

type inventoryFreshness struct {
	clusterID  uuid.UUID
	freshUntil time.Time
}

func (s *KubernetesProductHealthSource) Snapshots(ctx context.Context) ([]ProductHealthSnapshot, error) {
	if s == nil || s.pool == nil || s.q == nil || s.nodes == nil {
		return nil, fmt.Errorf("Kubernetes alert source is not configured")
	}
	orgs, err := s.q.ListOrganizations(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]ProductHealthSnapshot, 0, len(orgs))
	for _, org := range orgs {
		clusters, err := s.q.ListK8sClusterConnectorViewsForOrg(ctx, org.ID)
		if err != nil {
			return nil, err
		}
		services, err := s.q.ListActiveK8sServicesForOrg(ctx, org.ID)
		if err != nil {
			return nil, err
		}
		nodeRows, err := s.nodes.ListNodes(ctx, org.ID)
		if err != nil {
			return nil, err
		}
		nodeHealth := s.nodes.PolicyHealthForNodes(ctx, org.ID, nodeRows)
		freshness, err := s.inventoryFreshness(ctx, org.ID)
		if err != nil {
			return nil, err
		}
		out = append(out, ProductHealthSnapshot{OrgID: org.ID, Events: kubernetesEvents(org.ID, clusters, services, nodeHealth, freshness, s.now().UTC())})
	}
	return out, nil
}

func (s *KubernetesProductHealthSource) inventoryFreshness(ctx context.Context, orgID uuid.UUID) (map[uuid.UUID]time.Time, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT ON (cluster_id) cluster_id, fresh_until
		FROM k8s_service_inventory_reports
		WHERE org_id=$1
		ORDER BY cluster_id, replay_sequence DESC, received_at DESC, id DESC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[uuid.UUID]time.Time{}
	for rows.Next() {
		var row inventoryFreshness
		if err := rows.Scan(&row.clusterID, &row.freshUntil); err != nil {
			return nil, err
		}
		out[row.clusterID] = row.freshUntil
	}
	return out, rows.Err()
}

func kubernetesEvents(orgID uuid.UUID, clusters []sqlc.ListK8sClusterConnectorViewsForOrgRow, services []sqlc.ListActiveK8sServicesForOrgRow, health map[uuid.UUID]nodes.PolicyHealth, freshness map[uuid.UUID]time.Time, now time.Time) []Event {
	events := make([]Event, 0)
	clusterNames := make(map[uuid.UUID]string, len(clusters))
	connectorUnavailable := make(map[uuid.UUID]string, len(clusters))
	for _, cluster := range clusters {
		clusterNames[cluster.ID] = cluster.Name
		connectorID, configured := selectedClusterConnector(cluster)
		reason := ""
		if !configured {
			reason = "no selected connector"
		} else if h, ok := health[connectorID]; !ok {
			reason = "selected connector is unavailable"
		} else if h.Kind == nodes.KindK8sEndpointsUnavailable {
			reason = "selected connector has no Kubernetes endpoint view"
		}
		if reason != "" {
			connectorUnavailable[cluster.ID] = reason
			events = append(events, Event{
				OrgID: orgID, Key: EventKubernetesConnectorDegraded, Severity: SeverityCritical,
				DedupKey: "kubernetes-cluster:" + cluster.ID.String() + ":connector-degraded",
				Subject:  "Kubernetes connector for " + cluster.Name + " requires attention",
				Fields:   map[string]string{"cluster_id": cluster.ID.String(), "cluster_name": cluster.Name, "reason": reason},
				Resource: &ResourceRef{Type: "kubernetes_cluster", ID: cluster.ID.String(), Name: cluster.Name},
			})
		}
		if until, ok := freshness[cluster.ID]; ok && !until.After(now) {
			events = append(events, Event{
				OrgID: orgID, Key: EventKubernetesInventoryStale, Severity: SeverityWarning,
				DedupKey: "kubernetes-cluster:" + cluster.ID.String() + ":inventory-stale",
				Subject:  "Kubernetes inventory for " + cluster.Name + " is stale",
				Fields:   map[string]string{"cluster_id": cluster.ID.String(), "cluster_name": cluster.Name, "fresh_until": until.UTC().Format(time.RFC3339)},
				Resource: &ResourceRef{Type: "kubernetes_cluster", ID: cluster.ID.String(), Name: cluster.Name},
			})
		}
	}
	serviceCount := map[uuid.UUID]int{}
	for _, service := range services {
		unavailable := connectorUnavailable[service.ClusterID] != ""
		if service.ConnectorPoolID.Valid && !service.PoolConnectorEligible {
			unavailable = true
		}
		if unavailable {
			serviceCount[service.ClusterID]++
		}
	}
	for clusterID, count := range serviceCount {
		name := clusterNames[clusterID]
		if name == "" {
			name = clusterID.String()[:8]
		}
		events = append(events, Event{
			OrgID: orgID, Key: EventKubernetesServiceUnavailable, Severity: SeverityCritical,
			DedupKey: "kubernetes-cluster:" + clusterID.String() + ":services-unavailable",
			Subject:  fmt.Sprintf("%d exposed Kubernetes service(s) in %s are unavailable", count, name),
			Fields:   map[string]string{"cluster_id": clusterID.String(), "cluster_name": name, "service_count": fmt.Sprint(count)},
			Resource: &ResourceRef{Type: "kubernetes_cluster", ID: clusterID.String(), Name: name},
		})
	}
	return events
}

func selectedClusterConnector(cluster sqlc.ListK8sClusterConnectorViewsForOrgRow) (uuid.UUID, bool) {
	if cluster.ConnectorPoolID.Valid {
		if !cluster.ActiveConnectorNodeID.Valid {
			return uuid.Nil, false
		}
		return uuid.UUID(cluster.ActiveConnectorNodeID.Bytes), true
	}
	if !cluster.ConnectorNodeID.Valid {
		return uuid.Nil, false
	}
	return uuid.UUID(cluster.ConnectorNodeID.Bytes), true
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
