package nodes

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/internal/k8s"
	"github.com/tunnexio/tunnex/apps/api/internal/leader"
	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
)

var ErrHandoffBootstrapPlanRefused = errors.New("handoff bootstrap plan refused")

type HandoffBootstrapServiceUID struct {
	ActiveNodeID        uuid.UUID
	PromotionGeneration uint64
	Namespace           string
	Service             string
	UID                 string
	ObservationRevision uint64
}

type handoffBootstrapMember struct {
	NodeID, SiteID uuid.UUID
	WGPublicKey    string
	Endpoint       string
}

type handoffBootstrapService struct {
	ID                   uuid.UUID
	Namespace, Name, VIP string
	Protocol             string
	PortLow, PortHigh    *int32
	UID                  string
	ObservationRevision  uint64
}

type handoffBootstrapTopology struct {
	Scope                        k8s.HandoffPoolScope
	Generation                   uint64
	ActiveNodeID                 uuid.UUID
	ClusterName, DNSZone, DNSVIP string
	ServiceCIDR, DevicePoolCIDR  string
	EdgeWGPublicKey              string
	Members                      []handoffBootstrapMember
	Services                     []handoffBootstrapService
	Counters                     map[uuid.UUID]handoffBootstrapCounter
	Existing                     map[uuid.UUID]PoolVIPOwnershipDeliveryEnvelopeV3
}

type handoffBootstrapCounter struct {
	ManifestRevision uint64
	LeaseEpoch       uint64
}

type HandoffBootstrapPlanSourceConfig struct {
	LeaseTTL time.Duration
}

// PostgresHandoffBootstrapPlanSource reads one explicitly named pool through
// the caller-held scheduler-lock connection. It locks the pool, cluster,
// membership, node, hub and exposure rows before constructing any manifest;
// it never calls DesiredState or treats a successful legacy delivery as
// ownership evidence.
type PostgresHandoffBootstrapPlanSource struct {
	pool   *pgxpool.Pool
	config HandoffBootstrapPlanSourceConfig
}

func NewPostgresHandoffBootstrapPlanSource(pool *pgxpool.Pool, config HandoffBootstrapPlanSourceConfig) *PostgresHandoffBootstrapPlanSource {
	return &PostgresHandoffBootstrapPlanSource{pool: pool, config: config}
}

func (s *PostgresHandoffBootstrapPlanSource) LoadHandoffBootstrapPlanWithLeadership(ctx context.Context, now time.Time, scope k8s.HandoffPoolScope, epoch k8s.HandoffLeadershipEpoch, conn *pgxpool.Conn) (HandoffBootstrapPlan, bool, error) {
	if s == nil || s.pool == nil || ctx == nil || now.IsZero() || s.config.LeaseTTL < time.Minute || !validHandoffBootstrapScope(scope) ||
		conn == nil || epoch.BackendPID <= 0 || epoch.LockKey != leader.SchedulerLockKey {
		return HandoffBootstrapPlan{}, false, ErrHandoffBootstrapPlanRefused
	}
	session := PoolVIPOwnershipHandoffLeaderSession{Epoch: PoolVIPOwnershipHandoffLeadershipEpoch{BackendPID: epoch.BackendPID, AdvisoryLockKey: epoch.LockKey}, Conn: conn}
	if err := validPoolVIPOwnershipHandoffLeaderSession(ctx, session); err != nil {
		return HandoffBootstrapPlan{}, false, err
	}
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return HandoffBootstrapPlan{}, false, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := validPoolVIPOwnershipHandoffLeaderSessionTx(ctx, tx, session.Epoch); err != nil {
		return HandoffBootstrapPlan{}, false, err
	}
	topology, found, err := loadHandoffBootstrapTopology(ctx, tx, scope)
	if err != nil || !found {
		return HandoffBootstrapPlan{}, found, err
	}
	expires := canonicalPoolVIPOwnershipDeliveryExpiry(now.UTC().Truncate(s.config.LeaseTTL).Add(2 * s.config.LeaseTTL))
	if !expires.After(now.UTC()) {
		return HandoffBootstrapPlan{}, false, ErrHandoffBootstrapPlanRefused
	}
	if err := loadHandoffBootstrapCounters(ctx, tx, &topology, expires); err != nil {
		return HandoffBootstrapPlan{}, false, err
	}
	plan, err := buildHandoffBootstrapPlan(topology, expires)
	if err != nil {
		return HandoffBootstrapPlan{}, false, err
	}
	if err := validPoolVIPOwnershipHandoffLeaderSessionTx(ctx, tx, session.Epoch); err != nil {
		return HandoffBootstrapPlan{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return HandoffBootstrapPlan{}, false, err
	}
	return plan, true, nil
}

// IssueHandoffBootstrapEnvelopeWithLeadership re-derives the exact envelope
// while the topology/UID locks are still held, then inserts it in that same
// transaction. The earlier plan read is therefore not a time-of-check authority
// and a Service recreation or topology change between planning and issue fails
// closed instead of delivering stale ownership.
func (s *PostgresPoolVIPOwnershipDeliveryStore) IssueHandoffBootstrapEnvelopeWithLeadership(ctx context.Context, epoch k8s.HandoffLeadershipEpoch, conn *pgxpool.Conn, envelope PoolVIPOwnershipDeliveryEnvelopeV3) error {
	if s == nil || s.pool == nil || conn == nil || epoch.BackendPID <= 0 || epoch.LockKey != leader.SchedulerLockKey {
		return ErrHandoffBootstrapPlanRefused
	}
	input, err := preparePoolVIPOwnershipDeliveryV3Issue(envelope)
	if err != nil {
		return err
	}
	artifact := poolVIPOwnershipHandoffArtifact(envelope)
	scope := k8s.HandoffPoolScope{}
	if scope.OrgID, err = uuid.Parse(artifact.OrgID); err != nil {
		return ErrHandoffBootstrapPlanRefused
	}
	if scope.SiteID, err = uuid.Parse(artifact.SiteID); err != nil {
		return ErrHandoffBootstrapPlanRefused
	}
	if scope.ClusterID, err = uuid.Parse(artifact.ClusterID); err != nil {
		return ErrHandoffBootstrapPlanRefused
	}
	if scope.PoolID, err = uuid.Parse(artifact.PoolID); err != nil {
		return ErrHandoffBootstrapPlanRefused
	}
	sessionEpoch := PoolVIPOwnershipHandoffLeadershipEpoch{BackendPID: epoch.BackendPID, AdvisoryLockKey: epoch.LockKey}
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := validPoolVIPOwnershipHandoffLeaderSessionTx(ctx, tx, sessionEpoch); err != nil {
		return err
	}
	topology, found, err := loadHandoffBootstrapTopology(ctx, tx, scope)
	if err != nil || !found || topology.Generation != envelope.PromotionGeneration {
		return ErrHandoffBootstrapPlanRefused
	}
	if err := loadHandoffBootstrapCounters(ctx, tx, &topology, envelope.ExpiresAt); err != nil {
		return err
	}
	plan, err := buildHandoffBootstrapPlan(topology, envelope.ExpiresAt)
	if err != nil {
		return err
	}
	var expected PoolVIPOwnershipDeliveryEnvelopeV3
	if envelope.TargetNodeID == plan.ActiveNodeID.String() {
		expected = plan.CurrentOwnerEnvelope
	} else {
		for _, prepared := range plan.StandbyEnvelopes {
			if prepared.TargetNodeID == envelope.TargetNodeID {
				expected = prepared
				break
			}
		}
	}
	if !reflect.DeepEqual(expected, envelope) {
		return ErrHandoffBootstrapPlanRefused
	}
	if s.leaderBoundPreWriteHook != nil {
		if err := s.leaderBoundPreWriteHook(ctx, conn); err != nil {
			return err
		}
	}
	if err := validPoolVIPOwnershipHandoffLeaderSessionTx(ctx, tx, sessionEpoch); err != nil {
		return err
	}
	return issuePoolVIPOwnershipDeliveryV3Tx(ctx, tx, input)
}

func validHandoffBootstrapScope(scope k8s.HandoffPoolScope) bool {
	return scope.OrgID != uuid.Nil && scope.SiteID != uuid.Nil && scope.ClusterID != uuid.Nil && scope.PoolID != uuid.Nil
}

func loadHandoffBootstrapTopology(ctx context.Context, tx pgx.Tx, scope k8s.HandoffPoolScope) (handoffBootstrapTopology, bool, error) {
	t := handoffBootstrapTopology{Scope: scope, Counters: map[uuid.UUID]handoffBootstrapCounter{}, Existing: map[uuid.UUID]PoolVIPOwnershipDeliveryEnvelopeV3{}}
	var generation int64
	err := tx.QueryRow(ctx, `SELECT p.active_node_id,p.generation,c.name,c.dns_zone,COALESCE(host(c.dns_vip),''),c.service_cidr::text,o.pool_cidr::text
		FROM k8s_connector_pools p
		JOIN k8s_clusters c ON c.id=p.cluster_id AND c.org_id=p.org_id AND c.site_id=p.site_id AND c.connector_pool_id=p.id
		JOIN organizations o ON o.id=p.org_id
		WHERE p.id=$1 AND p.org_id=$2 AND p.site_id=$3 AND p.cluster_id=$4
		FOR UPDATE OF p,c,o`, scope.PoolID, scope.OrgID, scope.SiteID, scope.ClusterID).Scan(
		&t.ActiveNodeID, &generation, &t.ClusterName, &t.DNSZone, &t.DNSVIP, &t.ServiceCIDR, &t.DevicePoolCIDR)
	if errors.Is(err, pgx.ErrNoRows) {
		return handoffBootstrapTopology{}, false, nil
	}
	if err != nil {
		return handoffBootstrapTopology{}, false, err
	}
	if generation <= 0 {
		return handoffBootstrapTopology{}, false, ErrHandoffBootstrapPlanRefused
	}
	t.Generation = uint64(generation)
	rows, err := tx.Query(ctx, `SELECT m.node_id,n.site_id,n.wg_public_key,n.endpoint
		FROM k8s_connector_pool_members m JOIN nodes n ON n.id=m.node_id AND n.org_id=m.org_id AND n.site_id=m.site_id
		WHERE m.pool_id=$1 AND m.org_id=$2 AND m.site_id=$3 AND n.status='active' AND n.revoked_at IS NULL
		ORDER BY m.node_id FOR SHARE OF m,n`, scope.PoolID, scope.OrgID, scope.SiteID)
	if err != nil {
		return handoffBootstrapTopology{}, false, err
	}
	for rows.Next() {
		var member handoffBootstrapMember
		if err := rows.Scan(&member.NodeID, &member.SiteID, &member.WGPublicKey, &member.Endpoint); err != nil {
			rows.Close()
			return handoffBootstrapTopology{}, false, err
		}
		t.Members = append(t.Members, member)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return handoffBootstrapTopology{}, false, err
	}
	rows.Close()
	if len(t.Members) < 2 {
		return handoffBootstrapTopology{}, false, ErrHandoffBootstrapPlanRefused
	}
	memberSet := make(map[uuid.UUID]struct{}, len(t.Members))
	for _, member := range t.Members {
		memberSet[member.NodeID] = struct{}{}
	}
	if _, ok := memberSet[t.ActiveNodeID]; !ok {
		return handoffBootstrapTopology{}, false, ErrHandoffBootstrapPlanRefused
	}
	var configured, demoted []uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT configured,demoted FROM org_hub_set WHERE org_id=$1 FOR SHARE`, scope.OrgID).Scan(&configured, &demoted); err != nil {
		return handoffBootstrapTopology{}, false, ErrHandoffBootstrapPlanRefused
	}
	for _, nodeID := range deriveActive(configured, demoted) {
		if _, isPoolMember := memberSet[nodeID]; isPoolMember {
			continue
		}
		var key, endpoint string
		err := tx.QueryRow(ctx, `SELECT wg_public_key,endpoint FROM nodes WHERE id=$1 AND org_id=$2 AND site_id=$3 AND status='active' AND revoked_at IS NULL FOR SHARE`, nodeID, scope.OrgID, scope.SiteID).Scan(&key, &endpoint)
		if err == nil && validHandoffBootstrapWGKey(key) && strings.TrimSpace(endpoint) != "" {
			t.EdgeWGPublicKey = key
			break
		}
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return handoffBootstrapTopology{}, false, err
		}
	}
	if t.EdgeWGPublicKey == "" {
		return handoffBootstrapTopology{}, false, ErrHandoffBootstrapPlanRefused
	}
	rows, err = tx.Query(ctx, `SELECT id,namespace,name,host(vip),protocol,port_low,port_high FROM k8s_services
		WHERE org_id=$1 AND cluster_id=$2 AND deleted_at IS NULL ORDER BY namespace,name,id FOR SHARE`, scope.OrgID, scope.ClusterID)
	if err != nil {
		return handoffBootstrapTopology{}, false, err
	}
	for rows.Next() {
		var service handoffBootstrapService
		if err := rows.Scan(&service.ID, &service.Namespace, &service.Name, &service.VIP, &service.Protocol, &service.PortLow, &service.PortHigh); err != nil {
			rows.Close()
			return handoffBootstrapTopology{}, false, err
		}
		t.Services = append(t.Services, service)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return handoffBootstrapTopology{}, false, err
	}
	rows.Close()
	if len(t.Services) == 0 || len(t.Services) > 512 {
		return handoffBootstrapTopology{}, false, ErrHandoffBootstrapPlanRefused
	}
	for i := range t.Services {
		var revision int64
		err := tx.QueryRow(ctx, `SELECT c.uid,c.replay_sequence
				FROM k8s_service_uid_observation_ledgers l
				JOIN k8s_service_uid_observation_current c ON c.ledger_id=l.id AND c.org_id=l.org_id
				JOIN k8s_service_uid_observation_current_attributions a
				  ON a.ledger_id=c.ledger_id AND a.org_id=c.org_id AND a.namespace=c.namespace AND a.service=c.service
				 AND a.replay_sequence=c.replay_sequence
				JOIN k8s_service_uid_observation_replay_states r
				  ON r.id=a.replay_state_id AND r.org_id=a.org_id AND r.site_id=l.site_id AND r.cluster_id=l.cluster_id
				WHERE l.org_id=$1 AND l.site_id=$2 AND l.cluster_id=$3 AND r.connector_node_id=$4
				  AND c.namespace=$5 AND c.service=$6 AND c.state='live'
				FOR SHARE OF l,r,c,a`, scope.OrgID, scope.SiteID, scope.ClusterID, t.ActiveNodeID, t.Services[i].Namespace, t.Services[i].Name).Scan(&t.Services[i].UID, &revision)
		if err != nil || revision <= 0 || t.Services[i].UID == "" {
			return handoffBootstrapTopology{}, false, ErrHandoffBootstrapPlanRefused
		}
		t.Services[i].ObservationRevision = uint64(revision)
	}
	return t, true, nil
}

func loadHandoffBootstrapCounters(ctx context.Context, tx pgx.Tx, topology *handoffBootstrapTopology, expires time.Time) error {
	evidence := handoffBootstrapUIDEvidence(topology.Services)
	for _, member := range topology.Members {
		role := policyspec.PoolVIPOwnershipPreparedNonServing
		if member.NodeID == topology.ActiveNodeID {
			role = policyspec.PoolVIPOwnershipServing
		}
		deliveryID := handoffBootstrapUUID("delivery", topology.Scope, topology.Generation, member.NodeID, role, evidence, expires)
		_, existing, err := scanPoolVIPOwnershipDeliveryV3(tx.QueryRow(ctx, poolVIPOwnershipDeliveryV3Select+` WHERE wire_version=3 AND org_id=$1 AND delivery_id=$2 FOR SHARE`, topology.Scope.OrgID, deliveryID))
		if err == nil {
			if existing.PromotionGeneration != topology.Generation || existing.TargetNodeID != member.NodeID.String() || existing.Role != role || !existing.ExpiresAt.Equal(expires) {
				return ErrHandoffBootstrapPlanRefused
			}
			topology.Counters[member.NodeID] = handoffBootstrapCounter{ManifestRevision: existing.ManifestRevision, LeaseEpoch: existing.LeaseEpoch}
			topology.Existing[member.NodeID] = existing
			continue
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		var revision, lease int64
		err = tx.QueryRow(ctx, `SELECT manifest_revision,lease_epoch FROM pool_vip_ownership_delivery_states
			WHERE org_id=$1 AND site_id=$2 AND cluster_id=$3 AND pool_id=$4 AND connector_node_id=$5 FOR SHARE`,
			topology.Scope.OrgID, topology.Scope.SiteID, topology.Scope.ClusterID, topology.Scope.PoolID, member.NodeID).Scan(&revision, &lease)
		if errors.Is(err, pgx.ErrNoRows) {
			revision, lease, err = 0, 0, nil
		}
		if err != nil || revision < 0 || lease < 0 || revision == math.MaxInt64 || lease == math.MaxInt64 {
			return ErrHandoffBootstrapPlanRefused
		}
		topology.Counters[member.NodeID] = handoffBootstrapCounter{ManifestRevision: uint64(revision + 1), LeaseEpoch: uint64(lease + 1)}
	}
	return nil
}

func buildHandoffBootstrapPlan(topology handoffBootstrapTopology, expires time.Time) (HandoffBootstrapPlan, error) {
	if !validHandoffBootstrapScope(topology.Scope) || topology.Generation == 0 || topology.ActiveNodeID == uuid.Nil || !expires.After(time.Time{}) ||
		!validHandoffBootstrapWGKey(topology.EdgeWGPublicKey) || len(topology.Members) < 2 || len(topology.Services) == 0 {
		return HandoffBootstrapPlan{}, fmt.Errorf("%w: incomplete topology", ErrHandoffBootstrapPlanRefused)
	}
	devicePool, err := netip.ParsePrefix(topology.DevicePoolCIDR)
	if err != nil || !devicePool.Addr().Is4() || devicePool != devicePool.Masked() || devicePool.String() != topology.DevicePoolCIDR {
		return HandoffBootstrapPlan{}, ErrHandoffBootstrapPlanRefused
	}
	serviceCIDR, err := netip.ParsePrefix(topology.ServiceCIDR)
	if err != nil || !serviceCIDR.Addr().Is4() || serviceCIDR != serviceCIDR.Masked() || serviceCIDR.String() != topology.ServiceCIDR {
		return HandoffBootstrapPlan{}, ErrHandoffBootstrapPlanRefused
	}
	dnsZone := topology.ClusterName + "." + topology.DNSZone
	plan := HandoffBootstrapPlan{Scope: topology.Scope, Generation: topology.Generation, ActiveNodeID: topology.ActiveNodeID}
	memberSeen := make(map[uuid.UUID]struct{}, len(topology.Members))
	for _, member := range topology.Members {
		if member.NodeID == uuid.Nil || member.SiteID != topology.Scope.SiteID || !validHandoffBootstrapWGKey(member.WGPublicKey) || strings.TrimSpace(member.Endpoint) == "" {
			return HandoffBootstrapPlan{}, fmt.Errorf("%w: incomplete member %s", ErrHandoffBootstrapPlanRefused, member.NodeID)
		}
		if _, duplicate := memberSeen[member.NodeID]; duplicate {
			return HandoffBootstrapPlan{}, ErrHandoffBootstrapPlanRefused
		}
		memberSeen[member.NodeID] = struct{}{}
	}
	if _, ok := memberSeen[topology.ActiveNodeID]; !ok {
		return HandoffBootstrapPlan{}, ErrHandoffBootstrapPlanRefused
	}
	services := make([]PoolVIPOwnershipServiceV3, 0, len(topology.Services))
	for _, service := range topology.Services {
		if service.ID == uuid.Nil || !validOpaqueK8sServiceUID(service.UID) || service.ObservationRevision == 0 || service.PortLow == nil || service.PortHigh == nil ||
			*service.PortLow != *service.PortHigh || (service.Protocol != "tcp" && service.Protocol != "udp") {
			return HandoffBootstrapPlan{}, fmt.Errorf("%w: incomplete service %s", ErrHandoffBootstrapPlanRefused, service.ID)
		}
		dnsName := k8s.FQDN(service.Name, service.Namespace, topology.ClusterName, topology.DNSZone)
		if dnsName == "" {
			return HandoffBootstrapPlan{}, ErrHandoffBootstrapPlanRefused
		}
		services = append(services, PoolVIPOwnershipServiceV3{ServiceID: service.ID.String(), VIP: service.VIP, Namespace: service.Namespace,
			Service: service.Name, ServiceCIDR: topology.ServiceCIDR, DNSName: dnsName, Protocol: service.Protocol, Port: int(*service.PortLow)})
		plan.ServiceUIDs = append(plan.ServiceUIDs, HandoffBootstrapServiceUID{ActiveNodeID: topology.ActiveNodeID, PromotionGeneration: topology.Generation,
			Namespace: service.Namespace, Service: service.Name, UID: service.UID, ObservationRevision: service.ObservationRevision})
	}
	sort.Slice(services, func(i, j int) bool { return services[i].ServiceID < services[j].ServiceID })
	evidence := handoffBootstrapUIDEvidence(topology.Services)
	operationID := handoffBootstrapUUID("operation", topology.Scope, topology.Generation, uuid.Nil, "", evidence, expires)
	for _, member := range topology.Members {
		role, phase, intent := policyspec.PoolVIPOwnershipPreparedNonServing, poolVIPOwnershipPhasePrepare, "non_serving"
		var peers []PoolVIPOwnershipWGPeerV3
		var routes []string
		var ownedServices []PoolVIPOwnershipServiceV3
		if member.NodeID == topology.ActiveNodeID {
			role, phase, intent = policyspec.PoolVIPOwnershipServing, poolVIPOwnershipPhaseServe, "serving"
			peers = []PoolVIPOwnershipWGPeerV3{{PublicKey: topology.EdgeWGPublicKey, AllowedIPs: []string{topology.DevicePoolCIDR}}}
			routes = []string{topology.DevicePoolCIDR}
			ownedServices = services
		}
		counter := topology.Counters[member.NodeID]
		if counter.ManifestRevision == 0 || counter.LeaseEpoch == 0 {
			return HandoffBootstrapPlan{}, ErrHandoffBootstrapPlanRefused
		}
		deliveryID := handoffBootstrapUUID("delivery", topology.Scope, topology.Generation, member.NodeID, role, evidence, expires)
		manifest := PoolVIPOwnershipManifestV3{Version: policyspec.PoolVIPOwnershipManifestVersion, OrgID: topology.Scope.OrgID.String(), SiteID: topology.Scope.SiteID.String(),
			ClusterID: topology.Scope.ClusterID.String(), PoolID: topology.Scope.PoolID.String(), ConnectorNodeID: member.NodeID.String(), Role: role,
			PromotionGeneration: topology.Generation, ManifestRevision: counter.ManifestRevision, LeaseEpoch: counter.LeaseEpoch, LeaseExpiresAt: expires,
			DNSZone: dnsZone, DNSVIP: topology.DNSVIP, HandoffOwnerID: operationID.String(), RouteIntent: intent, WGPeers: peers, Routes: routes, Services: ownedServices}
		identity, err := policyspec.PoolVIPOwnershipManifestIdentity(manifest.policyManifest())
		if err != nil {
			return HandoffBootstrapPlan{}, fmt.Errorf("%w: manifest: %v", ErrHandoffBootstrapPlanRefused, err)
		}
		routeDigest, err := PoolVIPOwnershipOwnedRouteDigest(routes)
		if err != nil {
			return HandoffBootstrapPlan{}, ErrHandoffBootstrapPlanRefused
		}
		envelope := PoolVIPOwnershipDeliveryEnvelopeV3{PoolVIPOwnershipDeliveryEnvelope: PoolVIPOwnershipDeliveryEnvelope{
			Version: PoolVIPOwnershipDeliveryHandoffVersion, OrgID: topology.Scope.OrgID.String(), SiteID: topology.Scope.SiteID.String(), ClusterID: topology.Scope.ClusterID.String(), PoolID: topology.Scope.PoolID.String(),
			ConnectorNodeID: member.NodeID.String(), TargetNodeID: member.NodeID.String(), OperationID: operationID.String(), ManifestIdentity: identity, Role: role,
			PromotionGeneration: topology.Generation, ManifestRevision: counter.ManifestRevision, LeaseEpoch: counter.LeaseEpoch, DeliveryPhase: phase,
			DeliveryID: deliveryID.String(), DeliveryNonce: handoffBootstrapNonce(deliveryID)}, ExpiresAt: expires, Manifest: manifest,
			ExpectedRouteDigest: routeDigest, ExpectedVIPMapDigest: poolVIPOwnershipManifestVIPMapDigest(manifest.policyManifest())}
		if err := ValidatePoolVIPOwnershipDeliveryEnvelopeV3(envelope); err != nil {
			return HandoffBootstrapPlan{}, fmt.Errorf("%w: envelope: %v", ErrHandoffBootstrapPlanRefused, err)
		}
		if existing, ok := topology.Existing[member.NodeID]; ok && !reflect.DeepEqual(existing, envelope) {
			return HandoffBootstrapPlan{}, fmt.Errorf("%w: durable bootstrap delivery disagrees with locked topology", ErrHandoffBootstrapPlanRefused)
		}
		delivery, err := p2HandoffDeliveryFromEnvelope(envelope)
		if err != nil {
			return HandoffBootstrapPlan{}, err
		}
		if member.NodeID == topology.ActiveNodeID {
			plan.CurrentOwnerEnvelope, plan.CurrentOwnerServing = envelope, delivery
		} else {
			plan.EligibleStandbyIDs = append(plan.EligibleStandbyIDs, member.NodeID)
			plan.StandbyEnvelopes = append(plan.StandbyEnvelopes, envelope)
			plan.StandbyPrepared = append(plan.StandbyPrepared, delivery)
		}
	}
	if !validHandoffBootstrapPlan(plan, expires.Add(-time.Nanosecond)) {
		return HandoffBootstrapPlan{}, fmt.Errorf("%w: projected plan is invalid", ErrHandoffBootstrapPlanRefused)
	}
	return plan, nil
}

func p2HandoffDeliveryFromEnvelope(envelope PoolVIPOwnershipDeliveryEnvelopeV3) (k8s.P2HandoffDelivery, error) {
	artifact := poolVIPOwnershipHandoffArtifact(envelope)
	org, e1 := uuid.Parse(artifact.OrgID)
	site, e2 := uuid.Parse(artifact.SiteID)
	cluster, e3 := uuid.Parse(artifact.ClusterID)
	pool, e4 := uuid.Parse(artifact.PoolID)
	connector, e5 := uuid.Parse(artifact.ConnectorNodeID)
	target, e6 := uuid.Parse(artifact.TargetNodeID)
	operation, e7 := uuid.Parse(artifact.OperationID)
	deliveryID, e8 := uuid.Parse(artifact.DeliveryID)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil || e6 != nil || e7 != nil || e8 != nil {
		return k8s.P2HandoffDelivery{}, ErrHandoffBootstrapPlanRefused
	}
	return k8s.P2HandoffDelivery{Identity: k8s.P2HandoffDeliveryIdentity{Version: PoolVIPOwnershipDeliveryHandoffVersion, OrgID: org, SiteID: site, ClusterID: cluster, PoolID: pool,
		ConnectorNodeID: connector, TargetNodeID: target, OperationID: operation, ManifestIdentity: artifact.ManifestIdentity, Role: k8s.P2HandoffRole(artifact.Role),
		PromotionGeneration: artifact.PromotionGeneration, ManifestRevision: artifact.ManifestRevision, LeaseEpoch: artifact.LeaseEpoch, PriorLeaseEpoch: artifact.PriorLeaseEpoch,
		DeliveryPhase: artifact.DeliveryPhase, DeliveryID: deliveryID, ExpectedRouteDigest: artifact.ExpectedRouteDigest, ExpectedVIPMapDigest: artifact.ExpectedVIPMapDigest}, LeaseExpiresAt: envelope.ExpiresAt}, nil
}

func handoffBootstrapUUID(kind string, scope k8s.HandoffPoolScope, generation uint64, node uuid.UUID, role, evidence string, expires time.Time) uuid.UUID {
	name := fmt.Sprintf("tunnex/handoff-bootstrap/v3/%s/%s/%s/%s/%s/%d/%s/%s/%s/%s", kind, scope.OrgID, scope.SiteID, scope.ClusterID, scope.PoolID, generation, node, role, evidence, expires.Format(time.RFC3339Nano))
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(name))
}

func handoffBootstrapUIDEvidence(services []handoffBootstrapService) string {
	values := append([]handoffBootstrapService(nil), services...)
	sort.Slice(values, func(i, j int) bool {
		if values[i].Namespace != values[j].Namespace {
			return values[i].Namespace < values[j].Namespace
		}
		if values[i].Name != values[j].Name {
			return values[i].Name < values[j].Name
		}
		return values[i].ID.String() < values[j].ID.String()
	})
	h := sha256.New()
	_, _ = h.Write([]byte("tunnex/handoff-bootstrap-service-uid-evidence/v1\n"))
	for _, service := range values {
		_, _ = fmt.Fprintf(h, "%s\t%s\t%s\t%s\t%d\n", service.ID, service.Namespace, service.Name, service.UID, service.ObservationRevision)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func handoffBootstrapNonce(deliveryID uuid.UUID) string {
	sum := sha256.Sum256([]byte("tunnex/handoff-bootstrap-delivery-nonce/v1\x00" + deliveryID.String()))
	return hex.EncodeToString(sum[:])
}

func validHandoffBootstrapWGKey(value string) bool {
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	return err == nil && len(decoded) == 32 && base64.StdEncoding.EncodeToString(decoded) == value
}
