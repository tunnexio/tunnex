// Package k8s is the control-plane side of exposing in-cluster Kubernetes Services to the fabric (S10.3).
// A k8s_cluster owns a disjoint synthetic VIP range (validated by the shared subnetguard collector); an
// exposed Service is a STABLE-IDENTITY destination allocated a /32 VIP from that range. The gateway DNATs
// VIP -> the real ClusterIP; the compiler resolves a grant's Service identity -> its CURRENT VIP at
// compile time (Slice 2), so a freed-then-reused VIP never confuses grants — see the VIP-stability note.
//
// Governance (a grant that reaches an exposed Service) is enterprise; the model here is CORE (like sites),
// with the enterprise gate landing in the API layer (Slice 7).
package k8s

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/agentaccessguard"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/ipalloc"
	"github.com/tunnexio/tunnex/apps/api/internal/pgerr"
	"github.com/tunnexio/tunnex/apps/api/internal/sites"
	"github.com/tunnexio/tunnex/apps/api/internal/subnetguard"
	"github.com/tunnexio/tunnex/apps/api/internal/subnetsrc"
)

// DNS naming validators (RFC 1123). A cluster name is ONE label; a zone is a dotted sequence of labels.
// Both feed the exposed-Service hostname <service>.<namespace>.svc.<cluster>.<zone>, so they are validated
// at RegisterCluster with typed teaching errors — a bad name never reaches the wire (S10.3 (B2)).
var (
	dnsLabelRE    = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	dnsNameRE     = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)
	wgPublicKeyRE = regexp.MustCompile(`^[A-Za-z0-9+/]{43}=$`)
)

func validDNSLabel(s string) bool { return len(s) >= 1 && len(s) <= 63 && dnsLabelRE.MatchString(s) }
func validDNSName(s string) bool  { return len(s) >= 1 && len(s) <= 253 && dnsNameRE.MatchString(s) }

type Service struct {
	pool   *pgxpool.Pool
	q      *sqlc.Queries
	notify Notifier // nil => no push (tests / provider-only); wired in main.go to the nodepush hub
	// connectorPoolConfigurationAfterMutationHook is an unexported test-only
	// rollback seam for the transactional pool configuration service.
	connectorPoolConfigurationAfterMutationHook func() error
}

// Notifier signals gateways to re-fetch desired state (the <5s push path, S7.2). The nodepush hub satisfies
// it. A K8s sweep is enterprise-grant-affecting (a deregister cascade-deletes grants), so it MUST ride the
// push path rather than wait ~25s for the agent long-poll (M5) — stale enforcement of a deleted grant is the
// gap the <5s revocation promise exists to close.
type Notifier interface{ NotifyMany(nodeIDs []uuid.UUID) }

func NewService(pool *pgxpool.Pool) *Service { return &Service{pool: pool, q: sqlc.New(pool)} }

// SetNotifier wires the push hub (M5). Call at construction in main.go; nil leaves the ~25s long-poll as the
// only propagation (acceptable for tests, not for a grant-cascading production sweep).
func (s *Service) SetNotifier(n Notifier) { s.notify = n }

// pushOrg notifies the org's active gateways to re-fetch after a sweep (M5). Best-effort: a push failure is
// never fatal (the ~25s long-poll remains the backstop), and no notifier (tests) is a silent no-op.
func (s *Service) pushOrg(ctx context.Context, orgID uuid.UUID) {
	if s.notify == nil {
		return
	}
	ids, err := s.q.ListActiveNodeIDsForOrg(ctx, orgID)
	if err != nil || len(ids) == 0 {
		return
	}
	s.notify.NotifyMany(ids)
}

func (s *Service) withTx(ctx context.Context, fn func(*sqlc.Queries) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := fn(s.q.WithTx(tx)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// audit writes one append-only audit row in the caller's tx (H2 — the swallowed-audit law: a K8s mutation
// must leave an actor-attributed trail, especially DeregisterCluster, which FK-cascade-deletes enterprise
// grants). RETURNS its error (never swallows — a swallowed InsertAuditLog poisons the tx). Mirrors
// sites.auditTarget.
// The actor is EITHER a human (actorUserID, actorSystem=="") OR a machine (actorSystem="operator:<name>",
// actorUserID==Nil), never both — the 0027 XOR. A machine's mutation is a SYSTEM-actor row with the cause
// in metadata, so a GitOps change can NEVER masquerade as a human (S10.2 D3). The caller passes
// authctx.Principal.AuditActor().
func (s *Service) audit(ctx context.Context, q *sqlc.Queries, orgID, actorUserID uuid.UUID, actorSystem, cause string, targetType, targetID, action string, meta map[string]any) error {
	tt, ti := targetType, targetID
	if meta == nil {
		meta = map[string]any{}
	}
	if cause != "" {
		meta["cause"] = cause
	}
	if actorSystem != "" {
		b, _ := json.Marshal(meta)
		as := actorSystem
		_, err := q.InsertSystemAuditLog(ctx, sqlc.InsertSystemAuditLogParams{
			OrgID: pgtype.UUID{Bytes: orgID, Valid: true}, ActorSystem: &as,
			Action: action, TargetType: &tt, TargetID: &ti, Metadata: b,
		})
		return err
	}
	b, _ := json.Marshal(meta)
	_, err := q.InsertAuditLog(ctx, sqlc.InsertAuditLogParams{
		OrgID: pgtype.UUID{Bytes: orgID, Valid: true},
		// NULL (not a fake zero) when there is no human actor — the schema allows a neither-actor row
		// (0027 CHECK: legacy/unattributed), and a zero uuid would violate the actor_user_id FK to users.
		// In production a human create always carries a real id; only a nil-actor path (tests) hits this.
		ActorUserID: pgtype.UUID{Bytes: actorUserID, Valid: actorUserID != uuid.Nil},
		Action:      action,
		TargetType:  &tt,
		TargetID:    &ti,
		Metadata:    b,
	})
	return err
}

// RegisterCluster creates a K8s cluster and its synthetic VIP range. The range must be DISJOINT from
// every allocatable class in the org — the device pool, every site subnet, AND other clusters' VIP
// ranges — assembled by the ONE shared collector (F2). A collision is the forbidden outcome (ambiguous
// routing), refused with a typed, teaching error naming the class and what to do.
// serviceCIDR is the cluster's real Kubernetes Service CIDR (where ClusterIPs live). It is NOT
// disjointness-validated — it is the very range that collides with the pool/sites (that is WHY exposed
// Services get synthetic VIPs). It is captured only so the gateway can classify a resolved address (in the
// Service CIDR = a ClusterIP to DNAT; outside = a pod IP = a headless Service, refused) without the K8s API.
// managedByMachine (S10.2 Slice 3a) records the operator's machine credential when a MACHINE principal
// registers the cluster (uuid.Nil for a human → NULL, inert). The ownership marker the dashboard surfaces
// in Slice 4; recorded here so that surface never retrofits live rows. NOTE (finding, held): the create
// path still does NOT write an audit row — the additive-creates-unaudited gap from the S10.3 review; the
// marker is a data property, not an audit, and closing the audit gap is its own disposition.
// RegisterCluster preserves the original programmatic core seam for existing
// callers and migrations. A nil connector is an honest unserved state; the
// HTTP/UI path uses RegisterClusterWithConnector and requires one.
func (s *Service) RegisterCluster(ctx context.Context, orgID, siteID uuid.UUID, name string, vipRange, serviceCIDR netip.Prefix, dnsZone string, managedByMachine, actorUserID uuid.UUID, actorSystem, cause string) (sqlc.K8sCluster, error) {
	return s.registerCluster(ctx, orgID, siteID, uuid.Nil, name, vipRange, serviceCIDR, dnsZone, managedByMachine, actorUserID, actorSystem, cause)
}

func (s *Service) RegisterClusterWithConnector(ctx context.Context, orgID, siteID, connectorNodeID uuid.UUID, name string, vipRange, serviceCIDR netip.Prefix, dnsZone string, managedByMachine, actorUserID uuid.UUID, actorSystem, cause string) (sqlc.K8sCluster, error) {
	return s.registerCluster(ctx, orgID, siteID, connectorNodeID, name, vipRange, serviceCIDR, dnsZone, managedByMachine, actorUserID, actorSystem, cause)
}

func (s *Service) registerCluster(ctx context.Context, orgID, siteID, connectorNodeID uuid.UUID, name string, vipRange, serviceCIDR netip.Prefix, dnsZone string, managedByMachine, actorUserID uuid.UUID, actorSystem, cause string) (sqlc.K8sCluster, error) {
	var out sqlc.K8sCluster
	err := s.withTx(ctx, func(q *sqlc.Queries) error {
		// The cluster name becomes a hostname label (<service>.<namespace>.svc.<name>.<zone>), so it must be
		// a DNS label; the zone is the customer's domain suffix. Typed teaching errors (S10.3 (B2)).
		if !validDNSLabel(name) {
			return apierr.BadRequest("invalid_cluster_name",
				"the cluster name must be a DNS label (lowercase a-z0-9 + hyphens, <=63 chars) — it becomes part of every exposed Service's hostname: <service>.<namespace>.svc."+name+"."+dnsZone)
		}
		if !validDNSName(dnsZone) {
			return apierr.BadRequest("invalid_dns_zone",
				"the cluster DNS zone must be a valid domain (e.g. k8s.acme.com) — the suffix of every exposed Service's hostname; it need not be publicly registered (names resolve only inside the tunnel)")
		}
		if !serviceCIDR.IsValid() {
			return apierr.BadRequest("invalid_service_cidr", "the cluster's Kubernetes Service CIDR is required (e.g. 10.96.0.0/12) — the gateway uses it to tell a ClusterIP from a pod IP")
		}
		// M6: take the org's tx-scoped advisory lock BEFORE the disjointness read, the SAME key ResizePool +
		// ApproveSubnet take. The Collect/Check is a read-then-write; under READ COMMITTED two concurrent
		// range writes (two RegisterClusters, or a RegisterCluster racing a pool-resize / subnet-approval)
		// would each snapshot a set excluding the other's uncommitted row and both pass, committing two
		// OVERLAPPING ranges the unique index can't catch (it only refuses IDENTICAL CIDRs). The lock
		// serializes all range-writing seams so the check reflects committed state. (Lock is the form because
		// the forbidden overlap spans THREE tables — pool, site subnets, cluster VIP ranges — which no single
		// per-table EXCLUDE constraint can represent; within-table EXCLUDE is a registered defense-in-depth.)
		if e := q.LockDeviceKey(ctx, orgID.String()); e != nil {
			return e
		}
		// The cluster must be fronted by a real site in THIS org (one gateway = one site, D1).
		if _, e := q.GetSite(ctx, sqlc.GetSiteParams{ID: siteID, OrgID: orgID}); e != nil {
			return apierr.NotFound("site_not_found", "no such site in this organization")
		}
		if connectorNodeID != uuid.Nil {
			if e := validateConnector(ctx, q, orgID, siteID, connectorNodeID); e != nil {
				return e
			}
		}
		// Cross-mechanism one-zone-one-resolver (S10.3 (A)): the cluster's DNS zone <cluster>.<dns_zone> must
		// not collide with a domain already forwarded by a site (the mirror of the check in sites.SetDNSForward).
		fwd, e := sites.ForwardedDomainsForOrg(ctx, q, orgID)
		if e != nil {
			return e
		}
		if sites.DNSDomainConflict(fwd, name+"."+dnsZone) {
			return apierr.Conflict("dns_domain_conflict", name+"."+dnsZone+" collides with a domain already forwarded by a site; a domain resolves one way")
		}
		ranges, e := subnetguard.Collect(ctx, subnetsrc.Source{Q: q}, orgID)
		if e != nil {
			return e
		}
		if ov, ok := subnetguard.Check(vipRange, ranges); !ok {
			return apierr.BadRequest("vip_range_overlap",
				"the VIP range "+vipRange.String()+" overlaps "+string(ov.Class)+" "+ov.With.String()+
					"; choose a range disjoint from your device pool, your site subnets, and other clusters' VIP ranges")
		}
		// Reserve the DNS VIP (the range's first allocatable, .2 — .1 is conventionally a gateway) so a
		// Service can never be handed it; the gateway answers DNS on it (fail-closed on the wire). The range
		// must fit the DNS VIP PLUS at least one Service VIP, else it is refused honestly (not left DNS-only).
		rangeStr := vipRange.Masked().String()
		dnsVIPStr, e := ipalloc.Allocate(rangeStr, nil)
		if errors.Is(e, ipalloc.ErrPoolExhausted) {
			return apierr.BadRequest("vip_range_too_small", "the VIP range must fit a reserved DNS address plus at least one Service VIP")
		}
		if e != nil {
			return e
		}
		if _, e := ipalloc.Allocate(rangeStr, []string{dnsVIPStr}); errors.Is(e, ipalloc.ErrPoolExhausted) {
			return apierr.BadRequest("vip_range_too_small", "the VIP range must fit a reserved DNS address plus at least one Service VIP")
		}
		dnsVIP, e := netip.ParseAddr(dnsVIPStr)
		if e != nil {
			return e
		}
		c, e := q.CreateK8sCluster(ctx, sqlc.CreateK8sClusterParams{
			OrgID: orgID, SiteID: siteID, ConnectorNodeID: pgtype.UUID{Bytes: connectorNodeID, Valid: connectorNodeID != uuid.Nil}, Name: name, VipRange: vipRange.Masked(), ServiceCidr: serviceCIDR.Masked(),
			DnsZone: dnsZone, DnsVip: &dnsVIP,
			ManagedByMachine: pgtype.UUID{Bytes: managedByMachine, Valid: managedByMachine != uuid.Nil},
		})
		if pgerr.IsUnique(e) {
			return apierr.Conflict("cluster_exists", "a cluster with that name or VIP range already exists in this organization")
		}
		if e != nil {
			return e
		}
		out = c
		// M1 (S10.2): audit the create — a network-reaching cluster ENTERING the fabric. Branches machine
		// (actor_system=operator:<name> + cause=the CR) vs human (actor_user_id), the same seam as the delete.
		return s.audit(ctx, q, orgID, actorUserID, actorSystem, cause, "k8s_cluster", c.ID.String(), "k8s.cluster_registered",
			map[string]any{"name": name, "vip_range": vipRange.Masked().String(), "dns_zone": dnsZone, "connector_node_id": connectorNodeID.String()})
	})
	return out, err
}

// SetClusterConnector assigns the one active same-site node that owns a
// cluster's EndpointSlice watch and private VIP DNAT. It is separate from site
// binding: a site may have HA edges, but selecting one by accident makes the
// synthetic service route dead-while-green.
func (s *Service) SetClusterConnector(ctx context.Context, orgID, clusterID, connectorNodeID, actorUserID uuid.UUID, actorSystem, cause string) error {
	err := s.withTx(ctx, func(q *sqlc.Queries) error {
		cluster, err := q.GetK8sClusterForConnectorSetForUpdate(ctx, sqlc.GetK8sClusterForConnectorSetForUpdateParams{OrgID: orgID, ClusterID: clusterID})
		if err != nil {
			return apierr.NotFound("cluster_not_found", "no such cluster in this organization")
		}
		if cluster.ConnectorPoolID.Valid {
			return apierr.Conflict("connector_pool_configured", "this cluster uses a connector pool; update its pool membership instead of selecting one direct connector")
		}
		if err := validateConnector(ctx, q, orgID, cluster.SiteID, connectorNodeID); err != nil {
			return err
		}
		changed, err := q.SetK8sClusterConnector(ctx, sqlc.SetK8sClusterConnectorParams{OrgID: orgID, ID: clusterID, ConnectorNodeID: pgtype.UUID{Bytes: connectorNodeID, Valid: true}})
		if err != nil {
			if pgerr.IsUnique(err) {
				return apierr.Conflict("connector_already_assigned", "that gateway already fronts another Kubernetes cluster")
			}
			return err
		}
		if changed != 1 {
			return apierr.Conflict("connector_mode_changed", "the cluster connector mode changed; reload and retry")
		}
		return s.audit(ctx, q, orgID, actorUserID, actorSystem, cause, "k8s_cluster", clusterID.String(), "k8s.cluster_connector_set", map[string]any{"connector_node_id": connectorNodeID.String()})
	})
	if err == nil {
		s.pushOrg(ctx, orgID)
	}
	return err
}

func validateConnector(ctx context.Context, q *sqlc.Queries, orgID, siteID, connectorNodeID uuid.UUID) error {
	if connectorNodeID == uuid.Nil {
		return apierr.BadRequest("connector_node_required", "select the active in-cluster gateway that fronts this cluster")
	}
	node, err := q.GetNodeForOrg(ctx, sqlc.GetNodeForOrgParams{ID: connectorNodeID, OrgID: orgID})
	if err != nil {
		return apierr.NotFound("connector_not_found", "no such gateway in this organization")
	}
	return validateConnectorNode(node, siteID)
}

// validateConnectorNode preserves the released legacy single-connector
// contract: the key and endpoint must be present, but historical non-empty
// values are not retroactively rejected by the P1 pool hardening.
func validateConnectorNode(node sqlc.Node, siteID uuid.UUID) error {
	if node.RevokedAt.Valid || node.Status != "active" || !node.SiteID.Valid || uuid.UUID(node.SiteID.Bytes) != siteID {
		return apierr.Conflict("connector_not_in_cluster_site", "the connector must be an active gateway already bound to this cluster's site")
	}
	if node.WgPublicKey == "" || node.Endpoint == "" {
		return apierr.Conflict("connector_not_ready", "the connector has not reported a WireGuard public key and endpoint yet")
	}
	return nil
}

// validateConnectorPoolMemberNode is the stricter P1 pool contract. Pool
// membership is new and can fail closed on the exact peer material consumed by
// topology without changing the released legacy setter.
func validateConnectorPoolMemberNode(node sqlc.Node, siteID uuid.UUID) error {
	if err := validateConnectorNode(node, siteID); err != nil {
		return err
	}
	if !wgPublicKeyRE.MatchString(node.WgPublicKey) || strings.TrimSpace(node.Endpoint) == "" {
		return apierr.Conflict("connector_not_ready", "a connector pool member needs a valid WireGuard public key and non-empty endpoint")
	}
	return nil
}

// ExposeService allocates a /32 VIP from the cluster's range (ipalloc, used-set = the cluster's LIVE VIPs)
// and records the exposed Service.
//
// VIP-STABILITY (the reassignment hazard is born here): the used-set is LIVE Services only, so a
// soft-deleted Service's VIP is immediately reusable. That is SAFE because a grant references a Service's
// stable ID, and the compiler resolves ID -> CURRENT VIP at compile time and NEVER caches a VIP (Slice 2):
// a deleted Service vanishes from the resolution set (its grant compiles to nothing), and the reused VIP
// belongs unambiguously to the NEW Service's identity. Identity-resolution is therefore sufficient — no
// VIP quarantine is needed. (The reassignment-trap red lives in Slice 2, where the resolution is built.)
func (s *Service) ExposeService(ctx context.Context, orgID, clusterID uuid.UUID, name, namespace, protocol string, portLow, portHigh *int32, managedByMachine, actorUserID uuid.UUID, actorSystem, cause string) (sqlc.K8sService, error) {
	if protocol == "" {
		protocol = "any"
	}
	// WF-K5 M8/M9: an exposed Service must name a SINGLE specific port. The gateway DNATs VIP:svcPort ->
	// podIP:targetPort; an all-ports exposure (nil port) can't remap and would silently hit the wrong pod
	// port, and a port RANGE would DNAT only the low port and blackhole the rest — both silently wrong, worse
	// than unsupported. Refuse with a teaching error (K8s Service ports are discrete). Range support is a
	// registered follow-up (trigger: a customer need).
	if portLow == nil || *portLow < 1 || *portLow > 65535 {
		return sqlc.K8sService{}, apierr.BadRequest("service_port_required",
			"expose a specific port (1-65535): the gateway maps the VIP's port to the Service's pod port, so it needs one — all-ports exposure isn't supported")
	}
	if portHigh != nil && *portHigh != *portLow {
		return sqlc.K8sService{}, apierr.BadRequest("service_port_range_unsupported",
			"expose a single specific port, not a range: the gateway DNATs one port per exposed Service (Kubernetes Service ports are discrete)")
	}
	var out sqlc.K8sService
	err := s.withTx(ctx, func(q *sqlc.Queries) error {
		cluster, e := q.GetK8sCluster(ctx, sqlc.GetK8sClusterParams{OrgID: orgID, ID: clusterID})
		if e != nil {
			return apierr.NotFound("cluster_not_found", "no such cluster in this organization")
		}
		used, e := q.ListUsedVIPsInCluster(ctx, sqlc.ListUsedVIPsInClusterParams{OrgID: orgID, ClusterID: clusterID})
		if e != nil {
			return e
		}
		// The reserved DNS VIP is NOT a live Service, so it is absent from the used-set — add it explicitly
		// so a Service can NEVER be handed the gateway's DNS address (the .2 reservation is inviolable).
		if cluster.DnsVip != nil {
			used = append(used, cluster.DnsVip.String())
		}
		vipStr, e := ipalloc.Allocate(cluster.VipRange.String(), used)
		if errors.Is(e, ipalloc.ErrPoolExhausted) {
			return apierr.Conflict("vip_range_exhausted",
				"the cluster's VIP range "+cluster.VipRange.String()+" is full; register the cluster with a larger range to expose more Services")
		}
		if e != nil {
			return e
		}
		vip, e := netip.ParseAddr(vipStr)
		if e != nil {
			return e
		}
		svc, e := q.CreateK8sService(ctx, sqlc.CreateK8sServiceParams{
			OrgID: orgID, ClusterID: clusterID, Name: name, Namespace: namespace,
			Protocol: protocol, PortLow: portLow, PortHigh: portHigh, Vip: vip,
			ManagedByMachine: pgtype.UUID{Bytes: managedByMachine, Valid: managedByMachine != uuid.Nil},
		})
		if pgerr.IsUnique(e) {
			return apierr.Conflict("service_exists", "that Service (namespace/name) is already exposed in this cluster")
		}
		if e != nil {
			return e
		}
		out = svc
		// M1 (S10.2): audit the exposure — a Service ENTERING the fabric (the mirror of the unexpose audit).
		return s.audit(ctx, q, orgID, actorUserID, actorSystem, cause, "k8s_service", svc.ID.String(), "k8s.service_exposed",
			map[string]any{"namespace": namespace, "name": name, "vip": vip.String()})
	})
	return out, err
}

// FQDN is the in-tunnel hostname for an exposed Service: <service>.<namespace>.svc.<cluster>.<zone>
// (S10.3 (B2), always-explicit). The ONE place the name is constructed — the compiler's loadSiteTopology
// builds the identical string; keep them in agreement.
func FQDN(service, namespace, cluster, zone string) string {
	return service + "." + namespace + ".svc." + cluster + "." + zone
}

// ServiceView is an exposed Service joined with its cluster's naming (the resolvable FQDN), for the read APIs.
type ServiceView struct {
	Svc     sqlc.K8sService
	FQDN    string
	Cluster string
	Zone    string
}

// GetCluster returns one cluster (org-scoped) — the read for building a Service's FQDN + the config UI.
func (s *Service) GetCluster(ctx context.Context, orgID, clusterID uuid.UUID) (sqlc.K8sCluster, error) {
	c, err := s.q.GetK8sCluster(ctx, sqlc.GetK8sClusterParams{OrgID: orgID, ID: clusterID})
	if err != nil {
		return sqlc.K8sCluster{}, apierr.NotFound("cluster_not_found", "no such cluster in this organization")
	}
	return c, nil
}

// GetService fetches one exposed Service by id (S10.2 C2): the operator's AUTHORITATIVE confirm-by-ID before a
// drift-recreate — a single-row lookup can't be fooled by a spurious empty LIST the way find-by-name can.
func (s *Service) GetService(ctx context.Context, orgID, serviceID uuid.UUID) (sqlc.K8sService, error) {
	svc, err := s.q.GetK8sService(ctx, sqlc.GetK8sServiceParams{OrgID: orgID, ID: serviceID})
	if err != nil {
		return sqlc.K8sService{}, apierr.NotFound("service_not_found", "no such exposed Service in this organization")
	}
	return svc, nil
}

// LiveServiceIDs returns the set of LIVE (not unexposed) Service IDs in the org — the read-time input for
// the vanished-Service warn (a grant whose dst Service is absent from this set compiles to nothing, S10.3).
func (s *Service) LiveServiceIDs(ctx context.Context, orgID uuid.UUID) (map[uuid.UUID]bool, error) {
	rows, err := s.q.ListActiveK8sServicesForOrg(ctx, orgID)
	if err != nil {
		return nil, err
	}
	out := make(map[uuid.UUID]bool, len(rows))
	for _, r := range rows {
		out[r.ID] = true
	}
	return out, nil
}

// ListClusters returns the org's clusters (config UI + list API).
func (s *Service) ListClusters(ctx context.Context, orgID uuid.UUID) ([]sqlc.K8sCluster, error) {
	return s.q.ListK8sClustersForOrg(ctx, orgID)
}

// ListServicesForOrg returns EVERY LIVE exposed Service in the org with its resolvable FQDN (the grant-
// destination picker + K8s overview). One query; the caller groups by cluster if needed.
func (s *Service) ListServicesForOrg(ctx context.Context, orgID uuid.UUID) ([]ServiceView, error) {
	rows, err := s.q.ListActiveK8sServicesForOrg(ctx, orgID)
	if err != nil {
		return nil, err
	}
	out := make([]ServiceView, 0, len(rows))
	for _, r := range rows {
		vip, _ := netip.ParseAddr(r.Vip)
		out = append(out, ServiceView{
			Svc: sqlc.K8sService{
				ID: r.ID, ClusterID: r.ClusterID, OrgID: orgID, Name: r.Name, Namespace: r.Namespace,
				Protocol: r.Protocol, PortLow: r.PortLow, PortHigh: r.PortHigh, Vip: vip,
				ManagedByMachine: r.ManagedByMachine,
			},
			FQDN:    FQDN(r.Name, r.Namespace, r.ClusterName, r.DnsZone),
			Cluster: r.ClusterName, Zone: r.DnsZone,
		})
	}
	return out, nil
}

// ListServicesForCluster returns a cluster's LIVE exposed Services with their resolvable FQDNs.
func (s *Service) ListServicesForCluster(ctx context.Context, orgID, clusterID uuid.UUID) ([]ServiceView, error) {
	if _, err := s.GetCluster(ctx, orgID, clusterID); err != nil {
		return nil, err
	}
	all, err := s.ListServicesForOrg(ctx, orgID)
	if err != nil {
		return nil, err
	}
	out := make([]ServiceView, 0, len(all))
	for _, v := range all {
		if v.Svc.ClusterID == clusterID {
			out = append(out, v)
		}
	}
	return out, nil
}

// UnexposeService soft-deletes an exposed Service (S10.3 sweep). Full-sweep by construction: the LIVE-only
// resolution (ListActiveK8sServicesForOrg) drops it on the next compile, so the VIP vanishes from every
// gateway's VIP map AND its DNS answer, and any grant that referenced it compiles to nothing (the honest
// vanished-Service surface, rendered in API/web). The freed VIP is immediately reusable — SAFE because a
// re-expose mints a NEW identity and the compiler resolves id -> CURRENT VIP, never a snapshot (Slice 2).
func (s *Service) UnexposeService(ctx context.Context, actorUserID uuid.UUID, actorSystem, cause string, orgID, serviceID uuid.UUID) error {
	err := s.withTx(ctx, func(q *sqlc.Queries) error {
		svc, e := q.GetK8sService(ctx, sqlc.GetK8sServiceParams{OrgID: orgID, ID: serviceID})
		if e != nil {
			return apierr.NotFound("service_not_found", "no such exposed Service in this organization")
		}
		if _, e := agentaccessguard.LockDestination(ctx, q, orgID, "k8s_service", serviceID); e != nil {
			return e
		}
		live, e := agentaccessguard.LiveDestinationRequests(ctx, q, orgID, "k8s_service", serviceID)
		if e != nil {
			return e
		}
		if live != 0 {
			return apierr.Conflict("agent_access_destination_in_use", fmt.Sprintf("%d pending or approved agent access requests reference this Service", live))
		}
		templateVersions, e := q.CountAgentPolicyTemplateK8sServiceReferences(ctx, sqlc.CountAgentPolicyTemplateK8sServiceReferencesParams{OrgID: orgID, DstK8sServiceID: pgtype.UUID{Bytes: serviceID, Valid: true}})
		if e != nil {
			return e
		}
		if templateVersions != 0 {
			return apierr.Conflict("agent_policy_template_destination", fmt.Sprintf("%d immutable agent policy template versions reference this Service", templateVersions))
		}
		if e := q.SoftDeleteK8sService(ctx, sqlc.SoftDeleteK8sServiceParams{OrgID: orgID, ID: serviceID}); e != nil {
			return e
		}
		// H2: audit the unexpose (a network-exposed Service leaving the fabric) — the RemoveSubnet analogue.
		return s.audit(ctx, q, orgID, actorUserID, actorSystem, cause, "k8s_service", serviceID.String(), "k8s.service_unexposed",
			map[string]any{"namespace": svc.Namespace, "name": svc.Name, "vip": svc.Vip.String()})
	})
	if err == nil {
		s.pushOrg(ctx, orgID) // M5: propagate at push speed, not the ~25s long-poll
	}
	return err
}

// DeregisterCluster removes a cluster (S10.3 sweep). Full-sweep: the FK CASCADE deletes its exposed Services
// AND every policy_rule that pointed at one (0049 dst_k8s_service_id ON DELETE CASCADE), and the row's removal
// frees the whole VIP range (incl the reserved DNS VIP) and the cluster's DNS zone for reuse — all in ONE
// atomic delete. The next compile recompiles every affected gateway without the vanished cluster.
func (s *Service) DeregisterCluster(ctx context.Context, actorUserID uuid.UUID, actorSystem, cause string, orgID, clusterID uuid.UUID) error {
	err := s.withTx(ctx, func(q *sqlc.Queries) error {
		cluster, e := q.GetK8sCluster(ctx, sqlc.GetK8sClusterParams{OrgID: orgID, ID: clusterID})
		if e != nil {
			return apierr.NotFound("cluster_not_found", "no such cluster in this organization")
		}
		if e := agentaccessguard.LockK8sClusterDestinations(ctx, q, orgID, clusterID); e != nil {
			return e
		}
		live, e := agentaccessguard.LiveK8sClusterRequests(ctx, q, orgID, clusterID)
		if e != nil {
			return e
		}
		if live != 0 {
			return apierr.Conflict("agent_access_destination_in_use", fmt.Sprintf("%d pending or approved agent access requests reference Services in this cluster", live))
		}
		// H2: capture the cascade counts BEFORE the delete — the FK cascade hard-deletes the cluster's Services
		// AND every enterprise grant referencing one, so the audit must name what vanished (the DeleteSite
		// analogue, which records rules_deleted/subnets_released). A governance cascade must never be untraceable.
		casc, e := q.CountClusterCascade(ctx, sqlc.CountClusterCascadeParams{OrgID: orgID, ClusterID: clusterID})
		if e != nil {
			return e
		}
		if e := q.DeleteK8sCluster(ctx, sqlc.DeleteK8sClusterParams{OrgID: orgID, ID: clusterID}); e != nil {
			return e
		}
		return s.audit(ctx, q, orgID, actorUserID, actorSystem, cause, "k8s_cluster", clusterID.String(), "k8s.cluster_deregistered",
			map[string]any{"name": cluster.Name, "services_deleted": casc.ServiceCount, "grants_deleted": casc.GrantCount})
	})
	if err == nil {
		s.pushOrg(ctx, orgID) // M5: a deregister cascade-deletes grants — propagate at push speed, not ~25s
	}
	return err
}
