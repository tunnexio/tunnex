package k8s

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/ipalloc"
)

// K8N-3 stage 1: the cluster's Kubernetes API as a named destination (docs/K8N-3-kubectl-access.md).
//
// "API access" is a per-cluster switch, off by default. On, the cluster's API server gets ONE address
// from the cluster's range, mapped to the Service default/kubernetes on TCP 443, under the name the
// mechanism already produces for that Service. A rule with dst_kind='k8s_api' then lets a person or a
// group open TCP 443 to it. Tunnex carries the connection; the user's own cluster credential still
// decides what they may do. Nothing here issues, stores or sees a cluster credential.

const (
	// The Service every cluster publishes its API server under.
	APIServiceNamespace = "default"
	APIServiceName      = "kubernetes"
	// APIServicePort is the Service port of default/kubernetes on every conformant cluster.
	APIServicePort = 443
)

// IsAPIServerService reports whether a Service is the cluster's own API server.
func IsAPIServerService(namespace, name string) bool {
	return namespace == APIServiceNamespace && name == APIServiceName
}

// ErrAPIServerNotAService is the one refusal for "expose default/kubernetes as an ordinary Service",
// returned by every exposure path. The API server is reached through API access, which has its own
// permission, its own rule kind and its own audit entry.
func ErrAPIServerNotAService() error {
	return apierr.BadRequest("k8s_api_server_not_a_service",
		"default/kubernetes is the cluster's API server and cannot be exposed as a Service. Turn on API access for the cluster instead (it needs the k8s_api:manage permission)")
}

// APIFQDN is the name a kubeconfig's server line points at: the one the mechanism already produces for
// default/kubernetes, so the gateway's forwarding and DNS are the ones Services use.
func APIFQDN(cluster, zone string) string {
	return FQDN(APIServiceName, APIServiceNamespace, cluster, zone)
}

// APIAccess is one cluster's API access as the dashboard shows it.
type APIAccess struct {
	ClusterID   uuid.UUID
	ClusterName string
	// EndpointID is uuid.Nil until API access has been turned on once.
	EndpointID uuid.UUID
	Enabled    bool
	// VIP is the allocated address; "" while off.
	VIP string
	// FQDN is the name the API has (or would have) in the tunnel. It is known before enabling.
	FQDN string
	Port int
	// RuleCount is how many rules name this cluster's API, whatever their state. They stay when API
	// access is turned off (and allow nothing) and take effect again when it is turned back on.
	RuleCount int
	// OrdinaryExposure is true when default/kubernetes is already exposed as an ordinary Service in
	// this cluster (made before this feature). It is left in place; API access cannot be turned on
	// beside it because two addresses would answer to one name.
	OrdinaryExposure bool
	EnabledAt        *time.Time
}

func requireAPIAccessHuman(actor *authctx.Principal) (uuid.UUID, error) {
	if actor == nil || actor.UserID == uuid.Nil || actor.IsMachine() || actor.AuthMethod == authctx.AuthAgent || actor.NodeID != uuid.Nil {
		return uuid.Nil, apierr.Forbidden("human_actor_required", "Kubernetes API access is turned on and off by a signed-in administrator")
	}
	if !actor.EmailVerified {
		return uuid.Nil, apierr.Forbidden("email_not_verified", "verify your email before changing Kubernetes API access")
	}
	return actor.UserID, nil
}

type apiAccessQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func loadAPIAccess(ctx context.Context, db apiAccessQuerier, orgID, clusterID uuid.UUID) (APIAccess, error) {
	out := APIAccess{ClusterID: clusterID, Port: APIServicePort}
	var zone string
	var endpointID *uuid.UUID
	var enabled *bool
	var vip *string
	err := db.QueryRow(ctx, `
		SELECT c.name, c.dns_zone, e.id, e.enabled, host(e.vip), e.enabled_at,
		       (SELECT count(*) FROM policy_rules r WHERE r.org_id=c.org_id AND r.dst_kind='k8s_api' AND r.dst_k8s_api_endpoint_id=e.id),
		       EXISTS (SELECT 1 FROM k8s_services s WHERE s.org_id=c.org_id AND s.cluster_id=c.id
		               AND s.namespace=$3 AND s.name=$4 AND s.deleted_at IS NULL)
		FROM k8s_clusters c
		LEFT JOIN k8s_api_endpoints e ON e.cluster_id=c.id AND e.org_id=c.org_id
		WHERE c.id=$1 AND c.org_id=$2`, clusterID, orgID, APIServiceNamespace, APIServiceName).
		Scan(&out.ClusterName, &zone, &endpointID, &enabled, &vip, &out.EnabledAt, &out.RuleCount, &out.OrdinaryExposure)
	if errors.Is(err, pgx.ErrNoRows) {
		return APIAccess{}, apierr.NotFound("cluster_not_found", "no such cluster in this organization")
	}
	if err != nil {
		return APIAccess{}, err
	}
	out.FQDN = APIFQDN(out.ClusterName, zone)
	if endpointID != nil {
		out.EndpointID = *endpointID
	}
	if enabled != nil && *enabled && vip != nil {
		out.Enabled, out.VIP = true, *vip
	} else {
		out.EnabledAt = nil
	}
	return out, nil
}

// GetAPIAccess reads one cluster's API access. Another organization's cluster is not found.
func (s *Service) GetAPIAccess(ctx context.Context, orgID, clusterID uuid.UUID) (APIAccess, error) {
	return loadAPIAccess(ctx, s.pool, orgID, clusterID)
}

// SetAPIAccess turns one cluster's API access on or off and writes the audit entry. Asking for the
// state it is already in changes nothing and writes nothing.
//
// On: one address is allocated from the cluster's range, around every exposed Service and the reserved
// DNS address. Off: the address is given back and the endpoint row is kept, so rules that name this API
// stay in place and compile to nothing.
func (s *Service) SetAPIAccess(ctx context.Context, orgID, clusterID uuid.UUID, enabled bool, actor *authctx.Principal) (APIAccess, error) {
	actorID, err := requireAPIAccessHuman(actor)
	if err != nil {
		return APIAccess{}, err
	}
	changed := false
	err = s.withTxRaw(ctx, func(q *sqlc.Queries, tx pgx.Tx) error {
		// The cluster row is the lock every address allocation in this cluster takes (ExposeService,
		// ExposeInventoryService, a namespace rule's pass). It is written, not only locked, so a
		// serializable allocation that started before this one fails on the row instead of allocating
		// from a snapshot that cannot see the API's address.
		var vipRange string
		var dnsVIP *string
		var poolBound bool
		if e := tx.QueryRow(ctx, `UPDATE k8s_clusters SET updated_at=now() WHERE id=$1 AND org_id=$2 RETURNING vip_range::text, host(dns_vip), connector_pool_id IS NOT NULL`, clusterID, orgID).
			Scan(&vipRange, &dnsVIP, &poolBound); errors.Is(e, pgx.ErrNoRows) {
			return apierr.NotFound("cluster_not_found", "no such cluster in this organization")
		} else if e != nil {
			return e
		}
		current, e := loadAPIAccess(ctx, tx, orgID, clusterID)
		if e != nil {
			return e
		}
		if current.Enabled == enabled {
			return nil
		}
		if !enabled {
			if _, e := tx.Exec(ctx, `UPDATE k8s_api_endpoints SET enabled=false, vip=NULL WHERE org_id=$1 AND cluster_id=$2`, orgID, clusterID); e != nil {
				return e
			}
			changed = true
			return s.audit(ctx, q, orgID, actorID, "", "", "k8s_cluster", clusterID.String(), "k8s.api_access_disabled",
				map[string]any{"cluster": current.ClusterName, "name": current.FQDN, "vip": current.VIP, "rules_kept": current.RuleCount})
		}
		if poolBound {
			// A connector pool's handoff plan is built from the exposed Services alone, so the API's
			// address would not follow a handoff. Refused rather than served by one member only.
			return apierr.Conflict("k8s_api_connector_pool_unsupported",
				"API access is not available yet for a cluster served by a connector pool: a handoff between pool members does not carry the API address")
		}
		if current.OrdinaryExposure {
			return apierr.Conflict("k8s_api_ordinary_exposure_exists",
				"default/kubernetes is already exposed as an ordinary Service in this cluster. Unexpose it first, then turn on API access: two addresses cannot answer to "+current.FQDN)
		}
		// The used-set: every live exposure and the reserved DNS address. (The API's own address is not
		// in it: this branch runs only while API access is off, when it has none.)
		used, e := q.ListUsedVIPsInCluster(ctx, sqlc.ListUsedVIPsInClusterParams{OrgID: orgID, ClusterID: clusterID})
		if e != nil {
			return e
		}
		if dnsVIP != nil {
			used = append(used, *dnsVIP)
		}
		vipStr, e := ipalloc.Allocate(vipRange, used)
		if errors.Is(e, ipalloc.ErrPoolExhausted) {
			return apierr.Conflict("vip_range_exhausted",
				"the cluster's address range "+vipRange+" is full; unexpose a Service you no longer need, or register the cluster again with a larger range, then turn on API access")
		}
		if e != nil {
			return e
		}
		vip, e := netip.ParseAddr(vipStr)
		if e != nil {
			return e
		}
		if _, e := tx.Exec(ctx, `
			INSERT INTO k8s_api_endpoints(org_id,cluster_id,enabled,vip,enabled_at,enabled_by_user_id)
			VALUES($1,$2,true,$3::inet,now(),$4)
			ON CONFLICT (cluster_id) DO UPDATE
			SET enabled=true, vip=EXCLUDED.vip, enabled_at=EXCLUDED.enabled_at, enabled_by_user_id=EXCLUDED.enabled_by_user_id`,
			orgID, clusterID, vip.String(), pgUUID(actorID, true)); e != nil {
			return e
		}
		changed = true
		return s.audit(ctx, q, orgID, actorID, "", "", "k8s_cluster", clusterID.String(), "k8s.api_access_enabled",
			map[string]any{"cluster": current.ClusterName, "name": current.FQDN, "vip": vip.String(), "port": APIServicePort,
				"rules_taking_effect": current.RuleCount})
	})
	if err != nil {
		return APIAccess{}, err
	}
	if changed {
		// The address and the rules that name it both changed for every gateway: push, do not wait.
		s.pushOrg(ctx, orgID)
	}
	return s.GetAPIAccess(ctx, orgID, clusterID)
}

// APIEndpointRef names one cluster API endpoint for a rule list or the access diagnostic.
type APIEndpointRef struct {
	EndpointID  uuid.UUID
	ClusterID   uuid.UUID
	ClusterName string
	Enabled     bool
	VIP         string
	FQDN        string
}

// APIEndpointsForOrg returns every cluster API endpoint of the organization, on or off.
func (s *Service) APIEndpointsForOrg(ctx context.Context, orgID uuid.UUID) ([]APIEndpointRef, error) {
	rows, err := s.q.ListK8sAPIEndpointsForOrg(ctx, orgID)
	if err != nil {
		return nil, err
	}
	out := make([]APIEndpointRef, 0, len(rows))
	for _, row := range rows {
		ref := APIEndpointRef{EndpointID: row.ID, ClusterID: row.ClusterID, ClusterName: row.ClusterName,
			FQDN: APIFQDN(row.ClusterName, row.DnsZone)}
		if row.Enabled && row.Vip != "" {
			ref.Enabled, ref.VIP = true, row.Vip
		}
		out = append(out, ref)
	}
	return out, nil
}

// APIDestination is a "Test access" destination recognised as a cluster's Kubernetes API.
type APIDestination struct {
	ClusterID   uuid.UUID
	ClusterName string
	FQDN        string
	Enabled     bool
	// VIP is the API's address; "" while API access is off.
	VIP string
	// ConnectorNodeID is the cluster's gateway, uuid.Nil when none is assigned (or the cluster is served
	// by a connector pool, where API access is not available).
	ConnectorNodeID uuid.UUID
}

// ResolveAPIDestination recognises a destination as a cluster's Kubernetes API: by the name the API has
// in the tunnel (whether or not API access is on, so "off" can be said plainly), or by the address of an
// API whose access is on. ok is false for anything else.
func (s *Service) ResolveAPIDestination(ctx context.Context, orgID uuid.UUID, destination string) (APIDestination, bool, error) {
	name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(destination)), ".")
	if name == "" {
		return APIDestination{}, false, nil
	}
	clusters, err := s.q.ListK8sClustersForOrg(ctx, orgID)
	if err != nil {
		return APIDestination{}, false, err
	}
	if len(clusters) == 0 {
		return APIDestination{}, false, nil
	}
	endpoints, err := s.APIEndpointsForOrg(ctx, orgID)
	if err != nil {
		return APIDestination{}, false, err
	}
	endpointOf := make(map[uuid.UUID]APIEndpointRef, len(endpoints))
	for _, endpoint := range endpoints {
		endpointOf[endpoint.ClusterID] = endpoint
	}
	address, addressErr := netip.ParseAddr(name)
	for _, cluster := range clusters {
		fqdn := APIFQDN(cluster.Name, cluster.DnsZone)
		endpoint := endpointOf[cluster.ID]
		byName := addressErr != nil && name == fqdn
		byAddress := false
		if addressErr == nil && endpoint.Enabled {
			if vip, e := netip.ParseAddr(endpoint.VIP); e == nil && vip == address.Unmap() {
				byAddress = true
			}
		}
		if !byName && !byAddress {
			continue
		}
		out := APIDestination{ClusterID: cluster.ID, ClusterName: cluster.Name, FQDN: fqdn, Enabled: endpoint.Enabled, VIP: endpoint.VIP}
		if cluster.ConnectorNodeID.Valid && !cluster.ConnectorPoolID.Valid {
			out.ConnectorNodeID = uuid.UUID(cluster.ConnectorNodeID.Bytes)
		}
		return out, true, nil
	}
	return APIDestination{}, false, nil
}
