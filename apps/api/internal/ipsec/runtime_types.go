package ipsec

import (
	"context"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
	"time"
)

// RuntimePrincipal must be derived from the authenticated agent certificate.
// Every operation repeats its current serial/status binding inside its transaction.
type RuntimePrincipal struct {
	OrgID, NodeID     uuid.UUID
	CertificateSerial string
}
type RuntimePolicyInput struct {
	OrgID, NodeID, SiteID, ConnectionID uuid.UUID
	Config                              StaticConfig
	// Supplied only by the locked runtime transaction, never agent input.
	ConfigurationRevision int64     `json:"-"`
	FQDNPolicyVersion     int       `json:"-"`
	Transaction           sqlc.DBTX `json:"-"`
}
type RuntimeGrant struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Protocol    string `json:"protocol"`
	PortLow     uint16 `json:"port_low"`
	PortHigh    uint16 `json:"port_high"`
	RuleID      string `json:"rule_id"`
}

// RuntimeFQDNGrant preserves answer provenance independently of ordinary grants.
// A capability-1 receiver must retain this ownership when rendering and withdrawing.
type RuntimeFQDNGrant struct {
	RuntimeGrant
	FQDNManaged           bool   `json:"fqdn_managed"`
	ResourceID            string `json:"resource_id"`
	Name                  string `json:"name"`
	Generation            string `json:"generation"`
	ResolverConfigID      string `json:"resolver_config_id"`
	ResolverConfigVersion int64  `json:"resolver_config_version"`
	SelectedSiteID        string `json:"selected_site_id"`
	SelectedGatewayID     string `json:"selected_gateway_id"`
	ResolverProfileID     string `json:"resolver_profile_id"`
	ResolverMatchSuffix   string `json:"resolver_match_suffix"`
	ConnectionID          string `json:"connection_id"`
	ConfigurationRevision int64  `json:"configuration_revision"`
}

type RuntimeDNSResolverGrant struct {
	ContextConfigID       string `json:"context_config_id"`
	ContextConfigVersion  int64  `json:"context_config_version"`
	ProfileID             string `json:"profile_id"`
	ConnectionID          string `json:"connection_id"`
	ConfigurationRevision int64  `json:"configuration_revision"`
	SourceAddress         string `json:"source_address"`
	ResolverAddress       string `json:"resolver_address"`
}
type RuntimePolicy struct {
	// Selected answer expiry is server-only authority, excluded from wire/hash.
	FQDNValidUntil      time.Time                       `json:"-"`
	FQDNPolicyVersion   int                             `json:"fqdn_policy_version,omitempty"`
	FQDNGrants          []RuntimeFQDNGrant              `json:"fqdn_grants,omitempty"`
	DNSResolverGrants   []RuntimeDNSResolverGrant       `json:"dns_resolver_grants,omitempty"`
	DNSResolverProfiles []policyspec.DNSResolverProfile `json:"dns_resolver_profiles,omitempty"`
	Hash                string                          `json:"hash"`
	Grants              []RuntimeGrant                  `json:"grants"`
}
type RuntimePolicyCompiler func(context.Context, *sqlc.Queries, RuntimePolicyInput) (RuntimePolicy, error)

type RuntimeTunnel struct {
	ID                    uuid.UUID `json:"id"`
	Slot                  int       `json:"slot"`
	SecretRevision        int64     `json:"secret_revision"`
	LinkName              string    `json:"link_name"`
	XFRMID                uint32    `json:"xfrm_id"`
	ReqID                 uint32    `json:"reqid"`
	OutsideAddress        string    `json:"outside_address"`
	InsideCIDR            string    `json:"inside_cidr"`
	CustomerInsideAddress string    `json:"customer_inside_address"`
	CloudInsideAddress    string    `json:"cloud_inside_address"`
	RouteTable            uint32    `json:"route_table"`
	RouteProtocol         uint8     `json:"route_protocol"`
	RouteMetric           uint32    `json:"route_metric"`
	Selected              bool      `json:"selected"`
}

// RuntimeManifest contains CP-owned stable intent, never observed namespace or
// interface indices, credentials, dynamic policy authority or daemon output.
type RuntimeManifest struct {
	OrgID                  uuid.UUID        `json:"org_id"`
	NodeID                 uuid.UUID        `json:"node_id"`
	SiteID                 uuid.UUID        `json:"site_id"`
	ConnectionID           uuid.UUID        `json:"connection_id"`
	DesiredRevision        int64            `json:"desired_revision"`
	ConfigurationRevision  int64            `json:"configuration_revision"`
	ProfileID              string           `json:"profile_id"`
	CustomerOutsideAddress string           `json:"customer_outside_address"`
	LocalPrefixes          []string         `json:"local_prefixes"`
	RemotePrefixes         []string         `json:"remote_prefixes"`
	Tunnels                [2]RuntimeTunnel `json:"tunnels"`
	// RecoveryVersion is explicit delivery authorization; nil preserves the legacy digest.
	TransportVersion          *int                              `json:"transport_version,omitempty"`
	TunnelCount               *int                              `json:"tunnel_count,omitempty"`
	RecoveryVersion           *int                              `json:"recovery_version,omitempty"`
	BGP                       *BGPConfig                        `json:"bgp,omitempty"`
	BGPVersion                *int                              `json:"bgp_version,omitempty"`
	RetainedGuardPredecessors []RuntimeRetainedGuardPredecessor `json:"retained_guard_predecessors,omitempty"`
}

// RuntimeRetainedGuardPredecessor names one immutable, finalized cleanup lineage.
// Its ownership digest belongs to the predecessor apply delivery.
type RuntimeRetainedGuardPredecessor struct {
	ConnectionID      uuid.UUID `json:"connection_id"`
	DeliveryID        uuid.UUID `json:"delivery_id"`
	CleanupDeliveryID uuid.UUID `json:"cleanup_delivery_id"`
	OwnershipDigest   string    `json:"ownership_digest"`
}

type RuntimeDelivery struct {
	ID                     uuid.UUID       `json:"delivery_id"`
	DesiredRevision        int64           `json:"desired_revision"`
	Kind                   string          `json:"kind"`
	OwnershipDigest        string          `json:"ownership_digest"`
	CoversDeliveryRevision int64           `json:"covers_delivery_revision,omitempty"`
	Manifest               RuntimeManifest `json:"manifest"`
}
type RuntimeSecret struct {
	TunnelID uuid.UUID `json:"tunnel_id"`
	Revision int64     `json:"revision"`
	PSK      string    `json:"psk"`
}

// RuntimeMaterial is the sole secret-bearing response, only for the exact agent
// after its delivery transaction commits. Never log or use in human projections.
type RuntimeMaterial struct {
	RuntimeDelivery
	Policy  RuntimePolicy    `json:"policy"`
	Secrets [2]RuntimeSecret `json:"secrets"`
}
type RuntimeCleanup struct {
	RuntimeDelivery
	RetainGuard bool              `json:"retain_guard"`
	Lineage     []RuntimeDelivery `json:"lineage"`
}
type RuntimePending struct {
	ConnectionID    uuid.UUID `json:"connection_id"`
	DesiredRevision int64     `json:"desired_revision"`
	Kind            string    `json:"kind"`
}
type RuntimePendingPage struct {
	IPsecEnabled bool             `json:"ipsec_enabled"`
	OrgID        uuid.UUID        `json:"org_id"`
	NodeID       uuid.UUID        `json:"node_id"`
	Items        []RuntimePending `json:"items"`
	NextCursor   *uuid.UUID       `json:"next_cursor,omitempty"`
}
type RuntimeAcknowledgement struct {
	DeliveryID      uuid.UUID `json:"delivery_id"`
	DesiredRevision int64     `json:"desired_revision"`
	Kind            string    `json:"kind"`
	Result          string    `json:"result"`
	OwnershipDigest string    `json:"ownership_digest"`
	// Cleanup attests exact lineage removed except the mandatory retained denial.
	GuardRetained bool `json:"guard_retained"`
}
type RuntimeLeaseRequest struct {
	DeliveryID      uuid.UUID `json:"delivery_id"`
	DesiredRevision int64     `json:"desired_revision"`
	PolicyHash      string    `json:"policy_hash"`
	Nonce           string    `json:"nonce"`
}
type RuntimeLease struct {
	RuntimeLeaseRequest
	TTLMS int64 `json:"ttl_ms"`
}
