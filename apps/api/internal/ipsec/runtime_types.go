package ipsec

import (
	"context"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
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
}
type RuntimeGrant struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Protocol    string `json:"protocol"`
	PortLow     uint16 `json:"port_low"`
	PortHigh    uint16 `json:"port_high"`
	RuleID      string `json:"rule_id"`
}
type RuntimePolicy struct {
	Hash   string         `json:"hash"`
	Grants []RuntimeGrant `json:"grants"`
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
