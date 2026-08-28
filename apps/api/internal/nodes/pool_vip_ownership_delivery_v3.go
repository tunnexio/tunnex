package nodes

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
)

// PoolVIPOwnershipDeliveryHandoffVersion is the first ownership wire version
// that carries enough CP-issued state to authorize a handoff. Versions 1 and 2
// remain decodable by their existing paths, but are never handoff authority.
const PoolVIPOwnershipDeliveryHandoffVersion = 3

const poolVIPOwnershipDeliveryV3JSONLimit = 16 << 10

// PoolVIPOwnershipCapabilityAuthorizesHandoff deliberately compares the raw
// capability token. Values such as "03", lists, older, or future versions are
// not accepted optimistically.
func PoolVIPOwnershipCapabilityAuthorizesHandoff(capability string) bool {
	return capability == "3"
}

// PoolVIPOwnershipManifestV3 is the complete canonical wire payload. It has an
// explicit JSON shape rather than relying on Go field-name encoding.
type PoolVIPOwnershipManifestV3 struct {
	Version             int                         `json:"version"`
	OrgID               string                      `json:"org_id"`
	SiteID              string                      `json:"site_id"`
	ClusterID           string                      `json:"cluster_id"`
	PoolID              string                      `json:"pool_id"`
	ConnectorNodeID     string                      `json:"connector_node_id"`
	Role                string                      `json:"role"`
	PromotionGeneration uint64                      `json:"promotion_generation"`
	ManifestRevision    uint64                      `json:"manifest_revision"`
	LeaseEpoch          uint64                      `json:"lease_epoch"`
	LeaseExpiresAt      time.Time                   `json:"lease_expires_at"`
	DNSZone             string                      `json:"dns_zone"`
	DNSVIP              string                      `json:"dns_vip"`
	HandoffOwnerID      string                      `json:"handoff_owner_id"`
	RouteIntent         string                      `json:"route_intent"`
	WGPeers             []PoolVIPOwnershipWGPeerV3  `json:"wg_peers"`
	Routes              []string                    `json:"routes"`
	Services            []PoolVIPOwnershipServiceV3 `json:"services"`
}

type PoolVIPOwnershipWGPeerV3 struct {
	PublicKey  string   `json:"public_key"`
	AllowedIPs []string `json:"allowed_ips"`
}

type PoolVIPOwnershipServiceV3 struct {
	ServiceID   string `json:"service_id"`
	VIP         string `json:"vip"`
	Namespace   string `json:"namespace"`
	Service     string `json:"service"`
	ServiceCIDR string `json:"service_cidr"`
	DNSName     string `json:"dns_name"`
	Protocol    string `json:"protocol"`
	Port        int    `json:"port"`
}

// PoolVIPOwnershipDeliveryEnvelopeV3 binds the complete manifest to the
// authenticated delivery scope and to CP-owned expiry. The expected digests
// remain explicit so downstream handoff state can compare without projecting
// raw routes or Services.
type PoolVIPOwnershipDeliveryEnvelopeV3 struct {
	PoolVIPOwnershipDeliveryEnvelope
	ExpiresAt            time.Time                  `json:"expires_at"`
	Manifest             PoolVIPOwnershipManifestV3 `json:"manifest"`
	ExpectedRouteDigest  string                     `json:"expected_route_digest"`
	ExpectedVIPMapDigest string                     `json:"expected_vip_map_digest"`
	PriorLeaseEpoch      uint64                     `json:"prior_lease_epoch,omitempty"`
}

// PoolVIPOwnershipDeliveryAckV3 echoes the immutable delivery and returns the
// full applied readback. CP validates its canonical identity and expiry rather
// than accepting a desired-state digest copied from the request.
type PoolVIPOwnershipDeliveryAckV3 struct {
	PoolVIPOwnershipDeliveryAck
	AppliedManifest   PoolVIPOwnershipManifestV3 `json:"applied_manifest"`
	AppliedLeaseEpoch uint64                     `json:"applied_lease_epoch"`
}

// PoolVIPOwnershipDeliveryHandoffStore is intentionally separate from the
// v1/v2 stores so capability 3 cannot fall through to an older loader.
type PoolVIPOwnershipDeliveryHandoffStore interface {
	LoadIssuedPoolVIPOwnershipDeliveryV3(context.Context, PoolVIPOwnershipAgentIdentity) (PoolVIPOwnershipDeliveryEnvelopeV3, bool, error)
	UpdatePoolVIPOwnershipAckV3(context.Context, PoolVIPOwnershipAgentIdentity, PoolVIPOwnershipDeliveryAckV3, time.Time, func(PoolVIPOwnershipDeliveryEnvelopeV3, PoolVIPOwnershipAckState) (PoolVIPOwnershipAckValidation, error)) (PoolVIPOwnershipAckValidation, error)
}

func ValidatePoolVIPOwnershipDeliveryEnvelopeV3(envelope PoolVIPOwnershipDeliveryEnvelopeV3) error {
	base := envelope.PoolVIPOwnershipDeliveryEnvelope
	if base.Version != PoolVIPOwnershipDeliveryHandoffVersion {
		return fmt.Errorf("unsupported ownership handoff version")
	}
	base.Version = PoolVIPOwnershipDeliveryVersion
	if err := ValidatePoolVIPOwnershipDeliveryEnvelope(base); err != nil {
		return err
	}
	if !PoolVIPOwnershipCapabilityAuthorizesHandoff(fmt.Sprint(envelope.Version)) {
		return fmt.Errorf("ownership delivery does not authorize handoff")
	}
	manifest := envelope.Manifest.policyManifest()
	identity, err := policyspec.PoolVIPOwnershipManifestIdentity(manifest)
	if err != nil {
		return fmt.Errorf("invalid ownership handoff manifest: %w", err)
	}
	if identity != envelope.ManifestIdentity || envelope.ExpiresAt.IsZero() || envelope.ExpiresAt.Location() != time.UTC ||
		!envelope.ExpiresAt.Equal(manifest.LeaseExpiresAt) || manifest.OrgID != envelope.OrgID || manifest.SiteID != envelope.SiteID ||
		manifest.ClusterID != envelope.ClusterID || manifest.PoolID != envelope.PoolID || manifest.ConnectorNodeID != envelope.ConnectorNodeID ||
		manifest.HandoffOwnerID != envelope.OperationID || manifest.Role != envelope.Role ||
		manifest.PromotionGeneration != envelope.PromotionGeneration || manifest.ManifestRevision != envelope.ManifestRevision ||
		manifest.LeaseEpoch != envelope.LeaseEpoch {
		return fmt.Errorf("ownership handoff manifest does not exactly match delivery")
	}
	routeDigest, err := PoolVIPOwnershipOwnedRouteDigest(manifest.Routes)
	if err != nil || routeDigest != envelope.ExpectedRouteDigest {
		return fmt.Errorf("ownership handoff route payload does not match digest")
	}
	vipDigest := poolVIPOwnershipManifestVIPMapDigest(manifest)
	if vipDigest != envelope.ExpectedVIPMapDigest {
		return fmt.Errorf("ownership handoff VIP payload does not match digest")
	}
	switch manifest.Role {
	case policyspec.PoolVIPOwnershipServing:
		if envelope.PriorLeaseEpoch != 0 || len(manifest.WGPeers) == 0 || len(manifest.Routes) == 0 || len(manifest.Services) == 0 || vipDigest == "" {
			return fmt.Errorf("serving handoff requires complete WG, route, VIP, and DNS payload")
		}
	case policyspec.PoolVIPOwnershipPreparedNonServing:
		if envelope.PriorLeaseEpoch != 0 || len(manifest.Services) != 0 || envelope.ExpectedVIPMapDigest != "" {
			return fmt.Errorf("prepared handoff must carry no VIP ownership")
		}
	case policyspec.PoolVIPOwnershipWithdrawal:
		if envelope.PriorLeaseEpoch == 0 || envelope.PriorLeaseEpoch >= envelope.LeaseEpoch || len(manifest.Services) != 0 || envelope.ExpectedVIPMapDigest != "" {
			return fmt.Errorf("withdrawal handoff must bind a prior lease and no VIP ownership")
		}
	}
	b, err := json.Marshal(envelope)
	if err != nil || len(b) > poolVIPOwnershipDeliveryV3JSONLimit {
		return fmt.Errorf("ownership handoff frame exceeds protocol limit")
	}
	return nil
}

func ValidatePoolVIPOwnershipDeliveryAckV3(receiptTime time.Time, agent PoolVIPOwnershipAgentIdentity, envelope PoolVIPOwnershipDeliveryEnvelopeV3, ack PoolVIPOwnershipDeliveryAckV3, state PoolVIPOwnershipAckState) (PoolVIPOwnershipAckValidation, error) {
	if receiptTime.IsZero() || !receiptTime.UTC().Before(envelope.ExpiresAt) {
		return PoolVIPOwnershipAckValidation{}, fmt.Errorf("ownership handoff acknowledgement is absent or expired")
	}
	if err := ValidatePoolVIPOwnershipDeliveryEnvelopeV3(envelope); err != nil {
		return PoolVIPOwnershipAckValidation{}, err
	}
	if agent.NodeID == uuid.Nil || agent.OrgID == uuid.Nil || envelope.TargetNodeID != agent.NodeID.String() || envelope.OrgID != agent.OrgID.String() {
		return PoolVIPOwnershipAckValidation{}, fmt.Errorf("authenticated agent does not own delivery scope")
	}
	if err := validPoolVIPOwnershipAckV3Echo(envelope, ack); err != nil {
		return PoolVIPOwnershipAckValidation{}, err
	}
	appliedIdentity, err := policyspec.PoolVIPOwnershipManifestIdentity(ack.AppliedManifest.policyManifest())
	if err != nil || appliedIdentity != envelope.ManifestIdentity || !ack.AppliedManifest.LeaseExpiresAt.Equal(envelope.ExpiresAt) {
		return PoolVIPOwnershipAckValidation{}, fmt.Errorf("applied ownership manifest does not exactly match delivery")
	}
	wantLease := envelope.LeaseEpoch
	if envelope.Role == policyspec.PoolVIPOwnershipWithdrawal {
		wantLease = envelope.PriorLeaseEpoch
	}
	if ack.AppliedLeaseEpoch != wantLease {
		return PoolVIPOwnershipAckValidation{}, fmt.Errorf("applied ownership lease epoch does not match delivery")
	}
	scopeIdentity, err := poolVIPOwnershipDeliveryScopeIdentityV3(envelope)
	if err != nil {
		return PoolVIPOwnershipAckValidation{}, err
	}
	if state.ScopeIdentity != "" && state.ScopeIdentity != scopeIdentity {
		return PoolVIPOwnershipAckValidation{}, fmt.Errorf("acknowledgement state belongs to another delivery scope")
	}
	fingerprint, err := poolVIPOwnershipAckV3Fingerprint(ack)
	if err != nil {
		return PoolVIPOwnershipAckValidation{}, err
	}
	if prior, ok := state.Seen[ack.DeliveryID]; ok {
		if prior.Fingerprint != fingerprint {
			return PoolVIPOwnershipAckValidation{}, fmt.Errorf("delivery ID replayed with different acknowledgement")
		}
		return PoolVIPOwnershipAckValidation{Duplicate: true, ReceiptTime: prior.ReceiptTime, NextState: clonePoolVIPOwnershipAckState(state)}, nil
	}
	if envelope.ManifestRevision <= state.ManifestRevision || envelope.LeaseEpoch < state.LeaseEpoch || envelope.PromotionGeneration < state.PromotionGeneration {
		return PoolVIPOwnershipAckValidation{}, fmt.Errorf("stale promotion generation, manifest revision, or lease epoch")
	}
	next := clonePoolVIPOwnershipAckState(state)
	if next.Seen == nil {
		next.Seen = make(map[string]PoolVIPOwnershipAckReceipt)
	}
	next.ScopeIdentity, next.PromotionGeneration, next.ManifestRevision, next.LeaseEpoch = scopeIdentity, envelope.PromotionGeneration, envelope.ManifestRevision, envelope.LeaseEpoch
	next.Seen[envelope.DeliveryID] = PoolVIPOwnershipAckReceipt{Fingerprint: fingerprint, ReceiptTime: receiptTime.UTC()}
	return PoolVIPOwnershipAckValidation{ReceiptTime: receiptTime.UTC(), NextState: next}, nil
}

func validPoolVIPOwnershipAckV3Echo(envelope PoolVIPOwnershipDeliveryEnvelopeV3, ack PoolVIPOwnershipDeliveryAckV3) error {
	base := ack.PoolVIPOwnershipDeliveryAck
	if base.Version != envelope.Version || base.OrgID != envelope.OrgID || base.SiteID != envelope.SiteID || base.ClusterID != envelope.ClusterID ||
		base.PoolID != envelope.PoolID || base.ConnectorNodeID != envelope.ConnectorNodeID || base.TargetNodeID != envelope.TargetNodeID ||
		base.OperationID != envelope.OperationID || base.ManifestIdentity != envelope.ManifestIdentity || base.Role != envelope.Role ||
		base.PromotionGeneration != envelope.PromotionGeneration || base.ManifestRevision != envelope.ManifestRevision || base.LeaseEpoch != envelope.LeaseEpoch ||
		base.DeliveryPhase != envelope.DeliveryPhase || base.DeliveryID != envelope.DeliveryID || base.DeliveryNonce != envelope.DeliveryNonce {
		return fmt.Errorf("handoff acknowledgement does not exactly match delivery")
	}
	return nil
}

func (m PoolVIPOwnershipManifestV3) policyManifest() policyspec.PoolVIPOwnershipManifest {
	peers := make([]policyspec.PoolVIPOwnershipWGPeer, len(m.WGPeers))
	for i, peer := range m.WGPeers {
		peers[i] = policyspec.PoolVIPOwnershipWGPeer{PublicKey: peer.PublicKey, AllowedIPs: append([]string(nil), peer.AllowedIPs...)}
	}
	services := make([]policyspec.PoolVIPOwnershipService, len(m.Services))
	for i, service := range m.Services {
		services[i] = policyspec.PoolVIPOwnershipService{ServiceID: service.ServiceID, VIP: service.VIP, Namespace: service.Namespace, Service: service.Service, ServiceCIDR: service.ServiceCIDR, DNSName: service.DNSName, Protocol: service.Protocol, Port: service.Port}
	}
	return policyspec.PoolVIPOwnershipManifest{Version: m.Version, OrgID: m.OrgID, SiteID: m.SiteID, ClusterID: m.ClusterID, PoolID: m.PoolID,
		ConnectorNodeID: m.ConnectorNodeID, Role: m.Role, PromotionGeneration: m.PromotionGeneration, ManifestRevision: m.ManifestRevision,
		LeaseEpoch: m.LeaseEpoch, LeaseExpiresAt: m.LeaseExpiresAt, DNSZone: m.DNSZone, DNSVIP: m.DNSVIP, HandoffOwnerID: m.HandoffOwnerID,
		RouteIntent: m.RouteIntent, WGPeers: peers, Routes: append([]string(nil), m.Routes...), Services: services}
}

func poolVIPOwnershipManifestVIPMapDigest(manifest policyspec.PoolVIPOwnershipManifest) string {
	mappings := make([]policyspec.VIPMapping, len(manifest.Services))
	for i, service := range manifest.Services {
		mappings[i] = policyspec.VIPMapping{ServiceID: service.ServiceID, VIP: service.VIP, Namespace: service.Namespace, Service: service.Service,
			ServiceCIDR: service.ServiceCIDR, DNSName: service.DNSName, Protocol: service.Protocol, PortLow: service.Port, PortHigh: service.Port}
	}
	return policyspec.VIPMapDigest(mappings)
}

func poolVIPOwnershipDeliveryScopeIdentityV3(envelope PoolVIPOwnershipDeliveryEnvelopeV3) (string, error) {
	base := envelope.PoolVIPOwnershipDeliveryEnvelope
	base.Version = PoolVIPOwnershipDeliveryVersion
	return PoolVIPOwnershipDeliveryScopeIdentity(base)
}

func poolVIPOwnershipAckV3Fingerprint(ack PoolVIPOwnershipDeliveryAckV3) (string, error) {
	v := ack
	v.AgentObservedAt = time.Time{}
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
