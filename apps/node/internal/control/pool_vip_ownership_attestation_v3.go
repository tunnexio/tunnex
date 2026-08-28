package control

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
)

// PoolVIPOwnershipDeliveryHandoffVersion is the first complete handoff wire
// contract. v1 receipt and v2 digest attestation remain supported by their
// existing explicit methods but cannot authorize ownership handoff.
const PoolVIPOwnershipDeliveryHandoffVersion = 3

func PoolVIPOwnershipCapabilityAuthorizesHandoff(capability string) bool {
	return capability == "3"
}

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

type PoolVIPOwnershipDeliveryEnvelopeV3 struct {
	PoolVIPOwnershipDeliveryEnvelope
	ExpiresAt            time.Time                  `json:"expires_at"`
	Manifest             PoolVIPOwnershipManifestV3 `json:"manifest"`
	ExpectedRouteDigest  string                     `json:"expected_route_digest"`
	ExpectedVIPMapDigest string                     `json:"expected_vip_map_digest"`
	PriorLeaseEpoch      uint64                     `json:"prior_lease_epoch,omitempty"`
}

type PoolVIPOwnershipDeliveryAckV3 struct {
	PoolVIPOwnershipDeliveryAck
	AppliedManifest   PoolVIPOwnershipManifestV3 `json:"applied_manifest"`
	AppliedLeaseEpoch uint64                     `json:"applied_lease_epoch"`
}

type PoolVIPOwnershipApplyReadbackV3 interface {
	ApplyPoolVIPOwnershipV3(context.Context, PoolVIPOwnershipDeliveryEnvelopeV3) error
	ReadPoolVIPOwnershipV3(context.Context, PoolVIPOwnershipDeliveryEnvelopeV3) (PoolVIPOwnershipManifestV3, error)
}

type PoolVIPOwnershipAttestorV3 struct {
	apply PoolVIPOwnershipApplyReadbackV3
	state PoolVIPOwnershipAppliedStateStore
	now   func() time.Time
}

func NewPoolVIPOwnershipAttestorV3(apply PoolVIPOwnershipApplyReadbackV3, state PoolVIPOwnershipAppliedStateStore) *PoolVIPOwnershipAttestorV3 {
	return &PoolVIPOwnershipAttestorV3{apply: apply, state: state, now: time.Now}
}

func (a *PoolVIPOwnershipAttestorV3) PreparePoolVIPOwnershipDeliveryAckV3(ctx context.Context, envelope PoolVIPOwnershipDeliveryEnvelopeV3) (PoolVIPOwnershipDeliveryAckV3, error) {
	if a == nil || a.apply == nil || a.state == nil || a.now == nil {
		return PoolVIPOwnershipDeliveryAckV3{}, fmt.Errorf("ownership v3 attestor is not configured")
	}
	if err := ValidatePoolVIPOwnershipDeliveryEnvelopeV3(envelope); err != nil {
		return PoolVIPOwnershipDeliveryAckV3{}, err
	}
	if !a.now().UTC().Before(envelope.ExpiresAt) {
		return PoolVIPOwnershipDeliveryAckV3{}, fmt.Errorf("ownership lease expired before apply")
	}
	scope := poolVIPOwnershipAttestationScopeV3(envelope)
	fingerprint, err := poolVIPOwnershipAttestationFingerprintV3(envelope)
	if err != nil {
		return PoolVIPOwnershipDeliveryAckV3{}, err
	}
	var ack PoolVIPOwnershipDeliveryAckV3
	err = a.state.TransitionPoolVIPOwnershipAppliedState(ctx, scope, func(prior PoolVIPOwnershipAppliedState, found bool) (PoolVIPOwnershipAppliedState, bool, error) {
		if found {
			if !validPoolVIPOwnershipStoredAttestation(prior, scope) {
				return PoolVIPOwnershipAppliedState{}, false, fmt.Errorf("stored ownership attestation scope is invalid")
			}
			if prior.DeliveryID == envelope.DeliveryID {
				if prior.WireVersion != PoolVIPOwnershipDeliveryHandoffVersion || prior.Fingerprint != fingerprint || prior.LeaseExpiresAt == nil ||
					!prior.LeaseExpiresAt.Equal(envelope.ExpiresAt) || prior.AppliedManifest == nil {
					return PoolVIPOwnershipAppliedState{}, false, fmt.Errorf("delivery ID replayed with different v3 applied state")
				}
				actual, err := a.apply.ReadPoolVIPOwnershipV3(ctx, envelope)
				if err != nil || validatePoolVIPOwnershipAppliedManifestV3(envelope, actual) != nil || !a.now().UTC().Before(envelope.ExpiresAt) {
					return PoolVIPOwnershipAppliedState{}, false, fmt.Errorf("v3 ownership readback or lease is invalid")
				}
				ack = poolVIPOwnershipDeliveryAckV3(envelope, actual, a.now().UTC())
				return prior, false, nil
			}
			if envelope.PromotionGeneration < prior.Readback.PromotionGeneration || envelope.ManifestRevision <= prior.Readback.ManifestRevision || envelope.LeaseEpoch < prior.Readback.LeaseEpoch {
				return PoolVIPOwnershipAppliedState{}, false, fmt.Errorf("stale ownership promotion generation, manifest revision, or lease epoch")
			}
		}
		if err := a.apply.ApplyPoolVIPOwnershipV3(ctx, envelope); err != nil {
			return PoolVIPOwnershipAppliedState{}, false, fmt.Errorf("apply ownership v3 delivery: %w", err)
		}
		actual, err := a.apply.ReadPoolVIPOwnershipV3(ctx, envelope)
		if err != nil {
			return PoolVIPOwnershipAppliedState{}, false, fmt.Errorf("read back ownership v3 delivery: %w", err)
		}
		if err := validatePoolVIPOwnershipAppliedManifestV3(envelope, actual); err != nil {
			return PoolVIPOwnershipAppliedState{}, false, err
		}
		observed := a.now().UTC()
		if !observed.Before(envelope.ExpiresAt) {
			return PoolVIPOwnershipAppliedState{}, false, fmt.Errorf("ownership lease expired during apply")
		}
		ack = poolVIPOwnershipDeliveryAckV3(envelope, actual, observed)
		applied := actual
		expiresAt := envelope.ExpiresAt
		return PoolVIPOwnershipAppliedState{Scope: scope, DeliveryID: envelope.DeliveryID, Fingerprint: fingerprint,
			Readback: poolVIPOwnershipReadbackV3(envelope, actual), WireVersion: PoolVIPOwnershipDeliveryHandoffVersion,
			LeaseExpiresAt: &expiresAt, AppliedManifest: &applied}, true, nil
	})
	if err != nil {
		return PoolVIPOwnershipDeliveryAckV3{}, err
	}
	return ack, nil
}

// PollPoolVIPOwnershipDeliveryV3 is the compatibility wrapper used by tests
// and direct callers. Production splits fetch/apply/ACK so transport waits do
// not block the serialized data-plane command lane.
func (c *Client) PollPoolVIPOwnershipDeliveryV3(ctx context.Context, attestor *PoolVIPOwnershipAttestorV3) (bool, error) {
	envelope, found, err := c.FetchPoolVIPOwnershipDeliveryV3(ctx)
	if err != nil || !found {
		return false, err
	}
	ack, err := attestor.PreparePoolVIPOwnershipDeliveryAckV3(ctx, envelope)
	if err != nil {
		return false, err
	}
	if err := c.AcknowledgePoolVIPOwnershipDeliveryV3(ctx, ack); err != nil {
		return false, err
	}
	return true, nil
}

// FetchPoolVIPOwnershipDeliveryV3 performs only authenticated transport I/O.
// It is safe to run outside the data-plane command lane; no local ownership
// state is read or changed until the attestor is invoked on that lane.
func (c *Client) FetchPoolVIPOwnershipDeliveryV3(ctx context.Context) (PoolVIPOwnershipDeliveryEnvelopeV3, bool, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/agent/pool-vip-ownership-delivery", nil)
	req.Header.Set(poolVIPOwnershipDeliveryCapabilityHeader, "3")
	resp, err := c.http.Do(req)
	if err != nil {
		return PoolVIPOwnershipDeliveryEnvelopeV3{}, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return PoolVIPOwnershipDeliveryEnvelopeV3{}, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return PoolVIPOwnershipDeliveryEnvelopeV3{}, false, fmt.Errorf("ownership delivery status %d", resp.StatusCode)
	}
	var envelope PoolVIPOwnershipDeliveryEnvelopeV3
	if err := decodePoolVIPOwnershipDeliveryJSON(resp.Body, &envelope); err != nil {
		return PoolVIPOwnershipDeliveryEnvelopeV3{}, false, fmt.Errorf("decode ownership delivery: %w", err)
	}
	return envelope, true, nil
}

// AcknowledgePoolVIPOwnershipDeliveryV3 posts a previously persisted exact
// applied-state proof. Transport retry is outside the mutation lane.
func (c *Client) AcknowledgePoolVIPOwnershipDeliveryV3(ctx context.Context, ack PoolVIPOwnershipDeliveryAckV3) error {
	body, err := json.Marshal(ack)
	if err != nil {
		return err
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/agent/pool-vip-ownership-delivery/ack", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(poolVIPOwnershipDeliveryCapabilityHeader, "3")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("ownership delivery acknowledgement status %d", resp.StatusCode)
	}
	return nil
}

func ValidatePoolVIPOwnershipDeliveryEnvelopeV3(envelope PoolVIPOwnershipDeliveryEnvelopeV3) error {
	base := envelope.PoolVIPOwnershipDeliveryEnvelope
	if base.Version != PoolVIPOwnershipDeliveryHandoffVersion || !PoolVIPOwnershipCapabilityAuthorizesHandoff(fmt.Sprint(base.Version)) {
		return fmt.Errorf("unsupported ownership handoff version")
	}
	base.Version = PoolVIPOwnershipDeliveryVersion
	if err := validPoolVIPOwnershipDeliveryEnvelope(base); err != nil {
		return err
	}
	manifest := envelope.Manifest.policyManifest()
	identity, err := nodepolicy.PoolVIPOwnershipManifestIdentity(manifest)
	if err != nil {
		return err
	}
	if identity != envelope.ManifestIdentity || envelope.ExpiresAt.IsZero() || envelope.ExpiresAt.Location() != time.UTC || !envelope.ExpiresAt.Equal(manifest.LeaseExpiresAt) ||
		manifest.OrgID != envelope.OrgID || manifest.SiteID != envelope.SiteID || manifest.ClusterID != envelope.ClusterID || manifest.PoolID != envelope.PoolID ||
		manifest.ConnectorNodeID != envelope.ConnectorNodeID || manifest.HandoffOwnerID != envelope.OperationID || manifest.Role != envelope.Role ||
		manifest.PromotionGeneration != envelope.PromotionGeneration || manifest.ManifestRevision != envelope.ManifestRevision || manifest.LeaseEpoch != envelope.LeaseEpoch {
		return fmt.Errorf("ownership handoff manifest does not exactly match delivery")
	}
	routeDigest, err := PoolVIPOwnershipOwnedRouteDigest(manifest.Routes)
	if err != nil || routeDigest != envelope.ExpectedRouteDigest || poolVIPOwnershipManifestVIPMapDigestV3(manifest) != envelope.ExpectedVIPMapDigest {
		return fmt.Errorf("ownership handoff dataplane payload does not match digest")
	}
	switch manifest.Role {
	case nodepolicy.PoolVIPOwnershipServing:
		if envelope.PriorLeaseEpoch != 0 || len(manifest.WGPeers) == 0 || len(manifest.Routes) == 0 || len(manifest.Services) == 0 || envelope.ExpectedVIPMapDigest == "" {
			return fmt.Errorf("serving handoff requires complete WG, route, VIP, and DNS payload")
		}
	case nodepolicy.PoolVIPOwnershipPreparedNonServing:
		if envelope.PriorLeaseEpoch != 0 || len(manifest.Services) != 0 || envelope.ExpectedVIPMapDigest != "" {
			return fmt.Errorf("prepared handoff must carry no VIP ownership")
		}
	case nodepolicy.PoolVIPOwnershipWithdrawal:
		if envelope.PriorLeaseEpoch == 0 || envelope.PriorLeaseEpoch >= envelope.LeaseEpoch || len(manifest.Services) != 0 || envelope.ExpectedVIPMapDigest != "" {
			return fmt.Errorf("withdrawal handoff must bind prior lease and no VIP ownership")
		}
	}
	return nil
}

func ValidatePoolVIPOwnershipDeliveryAckV3(envelope PoolVIPOwnershipDeliveryEnvelopeV3, ack PoolVIPOwnershipDeliveryAckV3) error {
	if err := ValidatePoolVIPOwnershipDeliveryEnvelopeV3(envelope); err != nil {
		return err
	}
	base := ack.PoolVIPOwnershipDeliveryAck
	if base.Version != envelope.Version || base.OrgID != envelope.OrgID || base.SiteID != envelope.SiteID || base.ClusterID != envelope.ClusterID || base.PoolID != envelope.PoolID ||
		base.ConnectorNodeID != envelope.ConnectorNodeID || base.TargetNodeID != envelope.TargetNodeID || base.OperationID != envelope.OperationID ||
		base.ManifestIdentity != envelope.ManifestIdentity || base.Role != envelope.Role || base.PromotionGeneration != envelope.PromotionGeneration ||
		base.ManifestRevision != envelope.ManifestRevision || base.LeaseEpoch != envelope.LeaseEpoch || base.DeliveryPhase != envelope.DeliveryPhase ||
		base.DeliveryID != envelope.DeliveryID || base.DeliveryNonce != envelope.DeliveryNonce {
		return fmt.Errorf("handoff acknowledgement does not exactly match delivery")
	}
	if err := validatePoolVIPOwnershipAppliedManifestV3(envelope, ack.AppliedManifest); err != nil {
		return err
	}
	wantLease := envelope.LeaseEpoch
	if envelope.Role == nodepolicy.PoolVIPOwnershipWithdrawal {
		wantLease = envelope.PriorLeaseEpoch
	}
	if ack.AppliedLeaseEpoch != wantLease {
		return fmt.Errorf("applied ownership lease epoch does not match delivery")
	}
	return nil
}

func validatePoolVIPOwnershipAppliedManifestV3(envelope PoolVIPOwnershipDeliveryEnvelopeV3, actual PoolVIPOwnershipManifestV3) error {
	identity, err := nodepolicy.PoolVIPOwnershipManifestIdentity(actual.policyManifest())
	if err != nil || identity != envelope.ManifestIdentity || !actual.LeaseExpiresAt.Equal(envelope.ExpiresAt) {
		return fmt.Errorf("applied ownership manifest does not exactly match delivery")
	}
	return nil
}

func poolVIPOwnershipDeliveryAckV3(envelope PoolVIPOwnershipDeliveryEnvelopeV3, actual PoolVIPOwnershipManifestV3, observed time.Time) PoolVIPOwnershipDeliveryAckV3 {
	wantLease := envelope.LeaseEpoch
	if envelope.Role == nodepolicy.PoolVIPOwnershipWithdrawal {
		wantLease = envelope.PriorLeaseEpoch
	}
	return PoolVIPOwnershipDeliveryAckV3{PoolVIPOwnershipDeliveryAck: poolVIPOwnershipDeliveryAck(envelope.PoolVIPOwnershipDeliveryEnvelope, observed), AppliedManifest: actual, AppliedLeaseEpoch: wantLease}
}

func poolVIPOwnershipReadbackV3(envelope PoolVIPOwnershipDeliveryEnvelopeV3, actual PoolVIPOwnershipManifestV3) PoolVIPOwnershipAppliedReadback {
	return PoolVIPOwnershipAppliedReadback{Role: actual.Role, ManifestIdentity: envelope.ManifestIdentity, PromotionGeneration: actual.PromotionGeneration,
		ManifestRevision: actual.ManifestRevision, LeaseEpoch: envelope.LeaseEpoch, OwnedRoutes: append([]string(nil), actual.Routes...),
		VIPMapDigest: poolVIPOwnershipManifestVIPMapDigestV3(actual.policyManifest())}
}

func (m PoolVIPOwnershipManifestV3) policyManifest() nodepolicy.PoolVIPOwnershipManifest {
	peers := make([]nodepolicy.PoolVIPOwnershipWGPeer, len(m.WGPeers))
	for i, peer := range m.WGPeers {
		peers[i] = nodepolicy.PoolVIPOwnershipWGPeer{PublicKey: peer.PublicKey, AllowedIPs: append([]string(nil), peer.AllowedIPs...)}
	}
	services := make([]nodepolicy.PoolVIPOwnershipService, len(m.Services))
	for i, service := range m.Services {
		services[i] = nodepolicy.PoolVIPOwnershipService{ServiceID: service.ServiceID, VIP: service.VIP, Namespace: service.Namespace, Service: service.Service, ServiceCIDR: service.ServiceCIDR, DNSName: service.DNSName, Protocol: service.Protocol, Port: service.Port}
	}
	return nodepolicy.PoolVIPOwnershipManifest{Version: m.Version, OrgID: m.OrgID, SiteID: m.SiteID, ClusterID: m.ClusterID, PoolID: m.PoolID,
		ConnectorNodeID: m.ConnectorNodeID, Role: m.Role, PromotionGeneration: m.PromotionGeneration, ManifestRevision: m.ManifestRevision,
		LeaseEpoch: m.LeaseEpoch, LeaseExpiresAt: m.LeaseExpiresAt, DNSZone: m.DNSZone, DNSVIP: m.DNSVIP, HandoffOwnerID: m.HandoffOwnerID,
		RouteIntent: m.RouteIntent, WGPeers: peers, Routes: append([]string(nil), m.Routes...), Services: services}
}

func poolVIPOwnershipManifestVIPMapDigestV3(manifest nodepolicy.PoolVIPOwnershipManifest) string {
	mappings := make([]nodepolicy.VIPMapping, len(manifest.Services))
	for i, service := range manifest.Services {
		mappings[i] = nodepolicy.VIPMapping{ServiceID: service.ServiceID, VIP: service.VIP, Namespace: service.Namespace, Service: service.Service,
			ServiceCIDR: service.ServiceCIDR, DNSName: service.DNSName, Protocol: service.Protocol, PortLow: service.Port, PortHigh: service.Port}
	}
	return nodepolicy.VIPMapDigest(mappings)
}

func poolVIPOwnershipAttestationScopeV3(envelope PoolVIPOwnershipDeliveryEnvelopeV3) string {
	base := PoolVIPOwnershipDeliveryEnvelopeV2{PoolVIPOwnershipDeliveryEnvelope: envelope.PoolVIPOwnershipDeliveryEnvelope}
	return poolVIPOwnershipAttestationScope(base)
}

func poolVIPOwnershipAttestationFingerprintV3(envelope PoolVIPOwnershipDeliveryEnvelopeV3) (string, error) {
	b, err := json.Marshal(envelope)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
