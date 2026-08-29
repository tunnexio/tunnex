package ownershiplease

import (
	"context"
	"fmt"

	"github.com/tunnexio/tunnex/apps/node/internal/control"
	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
)

// V3DeliveryAdapter is the compatibility boundary between authenticated v3
// delivery envelopes and the fail-closed durable ownership lifecycle.
type V3DeliveryAdapter struct {
	lifecycle   *Lifecycle
	coordinator *Coordinator
}

func NewV3DeliveryAdapter(lifecycle *Lifecycle, coordinator *Coordinator) (*V3DeliveryAdapter, error) {
	if lifecycle == nil || coordinator == nil {
		return nil, fmt.Errorf("ownership v3 lifecycle adapter is not configured")
	}
	return &V3DeliveryAdapter{lifecycle: lifecycle, coordinator: coordinator}, nil
}

func (a *V3DeliveryAdapter) ApplyPoolVIPOwnershipV3(ctx context.Context, envelope control.PoolVIPOwnershipDeliveryEnvelopeV3) error {
	if a == nil || a.lifecycle == nil || a.coordinator == nil {
		return fmt.Errorf("ownership v3 lifecycle adapter is not configured")
	}
	switch envelope.Role {
	case nodepolicy.PoolVIPOwnershipServing:
		return a.lifecycle.InstallServingLease(ctx, Grant{Effective: effectiveFromV3(envelope), LeaseExpiresAt: envelope.ExpiresAt})
	case nodepolicy.PoolVIPOwnershipPreparedNonServing, nodepolicy.PoolVIPOwnershipWithdrawal:
		return a.lifecycle.Withdraw(ctx)
	default:
		return fmt.Errorf("unsupported ownership v3 role")
	}
}

func (a *V3DeliveryAdapter) ReadPoolVIPOwnershipV3(ctx context.Context, envelope control.PoolVIPOwnershipDeliveryEnvelopeV3) (control.PoolVIPOwnershipManifestV3, error) {
	if a == nil || a.coordinator == nil {
		return control.PoolVIPOwnershipManifestV3{}, fmt.Errorf("ownership v3 lifecycle adapter is not configured")
	}
	want := EffectiveOwnership{}
	if envelope.Role == nodepolicy.PoolVIPOwnershipServing {
		want = effectiveFromV3(envelope)
	}
	if err := a.coordinator.VerifyCurrent(ctx, want); err != nil {
		return control.PoolVIPOwnershipManifestV3{}, fmt.Errorf("verify ownership v3 applied state: %w", err)
	}
	return cloneV3Manifest(envelope.Manifest), nil
}

func effectiveFromV3(envelope control.PoolVIPOwnershipDeliveryEnvelopeV3) EffectiveOwnership {
	m := envelope.Manifest
	out := EffectiveOwnership{
		OrgID: m.OrgID, SiteID: m.SiteID, ClusterID: m.ClusterID, PoolID: m.PoolID, ConnectorNodeID: m.ConnectorNodeID,
		ManifestIdentity: envelope.ManifestIdentity, PromotionGeneration: m.PromotionGeneration, ManifestRevision: m.ManifestRevision,
		LeaseEpoch: m.LeaseEpoch, Routes: append([]string(nil), m.Routes...),
	}
	for _, peer := range m.WGPeers {
		out.WGPeers = append(out.WGPeers, WGPeerOwnership{PublicKey: peer.PublicKey, AllowedIPs: append([]string(nil), peer.AllowedIPs...)})
	}
	for _, service := range m.Services {
		out.VIPMappings = append(out.VIPMappings, nodepolicy.VIPMapping{ServiceID: service.ServiceID, VIP: service.VIP, Namespace: service.Namespace,
			Service: service.Service, ServiceCIDR: service.ServiceCIDR, Protocol: service.Protocol, PortLow: service.Port, PortHigh: service.Port, DNSName: service.DNSName})
	}
	if m.DNSVIP != "" || m.DNSZone != "" {
		out.DNSZones = []nodepolicy.K8sDNSZone{{ListenVIP: m.DNSVIP, Zone: m.DNSZone}}
	}
	return out
}

func cloneV3Manifest(in control.PoolVIPOwnershipManifestV3) control.PoolVIPOwnershipManifestV3 {
	out := in
	out.Routes = append([]string(nil), in.Routes...)
	out.WGPeers = make([]control.PoolVIPOwnershipWGPeerV3, len(in.WGPeers))
	for i, peer := range in.WGPeers {
		out.WGPeers[i] = peer
		out.WGPeers[i].AllowedIPs = append([]string(nil), peer.AllowedIPs...)
	}
	out.Services = append([]control.PoolVIPOwnershipServiceV3(nil), in.Services...)
	return out
}
