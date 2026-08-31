package ownershiplease

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"sort"
	"strings"

	"github.com/tunnexio/tunnex/apps/node/internal/reconcile"
)

// WGReadbackOwner is the read-only production seam supplied by the existing
// reconcile backend. It is intentionally narrower than WGBackend: this adapter
// delegates every write to the existing DomainSurface and cannot become a
// second WireGuard or route writer.
type WGReadbackOwner interface {
	Readback(ctx context.Context) (reconcile.WGBackendReadback, error)
}

type emergencyWGOwner interface {
	ApplyPeers(context.Context, []reconcile.Peer) error
	ApplyRoutes(context.Context, []string, string) error
}

// productionWGReadbackSurface replaces any desired-state echo returned by the
// remaining domain adapter with actual WireGuard, route and policy-rule state
// from reconcile's current owner. DNS, DNAT and OpenVPN remain delegated.
type productionWGReadbackSurface struct {
	domain DomainSurface
	wg     WGReadbackOwner
}

func NewProductionWGReadbackSurface(domain DomainSurface, wg WGReadbackOwner) (DomainSurface, error) {
	if domain == nil || wg == nil {
		return nil, fmt.Errorf("%w: production WG readback dependencies are not configured", ErrProductionAdapterUnavailable)
	}
	return &productionWGReadbackSurface{domain: domain, wg: wg}, nil
}

// NewCoordinatorWithProductionWGReadback is the bounded production composition
// point. It leaves stage ownership unchanged and only strengthens the
// coordinator's post-apply proof with reconcile-owned actual state.
func NewCoordinatorWithProductionWGReadback(projector *Projector, domain DomainSurface, wg WGReadbackOwner, store FenceStore) (*Coordinator, error) {
	surface, err := NewProductionWGReadbackSurface(domain, wg)
	if err != nil {
		return nil, err
	}
	return NewCoordinator(projector, surface, store), nil
}

func (s *productionWGReadbackSurface) ApplyStage(ctx context.Context, stage Stage, desired reconcile.DesiredState) error {
	return s.domain.ApplyStage(ctx, stage, desired)
}

func (s *productionWGReadbackSurface) ObserveDesired(desired reconcile.DesiredState) {
	if observer, ok := s.domain.(desiredStateObserver); ok {
		observer.ObserveDesired(desired)
	}
}

func (s *productionWGReadbackSurface) EmergencyWithdraw(ctx context.Context, fences []PoolFence) error {
	if len(fences) == 0 {
		if downstream, ok := s.domain.(EmergencyDomainSurface); ok {
			return downstream.EmergencyWithdraw(ctx, nil)
		}
		return nil
	}
	wg, err := s.wg.Readback(ctx)
	if err != nil {
		if isWGInterfaceAbsent(err) {
			// There is no kernel interface carrying the fenced state. This is a
			// successful non-serving withdrawal at cold start, not an unknown
			// readback; still let lower owners remove their Kubernetes state.
			if downstream, ok := s.domain.(EmergencyDomainSurface); ok {
				return downstream.EmergencyWithdraw(ctx, fences)
			}
			return nil
		}
		return fmt.Errorf("read emergency WireGuard ownership: %w", err)
	}
	blockedRoutes := map[string]struct{}{}
	blockedByPeer := map[string]map[string]struct{}{}
	for _, fence := range fences {
		for _, route := range fence.Suppressed.Routes {
			blockedRoutes[route] = struct{}{}
		}
		for _, peer := range fence.Suppressed.WGPeers {
			set := blockedByPeer[peer.PublicKey]
			if set == nil {
				set = map[string]struct{}{}
				blockedByPeer[peer.PublicKey] = set
			}
			for _, prefix := range peer.AllowedIPs {
				set[prefix] = struct{}{}
			}
		}
	}
	var peers []reconcile.Peer
	for _, peer := range wg.Peers {
		kept := peer
		kept.AllowedIPs = nil
		for _, prefix := range peer.AllowedIPs {
			if _, blocked := blockedByPeer[peer.PublicKey][prefix]; !blocked {
				kept.AllowedIPs = append(kept.AllowedIPs, prefix)
			}
		}
		peers = append(peers, kept)
	}
	var routes []string
	for _, route := range wg.Routes {
		if _, blocked := blockedRoutes[route]; !blocked {
			routes = append(routes, route)
		}
	}
	writer, ok := s.wg.(emergencyWGOwner)
	if !ok {
		return fmt.Errorf("%w: emergency WireGuard writer is unavailable", ErrProductionAdapterUnavailable)
	}
	if err := writer.ApplyPeers(ctx, peers); err != nil {
		return err
	}
	if err := writer.ApplyRoutes(ctx, routes, ""); err != nil {
		return err
	}
	if downstream, ok := s.domain.(EmergencyDomainSurface); ok {
		if err := downstream.EmergencyWithdraw(ctx, fences); err != nil {
			return err
		}
	}
	actual, err := s.wg.Readback(ctx)
	if err != nil {
		return err
	}
	for _, route := range actual.Routes {
		if _, blocked := blockedRoutes[route]; blocked {
			return fmt.Errorf("emergency route withdrawal readback retained %s", route)
		}
	}
	for _, peer := range actual.Peers {
		for _, prefix := range peer.AllowedIPs {
			if _, blocked := blockedByPeer[peer.PublicKey][prefix]; blocked {
				return fmt.Errorf("emergency WireGuard withdrawal readback retained %s", prefix)
			}
		}
	}
	return nil
}

func isWGInterfaceAbsent(err error) bool {
	if errors.Is(err, reconcile.ErrWGInterfaceAbsent) {
		return true
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "device") &&
		(strings.Contains(message, "does not exist") || strings.Contains(message, "cannot find device"))
}

func (s *productionWGReadbackSurface) Readback(ctx context.Context) (AppliedDomainState, error) {
	actual, err := s.domain.Readback(ctx)
	if err != nil {
		return AppliedDomainState{}, err
	}
	wg, err := s.wg.Readback(ctx)
	if err != nil {
		return AppliedDomainState{}, fmt.Errorf("read reconcile-owned WireGuard domain: %w", err)
	}
	if err := validateStructuredRouteReadback(wg); err != nil {
		return AppliedDomainState{}, err
	}
	actual.WGPeers = make([]WGAppliedPeer, len(wg.Peers))
	for i, peer := range wg.Peers {
		actual.WGPeers[i] = WGAppliedPeer{PublicKey: peer.PublicKey, AllowedIPs: append([]string(nil), peer.AllowedIPs...)}
	}
	actual.Routes = append([]string(nil), wg.Routes...)
	actual.ReturnRules = append([]reconcile.ReturnRule(nil), wg.ReturnRules...)
	return actual, nil
}

func validateStructuredRouteReadback(wg reconcile.WGBackendReadback) error {
	destinations := make([]string, len(wg.RouteDetails))
	for i, route := range wg.RouteDetails {
		prefix, err := netip.ParsePrefix(route.Destination)
		if err != nil || prefix.Masked().String() != route.Destination {
			return fmt.Errorf("invalid structured route destination %q", route.Destination)
		}
		family := "ipv6"
		if prefix.Addr().Is4() {
			family = "ipv4"
		}
		if route.Family != family || route.Device == "" || route.Protocol != "static" || route.Metric != 8021 {
			return fmt.Errorf("incomplete structured ownership proof for route %q", route.Destination)
		}
		if route.Source != "" {
			source, err := netip.ParseAddr(route.Source)
			if err != nil || source.Is4() != prefix.Addr().Is4() || source.String() != route.Source {
				return fmt.Errorf("invalid structured route source %q", route.Source)
			}
		}
		destinations[i] = route.Destination
	}
	// Keep an empty owned-route enumeration as an empty slice on both sides.
	// A cold/non-serving gateway legitimately has no owned routes; comparing a
	// nil copy against make([]string, 0) would otherwise turn that valid proof
	// into a false route-ownership mismatch.
	canonicalRoutes := make([]string, len(wg.Routes))
	copy(canonicalRoutes, wg.Routes)
	sort.Strings(canonicalRoutes)
	sort.Strings(destinations)
	if !reflect.DeepEqual(canonicalRoutes, destinations) {
		return fmt.Errorf("structured route ownership proof does not match route enumeration")
	}
	return nil
}

func expectedReturnRules(desired reconcile.DesiredState) []reconcile.ReturnRule {
	if desired.Policy == nil {
		return nil
	}
	routes := make(map[netip.Prefix]bool, len(desired.Policy.Routes))
	for _, route := range desired.Policy.Routes {
		if prefix, err := netip.ParsePrefix(route.DstCIDR); err == nil {
			routes[prefix.Masked()] = true
		}
	}
	var out []reconcile.ReturnRule
	for _, raw := range strings.Split(desired.InterfaceAddress, ",") {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			continue
		}
		prefix = prefix.Masked()
		if routes[prefix] {
			out = append(out, reconcile.ReturnRule{Priority: 100, Destination: prefix.String(), Lookup: "main"})
		}
	}
	return out
}
