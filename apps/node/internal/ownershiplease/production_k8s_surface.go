package ownershiplease

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"

	"github.com/tunnexio/tunnex/apps/node/internal/dnsforward"
	"github.com/tunnexio/tunnex/apps/node/internal/egress"
	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
	"github.com/tunnexio/tunnex/apps/node/internal/ovpnserver"
	"github.com/tunnexio/tunnex/apps/node/internal/reconcile"
)

type ProductionEgressOwner interface {
	SetPolicy(*nodepolicy.Compiled)
	ResolveK8sVIPs(context.Context)
	ReconcileDNSVIPsWithCandidates(context.Context, []string) error
	Reconcile(context.Context) (bool, bool, error)
	RequestedK8sDNATReceipts() []egress.K8sDNATReceipt
	ReadK8sDNATReceiptDigests(context.Context) ([]string, error)
	ReadDNSVIPs(context.Context, []string) ([]string, error)
	EmergencyWithdrawK8s(context.Context, []string) error
	SetOVPNTun(string)
	AppliedOVPNTun() string
	ReconcileOVPNTunnel(context.Context, string) error
	ReadAppliedOVPNTunnel(context.Context) (string, error)
}

func (s *productionK8sSurface) EmergencyWithdraw(ctx context.Context, fences []PoolFence) error {
	candidates, _ := k8sReadbackCandidates(reconcile.DesiredState{}, fences)
	if err := s.egress.EmergencyWithdrawK8s(ctx, candidates); err != nil {
		return err
	}
	s.dns.SetK8sAnswers(nil, nil)
	s.dns.ReconcileK8sBinds(ctx, s.wgIface)
	if downstream, ok := s.delegate.(EmergencyDomainSurface); ok {
		return downstream.EmergencyWithdraw(ctx, fences)
	}
	return nil
}

type ProductionDNSOwner interface {
	SetK8sAnswers([]dnsforward.K8sEntry, []string)
	ReconcileK8sBinds(context.Context, string)
	AppliedK8sState() dnsforward.AppliedK8sState
}

// ProductionOVPNOwner is the existing ovpnserver.Manager seam. AppliedState
// proves the live process loaded the exact config/material/CCD artifact digest;
// cached desired input alone is never accepted.
type ProductionOVPNOwner interface {
	SetDesired(ovpnserver.Desired)
	WriteServerMaterial(ca, cert, key, crl string) error
	Reconcile(context.Context) error
	AppliedState() (ovpnserver.ProcessState, error)
	TunActive() bool
	TunName() string
}

// productionK8sSurface is the single egress/dnsforward owner composition. The
// delegate retains non-Kubernetes stage ownership. OVPN remains deliberately
// blocked when enabled; this slice cannot prove a running process loaded the
// rewritten config.
type productionK8sSurface struct {
	delegate DomainSurface
	egress   ProductionEgressOwner
	dns      ProductionDNSOwner
	ovpn     ProductionOVPNOwner
	fences   FenceStore
	wgIface  string

	mu      sync.Mutex
	desired *reconcile.DesiredState
}

func (s *productionK8sSurface) ObserveDesired(desired reconcile.DesiredState) { s.remember(desired) }

func NewProductionK8sSurface(delegate DomainSurface, egressOwner ProductionEgressOwner, dnsOwner ProductionDNSOwner, fences FenceStore, wgIface string) (DomainSurface, error) {
	if delegate == nil || egressOwner == nil || dnsOwner == nil || fences == nil || strings.TrimSpace(wgIface) == "" {
		return nil, fmt.Errorf("%w: production Kubernetes surface dependencies are not configured", ErrProductionAdapterUnavailable)
	}
	return &productionK8sSurface{delegate: delegate, egress: egressOwner, dns: dnsOwner, fences: fences, wgIface: wgIface}, nil
}

func NewProductionK8sSurfaceWithOVPN(delegate DomainSurface, egressOwner ProductionEgressOwner, dnsOwner ProductionDNSOwner, ovpn ProductionOVPNOwner, fences FenceStore, wgIface string) (DomainSurface, error) {
	surface, err := NewProductionK8sSurface(delegate, egressOwner, dnsOwner, fences, wgIface)
	if err != nil {
		return nil, err
	}
	if ovpn == nil {
		return nil, fmt.Errorf("%w: production OpenVPN owner is not configured", ErrProductionAdapterUnavailable)
	}
	surface.(*productionK8sSurface).ovpn = ovpn
	return surface, nil
}

// NewProductionOwnerSurface composes current egress/dnsforward owners and then
// overlays the C3 reconcile-owned WireGuard/route readback decorator.
func NewProductionOwnerSurface(delegate DomainSurface, egressOwner ProductionEgressOwner, dnsOwner ProductionDNSOwner, wg WGReadbackOwner, fences FenceStore, wgIface string) (DomainSurface, error) {
	k8s, err := NewProductionK8sSurface(delegate, egressOwner, dnsOwner, fences, wgIface)
	if err != nil {
		return nil, err
	}
	return NewProductionWGReadbackSurface(k8s, wg)
}

func NewProductionOwnerSurfaceWithOVPN(delegate DomainSurface, egressOwner ProductionEgressOwner, dnsOwner ProductionDNSOwner, ovpn ProductionOVPNOwner, wg WGReadbackOwner, fences FenceStore, wgIface string) (DomainSurface, error) {
	k8s, err := NewProductionK8sSurfaceWithOVPN(delegate, egressOwner, dnsOwner, ovpn, fences, wgIface)
	if err != nil {
		return nil, err
	}
	return NewProductionWGReadbackSurface(k8s, wg)
}

func (s *productionK8sSurface) ApplyStage(ctx context.Context, stage Stage, desired reconcile.DesiredState) error {
	switch stage {
	case StageDNS:
		s.egress.SetPolicy(desired.Policy)
		fences, err := s.fences.LoadFences(ctx)
		if err != nil {
			return fmt.Errorf("load DNS apply fence candidates: %w", err)
		}
		candidates, _ := k8sReadbackCandidates(desired, fences)
		if err := s.egress.ReconcileDNSVIPsWithCandidates(ctx, candidates); err != nil {
			return fmt.Errorf("reconcile Kubernetes DNS VIPs: %w", err)
		}
		entries, zones := desiredDNS(desired)
		s.dns.SetK8sAnswers(entries, zones)
		s.dns.ReconcileK8sBinds(ctx, s.wgIface)
		s.remember(desired)
		return nil
	case StageDNAT:
		s.egress.SetPolicy(desired.Policy)
		s.egress.ResolveK8sVIPs(ctx)
		if _, _, err := s.egress.Reconcile(ctx); err != nil {
			return fmt.Errorf("reconcile Kubernetes VIP DNAT: %w", err)
		}
		s.remember(desired)
		return nil
	case StageOVPN:
		if s.ovpn == nil {
			if !desired.OVPNEnabled {
				return nil
			}
			return fmt.Errorf("%w: %s", ErrProductionAdapterUnavailable, BlockOVPNAppliedReadback)
		}
		ovpnDesired := desiredOVPN(desired)
		if desired.OVPNEnabled && desired.OVPNServer != nil {
			material := desired.OVPNServer
			if err := s.ovpn.WriteServerMaterial(material.CA, material.Cert, material.Key, material.CRL); err != nil {
				return fmt.Errorf("write OpenVPN server material: %w", err)
			}
		}
		s.ovpn.SetDesired(ovpnDesired)
		if err := s.ovpn.Reconcile(ctx); err != nil {
			return fmt.Errorf("reconcile OpenVPN server: %w", errors.Join(err, s.egress.ReconcileOVPNTunnel(ctx, "")))
		}
		ovpnTun := ""
		if s.ovpn.TunActive() {
			ovpnTun = s.ovpn.TunName()
		}
		if err := s.egress.ReconcileOVPNTunnel(ctx, ovpnTun); err != nil {
			return fmt.Errorf("reconcile OpenVPN tunnel-ingress rules: %w", err)
		}
		s.remember(desired)
		return nil
	default:
		return s.delegate.ApplyStage(ctx, stage, desired)
	}
}

func (s *productionK8sSurface) Readback(ctx context.Context) (AppliedDomainState, error) {
	actual, err := s.delegate.Readback(ctx)
	if err != nil {
		return AppliedDomainState{}, err
	}
	desired, ok := s.snapshot()
	if !ok {
		return AppliedDomainState{}, fmt.Errorf("production Kubernetes desired state is unavailable")
	}
	if desired.OVPNEnabled && s.ovpn == nil {
		return AppliedDomainState{}, fmt.Errorf("%w: %s", ErrProductionAdapterUnavailable, BlockOVPNAppliedReadback)
	}
	actual.VIPMappings = nil
	actual.DNSZones = nil
	actual.DNSAnswers = nil
	actual.DNSVIPs = nil
	actual.DNSListeners = nil
	actual.OVPN = OVPNDerivedState{}
	if s.ovpn != nil {
		process, err := s.ovpn.AppliedState()
		if err != nil {
			return AppliedDomainState{}, fmt.Errorf("read OpenVPN applied state: %w", err)
		}
		if desired.OVPNEnabled {
			if !process.Serving || process.AppliedDigest == "" {
				return AppliedDomainState{}, fmt.Errorf("OpenVPN process is not serving the exact applied artifact")
			}
			logicalDigest, err := ovpnserver.DesiredDigest(desiredOVPN(desired))
			if err != nil || process.DesiredDigest != logicalDigest {
				return AppliedDomainState{}, fmt.Errorf("OpenVPN logical desired digest does not match applied process")
			}
			appliedTun, err := s.egress.ReadAppliedOVPNTunnel(ctx)
			if err != nil || appliedTun != s.ovpn.TunName() {
				return AppliedDomainState{}, fmt.Errorf("OpenVPN egress tunnel marker is not applied")
			}
			actual.OVPN = expectedDomainState(desired).OVPN
		} else {
			appliedTun, err := s.egress.ReadAppliedOVPNTunnel(ctx)
			if err != nil || process.Serving || appliedTun != "" {
				return AppliedDomainState{}, fmt.Errorf("OpenVPN process or tunnel-ingress rules remain serving after withdrawal")
			}
		}
	}

	fences, err := s.fences.LoadFences(ctx)
	if err != nil {
		return AppliedDomainState{}, fmt.Errorf("load DNS readback fence candidates: %w", err)
	}
	candidates, knownZones := k8sReadbackCandidates(desired, fences)
	actual.DNSVIPs, err = s.egress.ReadDNSVIPs(ctx, candidates)
	if err != nil {
		return AppliedDomainState{}, fmt.Errorf("read Kubernetes DNS VIPs: %w", err)
	}

	dnsState := s.dns.AppliedK8sState()
	actual.DNSListeners, err = intersectCanonicalIPs(dnsState.Listeners, candidates)
	if err != nil {
		return AppliedDomainState{}, fmt.Errorf("read Kubernetes DNS listeners: %w", err)
	}
	for _, answer := range dnsState.Answers {
		actual.DNSAnswers = append(actual.DNSAnswers, K8sDNSAnswer{Name: answer.FQDN, VIP: answer.VIP})
	}
	for _, zone := range dnsState.Zones {
		mapping, exists := knownZones[normalizeDNS(zone)]
		if !exists {
			return AppliedDomainState{}, fmt.Errorf("unexpected applied Kubernetes DNS zone %q", zone)
		}
		actual.DNSZones = append(actual.DNSZones, mapping)
	}

	requested := s.egress.RequestedK8sDNATReceipts()
	observed, err := s.egress.ReadK8sDNATReceiptDigests(ctx)
	if err != nil {
		return AppliedDomainState{}, fmt.Errorf("read Kubernetes VIP DNAT: %w", err)
	}
	observedSet := make(map[string]struct{}, len(observed))
	for _, digest := range observed {
		observedSet[digest] = struct{}{}
	}
	requestedSet := make(map[string]struct{}, len(requested))
	requestedByVIP := make(map[string]string, len(requested))
	for _, receipt := range requested {
		requestedSet[receipt.Digest] = struct{}{}
		requestedByVIP[receipt.VIP] = receipt.Digest
	}
	for digest := range observedSet {
		if _, expected := requestedSet[digest]; !expected {
			return AppliedDomainState{}, fmt.Errorf("unexpected applied Kubernetes DNAT receipt %s", digest)
		}
	}
	if desired.Policy != nil {
		for _, mapping := range desired.Policy.VIPMappings {
			digest, requested := requestedByVIP[mapping.VIP]
			if !requested {
				continue
			}
			if _, applied := observedSet[digest]; applied {
				actual.VIPMappings = append(actual.VIPMappings, mapping)
			}
		}
	}
	return actual, nil
}

func (s *productionK8sSurface) remember(desired reconcile.DesiredState) {
	cloned := cloneDesiredState(desired)
	s.mu.Lock()
	s.desired = &cloned
	s.mu.Unlock()
}

func (s *productionK8sSurface) snapshot() (reconcile.DesiredState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.desired == nil {
		return reconcile.DesiredState{}, false
	}
	return cloneDesiredState(*s.desired), true
}

func desiredDNS(desired reconcile.DesiredState) ([]dnsforward.K8sEntry, []string) {
	if desired.Policy == nil {
		return nil, nil
	}
	entries := make([]dnsforward.K8sEntry, 0, len(desired.Policy.VIPMappings))
	for _, mapping := range desired.Policy.VIPMappings {
		if mapping.DNSName != "" && mapping.VIP != "" {
			entries = append(entries, dnsforward.K8sEntry{FQDN: mapping.DNSName, VIP: mapping.VIP})
		}
	}
	zones := make([]string, 0, len(desired.Policy.K8sDNSZones))
	for _, zone := range desired.Policy.K8sDNSZones {
		zones = append(zones, zone.Zone)
	}
	return entries, zones
}

func desiredOVPN(desired reconcile.DesiredState) ovpnserver.Desired {
	if !desired.OVPNEnabled {
		return ovpnserver.Desired{}
	}
	out := ovpnserver.Desired{PoolCIDR: desired.InterfaceAddress, Routes: reconcile.OVPNPushRoutes(desired.Policy)}
	for _, client := range desired.OVPNClients {
		out.Clients = append(out.Clients, ovpnserver.Client{CommonName: client.CommonName, IP: client.IP, FullTunnel: client.FullTunnel})
	}
	if desired.Policy != nil {
		for _, forward := range desired.Policy.DNSForwards {
			out.DNS = append(out.DNS, forward.ResolverIP)
		}
		for _, zone := range desired.Policy.K8sDNSZones {
			if zone.ListenVIP != "" {
				out.DNS = append(out.DNS, zone.ListenVIP)
			}
		}
	}
	return out
}

func k8sReadbackCandidates(desired reconcile.DesiredState, fences []PoolFence) ([]string, map[string]nodepolicy.K8sDNSZone) {
	var candidates []string
	known := map[string]nodepolicy.K8sDNSZone{}
	add := func(zones []nodepolicy.K8sDNSZone) {
		for _, zone := range zones {
			candidates = append(candidates, zone.ListenVIP)
			known[normalizeDNS(zone.Zone)] = zone
		}
	}
	for _, fence := range fences {
		add(fence.Suppressed.DNSZones)
	}
	// Current desired is authoritative for a serving readback when an older
	// fenced revision reused the same normalized zone with a different VIP.
	if desired.Policy != nil {
		add(desired.Policy.K8sDNSZones)
	}
	sort.Strings(candidates)
	return candidates, known
}

func intersectCanonicalIPs(observed, candidates []string) ([]string, error) {
	want := map[string]struct{}{}
	for _, raw := range candidates {
		addr, err := netip.ParseAddr(raw)
		if err != nil || !addr.Is4() || addr.String() != raw {
			return nil, fmt.Errorf("invalid DNS VIP candidate %q", raw)
		}
		want[raw] = struct{}{}
	}
	seen := map[string]struct{}{}
	for _, raw := range observed {
		addr, err := netip.ParseAddr(raw)
		if err != nil || !addr.Is4() || addr.String() != raw {
			return nil, fmt.Errorf("invalid observed DNS listener %q", raw)
		}
		if _, candidate := want[raw]; candidate {
			seen[raw] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for raw := range seen {
		out = append(out, raw)
	}
	sort.Strings(out)
	return out, nil
}

func normalizeDNS(value string) string { return strings.TrimSuffix(strings.ToLower(value), ".") }
