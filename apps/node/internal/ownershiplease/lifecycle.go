// Package ownershiplease owns the fail-closed lifetime of pool-scoped
// Kubernetes dataplane authority. It is deliberately not wired into the agent
// loop yet: callers must first provide one real atomic dataplane adapter.
package ownershiplease

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
)

const StateVersion = 1

// Recovery must outlive a cancelled delivery/watch request, but it must never
// become an unbounded background writer. Lifecycle serialization remains the
// outer fence; this timeout bounds the one fail-closed withdrawal attempt.
const recoveryTimeout = 30 * time.Second

var (
	ErrClockMovedBackward = errors.New("ownership lease wall clock moved backward")
	ErrCorruptState       = errors.New("ownership lease state is corrupt")
	ErrLeaseExpired       = errors.New("ownership lease expired")
	ErrReadbackMismatch   = errors.New("ownership dataplane readback mismatch")

	uuidRE     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	hex64RE    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	dnsLabelRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
)

// EffectiveOwnership is the complete pool-scoped Kubernetes ownership overlay.
// A real adapter must project every field onto the latest ordinary desired
// state atomically: splitting these surfaces could leave routes or WireGuard
// reachability live after VIP/DNAT or DNS withdrawal. The zero value withdraws
// only this overlay. It reveals unfenced ordinary state while a durable pool
// fence continues suppressing generation-1 Kubernetes fields adopted by v3.
type EffectiveOwnership struct {
	OrgID               string                  `json:"org_id,omitempty"`
	SiteID              string                  `json:"site_id,omitempty"`
	ClusterID           string                  `json:"cluster_id,omitempty"`
	PoolID              string                  `json:"pool_id,omitempty"`
	ConnectorNodeID     string                  `json:"connector_node_id,omitempty"`
	ManifestIdentity    string                  `json:"manifest_identity,omitempty"`
	PromotionGeneration uint64                  `json:"promotion_generation,omitempty"`
	ManifestRevision    uint64                  `json:"manifest_revision,omitempty"`
	LeaseEpoch          uint64                  `json:"lease_epoch,omitempty"`
	Routes              []string                `json:"routes,omitempty"`
	WGPeers             []WGPeerOwnership       `json:"wg_peers,omitempty"`
	VIPMappings         []nodepolicy.VIPMapping `json:"vip_mappings,omitempty"`
	DNSZones            []nodepolicy.K8sDNSZone `json:"dns_zones,omitempty"`
}

// WGPeerOwnership binds owned prefixes to one exact already-present WireGuard
// peer. The projector never guesses a public key from a node or prefix.
type WGPeerOwnership struct {
	PublicKey  string   `json:"public_key"`
	AllowedIPs []string `json:"allowed_ips"`
}

// Grant is one CP-issued serving lease and the exact effective state it gates.
type Grant struct {
	Effective      EffectiveOwnership `json:"effective"`
	LeaseExpiresAt time.Time          `json:"lease_expires_at"`
}

// State is the durable crash/restart checkpoint. LastWallTime is security
// state: observing a wall clock earlier than it causes immediate withdrawal.
type State struct {
	Version      int       `json:"version"`
	Grant        Grant     `json:"grant"`
	LastWallTime time.Time `json:"last_wall_time"`
}

// AtomicDataplane owns one serialized full-domain apply followed by actual
// readback of routes, WireGuard, VIP/DNAT, DNS, and derived OpenVPN state. It
// must not return desired-state echo data.
type AtomicDataplane interface {
	ApplyAndReadback(ctx context.Context, desired EffectiveOwnership) (EffectiveOwnership, error)
}

// StateStore persists one active lease checkpoint. Clear is called only after
// the pool-scoped overlay withdrawal has been read back exactly.
type StateStore interface {
	Load(ctx context.Context) (State, bool, error)
	Save(ctx context.Context, state State) error
	Clear(ctx context.Context) error
}

// Lifecycle serializes lease installation, watchdog checks, and withdrawal.
type Lifecycle struct {
	mu              sync.Mutex
	dataplane       AtomicDataplane
	store           StateStore
	now             func() time.Time
	current         *State
	withdrawPending bool
}

func New(dataplane AtomicDataplane, store StateStore) *Lifecycle {
	return &Lifecycle{dataplane: dataplane, store: store, now: time.Now}
}

func (l *Lifecycle) setClock(now func() time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now == nil {
		l.now = time.Now
		return
	}
	l.now = now
}

// StartupReconcile never trusts live kernel/nft/DNS state. It either reapplies
// an unexpired valid checkpoint and verifies it, or withdraws its overlay.
func (l *Lifecycle) StartupReconcile(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.configured(); err != nil {
		return err
	}
	state, found, err := l.store.Load(ctx)
	if err != nil {
		withdrawErr := l.withdrawLocked(ctx)
		return errors.Join(ErrCorruptState, err, withdrawErr)
	}
	if !found {
		return l.withdrawLocked(ctx)
	}
	canonical, err := canonicalState(state)
	if err != nil {
		withdrawErr := l.withdrawLocked(ctx)
		return errors.Join(ErrCorruptState, err, withdrawErr)
	}
	now := l.wallNow()
	if now.Before(canonical.LastWallTime) {
		l.current = &canonical
		withdrawErr := l.withdrawLocked(ctx)
		return errors.Join(ErrClockMovedBackward, withdrawErr)
	}
	if !now.Before(canonical.Grant.LeaseExpiresAt) {
		l.current = &canonical
		if err := l.withdrawLocked(ctx); err != nil {
			return errors.Join(ErrLeaseExpired, err)
		}
		return nil
	}
	if err := l.applyExactBefore(ctx, canonical.Grant.Effective, canonical.Grant.LeaseExpiresAt, now); err != nil {
		l.current = &canonical
		withdrawErr := l.withdrawLocked(ctx)
		// Production starts fail closed before the first ordinary base arrives.
		// A durable lease cannot be replayed without that base; once emergency
		// withdrawal is proven, discard it and await a fresh CP delivery.
		if errors.Is(err, ErrBaseDesiredUnavailable) && withdrawErr == nil {
			return nil
		}
		return errors.Join(err, withdrawErr)
	}
	postApply := l.wallNow()
	if postApply.Before(now) || postApply.Before(canonical.LastWallTime) {
		l.current = &canonical
		return errors.Join(ErrClockMovedBackward, l.withdrawLocked(ctx))
	}
	if !postApply.Before(canonical.Grant.LeaseExpiresAt) {
		l.current = &canonical
		return errors.Join(ErrLeaseExpired, l.withdrawLocked(ctx))
	}
	canonical.LastWallTime = postApply
	if err := l.store.Save(ctx, canonical); err != nil {
		l.current = &canonical
		withdrawErr := l.withdrawLocked(ctx)
		return errors.Join(fmt.Errorf("persist startup ownership lease checkpoint: %w", err), withdrawErr)
	}
	beforeSuccess := l.wallNow()
	if beforeSuccess.Before(postApply) {
		l.current = &canonical
		return errors.Join(ErrClockMovedBackward, l.withdrawLocked(ctx))
	}
	if !beforeSuccess.Before(canonical.Grant.LeaseExpiresAt) {
		l.current = &canonical
		return errors.Join(ErrLeaseExpired, l.withdrawLocked(ctx))
	}
	if beforeSuccess.After(canonical.LastWallTime) {
		canonical.LastWallTime = beforeSuccess
	}
	l.current = &canonical
	l.withdrawPending = false
	return nil
}

// InstallServingLease installs a fresh CP lease. An apply/readback or durable
// checkpoint failure triggers immediate overlay withdrawal before returning.
func (l *Lifecycle) InstallServingLease(ctx context.Context, grant Grant) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.configured(); err != nil {
		return err
	}
	now := l.wallNow()
	state, err := canonicalState(State{Version: StateVersion, Grant: grant, LastWallTime: now})
	if err != nil {
		withdrawErr := l.withdrawLocked(ctx)
		return errors.Join(err, withdrawErr)
	}
	if !now.Before(state.Grant.LeaseExpiresAt) {
		withdrawErr := l.withdrawLocked(ctx)
		return errors.Join(ErrLeaseExpired, withdrawErr)
	}
	if l.current != nil && now.Before(l.current.LastWallTime) {
		withdrawErr := l.withdrawLocked(ctx)
		return errors.Join(ErrClockMovedBackward, withdrawErr)
	}
	if err := l.applyExactBefore(ctx, state.Grant.Effective, state.Grant.LeaseExpiresAt, now); err != nil {
		withdrawErr := l.withdrawLocked(ctx)
		return errors.Join(err, withdrawErr)
	}
	postApply := l.wallNow()
	if postApply.Before(now) || (l.current != nil && postApply.Before(l.current.LastWallTime)) {
		return errors.Join(ErrClockMovedBackward, l.withdrawLocked(ctx))
	}
	if !postApply.Before(state.Grant.LeaseExpiresAt) {
		return errors.Join(ErrLeaseExpired, l.withdrawLocked(ctx))
	}
	state.LastWallTime = postApply
	if err := l.store.Save(ctx, state); err != nil {
		withdrawErr := l.withdrawLocked(ctx)
		return errors.Join(fmt.Errorf("persist ownership lease: %w", err), withdrawErr)
	}
	beforeSuccess := l.wallNow()
	if beforeSuccess.Before(postApply) {
		return errors.Join(ErrClockMovedBackward, l.withdrawLocked(ctx))
	}
	if !beforeSuccess.Before(state.Grant.LeaseExpiresAt) {
		return errors.Join(ErrLeaseExpired, l.withdrawLocked(ctx))
	}
	if beforeSuccess.After(state.LastWallTime) {
		state.LastWallTime = beforeSuccess
	}
	l.current = &state
	l.withdrawPending = false
	return nil
}

// Withdraw revokes any serving lease and proves the pool-scoped overlay is
// absent before clearing its durable checkpoint. Prepared-non-serving and
// explicit withdrawal deliveries both use this fail-closed transition.
func (l *Lifecycle) Withdraw(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.configured(); err != nil {
		return err
	}
	return l.withdrawLocked(ctx)
}

// Check is one watchdog tick. No CP-disconnect signal is required: without a
// successor lease, the deadline expires and the same overlay withdrawal runs.
func (l *Lifecycle) Check(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.configured(); err != nil {
		return err
	}
	if l.withdrawPending {
		return l.withdrawLocked(ctx)
	}
	if l.current == nil {
		return nil
	}
	now := l.wallNow()
	if now.Before(l.current.LastWallTime) {
		withdrawErr := l.withdrawLocked(ctx)
		return errors.Join(ErrClockMovedBackward, withdrawErr)
	}
	if !now.Before(l.current.Grant.LeaseExpiresAt) {
		return l.withdrawLocked(ctx)
	}
	l.current.LastWallTime = now
	if err := l.store.Save(ctx, *l.current); err != nil {
		withdrawErr := l.withdrawLocked(ctx)
		return errors.Join(fmt.Errorf("persist ownership lease watchdog checkpoint: %w", err), withdrawErr)
	}
	return nil
}

// LeaseDeadline exposes only the current CP-issued deadline to the serialized
// mutation lane. Normal substrate work is cancelled at this instant and the
// lane immediately runs Check before accepting more ordinary work.
func (l *Lifecycle) LeaseDeadline() (time.Time, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l == nil || l.current == nil {
		return time.Time{}, false
	}
	return l.current.Grant.LeaseExpiresAt, true
}

// RunWatchdog performs startup reconciliation and then checks until cancelled.
// It is intentionally not called from main in this slice.
func (l *Lifecycle) RunWatchdog(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		return fmt.Errorf("ownership lease watchdog interval must be positive")
	}
	if err := l.StartupReconcile(ctx); err != nil {
		return err
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := l.Check(ctx); err != nil {
				return err
			}
		}
	}
}

func (l *Lifecycle) configured() error {
	if l == nil || l.dataplane == nil || l.store == nil || l.now == nil {
		return fmt.Errorf("ownership lease lifecycle is not configured")
	}
	return nil
}

func (l *Lifecycle) wallNow() time.Time { return l.now().UTC() }

func (l *Lifecycle) withdrawLocked(_ context.Context) error {
	l.withdrawPending = true
	recoveryCtx, cancel := context.WithTimeout(context.Background(), recoveryTimeout)
	defer cancel()
	if err := l.applyExact(recoveryCtx, EffectiveOwnership{}); err != nil {
		return fmt.Errorf("withdraw Kubernetes ownership: %w", err)
	}
	if err := l.store.Clear(recoveryCtx); err != nil {
		return fmt.Errorf("clear withdrawn ownership lease: %w", err)
	}
	l.current = nil
	l.withdrawPending = false
	return nil
}

func (l *Lifecycle) applyExact(ctx context.Context, desired EffectiveOwnership) error {
	want, err := canonicalEffective(desired, !isZeroEffective(desired))
	if err != nil {
		return err
	}
	actual, err := l.dataplane.ApplyAndReadback(ctx, want)
	if err != nil {
		return err
	}
	got, err := canonicalEffective(actual, !isZeroEffective(actual))
	if err != nil || !reflect.DeepEqual(got, want) {
		return ErrReadbackMismatch
	}
	return nil
}

func (l *Lifecycle) applyExactBefore(ctx context.Context, desired EffectiveOwnership, deadline, observedNow time.Time) error {
	remaining := deadline.Sub(observedNow)
	if remaining <= 0 {
		return ErrLeaseExpired
	}
	applyCtx, cancel := context.WithTimeout(ctx, remaining)
	defer cancel()
	if err := l.applyExact(applyCtx, desired); err != nil {
		if errors.Is(applyCtx.Err(), context.DeadlineExceeded) {
			return errors.Join(ErrLeaseExpired, err)
		}
		return err
	}
	if errors.Is(applyCtx.Err(), context.DeadlineExceeded) {
		return ErrLeaseExpired
	}
	return nil
}

func isZeroEffective(value EffectiveOwnership) bool {
	return reflect.DeepEqual(value, EffectiveOwnership{})
}

func canonicalState(state State) (State, error) {
	if state.Version != StateVersion {
		return State{}, fmt.Errorf("unsupported ownership lease state version")
	}
	if state.Grant.LeaseExpiresAt.IsZero() || state.LastWallTime.IsZero() {
		return State{}, fmt.Errorf("ownership lease times are required")
	}
	effective, err := canonicalEffective(state.Grant.Effective, true)
	if err != nil {
		return State{}, err
	}
	state.Grant.Effective = effective
	state.Grant.LeaseExpiresAt = state.Grant.LeaseExpiresAt.UTC()
	state.LastWallTime = state.LastWallTime.UTC()
	return state, nil
}

func canonicalEffective(in EffectiveOwnership, serving bool) (EffectiveOwnership, error) {
	if !serving {
		if !reflect.DeepEqual(in, EffectiveOwnership{}) {
			return EffectiveOwnership{}, fmt.Errorf("withdrawal must be the zero effective ownership")
		}
		return EffectiveOwnership{}, nil
	}
	for name, value := range map[string]string{
		"org_id": in.OrgID, "site_id": in.SiteID, "cluster_id": in.ClusterID,
		"pool_id": in.PoolID, "connector_node_id": in.ConnectorNodeID,
	} {
		if !uuidRE.MatchString(value) || value == "00000000-0000-0000-0000-000000000000" {
			return EffectiveOwnership{}, fmt.Errorf("invalid %s", name)
		}
	}
	if !hex64RE.MatchString(in.ManifestIdentity) || in.PromotionGeneration == 0 || in.ManifestRevision == 0 || in.LeaseEpoch == 0 {
		return EffectiveOwnership{}, fmt.Errorf("invalid ownership identity or monotonic fields")
	}
	var err error
	if in.Routes, err = canonicalPrefixes(in.Routes); err != nil || len(in.Routes) == 0 {
		return EffectiveOwnership{}, fmt.Errorf("invalid ownership routes")
	}
	if in.WGPeers, err = canonicalWGPeers(in.WGPeers); err != nil || len(in.WGPeers) == 0 {
		return EffectiveOwnership{}, fmt.Errorf("invalid ownership WireGuard peers")
	}
	if in.VIPMappings, err = canonicalVIPMappings(in.VIPMappings); err != nil {
		return EffectiveOwnership{}, err
	}
	if in.DNSZones, err = canonicalDNSZones(in.DNSZones); err != nil {
		return EffectiveOwnership{}, err
	}
	return in, nil
}

func canonicalWGPeers(values []WGPeerOwnership) ([]WGPeerOwnership, error) {
	out := make([]WGPeerOwnership, 0, len(values))
	seenKeys := make(map[string]struct{}, len(values))
	seenPrefixes := map[string]string{}
	for _, value := range values {
		decoded, err := base64.StdEncoding.Strict().DecodeString(value.PublicKey)
		if err != nil || len(decoded) != 32 || base64.StdEncoding.EncodeToString(decoded) != value.PublicKey {
			return nil, fmt.Errorf("invalid WireGuard public key")
		}
		if _, exists := seenKeys[value.PublicKey]; exists {
			return nil, fmt.Errorf("duplicate WireGuard public key")
		}
		allowed, err := canonicalPrefixes(value.AllowedIPs)
		if err != nil || len(allowed) == 0 {
			return nil, fmt.Errorf("WireGuard peer requires canonical allowed IPs")
		}
		for _, prefix := range allowed {
			if prior, exists := seenPrefixes[prefix]; exists {
				return nil, fmt.Errorf("allowed IP %s belongs to multiple peers (%s and %s)", prefix, prior, value.PublicKey)
			}
			seenPrefixes[prefix] = value.PublicKey
		}
		seenKeys[value.PublicKey] = struct{}{}
		out = append(out, WGPeerOwnership{PublicKey: value.PublicKey, AllowedIPs: allowed})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PublicKey < out[j].PublicKey })
	return out, nil
}

func canonicalPrefixes(values []string) ([]string, error) {
	out := append([]string(nil), values...)
	for _, value := range out {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() || prefix.String() != value {
			return nil, fmt.Errorf("noncanonical IPv4 prefix")
		}
	}
	sort.Strings(out)
	for i := 1; i < len(out); i++ {
		if out[i] == out[i-1] {
			return nil, fmt.Errorf("duplicate prefix")
		}
	}
	return out, nil
}

func canonicalVIPMappings(values []nodepolicy.VIPMapping) ([]nodepolicy.VIPMapping, error) {
	out := append([]nodepolicy.VIPMapping(nil), values...)
	seen := make(map[string]struct{}, len(out))
	for _, value := range out {
		vip, vipErr := netip.ParseAddr(value.VIP)
		serviceCIDR, cidrErr := netip.ParsePrefix(value.ServiceCIDR)
		if !uuidRE.MatchString(value.ServiceID) || vipErr != nil || !vip.Is4() || vip.String() != value.VIP ||
			cidrErr != nil || !serviceCIDR.Addr().Is4() || serviceCIDR != serviceCIDR.Masked() || serviceCIDR.String() != value.ServiceCIDR ||
			!validDNSName(value.Namespace) || !validDNSName(value.Service) || !validDNSName(value.DNSName) ||
			(value.Protocol != "tcp" && value.Protocol != "udp") || value.PortLow < 1 || value.PortLow != value.PortHigh || value.PortHigh > 65535 {
			return nil, fmt.Errorf("invalid ownership VIP mapping")
		}
		if _, exists := seen[value.ServiceID]; exists {
			return nil, fmt.Errorf("duplicate ownership VIP mapping")
		}
		seen[value.ServiceID] = struct{}{}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ServiceID < out[j].ServiceID })
	return out, nil
}

func canonicalDNSZones(values []nodepolicy.K8sDNSZone) ([]nodepolicy.K8sDNSZone, error) {
	out := append([]nodepolicy.K8sDNSZone(nil), values...)
	seen := make(map[string]struct{}, len(out))
	for _, value := range out {
		vip, err := netip.ParseAddr(value.ListenVIP)
		zone := strings.TrimSuffix(strings.ToLower(value.Zone), ".")
		if err != nil || !vip.Is4() || vip.String() != value.ListenVIP || !validDNSName(zone) || zone != value.Zone {
			return nil, fmt.Errorf("invalid ownership DNS zone")
		}
		key := value.ListenVIP + "\x00" + value.Zone
		if _, exists := seen[key]; exists {
			return nil, fmt.Errorf("duplicate ownership DNS zone")
		}
		seen[key] = struct{}{}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ListenVIP != out[j].ListenVIP {
			return out[i].ListenVIP < out[j].ListenVIP
		}
		return out[i].Zone < out[j].Zone
	})
	return out, nil
}

func validDNSName(value string) bool {
	if value == "" || len(value) > 253 || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) > 63 || !dnsLabelRE.MatchString(label) {
			return false
		}
	}
	return true
}
