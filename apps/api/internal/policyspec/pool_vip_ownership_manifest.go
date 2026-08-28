package policyspec

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"
)

// PoolVIPOwnershipManifestVersion versions only the future ownership-manifest
// identity. It is deliberately independent from compiled-policy versions,
// CanonicalHash, and VIPMapDigest.
const PoolVIPOwnershipManifestVersion = 1

const (
	PoolVIPOwnershipPreparedNonServing = "prepared_non_serving"
	PoolVIPOwnershipServing            = "serving"
	PoolVIPOwnershipWithdrawal         = "withdrawal"
)

var (
	poolVIPOwnershipUUIDRE     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	poolVIPOwnershipDNSLabelRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
)

// PoolVIPOwnershipManifest is a pure, future wire-independent assertion of
// one pool's VIP handoff ownership. It is neither signed nor authenticated and
// does not cause a route, peer, policy, report, or storage change in this slice.
// A later transport must authenticate and compare it with control-plane state.
type PoolVIPOwnershipManifest struct {
	Version             int
	OrgID               string
	SiteID              string
	ClusterID           string
	PoolID              string
	ConnectorNodeID     string
	Role                string
	PromotionGeneration uint64
	ManifestRevision    uint64
	LeaseEpoch          uint64
	LeaseExpiresAt      time.Time
	DNSZone             string
	DNSVIP              string
	HandoffOwnerID      string
	RouteIntent         string
	WGPeers             []PoolVIPOwnershipWGPeer
	Routes              []string
	Services            []PoolVIPOwnershipService
}

// PoolVIPOwnershipWGPeer binds every owned prefix to the exact WireGuard peer
// public key that must receive it. A flat prefix set cannot authorize or attest
// a concrete wg peer configuration.
type PoolVIPOwnershipWGPeer struct {
	PublicKey  string
	AllowedIPs []string
}

// PoolVIPOwnershipService is one exact exposed Service child in the manifest.
type PoolVIPOwnershipService struct {
	ServiceID string
	VIP       string
	Namespace string
	Service   string
	// ServiceCIDR drives ClusterIP-vs-headless endpoint classification; DNSName
	// is the exact authoritative name answered by the node. Both are dataplane
	// inputs and therefore part of the ownership identity.
	ServiceCIDR string
	DNSName     string
	Protocol    string
	Port        int
}

// PoolVIPOwnershipManifestIdentity returns the full, domain-separated SHA-256
// identity of a canonical typed projection. It rejects malformed or ambiguous
// data rather than hashing a partial or noncanonical manifest.
func PoolVIPOwnershipManifestIdentity(m PoolVIPOwnershipManifest) (string, error) {
	v, err := projectPoolVIPOwnershipManifest(m)
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// ValidatePoolVIPOwnershipManifestSuccessor is a pure progression check for a
// later durable owner. It requires an unchanged scope and a strictly advancing
// revision; it does not store, deliver, authenticate, or apply either manifest.
func ValidatePoolVIPOwnershipManifestSuccessor(previous, next PoolVIPOwnershipManifest) error {
	if _, err := PoolVIPOwnershipManifestIdentity(previous); err != nil {
		return fmt.Errorf("invalid previous manifest: %w", err)
	}
	if _, err := PoolVIPOwnershipManifestIdentity(next); err != nil {
		return fmt.Errorf("invalid next manifest: %w", err)
	}
	if previous.Version != next.Version || previous.OrgID != next.OrgID || previous.SiteID != next.SiteID ||
		previous.ClusterID != next.ClusterID || previous.PoolID != next.PoolID || previous.ConnectorNodeID != next.ConnectorNodeID {
		return fmt.Errorf("manifest scope changed")
	}
	if next.ManifestRevision <= previous.ManifestRevision {
		return fmt.Errorf("manifest revision did not advance")
	}
	if next.PromotionGeneration < previous.PromotionGeneration || next.LeaseEpoch < previous.LeaseEpoch {
		return fmt.Errorf("promotion generation or lease epoch regressed")
	}
	return nil
}

type poolVIPOwnershipManifestView struct {
	Domain              string                        `json:"domain"`
	Version             int                           `json:"version"`
	OrgID               string                        `json:"org_id"`
	SiteID              string                        `json:"site_id"`
	ClusterID           string                        `json:"cluster_id"`
	PoolID              string                        `json:"pool_id"`
	ConnectorNodeID     string                        `json:"connector_node_id"`
	Role                string                        `json:"role"`
	PromotionGeneration uint64                        `json:"promotion_generation"`
	ManifestRevision    uint64                        `json:"manifest_revision"`
	LeaseEpoch          uint64                        `json:"lease_epoch"`
	LeaseExpiresAt      string                        `json:"lease_expires_at"`
	DNSZone             string                        `json:"dns_zone"`
	DNSVIP              string                        `json:"dns_vip"`
	HandoffOwnerID      string                        `json:"handoff_owner_id"`
	RouteIntent         string                        `json:"route_intent"`
	WGPeers             []poolVIPOwnershipWGPeerView  `json:"wg_peers"`
	Routes              []string                      `json:"routes"`
	Services            []poolVIPOwnershipServiceView `json:"services"`
}

type poolVIPOwnershipWGPeerView struct {
	PublicKey  string   `json:"public_key"`
	AllowedIPs []string `json:"allowed_ips"`
}

type poolVIPOwnershipServiceView struct {
	ServiceID   string `json:"service_id"`
	VIP         string `json:"vip"`
	Namespace   string `json:"namespace"`
	Service     string `json:"service"`
	ServiceCIDR string `json:"service_cidr"`
	DNSName     string `json:"dns_name"`
	Protocol    string `json:"protocol"`
	Port        int    `json:"port"`
}

func projectPoolVIPOwnershipManifest(m PoolVIPOwnershipManifest) (poolVIPOwnershipManifestView, error) {
	if m.Version != PoolVIPOwnershipManifestVersion {
		return poolVIPOwnershipManifestView{}, fmt.Errorf("unsupported ownership manifest version")
	}
	for field, value := range map[string]string{
		"org_id": m.OrgID, "site_id": m.SiteID, "cluster_id": m.ClusterID, "pool_id": m.PoolID,
		"connector_node_id": m.ConnectorNodeID, "handoff_owner_id": m.HandoffOwnerID,
	} {
		if !validPoolVIPOwnershipUUID(value) {
			return poolVIPOwnershipManifestView{}, fmt.Errorf("invalid %s", field)
		}
	}
	if m.PromotionGeneration == 0 || m.ManifestRevision == 0 || m.LeaseEpoch == 0 {
		return poolVIPOwnershipManifestView{}, fmt.Errorf("promotion generation, manifest revision, and lease epoch must be positive")
	}
	if m.LeaseExpiresAt.IsZero() || m.LeaseExpiresAt.Location() != time.UTC {
		return poolVIPOwnershipManifestView{}, fmt.Errorf("lease expiry must be a nonzero UTC time")
	}
	if !validPoolVIPOwnershipDNSName(m.DNSZone) || !validPoolVIPOwnershipIPv4(m.DNSVIP) {
		return poolVIPOwnershipManifestView{}, fmt.Errorf("invalid DNS zone or DNS VIP")
	}
	if err := validPoolVIPOwnershipRoleIntent(m.Role, m.RouteIntent, m.WGPeers, m.Routes); err != nil {
		return poolVIPOwnershipManifestView{}, err
	}
	wgPeers, err := canonicalPoolVIPOwnershipWGPeers(m.WGPeers)
	if err != nil {
		return poolVIPOwnershipManifestView{}, fmt.Errorf("invalid WireGuard peers: %w", err)
	}
	routes, err := canonicalPoolVIPOwnershipPrefixes(m.Routes)
	if err != nil {
		return poolVIPOwnershipManifestView{}, fmt.Errorf("invalid routes: %w", err)
	}
	services := make([]poolVIPOwnershipServiceView, 0, len(m.Services))
	ids := make(map[string]struct{}, len(m.Services))
	tuples := make(map[string]struct{}, len(m.Services))
	for _, service := range m.Services {
		serviceCIDR, serviceCIDRErr := netip.ParsePrefix(service.ServiceCIDR)
		if !validPoolVIPOwnershipUUID(service.ServiceID) || !validPoolVIPOwnershipIPv4(service.VIP) ||
			!validPoolVIPOwnershipDNSLabel(service.Namespace) || !validPoolVIPOwnershipDNSLabel(service.Service) ||
			serviceCIDRErr != nil || !serviceCIDR.Addr().Is4() || serviceCIDR != serviceCIDR.Masked() || serviceCIDR.String() != service.ServiceCIDR ||
			!validPoolVIPOwnershipDNSName(service.DNSName) ||
			(service.Protocol != "tcp" && service.Protocol != "udp") || service.Port < 1 || service.Port > 65535 {
			return poolVIPOwnershipManifestView{}, fmt.Errorf("invalid service entry")
		}
		tuple := strings.Join([]string{service.VIP, service.Namespace, service.Service, service.Protocol, fmt.Sprint(service.Port)}, "\x00")
		if _, exists := ids[service.ServiceID]; exists {
			return poolVIPOwnershipManifestView{}, fmt.Errorf("duplicate service ID")
		}
		if _, exists := tuples[tuple]; exists {
			return poolVIPOwnershipManifestView{}, fmt.Errorf("duplicate service tuple")
		}
		ids[service.ServiceID] = struct{}{}
		tuples[tuple] = struct{}{}
		services = append(services, poolVIPOwnershipServiceView(service))
	}
	sort.Slice(services, func(i, j int) bool {
		a, b := services[i], services[j]
		if a.ServiceID != b.ServiceID {
			return a.ServiceID < b.ServiceID
		}
		if a.VIP != b.VIP {
			return a.VIP < b.VIP
		}
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		if a.Service != b.Service {
			return a.Service < b.Service
		}
		if a.ServiceCIDR != b.ServiceCIDR {
			return a.ServiceCIDR < b.ServiceCIDR
		}
		if a.DNSName != b.DNSName {
			return a.DNSName < b.DNSName
		}
		if a.Protocol != b.Protocol {
			return a.Protocol < b.Protocol
		}
		return a.Port < b.Port
	})
	return poolVIPOwnershipManifestView{
		Domain: "tunnex.pool-vip-ownership-manifest/v1", Version: m.Version,
		OrgID: m.OrgID, SiteID: m.SiteID, ClusterID: m.ClusterID, PoolID: m.PoolID, ConnectorNodeID: m.ConnectorNodeID,
		Role: m.Role, PromotionGeneration: m.PromotionGeneration, ManifestRevision: m.ManifestRevision, LeaseEpoch: m.LeaseEpoch,
		LeaseExpiresAt: m.LeaseExpiresAt.Format(time.RFC3339Nano), DNSZone: m.DNSZone, DNSVIP: m.DNSVIP,
		HandoffOwnerID: m.HandoffOwnerID, RouteIntent: m.RouteIntent, WGPeers: wgPeers, Routes: routes, Services: services,
	}, nil
}

func validPoolVIPOwnershipRoleIntent(role, intent string, peers []PoolVIPOwnershipWGPeer, routes []string) error {
	switch role {
	case PoolVIPOwnershipServing:
		if intent != "serving" || len(peers) == 0 || len(routes) == 0 {
			return fmt.Errorf("serving manifest requires serving intent, WireGuard peers, and routes")
		}
	case PoolVIPOwnershipPreparedNonServing:
		if intent != "non_serving" || len(peers) != 0 || len(routes) != 0 {
			return fmt.Errorf("prepared manifest must be explicitly non-serving without WireGuard peers or routes")
		}
	case PoolVIPOwnershipWithdrawal:
		if intent != "withdrawal" || len(peers) != 0 || len(routes) != 0 {
			return fmt.Errorf("withdrawal manifest must be explicit without WireGuard peers or routes")
		}
	default:
		return fmt.Errorf("invalid ownership manifest role")
	}
	return nil
}

func canonicalPoolVIPOwnershipWGPeers(values []PoolVIPOwnershipWGPeer) ([]poolVIPOwnershipWGPeerView, error) {
	out := make([]poolVIPOwnershipWGPeerView, 0, len(values))
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
		allowed, err := canonicalPoolVIPOwnershipPrefixes(value.AllowedIPs)
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
		out = append(out, poolVIPOwnershipWGPeerView{PublicKey: value.PublicKey, AllowedIPs: allowed})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PublicKey < out[j].PublicKey })
	return out, nil
}

func canonicalPoolVIPOwnershipPrefixes(values []string) ([]string, error) {
	out := append([]string(nil), values...)
	for _, value := range out {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() || prefix.String() != value {
			return nil, fmt.Errorf("noncanonical prefix")
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

func validPoolVIPOwnershipUUID(value string) bool {
	return poolVIPOwnershipUUIDRE.MatchString(value) && value != "00000000-0000-0000-0000-000000000000"
}
func validPoolVIPOwnershipIPv4(value string) bool {
	addr, err := netip.ParseAddr(value)
	return err == nil && addr.Is4() && addr.String() == value
}
func validPoolVIPOwnershipDNSLabel(value string) bool {
	return len(value) >= 1 && len(value) <= 63 && poolVIPOwnershipDNSLabelRE.MatchString(value)
}
func validPoolVIPOwnershipDNSName(value string) bool {
	if len(value) < 1 || len(value) > 253 {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if !validPoolVIPOwnershipDNSLabel(label) {
			return false
		}
	}
	return true
}
