package nodes

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
)

const KubernetesOwnershipBaseAuthorityWireVersion = 1

var (
	ErrKubernetesOwnershipBaseAuthorityInvalid  = errors.New("Kubernetes ownership base authority is invalid")
	ErrKubernetesOwnershipBaseAuthorityConflict = errors.New("Kubernetes ownership base authority conflicts with durable state")
	kubernetesOwnershipHex64RE                  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	kubernetesOwnershipDNSLabelRE               = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

type KubernetesOwnershipPoolDisposition string

const (
	KubernetesOwnershipPoolDispositionArmFence      KubernetesOwnershipPoolDisposition = "arm_fence"
	KubernetesOwnershipPoolDispositionMaintainFence KubernetesOwnershipPoolDisposition = "maintain_fence"
)

type KubernetesOwnershipPoolScope struct {
	OrgID     string `json:"org_id"`
	SiteID    string `json:"site_id"`
	ClusterID string `json:"cluster_id"`
	PoolID    string `json:"pool_id"`
}

type KubernetesOwnershipWGPeer struct {
	PublicKey  string   `json:"public_key"`
	AllowedIPs []string `json:"allowed_ips"`
}

type KubernetesOwnershipPoolFields struct {
	Routes      []string                    `json:"routes"`
	WGPeers     []KubernetesOwnershipWGPeer `json:"wg_peers"`
	VIPMappings []policyspec.VIPMapping     `json:"vip_mappings"`
	DNSZones    []policyspec.K8sDNSZone     `json:"dns_zones"`
}

type KubernetesOwnershipPoolClassification struct {
	Scope       KubernetesOwnershipPoolScope       `json:"scope"`
	Disposition KubernetesOwnershipPoolDisposition `json:"disposition"`
	Fields      KubernetesOwnershipPoolFields      `json:"fields"`
}

type KubernetesOwnershipBaseAuthority struct {
	WireVersion       int                                     `json:"wire_version"`
	AuthorityRevision uint64                                  `json:"authority_revision"`
	NodeID            string                                  `json:"node_id"`
	OrgID             string                                  `json:"org_id"`
	SiteID            string                                  `json:"site_id"`
	BaseVersion       uint64                                  `json:"base_version"`
	BaseHash          string                                  `json:"base_hash"`
	Classifications   []KubernetesOwnershipPoolClassification `json:"classifications"`
	UnfencedPools     []KubernetesOwnershipPoolScope          `json:"unfenced_pools"`
}

type KubernetesOwnershipBaseAuthorityAck struct {
	WireVersion       int    `json:"wire_version"`
	AuthorityRevision uint64 `json:"authority_revision"`
	NodeID            string `json:"node_id"`
	OrgID             string `json:"org_id"`
	SiteID            string `json:"site_id"`
	BaseVersion       uint64 `json:"base_version"`
	BaseHash          string `json:"base_hash"`
	AuthorityDigest   string `json:"authority_digest"`
	AppliedAt         string `json:"applied_at"`
}

type KubernetesOwnershipBaseAuthorityAgentIdentity struct {
	NodeID uuid.UUID
	OrgID  uuid.UUID
	SiteID uuid.UUID
}

type KubernetesOwnershipBaseAuthorityPoolGeneration struct {
	Scope               KubernetesOwnershipPoolScope
	PromotionGeneration uint64
}

type KubernetesOwnershipBaseAuthorityIssue struct {
	Authority          KubernetesOwnershipBaseAuthority
	Pools              []KubernetesOwnershipBaseAuthorityPoolGeneration
	TransitionRevision uint64
	ExpiresAt          time.Time
	// OrdinaryBaseUpdate is the closed exception to transition-revision replay:
	// after a pool is fenced, a later full desired-state snapshot must carry a
	// newer maintain_fence authority even though no operator transition changed.
	// The store accepts this mode only for maintain_fence classifications and
	// never for arm_fence or unfence deliveries.
	OrdinaryBaseUpdate bool
}

type KubernetesOwnershipBaseAuthorityIssueResult struct {
	DeliveryID    uuid.UUID
	Authority     KubernetesOwnershipBaseAuthority
	PayloadDigest string
	Duplicate     bool
}

func CanonicalKubernetesOwnershipBaseAuthority(value KubernetesOwnershipBaseAuthority) (KubernetesOwnershipBaseAuthority, string, error) {
	if value.WireVersion != KubernetesOwnershipBaseAuthorityWireVersion || value.AuthorityRevision == 0 || value.BaseVersion == 0 ||
		!validKubernetesOwnershipUUID(value.NodeID) || !validKubernetesOwnershipUUID(value.OrgID) || !validKubernetesOwnershipUUID(value.SiteID) ||
		!kubernetesOwnershipHex64RE.MatchString(value.BaseHash) {
		return KubernetesOwnershipBaseAuthority{}, "", ErrKubernetesOwnershipBaseAuthorityInvalid
	}
	seen := map[string]struct{}{}
	for i := range value.Classifications {
		item := &value.Classifications[i]
		if !validKubernetesOwnershipScope(item.Scope) || item.Scope.OrgID != value.OrgID || item.Scope.SiteID != value.SiteID ||
			(item.Disposition != KubernetesOwnershipPoolDispositionArmFence && item.Disposition != KubernetesOwnershipPoolDispositionMaintainFence) {
			return KubernetesOwnershipBaseAuthority{}, "", ErrKubernetesOwnershipBaseAuthorityInvalid
		}
		if _, duplicate := seen[item.Scope.PoolID]; duplicate {
			return KubernetesOwnershipBaseAuthority{}, "", ErrKubernetesOwnershipBaseAuthorityInvalid
		}
		seen[item.Scope.PoolID] = struct{}{}
		fields, err := canonicalKubernetesOwnershipPoolFields(item.Fields)
		if err != nil {
			return KubernetesOwnershipBaseAuthority{}, "", err
		}
		item.Fields = fields
	}
	for _, scope := range value.UnfencedPools {
		if !validKubernetesOwnershipScope(scope) || scope.OrgID != value.OrgID || scope.SiteID != value.SiteID {
			return KubernetesOwnershipBaseAuthority{}, "", ErrKubernetesOwnershipBaseAuthorityInvalid
		}
		if _, duplicate := seen[scope.PoolID]; duplicate {
			return KubernetesOwnershipBaseAuthority{}, "", ErrKubernetesOwnershipBaseAuthorityInvalid
		}
		seen[scope.PoolID] = struct{}{}
	}
	if len(seen) == 0 {
		return KubernetesOwnershipBaseAuthority{}, "", ErrKubernetesOwnershipBaseAuthorityInvalid
	}
	if value.Classifications == nil {
		value.Classifications = []KubernetesOwnershipPoolClassification{}
	}
	if value.UnfencedPools == nil {
		value.UnfencedPools = []KubernetesOwnershipPoolScope{}
	}
	sort.Slice(value.Classifications, func(i, j int) bool {
		return value.Classifications[i].Scope.PoolID < value.Classifications[j].Scope.PoolID
	})
	sort.Slice(value.UnfencedPools, func(i, j int) bool { return value.UnfencedPools[i].PoolID < value.UnfencedPools[j].PoolID })
	b, err := json.Marshal(value)
	if err != nil {
		return KubernetesOwnershipBaseAuthority{}, "", err
	}
	sum := sha256.Sum256(b)
	return value, hex.EncodeToString(sum[:]), nil
}

func KubernetesOwnershipBaseStateHash(base DesiredState) (string, error) {
	view := struct {
		ProtocolVersion  int                  `json:"protocol_version"`
		NodeID           string               `json:"node_id"`
		InterfaceAddress string               `json:"interface_address"`
		MTU              int                  `json:"mtu"`
		ListenPort       int                  `json:"listen_port"`
		Peers            []Peer               `json:"peers"`
		Policy           *policyspec.Compiled `json:"policy,omitempty"`
		OVPNEnabled      bool                 `json:"ovpn_enabled,omitempty"`
		OVPNClients      []OVPNClient         `json:"ovpn_clients,omitempty"`
		OVPNServer       *OVPNServerMaterial  `json:"ovpn_server,omitempty"`
	}{base.ProtocolVersion, base.NodeID, base.InterfaceAddress, base.MTU, base.ListenPort,
		base.Peers, base.Policy, base.OVPNEnabled, base.OVPNClients, base.OVPNServer}
	b, err := json.Marshal(view)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func ValidateKubernetesOwnershipBaseAuthorityAck(agent KubernetesOwnershipBaseAuthorityAgentIdentity, authority KubernetesOwnershipBaseAuthority, payloadDigest string, ack KubernetesOwnershipBaseAuthorityAck) (time.Time, error) {
	if agent.NodeID == uuid.Nil || agent.OrgID == uuid.Nil || agent.SiteID == uuid.Nil ||
		ack.WireVersion != KubernetesOwnershipBaseAuthorityWireVersion || ack.AuthorityRevision != authority.AuthorityRevision ||
		ack.NodeID != agent.NodeID.String() || ack.OrgID != agent.OrgID.String() || ack.SiteID != agent.SiteID.String() ||
		authority.NodeID != ack.NodeID || authority.OrgID != ack.OrgID || authority.SiteID != ack.SiteID ||
		ack.BaseVersion != authority.BaseVersion || ack.BaseHash != authority.BaseHash || ack.AuthorityDigest != payloadDigest ||
		!kubernetesOwnershipHex64RE.MatchString(ack.AuthorityDigest) {
		return time.Time{}, ErrKubernetesOwnershipBaseAuthorityInvalid
	}
	appliedAt, err := time.Parse(time.RFC3339Nano, ack.AppliedAt)
	if err != nil || appliedAt.IsZero() || ack.AppliedAt != appliedAt.UTC().Format(time.RFC3339Nano) {
		return time.Time{}, ErrKubernetesOwnershipBaseAuthorityInvalid
	}
	return appliedAt.UTC(), nil
}

func canonicalKubernetesOwnershipPoolFields(value KubernetesOwnershipPoolFields) (KubernetesOwnershipPoolFields, error) {
	var err error
	value.Routes, err = canonicalKubernetesOwnershipPrefixes(value.Routes)
	if err != nil || len(value.Routes) == 0 {
		return KubernetesOwnershipPoolFields{}, ErrKubernetesOwnershipBaseAuthorityInvalid
	}
	value.WGPeers, err = canonicalKubernetesOwnershipWGPeers(value.WGPeers)
	if err != nil || len(value.WGPeers) == 0 {
		return KubernetesOwnershipPoolFields{}, ErrKubernetesOwnershipBaseAuthorityInvalid
	}
	value.VIPMappings, err = canonicalKubernetesOwnershipVIPMappings(value.VIPMappings)
	if err != nil {
		return KubernetesOwnershipPoolFields{}, err
	}
	value.DNSZones, err = canonicalKubernetesOwnershipDNSZones(value.DNSZones)
	if err != nil {
		return KubernetesOwnershipPoolFields{}, err
	}
	return value, nil
}

func canonicalKubernetesOwnershipPrefixes(values []string) ([]string, error) {
	out := append([]string(nil), values...)
	for _, value := range out {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() || prefix.String() != value {
			return nil, ErrKubernetesOwnershipBaseAuthorityInvalid
		}
	}
	sort.Strings(out)
	for i := 1; i < len(out); i++ {
		if out[i] == out[i-1] {
			return nil, ErrKubernetesOwnershipBaseAuthorityInvalid
		}
	}
	return out, nil
}

func canonicalKubernetesOwnershipWGPeers(values []KubernetesOwnershipWGPeer) ([]KubernetesOwnershipWGPeer, error) {
	out := make([]KubernetesOwnershipWGPeer, 0, len(values))
	seenKeys, seenPrefixes := map[string]struct{}{}, map[string]struct{}{}
	for _, value := range values {
		decoded, err := base64.StdEncoding.Strict().DecodeString(value.PublicKey)
		if err != nil || len(decoded) != 32 || base64.StdEncoding.EncodeToString(decoded) != value.PublicKey {
			return nil, ErrKubernetesOwnershipBaseAuthorityInvalid
		}
		if _, duplicate := seenKeys[value.PublicKey]; duplicate {
			return nil, ErrKubernetesOwnershipBaseAuthorityInvalid
		}
		allowed, err := canonicalKubernetesOwnershipPrefixes(value.AllowedIPs)
		if err != nil || len(allowed) == 0 {
			return nil, ErrKubernetesOwnershipBaseAuthorityInvalid
		}
		for _, prefix := range allowed {
			if _, duplicate := seenPrefixes[prefix]; duplicate {
				return nil, ErrKubernetesOwnershipBaseAuthorityInvalid
			}
			seenPrefixes[prefix] = struct{}{}
		}
		seenKeys[value.PublicKey] = struct{}{}
		out = append(out, KubernetesOwnershipWGPeer{PublicKey: value.PublicKey, AllowedIPs: allowed})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PublicKey < out[j].PublicKey })
	return out, nil
}

func canonicalKubernetesOwnershipVIPMappings(values []policyspec.VIPMapping) ([]policyspec.VIPMapping, error) {
	out := append([]policyspec.VIPMapping(nil), values...)
	seen := map[string]struct{}{}
	for _, value := range out {
		vip, vipErr := netip.ParseAddr(value.VIP)
		serviceCIDR, cidrErr := netip.ParsePrefix(value.ServiceCIDR)
		if !validKubernetesOwnershipUUID(value.ServiceID) || vipErr != nil || !vip.Is4() || vip.String() != value.VIP ||
			cidrErr != nil || !serviceCIDR.Addr().Is4() || serviceCIDR != serviceCIDR.Masked() || serviceCIDR.String() != value.ServiceCIDR ||
			!validKubernetesOwnershipDNSName(value.Namespace) || !validKubernetesOwnershipDNSName(value.Service) || !validKubernetesOwnershipDNSName(value.DNSName) ||
			(value.Protocol != "tcp" && value.Protocol != "udp") || value.PortLow < 1 || value.PortLow != value.PortHigh || value.PortHigh > 65535 {
			return nil, ErrKubernetesOwnershipBaseAuthorityInvalid
		}
		if _, duplicate := seen[value.ServiceID]; duplicate {
			return nil, ErrKubernetesOwnershipBaseAuthorityInvalid
		}
		seen[value.ServiceID] = struct{}{}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ServiceID < out[j].ServiceID })
	return out, nil
}

func canonicalKubernetesOwnershipDNSZones(values []policyspec.K8sDNSZone) ([]policyspec.K8sDNSZone, error) {
	out := append([]policyspec.K8sDNSZone(nil), values...)
	seen := map[string]struct{}{}
	for _, value := range out {
		vip, err := netip.ParseAddr(value.ListenVIP)
		zone := strings.TrimSuffix(strings.ToLower(value.Zone), ".")
		if err != nil || !vip.Is4() || vip.String() != value.ListenVIP || !validKubernetesOwnershipDNSName(zone) || zone != value.Zone {
			return nil, ErrKubernetesOwnershipBaseAuthorityInvalid
		}
		key := value.ListenVIP + "\x00" + value.Zone
		if _, duplicate := seen[key]; duplicate {
			return nil, ErrKubernetesOwnershipBaseAuthorityInvalid
		}
		seen[key] = struct{}{}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ListenVIP+"\x00"+out[i].Zone < out[j].ListenVIP+"\x00"+out[j].Zone })
	return out, nil
}

func validKubernetesOwnershipScope(value KubernetesOwnershipPoolScope) bool {
	return validKubernetesOwnershipUUID(value.OrgID) && validKubernetesOwnershipUUID(value.SiteID) &&
		validKubernetesOwnershipUUID(value.ClusterID) && validKubernetesOwnershipUUID(value.PoolID)
}

func validKubernetesOwnershipUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

func validKubernetesOwnershipDNSName(value string) bool {
	if value == "" || len(value) > 253 || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) > 63 || !kubernetesOwnershipDNSLabelRE.MatchString(label) {
			return false
		}
	}
	return true
}

func canonicalKubernetesOwnershipBaseAuthorityJSON(value KubernetesOwnershipBaseAuthority) ([]byte, string, error) {
	canonical, digest, err := CanonicalKubernetesOwnershipBaseAuthority(value)
	if err != nil {
		return nil, "", err
	}
	b, err := json.Marshal(canonical)
	return b, digest, err
}

func sameKubernetesOwnershipBaseAuthority(a, b KubernetesOwnershipBaseAuthority) bool {
	aJSON, aDigest, aErr := canonicalKubernetesOwnershipBaseAuthorityJSON(a)
	bJSON, bDigest, bErr := canonicalKubernetesOwnershipBaseAuthorityJSON(b)
	return aErr == nil && bErr == nil && aDigest == bDigest && string(aJSON) == string(bJSON)
}

func validateKubernetesOwnershipIssuePools(authority KubernetesOwnershipBaseAuthority, pools []KubernetesOwnershipBaseAuthorityPoolGeneration) (map[string]KubernetesOwnershipBaseAuthorityPoolGeneration, error) {
	want := map[string]KubernetesOwnershipPoolScope{}
	for _, item := range authority.Classifications {
		want[item.Scope.PoolID] = item.Scope
	}
	for _, scope := range authority.UnfencedPools {
		want[scope.PoolID] = scope
	}
	got := make(map[string]KubernetesOwnershipBaseAuthorityPoolGeneration, len(pools))
	for _, item := range pools {
		if item.PromotionGeneration == 0 || item.PromotionGeneration > math.MaxInt64 || item.Scope != want[item.Scope.PoolID] {
			return nil, fmt.Errorf("%w: pool generation scope", ErrKubernetesOwnershipBaseAuthorityInvalid)
		}
		if _, duplicate := got[item.Scope.PoolID]; duplicate {
			return nil, fmt.Errorf("%w: duplicate pool generation", ErrKubernetesOwnershipBaseAuthorityInvalid)
		}
		got[item.Scope.PoolID] = item
	}
	if len(got) != len(want) {
		return nil, fmt.Errorf("%w: incomplete pool generations", ErrKubernetesOwnershipBaseAuthorityInvalid)
	}
	return got, nil
}
