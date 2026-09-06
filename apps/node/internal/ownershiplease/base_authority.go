package ownershiplease

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
	"github.com/tunnexio/tunnex/apps/node/internal/reconcile"
)

const BaseAuthorityStateVersion = 1

var (
	ErrBaseAuthorityInvalid       = errors.New("Kubernetes ownership base authority is invalid")
	ErrBaseAuthorityStale         = errors.New("Kubernetes ownership base authority revision is stale")
	ErrBaseAuthorityChangedReplay = errors.New("Kubernetes ownership base authority revision changed on replay")
)

type BaseAuthorityState struct {
	Version           int                                            `json:"version"`
	AuthorityRevision uint64                                         `json:"authority_revision"`
	Fingerprint       string                                         `json:"fingerprint"`
	PendingAck        *reconcile.KubernetesOwnershipBaseAuthorityAck `json:"pending_ack,omitempty"`
}

type BaseAuthorityStateStore interface {
	LoadBaseAuthorityState(context.Context) (BaseAuthorityState, bool, error)
	SaveBaseAuthorityState(context.Context, BaseAuthorityState) error
}

func BaseAuthorityFromWire(value *reconcile.KubernetesOwnershipBaseAuthority) BaseAuthority {
	if value == nil {
		return BaseAuthority{}
	}
	out := BaseAuthority{
		Present: true, WireVersion: value.WireVersion, AuthorityRevision: value.AuthorityRevision, NodeID: value.NodeID,
		OrgID: value.OrgID, SiteID: value.SiteID, BaseVersion: value.BaseVersion, BaseHash: value.BaseHash,
	}
	for _, item := range value.Classifications {
		fields := PoolOwnedBaseFields{Routes: append([]string(nil), item.Fields.Routes...), VIPMappings: append([]nodepolicy.VIPMapping(nil), item.Fields.VIPMappings...), DNSZones: append([]nodepolicy.K8sDNSZone(nil), item.Fields.DNSZones...)}
		for _, peer := range item.Fields.WGPeers {
			fields.WGPeers = append(fields.WGPeers, WGPeerOwnership{PublicKey: peer.PublicKey, AllowedIPs: append([]string(nil), peer.AllowedIPs...)})
		}
		out.Classifications = append(out.Classifications, PoolClassification{Scope: poolScopeFromWire(item.Scope), Disposition: PoolClassificationDisposition(item.Disposition), Fields: fields})
	}
	for _, scope := range value.UnfencedPools {
		out.UnfencedPools = append(out.UnfencedPools, poolScopeFromWire(scope))
	}
	return out
}

func poolScopeFromWire(value reconcile.KubernetesOwnershipPoolScope) PoolScope {
	return PoolScope{OrgID: value.OrgID, SiteID: value.SiteID, ClusterID: value.ClusterID, PoolID: value.PoolID}
}

// BaseStateHash is the canonical ordinary data-plane snapshot hash. The
// authority object is self-referential, the DNS RPC is a transient control
// request, and Version is only the node-push watch cursor, so none belongs to
// the ordinary data-plane base it authorizes.
func BaseStateHash(base reconcile.DesiredState) (string, error) {
	// Keep this explicit view mirrored by the control plane. It makes the hash
	// independent of incidental field ordering in either side's larger desired
	// response struct while retaining the exact wire field order as v1.
	view := struct {
		ProtocolVersion  int                           `json:"protocol_version"`
		NodeID           string                        `json:"node_id"`
		InterfaceAddress string                        `json:"interface_address"`
		MTU              int                           `json:"mtu"`
		ListenPort       int                           `json:"listen_port"`
		Peers            []reconcile.Peer              `json:"peers"`
		Policy           *nodepolicy.Compiled          `json:"policy,omitempty"`
		OVPNEnabled      bool                          `json:"ovpn_enabled,omitempty"`
		OVPNClients      []reconcile.OVPNClient        `json:"ovpn_clients,omitempty"`
		OVPNServer       *reconcile.OVPNServerMaterial `json:"ovpn_server,omitempty"`
	}{base.ProtocolVersion, base.NodeID, base.InterfaceAddress, base.MTU, base.ListenPort,
		base.Peers, base.Policy, base.OVPNEnabled, base.OVPNClients, base.OVPNServer}
	b, err := json.Marshal(view)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func canonicalBaseAuthority(base reconcile.DesiredState, value BaseAuthority) (BaseAuthority, string, error) {
	if value.WireVersion != reconcile.KubernetesOwnershipBaseAuthorityWireVersion || value.AuthorityRevision == 0 ||
		!uuidRE.MatchString(value.NodeID) || value.NodeID == "00000000-0000-0000-0000-000000000000" || value.NodeID != base.NodeID ||
		!uuidRE.MatchString(value.OrgID) || value.OrgID == "00000000-0000-0000-0000-000000000000" ||
		!uuidRE.MatchString(value.SiteID) || value.SiteID == "00000000-0000-0000-0000-000000000000" ||
		value.BaseVersion == 0 || value.BaseVersion != base.Version || !hex64RE.MatchString(value.BaseHash) {
		return BaseAuthority{}, "", ErrBaseAuthorityInvalid
	}
	hash, err := BaseStateHash(base)
	if err != nil || hash != value.BaseHash {
		return BaseAuthority{}, "", ErrBaseAuthorityInvalid
	}
	seen := map[string]struct{}{}
	for i := range value.Classifications {
		item := &value.Classifications[i]
		if !validScope(item.Scope) || item.Scope.OrgID != value.OrgID || item.Scope.SiteID != value.SiteID {
			return BaseAuthority{}, "", ErrBaseAuthorityInvalid
		}
		if item.Disposition != PoolClassificationArmFence && item.Disposition != PoolClassificationMaintainFence {
			return BaseAuthority{}, "", ErrBaseAuthorityInvalid
		}
		if _, duplicate := seen[item.Scope.PoolID]; duplicate {
			return BaseAuthority{}, "", ErrBaseAuthorityInvalid
		}
		seen[item.Scope.PoolID] = struct{}{}
		item.Fields, err = canonicalPoolOwnedBaseFields(item.Fields)
		if err != nil {
			return BaseAuthority{}, "", ErrBaseAuthorityInvalid
		}
	}
	for _, scope := range value.UnfencedPools {
		if !validScope(scope) || scope.OrgID != value.OrgID || scope.SiteID != value.SiteID {
			return BaseAuthority{}, "", ErrBaseAuthorityInvalid
		}
		if _, duplicate := seen[scope.PoolID]; duplicate {
			return BaseAuthority{}, "", ErrBaseAuthorityInvalid
		}
		seen[scope.PoolID] = struct{}{}
	}
	if len(seen) == 0 {
		return BaseAuthority{}, "", ErrBaseAuthorityInvalid
	}
	if value.Classifications == nil {
		value.Classifications = []PoolClassification{}
	}
	if value.UnfencedPools == nil {
		value.UnfencedPools = []PoolScope{}
	}
	sort.Slice(value.Classifications, func(i, j int) bool {
		return value.Classifications[i].Scope.PoolID < value.Classifications[j].Scope.PoolID
	})
	sort.Slice(value.UnfencedPools, func(i, j int) bool { return value.UnfencedPools[i].PoolID < value.UnfencedPools[j].PoolID })
	fingerprint, err := baseAuthorityFingerprint(value)
	if err != nil {
		return BaseAuthority{}, "", err
	}
	return value, fingerprint, nil
}

func baseAuthorityFingerprint(value BaseAuthority) (string, error) {
	b, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func canonicalBaseAuthorityState(value BaseAuthorityState) (BaseAuthorityState, error) {
	if value.Version != BaseAuthorityStateVersion || value.AuthorityRevision == 0 || !hex64RE.MatchString(value.Fingerprint) {
		return BaseAuthorityState{}, ErrBaseAuthorityInvalid
	}
	if value.PendingAck != nil {
		ack := *value.PendingAck
		if ack.WireVersion != reconcile.KubernetesOwnershipBaseAuthorityWireVersion || ack.AuthorityRevision != value.AuthorityRevision ||
			!uuidRE.MatchString(ack.NodeID) || !uuidRE.MatchString(ack.OrgID) || !uuidRE.MatchString(ack.SiteID) ||
			ack.BaseVersion == 0 || !hex64RE.MatchString(ack.BaseHash) || ack.AuthorityDigest != value.Fingerprint {
			return BaseAuthorityState{}, ErrBaseAuthorityInvalid
		}
		at, err := time.Parse(time.RFC3339Nano, ack.AppliedAt)
		if err != nil || at.IsZero() || ack.AppliedAt != at.UTC().Format(time.RFC3339Nano) {
			return BaseAuthorityState{}, ErrBaseAuthorityInvalid
		}
		value.PendingAck = &ack
	}
	return value, nil
}

func baseAuthorityAckMatches(a, b reconcile.KubernetesOwnershipBaseAuthorityAck) bool {
	return reflect.DeepEqual(a, b)
}
