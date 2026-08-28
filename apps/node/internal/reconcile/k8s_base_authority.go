package reconcile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
)

const KubernetesOwnershipBaseAuthorityWireVersion = 1

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

// KubernetesOwnershipPoolFields is base-state attribution only. It contains
// no lease epoch, manifest revision, or delivery identity because an authority
// classification may arm a non-serving standby before any serving lease
// exists.
type KubernetesOwnershipPoolFields struct {
	Routes      []string                    `json:"routes"`
	WGPeers     []KubernetesOwnershipWGPeer `json:"wg_peers"`
	VIPMappings []nodepolicy.VIPMapping     `json:"vip_mappings"`
	DNSZones    []nodepolicy.K8sDNSZone     `json:"dns_zones"`
}

type KubernetesOwnershipPoolClassification struct {
	Scope       KubernetesOwnershipPoolScope       `json:"scope"`
	Disposition KubernetesOwnershipPoolDisposition `json:"disposition"`
	Fields      KubernetesOwnershipPoolFields      `json:"fields"`
}

// KubernetesOwnershipBaseAuthority is an additive private-mTLS desired-state
// field. Older agents ignore it. New agents treat absence as legacy mode and
// never infer an unfence from omission.
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

// UnmarshalJSON makes the security-bearing authority object strict even
// though the surrounding desired-state response remains additive and
// mixed-version compatible.
func (a *KubernetesOwnershipBaseAuthority) UnmarshalJSON(raw []byte) error {
	if err := rejectDuplicateAuthorityJSONKeys(raw); err != nil {
		return err
	}
	type alias KubernetesOwnershipBaseAuthority
	var decoded alias
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple Kubernetes ownership base-authority values")
		}
		return err
	}
	*a = KubernetesOwnershipBaseAuthority(decoded)
	return nil
}

func rejectDuplicateAuthorityJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := scanAuthorityJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple Kubernetes ownership base-authority values")
		}
		return err
	}
	return nil
}

func scanAuthorityJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok {
				return fmt.Errorf("Kubernetes ownership base-authority key is not a string")
			}
			if _, duplicate := seen[name]; duplicate {
				return fmt.Errorf("duplicate Kubernetes ownership base-authority key %q", name)
			}
			seen[name] = struct{}{}
			if err := scanAuthorityJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		for decoder.More() {
			if err := scanAuthorityJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		return fmt.Errorf("invalid Kubernetes ownership base-authority JSON")
	}
}
