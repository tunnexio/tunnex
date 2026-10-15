package ipsec

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
)

func HashRuntimePolicy(result RuntimePolicy, input RuntimePolicyInput) (RuntimePolicy, error) {
	// Bind the hash to this exact connection even when its effective policy is
	// empty. Hash only canonical nonsecret forwarding authority, never PSKs.
	raw, err := json.Marshal(struct {
		Org, Node, Site, Connection uuid.UUID
		DesktopGrants               []RuntimeDesktopGrant `json:"desktop_grants,omitempty"`
		Grants                      []RuntimeGrant
		DNSResolverGrants           []RuntimeDNSResolverGrant       `json:"dns_resolver_grants,omitempty"`
		DNSResolverProfiles         []policyspec.DNSResolverProfile `json:"dns_resolver_profiles,omitempty"`
		FQDNPolicyVersion           int                             `json:"fqdn_policy_version,omitempty"`
		FQDNGrants                  []RuntimeFQDNGrant              `json:"fqdn_grants,omitempty"`
	}{input.OrgID, input.NodeID, input.SiteID, input.ConnectionID, result.DesktopGrants, result.Grants, result.DNSResolverGrants, result.DNSResolverProfiles, result.FQDNPolicyVersion, result.FQDNGrants})
	if err != nil {
		return RuntimePolicy{}, ErrConnectionUnavailable
	}
	hash := sha256.Sum256(raw)
	result.Hash = hex.EncodeToString(hash[:])
	return result, nil
}
