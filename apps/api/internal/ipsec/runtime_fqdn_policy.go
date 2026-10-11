package ipsec

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/fqdn"
	"net/netip"
	"strings"
	"time"
)

func validRuntimeFQDNPolicy(policy RuntimePolicy, input RuntimePolicyInput) bool {
	return validRuntimeFQDNPolicyAt(policy, input, input.CompiledAt, false)
}
func validRuntimeFQDNPolicyAt(policy RuntimePolicy, input RuntimePolicyInput, now time.Time, allowExpired bool) bool {
	if len(policy.FQDNGrants) == 0 {
		return policy.FQDNPolicyVersion == 0
	}
	if (input.FQDNPolicyVersion != 1 && input.FQDNPolicyVersion != 2) || policy.FQDNPolicyVersion != input.FQDNPolicyVersion || input.ConfigurationRevision != 1 {
		return false
	}
	seen := make(map[RuntimeFQDNGrant]bool)
	for _, g := range policy.FQDNGrants {
		if !g.FQDNManaged || seen[g] || g.ConnectionID != input.ConnectionID.String() || g.ConfigurationRevision != input.ConfigurationRevision || g.SelectedSiteID != input.SiteID.String() || g.SelectedGatewayID != input.NodeID.String() || !runtimeDigest(g.Generation) || g.ResolverConfigVersion < 1 {
			return false
		}
		for _, raw := range []string{g.RuleID, g.ResourceID, g.ResolverConfigID, g.ResolverProfileID} {
			id, err := uuid.Parse(raw)
			if err != nil || id == uuid.Nil || id.String() != raw {
				return false
			}
		}
		name, err := fqdn.Normalize(g.Name)
		if err != nil || name != g.Name {
			return false
		}
		if g.ResolverMatchSuffix != "" {
			suffix, err := fqdn.Normalize("resolver-root." + g.ResolverMatchSuffix)
			if err != nil || suffix != "resolver-root."+g.ResolverMatchSuffix || (name != g.ResolverMatchSuffix && !strings.HasSuffix(name, "."+g.ResolverMatchSuffix)) {
				return false
			}
		}
		source, err := netip.ParsePrefix(g.Source)
		if err != nil || !source.Addr().Is4() || source != source.Masked() || source.String() != g.Source || !runtimeFQDNWithin(source, input.Config.LocalPrefixes) {
			return false
		}
		destination, err := netip.ParsePrefix(g.Destination)
		if err != nil || !destination.Addr().Is4() || destination.Bits() != 32 || destination.String() != g.Destination || !runtimeFQDNWithin(destination, input.Config.RemotePrefixes) || !runtimeFQDNAddressSafe(destination.Addr()) {
			return false
		}
		if g.Protocol != "any" && g.Protocol != "tcp" && g.Protocol != "udp" || g.PortLow > g.PortHigh || (g.Protocol == "any" && (g.PortLow != 0 || g.PortHigh != 0)) || (g.Protocol != "any" && g.PortLow == 0 && g.PortHigh != 0) {
			return false
		}
		if policy.FQDNPolicyVersion == 1 {
			if !g.ExpiresAt.IsZero() || g.ResolverSourceAddress != "" {
				return false
			}
		} else {
			source, err := netip.ParseAddr(g.ResolverSourceAddress)
			if now.IsZero() || g.ExpiresAt.IsZero() || (!allowExpired && !g.ExpiresAt.After(now)) || g.ExpiresAt.After(now.Add(time.Hour)) || err != nil || source.String() != g.ResolverSourceAddress || !source.Is4() || !source.IsPrivate() || !runtimeFQDNWithin(netip.PrefixFrom(source, 32), input.Config.LocalPrefixes) {
				return false
			}
		}
		seen[g] = true
	}
	return true
}
func runtimeFQDNWithin(prefix netip.Prefix, ranges []string) bool {
	for _, raw := range ranges {
		outer, err := netip.ParsePrefix(raw)
		if err == nil && outer.Addr().Is4() && outer == outer.Masked() && outer.Bits() <= prefix.Bits() && outer.Contains(prefix.Addr()) {
			return true
		}
	}
	return false
}
func runtimeFQDNAddressSafe(address netip.Addr) bool {
	if !address.Is4() || address.IsUnspecified() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsMulticast() {
		return false
	}
	for _, raw := range []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "169.254.169.254/32"} {
		if netip.MustParsePrefix(raw).Contains(address) {
			return false
		}
	}
	return true
}

// Descriptor bytes are canonical API/node wire bytes. Renewal duration is not
// part of this identity; tuple, provenance, absolute expiry and source all are.
func runtimeFQDNGrantDigest(g RuntimeFQDNGrant) string {
	raw, _ := json.Marshal(g)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// Called only after transaction commit. observedAt is authoritative DB time;
// elapsed is measured from a monotonic fence BEFORE that query, conservatively
// charging the query and commit. API wall-clock skew cannot extend authority.
func runtimeFQDNLeasePermits(policy RuntimePolicy, observedAt time.Time, elapsed time.Duration) ([]RuntimeFQDNPermit, error) {
	if policy.FQDNPolicyVersion != 2 || len(policy.FQDNGrants) == 0 {
		return nil, nil
	}
	if observedAt.IsZero() || elapsed < 0 || len(policy.FQDNGrants) > 128 {
		return nil, ErrConnectionConflict
	}
	seen := map[string]bool{}
	out := make([]RuntimeFQDNPermit, 0, len(policy.FQDNGrants))
	for _, g := range policy.FQDNGrants {
		key := runtimeFQDNGrantDigest(g)
		if g.ExpiresAt.IsZero() || seen[key] {
			return nil, ErrConnectionConflict
		}
		seen[key] = true
		ttl := int64(0)
		if g.ExpiresAt.After(observedAt) {
			remaining := g.ExpiresAt.Sub(observedAt)
			if elapsed < remaining {
				ttl = (remaining - elapsed).Milliseconds()
			}
		}
		if ttl < 0 {
			ttl = 0
		}
		if ttl > 60000 {
			ttl = 60000
		}
		out = append(out, RuntimeFQDNPermit{GrantDigest: key, TTLMS: ttl})
	}
	return out, nil
}

// A zero-only expired descriptor can preserve the old immutable policy hash,
// but never restore retired application authority. Expired revoked descriptors
// cannot be distinguished from natural expiry; both get zero, while CURRENT
// ordinary/DNS and every CURRENT live descriptor remain mandatory.
func runtimeFQDNLeaseContinuity(current RuntimePolicy, request RuntimeLeaseRequest, input RuntimePolicyInput, fence time.Time) (RuntimePolicy, map[string]bool, error) {
	expired := map[string]bool{}
	if len(request.FQDNGrants) == 0 {
		if current.FQDNPolicyVersion == 2 && len(current.FQDNGrants) != 0 || current.Hash != request.PolicyHash {
			return RuntimePolicy{}, nil, ErrConnectionConflict
		}
		return current, expired, nil
	}
	if input.FQDNPolicyVersion != 2 || fence.IsZero() || len(current.Grants)+len(request.FQDNGrants)+2*len(current.DNSResolverGrants) > 128 {
		return RuntimePolicy{}, nil, ErrConnectionConflict
	}
	reconstructed := current
	reconstructed.FQDNPolicyVersion = 2
	reconstructed.FQDNGrants = append([]RuntimeFQDNGrant(nil), request.FQDNGrants...)
	if !validRuntimeFQDNPolicyAt(reconstructed, input, fence, true) {
		return RuntimePolicy{}, nil, ErrConnectionConflict
	}
	live := map[RuntimeFQDNGrant]bool{}
	for _, g := range current.FQDNGrants {
		live[g] = true
	}
	previous := ""
	for _, g := range request.FQDNGrants {
		raw, _ := json.Marshal(g)
		if previous != "" && string(raw) <= previous {
			return RuntimePolicy{}, nil, ErrConnectionConflict
		}
		previous = string(raw)
		if live[g] {
			delete(live, g)
		} else {
			if g.ExpiresAt.After(fence) {
				return RuntimePolicy{}, nil, ErrConnectionConflict
			}
			expired[runtimeFQDNGrantDigest(g)] = true
		}
	}
	if len(live) != 0 {
		return RuntimePolicy{}, nil, ErrConnectionConflict
	}
	reconstructed, e := HashRuntimePolicy(reconstructed, input)
	if e != nil || reconstructed.Hash != request.PolicyHash {
		return RuntimePolicy{}, nil, ErrConnectionConflict
	}
	return reconstructed, expired, nil
}

// V1 cannot selectively time individual memberships, so its whole owner lease
// ends at the earliest emitted answer/rule cutoff. V2 ordinary/DNS stay 60s.
func runtimeFQDNWholeLeaseTTL(policy RuntimePolicy, observedAt time.Time, elapsed time.Duration) (int64, error) {
	if policy.FQDNPolicyVersion != 1 || len(policy.FQDNGrants) == 0 {
		return 60000, nil
	}
	if observedAt.IsZero() || elapsed < 0 || !policy.FQDNLeaseDeadline.After(observedAt) {
		return 0, ErrConnectionConflict
	}
	remaining := policy.FQDNLeaseDeadline.Sub(observedAt)
	if elapsed >= remaining {
		return 0, ErrConnectionConflict
	}
	ttl := (remaining - elapsed).Milliseconds()
	if ttl <= 0 {
		return 0, ErrConnectionConflict
	}
	if ttl > 60000 {
		ttl = 60000
	}
	return ttl, nil
}

// Match the existing agent decoder's body ceiling. Count admission alone does
// not promise that 128 maximal descriptors fit this unchanged transport bound.
const runtimeLeaseRequestByteLimit = 128 << 10

func runtimeLeaseRequestFits(request RuntimeLeaseRequest) bool {
	raw, e := json.Marshal(request)
	return e == nil && len(raw) <= runtimeLeaseRequestByteLimit
}
func runtimeMaterialLeaseRequestFits(delivery RuntimeDelivery, policy RuntimePolicy) bool {
	if policy.FQDNPolicyVersion != 2 {
		return true
	}
	return runtimeLeaseRequestFits(RuntimeLeaseRequest{DeliveryID: delivery.ID, DesiredRevision: delivery.DesiredRevision, PolicyHash: policy.Hash, Nonce: strings.Repeat("0", 64), FQDNGrants: policy.FQDNGrants})
}
