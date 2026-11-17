package ipsec

import (
	"reflect"
	"time"
)

// The canonical replacement may intentionally omit a grant inside its commit
// cutoff while its original authority is still finite. Preserve only the need
// to fetch current material; deadline zero never claims an installed member.
// Unknown/refusal transports and expired or retracted policy cannot create it.
func (c *RuntimeController) fqdnOmittedWindowEligible(connection GuardConnection, owner runtimeActive) bool {
	if connection.PrefixOnly || connection.ID != owner.Entry.Allocation.ConnectionID || connection.PermitFor < time.Second || len(connection.PermittedInterfaceIndices) == 0 || len(connection.ReplyIngressIndices) == 0 || !runtimeFQDNFollowupEntrySupported(owner.Entry) || owner.Entry.Phase != RuntimeApplied || owner.Entry.AbsenceOnly {
		return false
	}
	for _, g := range connection.Grants {
		if g.FQDNManaged {
			return false
		}
	}
	return c.fqdnOmittedOwnerCurrent(owner)
}

func (c *RuntimeController) fqdnOmittedOwnerCurrent(owner runtimeActive) bool {
	// Restrict the new scheduling case to the same completed AWS desktop
	// transport contract. Other provider scheduling remains unchanged.
	if owner.Entry.Allocation.ProfileID != "" || (owner.Delivery.Manifest.ProfileID != "aws-static-ipv4-v1" && owner.Delivery.Manifest.ProfileID != "aws-bgp-ipv4-v1") || owner.Authority == nil || len(owner.FQDNLeaseDescriptors) == 0 || !c.fqdnGrantsCurrent(owner.Grants) {
		return false
	}
	if _, err := owner.Authority.RemainingForApply(owner.Identity, time.Millisecond); err != nil {
		return false
	}
	count := 0
	for _, g := range owner.Grants {
		if !g.FQDNManaged {
			continue
		}
		if g.FQDN.Version != 2 || !g.FQDN.valid() || !g.FQDN.ExpiresAt.After(time.Now()) {
			return false
		}
		key := guardFQDNGrantDigest(g)
		if _, err := owner.Authority.RemainingFQDNForApply(owner.Identity, key, time.Millisecond); err != nil {
			return false
		}
		matches := 0
		for _, descriptor := range owner.FQDNLeaseDescriptors {
			if runtimeFQDNGrantDigest(descriptor) == key {
				matches++
			}
		}
		if matches != 1 {
			return false
		}
		count++
	}
	return count == len(owner.FQDNLeaseDescriptors)
}

// Both cases bind exact current ownership. Omitted advice additionally requires
// every ORIGINAL FQDN deadline to remain live; it cannot resurrect expired
// material, infer a lease from DNS, or bypass the later full native proof.
func (c *RuntimeController) fqdnRefreshWindowCurrent(window runtimeFQDNNativeWindow, owner runtimeActive, now time.Duration) bool {
	if owner.Authority == nil || owner.Authority != window.owner.Authority || !reflect.DeepEqual(owner, window.owner) {
		return false
	}
	if window.omitted {
		return window.deadline == 0 && c.fqdnOmittedOwnerCurrent(owner)
	}
	return window.deadline > now
}
