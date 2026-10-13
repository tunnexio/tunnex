package ipsec

import (
	"context"
	"reflect"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
)

const (
	fqdnConntrackMarkMask uint32 = 0x0f000000
	fqdnConntrackMark     uint32 = 0x01000000
)

type runtimeFQDNPolicyView struct{ policy nodepolicy.Compiled }

// RuntimeFQDNPolicySource is wired only to the ordinary egress owner's apply
// callbacks. BeforePolicy may only retract; CommittedPolicy follows actual nft
// success and durable baseline/history commit. Desired policy is never authority.
type RuntimeFQDNPolicySource struct {
	view       atomic.Pointer[runtimeFQDNPolicyView]
	controller atomic.Pointer[RuntimeController]
}

func (s *RuntimeFQDNPolicySource) Attach(c *RuntimeController) { s.controller.Store(c) }
func copyFQDNPolicy(p *nodepolicy.Compiled) *runtimeFQDNPolicyView {
	if p == nil || p.Mesh || p.Mode != nodepolicy.ModeEnforcing || p.Version < 1 || p.Version > nodepolicy.MaxSupportedVersion {
		return nil
	}
	v := &runtimeFQDNPolicyView{}
	v.policy.NodeID, v.policy.Version = p.NodeID, p.Version
	v.policy.Allow = append([]nodepolicy.AllowEntry(nil), p.Allow...)
	v.policy.FQDNGenerations = append([]nodepolicy.FQDNGeneration(nil), p.FQDNGenerations...)
	for i := range v.policy.FQDNGenerations {
		v.policy.FQDNGenerations[i].Answers = append([]string(nil), v.policy.FQDNGenerations[i].Answers...)
	}
	v.policy.DNSResolverProfiles = append([]nodepolicy.DNSResolverProfile(nil), p.DNSResolverProfiles...)
	for i := range v.policy.DNSResolverProfiles {
		r := &v.policy.DNSResolverProfiles[i]
		r.ZoneSuffixes = append([]string(nil), r.ZoneSuffixes...)
		r.Endpoints = append([]nodepolicy.DNSResolverEndpoint(nil), r.Endpoints...)
		r.AllowedSources = append([]string(nil), r.AllowedSources...)
	}
	return v
}
func (s *RuntimeFQDNPolicySource) CommittedPolicy(p *nodepolicy.Compiled) {
	s.view.Store(copyFQDNPolicy(p))
}
func (s *RuntimeFQDNPolicySource) BeforePolicy(ctx context.Context, p *nodepolicy.Compiled) error {
	old, next := s.view.Load(), copyFQDNPolicy(p)
	if old == nil {
		return nil
	}
	keep := &runtimeFQDNPolicyView{}
	keep.policy.NodeID, keep.policy.Version = old.policy.NodeID, old.policy.Version
	if next != nil && next.policy.NodeID == old.policy.NodeID {
		for _, g := range old.policy.FQDNGenerations {
			for _, n := range next.policy.FQDNGenerations {
				if reflect.DeepEqual(g, n) {
					keep.policy.FQDNGenerations = append(keep.policy.FQDNGenerations, g)
					break
				}
			}
		}
		for _, a := range old.policy.Allow {
			for _, n := range next.policy.Allow {
				if a == n {
					keep.policy.Allow = append(keep.policy.Allow, a)
					break
				}
			}
		}
		for _, r := range old.policy.DNSResolverProfiles {
			for _, n := range next.policy.DNSResolverProfiles {
				if reflect.DeepEqual(r, n) {
					keep.policy.DNSResolverProfiles = append(keep.policy.DNSResolverProfiles, r)
					break
				}
			}
		}
	}
	// Publish only the old/next intersection before waiting on the runtime owner.
	// A failed egress transaction retains this conservative withdrawal.
	s.view.Store(keep)
	marked := false
	for _, a := range old.policy.Allow {
		marked = marked || a.FQDNManaged
	}
	if c := s.controller.Load(); c != nil && marked {
		return c.withdrawUncommittedFQDN(ctx)
	}
	return nil
}
func (v *runtimeFQDNPolicyView) matches(g GuardGrant) bool {
	if v == nil || v.policy.Version < 9 || v.policy.NodeID != g.FQDN.SelectedGatewayID.String() || !g.FQDNManaged || !g.FQDN.valid() {
		return false
	}
	b := g.FQDN
	if b.Version == 2 && !b.ExpiresAt.After(time.Now()) {
		return false
	}
	generation, tuple, profile := false, false, false
	for _, f := range v.policy.FQDNGenerations {
		if f.ResourceID == b.ResourceID.String() && f.Name == b.Name && f.Generation == b.Generation && f.ResolverConfigID == b.ResolverConfigID.String() && f.ResolverConfigVersion == b.ResolverConfigVersion {
			for _, a := range f.Answers {
				if a == g.Destination.String() {
					generation = true
				}
			}
		}
	}
	for _, a := range v.policy.Allow {
		if a.FQDNManaged && a.RuleID == b.RuleID.String() && a.SrcIP == g.Source.String() && a.DstCIDR == g.Destination.String() && a.Protocol == string(g.Protocol) && a.PortLow == int(g.PortLow) && a.PortHigh == int(g.PortHigh) {
			tuple = true
		}
	}
	for _, p := range v.policy.DNSResolverProfiles {
		if p.ContextConfigID == b.ResolverConfigID.String() && p.ContextConfigVersion == b.ResolverConfigVersion && p.ProfileID == b.ResolverProfileID.String() && p.IPsecPath.ConnectionID == b.ConnectionID.String() && p.IPsecPath.ConfigurationRevision == b.ConfigurationRevision && (b.Version == 0 || p.IPsecPath.SourceAddress == b.ResolverSourceAddress) {
			for _, z := range p.ZoneSuffixes {
				if z == b.ResolverMatchSuffix {
					profile = true
				}
			}
		}
	}
	return generation && tuple && profile
}
func (c *RuntimeController) fqdnGrantsCurrent(grants []GuardGrant) bool {
	for _, g := range grants {
		if g.FQDN.Version == 2 && !g.FQDN.ExpiresAt.After(time.Now()) {
			continue
		}
		if g.FQDN.Version == 2 && (c.qualification == nil || !c.qualification.fqdnExpiry) {
			return false
		}
		if g.FQDNManaged && (c.config.FQDNPolicy == nil || !c.config.FQDNPolicy.view.Load().matches(g)) {
			return false
		}
	}
	return true
}

// withdrawChangedFQDNMaterial runs under the runtime owner before any fresh
// environment/lease IO. A changed authenticated intent cannot retain a prior
// marked permit while the desired ordinary policy is still being reconciled.
func (c *RuntimeController) withdrawChangedFQDNMaterial(ctx context.Context, m RuntimeMaterial, grants []GuardGrant) error {
	old, ok := c.active[m.Manifest.ConnectionID]
	if !ok {
		return nil
	}
	marked := false
	for _, g := range old.Grants {
		marked = marked || g.FQDNManaged
	}
	if !marked || (old.Identity.DeliveryID == m.ID && old.Identity.PolicyHash == m.Policy.Hash && old.Identity.Binding == (Binding{OrgID: m.Manifest.OrgID, GatewayID: m.Manifest.NodeID, ConnectionID: m.Manifest.ConnectionID, ConfigurationRevision: m.Manifest.ConfigurationRevision, DesiredRevision: m.DesiredRevision}) && reflect.DeepEqual(old.Grants, grants)) {
		return nil
	}
	// Only an unchanged v2 descriptor can remain in the old authenticated view.
	sameBinding := old.Identity.DeliveryID == m.ID && old.Identity.Binding == (Binding{OrgID: m.Manifest.OrgID, GatewayID: m.Manifest.NodeID, ConnectionID: m.Manifest.ConnectionID, ConfigurationRevision: m.Manifest.ConfigurationRevision, DesiredRevision: m.DesiredRevision})
	kept := make([]GuardGrant, 0, len(old.Grants))
	for _, g := range old.Grants {
		if !g.FQDNManaged || g.FQDN.Version != 2 {
			kept = append(kept, g)
			continue
		}
		for _, next := range grants {
			if sameBinding && g == next {
				kept = append(kept, g)
				break
			}
		}
	}
	old.Grants = kept
	c.active[m.Manifest.ConnectionID] = old
	return c.withdrawFQDNActiveLocked(ctx, []uuid.UUID{m.Manifest.ConnectionID})
}
func (c *RuntimeController) withdrawUncommittedFQDN(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || !c.started {
		return ErrRuntimeController
	}
	var ids []uuid.UUID
	for id, a := range c.active {
		if !c.fqdnGrantsCurrent(a.Grants) {
			ids = append(ids, id)
		}
	}
	return c.withdrawFQDNActiveLocked(ctx, ids)
}
func (c *RuntimeController) withdrawFQDNActiveLocked(ctx context.Context, ids []uuid.UUID) error {
	if len(ids) == 0 {
		return nil
	}
	if c.closed || !c.started || c.journal == nil || ctx.Err() != nil {
		return ErrRuntimeController
	}
	for _, id := range ids {
		if current, ok := c.active[id]; ok {
			legacy := false
			for _, g := range current.Grants {
				if g.FQDNManaged && g.FQDN.Version != 2 {
					legacy = true
				}
			}
			if legacy {
				if current.Authority != nil {
					current.Authority.Invalidate()
				}
				c.withdrawDNSOwnerView(id)
				delete(c.active, id)
				continue
			}
			kept := make([]GuardGrant, 0, len(current.Grants))
			for _, g := range current.Grants {
				if !g.FQDNManaged || c.config.FQDNPolicy != nil && c.config.FQDNPolicy.view.Load().matches(g) {
					kept = append(kept, g)
				}
			}
			current.Grants = kept
			c.active[id] = current
		}
	}
	entries, e := c.journal.Entries()
	if e != nil {
		return ErrRuntimeController
	}
	if e = c.installActive(ctx, entries); e != nil {
		_, _ = c.refuse(ctx, entries)
		return ErrRuntimeController
	}
	return nil
}
func (c *RuntimeController) FQDNPolicyCapability() int {
	return c.fqdnPolicyCapabilityFor(runtime.GOOS, runtime.GOARCH)
}

// Production uses only compile-time platform facts, as in Capability.
func (c *RuntimeController) fqdnPolicyCapabilityFor(goos, goarch string) int {
	if c == nil || goos != "linux" {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.config.FQDNPolicy == nil {
		return 0
	}
	view := c.config.FQDNPolicy.view.Load()
	if view == nil || view.policy.NodeID != c.config.GatewayID.String() || c.capabilityFor(goos, goarch) != 1 {
		return 0
	}
	if c.qualification.fqdnExpiry {
		return 2
	}
	return 1
}
