package ipsec

import (
	"context"
	"net/netip"
	"reflect"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	bgpengine "github.com/tunnexio/tunnex/apps/node/internal/bgp"
)

// A view contains immutable owner-selected inputs, never observed health. DNS
// still independently checks native SA/route/guard/source and the original
// accepted lease before and after every exchange. Publication does not renew it.
type runtimeDNSEpoch struct{ revoked atomic.Bool }
type runtimeDNSOwnerEntry struct {
	active runtimeActive
	epoch  *runtimeDNSEpoch
}

// Only the serialized owner can complete this publication. Closing done
// synchronizes committed; readers never treat the descriptor as authority.
type runtimeDNSPublication struct {
	previous  *runtimeDNSOwnerView
	done      chan struct{}
	committed bool
}

func (c *RuntimeController) awaitDNSPublication(ctx context.Context, previous *runtimeDNSOwnerView) bool {
	publication := c.dnsPublication.Load()
	if publication == nil || publication.previous != previous {
		return false
	}
	select {
	case <-ctx.Done():
		return false
	case <-publication.done:
		return publication.committed && ctx.Err() == nil
	}
}

type runtimeDNSOwnerView struct {
	entries  map[uuid.UUID]runtimeDNSOwnerEntry
	guard    GuardManifest
	expected guardExpectedSnapshot
	observer runtimeDNSObserver
}
type runtimeDNSObserver struct {
	controller    *RuntimeController // read-only dependencies; no owner maps/journal
	qualification *RuntimePlatformQualification
	guardReader   *GuardReader
	source        func(netip.Addr, []int) (int, error)
	route         func(context.Context, string, ...string) ([]byte, error)
}

func sameDNSOwnerInputs(a, b runtimeActive) bool {
	return a.Identity == b.Identity && reflect.DeepEqual(a.Entry, b.Entry) && reflect.DeepEqual(a.Environment, b.Environment) && reflect.DeepEqual(a.Grants, b.Grants)
}
func hasDNSResolverGrant(a runtimeActive) bool {
	for _, g := range a.Grants {
		if g.DNSResolver != (DNSResolverBinding{}) {
			return true
		}
	}
	return false
}
func copyDNSSlice[T any](v []T) []T {
	if v == nil {
		return nil
	}
	return append(make([]T, 0, len(v)), v...)
}
func copyDNSPointer[T any](v *T) *T {
	if v == nil {
		return nil
	}
	copy := *v
	return &copy
}
func copyDNSProcess(v bgpengine.ProcessIdentity) bgpengine.ProcessIdentity {
	v.Files = copyDNSSlice(v.Files)
	v.Children = copyDNSSlice(v.Children)
	return v
}
func copyDNSEntry(e RuntimeJournalEntry) RuntimeJournalEntry {
	e.RetainedGuardPredecessors = copyDNSSlice(e.RetainedGuardPredecessors)
	e.BGPProcessHistory = copyDNSPointer(e.BGPProcessHistory)
	e.BGPProcessRetired = copyDNSSlice(e.BGPProcessRetired)
	for i := range e.BGPProcessRetired {
		e.BGPProcessRetired[i] = copyDNSProcess(e.BGPProcessRetired[i])
	}
	e.BGPProcess = copyDNSPointer(e.BGPProcess)
	if e.BGPProcess != nil {
		*e.BGPProcess = copyDNSProcess(*e.BGPProcess)
	}
	e.BGPRoutes = copyDNSPointer(e.BGPRoutes)
	if e.BGPRoutes != nil {
		e.BGPRoutes.Owned = copyDNSSlice(e.BGPRoutes.Owned)
		e.BGPRoutes.Target = copyDNSSlice(e.BGPRoutes.Target)
	}
	e.BGP = copyDNSPointer(e.BGP)
	e.Recovery = copyDNSPointer(e.Recovery)
	e.ResetCleanup = copyDNSPointer(e.ResetCleanup)
	e.Restoration = copyDNSPointer(e.Restoration)
	if e.Restoration != nil {
		e.Restoration.Compacted = copyDNSPointer(e.Restoration.Compacted)
		e.Restoration.Retired = copyDNSSlice(e.Restoration.Retired)
		for i := range e.Restoration.Retired {
			e.Restoration.Retired[i].Entry = copyDNSEntry(e.Restoration.Retired[i].Entry)
		}
	}
	for i := range e.Allocation.Tunnels {
		e.Allocation.Tunnels[i].BGP = copyDNSPointer(e.Allocation.Tunnels[i].BGP)
		e.Allocation.Tunnels[i].RemotePrefixes = copyDNSSlice(e.Allocation.Tunnels[i].RemotePrefixes)
		e.Engines[i].LocalPrefixes = copyDNSSlice(e.Engines[i].LocalPrefixes)
		e.Engines[i].RemotePrefixes = copyDNSSlice(e.Engines[i].RemotePrefixes)
	}
	return e
}
func cloneDNSOwnerActive(a runtimeActive) runtimeActive {
	a.Entry = copyDNSEntry(a.Entry)
	a.Environment.LocalIngressIndices = copyDNSSlice(a.Environment.LocalIngressIndices)
	a.Grants = copyDNSSlice(a.Grants)
	// Delivery is not read by the DNS observer; omit its mutable manifest slices.
	a.Delivery = RuntimeDelivery{}
	return a
}

// These methods are called only by the serial owner under c.mu. Epoch revocation
// is visible even to an in-flight query holding an earlier immutable view.
func (c *RuntimeController) withdrawDNSOwnerView(id uuid.UUID) {
	v := c.dnsView.Load()
	if v == nil {
		return
	}
	if id == uuid.Nil {
		for _, e := range v.entries {
			e.epoch.revoked.Store(true)
		}
		c.dnsView.Store(nil)
		return
	}
	e, ok := v.entries[id]
	if !ok {
		return
	}
	e.epoch.revoked.Store(true)
	next := *v
	next.entries = make(map[uuid.UUID]runtimeDNSOwnerEntry, len(v.entries)-1)
	for key, value := range v.entries {
		if key != id {
			next.entries[key] = value
		}
	}
	c.dnsView.Store(&next)
}
func (c *RuntimeController) reconcileDNSOwnerView() {
	v := c.dnsView.Load()
	if v == nil {
		return
	}
	for id, old := range v.entries {
		current, ok := c.active[id]
		if !ok || !sameDNSOwnerInputs(old.active, current) {
			c.withdrawDNSOwnerView(id)
		}
	}
}
func (c *RuntimeController) withdrawChangedDNSMaterial(m RuntimeMaterial, grants []GuardGrant) {
	v := c.dnsView.Load()
	if v == nil {
		return
	}
	old, ok := v.entries[m.Manifest.ConnectionID]
	if !ok {
		return
	}
	i := old.active.Identity
	if i.DeliveryID != m.ID || i.PolicyHash != m.Policy.Hash || i.Binding.DesiredRevision != m.DesiredRevision || i.Binding.ConfigurationRevision != m.Manifest.ConfigurationRevision || !reflect.DeepEqual(old.active.Grants, grants) {
		c.withdrawDNSOwnerView(m.Manifest.ConnectionID)
	}
}

// The only positive publication seam follows successful combined native guard
// replacement/readback and final qualification/lease validation in installActive.
func (c *RuntimeController) publishDNSOwnerView(g GuardManifest) {
	if !c.started || c.closed || c.qualification == nil || c.guard == nil || c.guard.reader == nil || g.OwnerID != c.config.GatewayID || g.Namespace != c.qualification.namespace || g.Revision <= 0 || !validDigest(g.Digest) || g.ExpectedJSON == "" {
		c.withdrawDNSOwnerView(uuid.Nil)
		return
	}
	objects, ok := normalizedGuardObjects([]byte(g.ExpectedJSON))
	if !ok {
		c.withdrawDNSOwnerView(uuid.Nil)
		return
	}
	previous := c.dnsView.Load()
	next := &runtimeDNSOwnerView{entries: map[uuid.UUID]runtimeDNSOwnerEntry{}, guard: g, expected: guardExpectedSnapshot{raw: g.ExpectedJSON, objects: objects}}
	next.observer = runtimeDNSObserver{
		controller:    &RuntimeController{config: c.config, kernel: c.kernel, prove: c.prove, recoveryObserve: c.recoveryObserve},
		qualification: c.qualification, guardReader: c.guard.reader, source: observeDNSSource, route: runKernelCommand,
	}
	for id, a := range c.active {
		if !hasDNSResolverGrant(a) || a.Authority == nil || a.Entry.Phase != RuntimeApplied || a.Entry.Allocation.Namespace != g.Namespace {
			continue
		}
		if _, err := a.Authority.RemainingForApply(a.Identity, time.Millisecond); err != nil {
			continue
		}
		copied := cloneDNSOwnerActive(a)
		epoch := &runtimeDNSEpoch{}
		if previous != nil {
			if old, ok := previous.entries[id]; ok && !old.epoch.revoked.Load() && sameDNSOwnerInputs(old.active, a) {
				epoch = old.epoch
			}
		}
		next.entries[id] = runtimeDNSOwnerEntry{active: copied, epoch: epoch}
	}
	if previous != nil {
		for id, old := range previous.entries {
			if n, ok := next.entries[id]; !ok || n.epoch != old.epoch {
				old.epoch.revoked.Store(true)
			}
		}
	}
	c.dnsView.Store(next)
}

func (c *RuntimeController) currentDNSOwnerEntry(id uuid.UUID, original runtimeDNSOwnerEntry) (runtimeDNSOwnerEntry, bool) {
	if original.epoch == nil || original.epoch.revoked.Load() {
		return runtimeDNSOwnerEntry{}, false
	}
	v := c.dnsView.Load()
	if v == nil {
		return runtimeDNSOwnerEntry{}, false
	}
	current, ok := v.entries[id]
	if !ok || current.epoch != original.epoch || current.epoch.revoked.Load() || !sameDNSOwnerInputs(original.active, current.active) {
		return runtimeDNSOwnerEntry{}, false
	}
	// A same-identity renewal may replace the Authority object. Neither acceptance
	// extends the original deadline; both exact authorities must still be live.
	if _, err := original.active.Authority.RemainingForApply(original.active.Identity, time.Second); err != nil {
		return runtimeDNSOwnerEntry{}, false
	}
	if _, err := current.active.Authority.RemainingForApply(current.active.Identity, time.Second); err != nil {
		return runtimeDNSOwnerEntry{}, false
	}
	return current, true
}
