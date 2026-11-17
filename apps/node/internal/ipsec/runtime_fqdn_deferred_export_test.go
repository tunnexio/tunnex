package ipsec

import (
	"context"
	"github.com/google/uuid"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Test-only adapter exposes the existing finite native model to the real control
// poller in an external test package. Public platform qualification is modeled;
// actual maintenance, nonce lease, BGP failure core and native replacement run.
type FQDNDeferredPollFixture struct {
	t                                  *testing.T
	rig                                *renewalCycleRig
	client                             *fqdnTurnoverClient
	ready                              *bool
	before                             runtimeActive
	deadline                           time.Duration
	page                               []RuntimeMaterial
	ApplyCalls, ACKs, Reports, Pending int
	gap                                bool
}

func NewFQDNDeferredPollFixture(t *testing.T, mixed, freshPage bool) *FQDNDeferredPollFixture {
	t.Helper()
	r, client, ready, _ := fqdnRestorationPendingRig(t)
	old := r.c.active[r.target]
	stale := client.material
	stale.Policy.FQDNGrants = nil
	stale.Policy.FQDNPolicyVersion = 0
	stale.Policy.Hash = old.Identity.PolicyHash
	f := &FQDNDeferredPollFixture{t: t, rig: r, client: client, ready: ready, before: cloneMaintenanceActive(old), deadline: old.Authority.deadline, page: []RuntimeMaterial{stale}}
	if mixed {
		for _, m := range r.materials {
			if m.Manifest.ConnectionID != r.target && r.c.active[m.Manifest.ConnectionID].Entry.ContractVersion == 3 {
				f.page = append(f.page, m)
				break
			}
		}
		if len(f.page) != 2 {
			t.Fatal("missing ordinary sibling")
		}
	}
	if freshPage {
		f.page[0] = client.material
	}
	diag := r.c.config.Diagnostic
	r.c.config.Diagnostic = func(d RuntimeDiagnostic) {
		if d.Stage == "maintenance_desktop_nat_pending" {
			f.Pending++
		}
		if diag != nil {
			diag(d)
		}
	}
	replace := r.c.replace
	r.c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
		m, e := replace(ctx, in)
		if e == nil {
			for _, n := range []string{guardLeaseName(r.target), guardReplyLeaseName(r.target), guardSALeaseName(r.target)} {
				f.gap = f.gap || r.installed[n] <= *r.now
			}
		}
		return m, e
	}
	return f
}
func (f *FQDNDeferredPollFixture) IPsecPending(context.Context, *uuid.UUID, int) (RuntimePendingPage, error) {
	var v []RuntimePending
	for _, m := range f.page {
		v = append(v, RuntimePending{ConnectionID: m.Manifest.ConnectionID, DesiredRevision: m.DesiredRevision, Kind: "apply"})
	}
	return RuntimePendingPage{Items: v}, nil
}
func (f *FQDNDeferredPollFixture) IPsecMaterial(_ context.Context, id uuid.UUID, _ int64) (RuntimeMaterial, error) {
	for _, m := range f.page {
		if m.Manifest.ConnectionID == id {
			return m, nil
		}
	}
	return RuntimeMaterial{}, ErrRuntimeController
}
func (f *FQDNDeferredPollFixture) IPsecCleanup(context.Context, uuid.UUID, int64) (RuntimeCleanup, error) {
	return RuntimeCleanup{}, ErrRuntimeController
}
func (f *FQDNDeferredPollFixture) Cleanup(context.Context, RuntimeCleanup) (RuntimeAcknowledgement, error) {
	return RuntimeAcknowledgement{}, ErrRuntimeController
}
func (f *FQDNDeferredPollFixture) IPsecAcknowledge(_ context.Context, _ uuid.UUID, a RuntimeAcknowledgement) error {
	f.ACKs++
	return nil
}
func (f *FQDNDeferredPollFixture) IPsecReportStatus(_ context.Context, _ uuid.UUID, r RuntimeStatusReport) error {
	f.Reports++
	return nil
}
func (f *FQDNDeferredPollFixture) ObserveIPsecStatus(ctx context.Context, d RuntimeDelivery) (RuntimeStatusReport, error) {
	return f.rig.c.ObserveIPsecStatus(ctx, d)
}
func (f *FQDNDeferredPollFixture) RefreshIPsecRecovery(ctx context.Context) error {
	return f.rig.c.RefreshIPsecRecovery(ctx)
}
func (f *FQDNDeferredPollFixture) MaintainIPsecRuntime(ctx context.Context, m []RuntimeMaterial) ([]RuntimeMaintenanceResult, error) {
	c := f.rig.c
	c.mu.Lock()
	defer c.mu.Unlock()
	out, e := c.maintainIPsecRuntime(ctx, m, maintenanceAuthority(f.rig), func() bool { return true })
	return out, e
}
func (f *FQDNDeferredPollFixture) Apply(ctx context.Context, m RuntimeMaterial) (RuntimeAcknowledgement, error) {
	f.ApplyCalls++
	c := f.rig.c
	c.mu.Lock()
	defer c.mu.Unlock()
	if m.Manifest.ConnectionID != f.rig.target {
		f.t.Fatal("unexpected sibling fallback")
	}
	entries, e := c.journal.Entries()
	if e != nil {
		return RuntimeAcknowledgement{}, e
	}
	pos := -1
	for i := range entries {
		if entries[i].DeliveryID == m.ID {
			pos = i
		}
	}
	if pos < 0 {
		return RuntimeAcknowledgement{}, ErrRuntimeController
	}
	_, grants, e := runtimeMaterialEntry(m, c.config.OrgID, c.config.GatewayID, f.before.Environment.Namespace)
	if e != nil {
		return RuntimeAcknowledgement{}, e
	}
	grants, e = c.observeDesktopGrants(ctx, grants)
	if e != nil {
		return RuntimeAcknowledgement{}, e
	}
	if !c.fqdnGrantsCurrent(grants) {
		return RuntimeAcknowledgement{}, ErrRuntimeController
	}
	return c.applyBGPProof(ctx, m, entries, pos, f.before.Environment, grants, func() bool { return true }, func(context.Context, RuntimeJournalEntry) error { return nil })
}
func (f *FQDNDeferredPollFixture) AssertPending(t *testing.T) {
	t.Helper()
	r := f.rig
	a, ok := r.c.active[r.target]
	t.Logf("pending=%d apply=%d ACK=%d reports=%d gap=%t active=%t original_remaining=%v", f.Pending, f.ApplyCalls, f.ACKs, f.Reports, f.gap, ok, f.deadline-*r.now)
	if !ok || f.gap || !reflect.DeepEqual(a, f.before) || f.before.Authority.deadline != f.deadline || !r.c.bgpProcesses[f.before.Entry.DeliveryID].Alive() {
		t.Fatal("pending poll destroyed or extended original ordinary authority")
	}
	for _, n := range []string{guardLeaseName(r.target), guardReplyLeaseName(r.target), guardSALeaseName(r.target)} {
		if r.installed[n] <= *r.now || r.installed[n] > f.deadline {
			t.Fatal("pending native deadline invalid")
		}
	}
	for n, end := range r.installed {
		if strings.HasPrefix(n, "fqdn_") && end > *r.now {
			t.Fatal("pending application permission appeared")
		}
	}
}
func (f *FQDNDeferredPollFixture) CatchUp() { *f.ready = true; f.page[0] = f.client.material }
func (f *FQDNDeferredPollFixture) AssertRestored(t *testing.T) {
	t.Helper()
	a := f.rig.c.active[f.rig.target]
	if f.gap || a.Authority == f.before.Authority || a.Identity.PolicyHash != f.client.material.Policy.Hash || f.before.Authority.deadline != f.deadline {
		t.Fatal("catch-up lacks independent authority")
	}
	found := false
	for _, g := range a.Grants {
		if g.FQDNManaged {
			found = true
			if f.rig.installed[guardFQDNSetName(g)] <= *f.rig.now {
				t.Fatal("fresh FQDN member absent")
			}
		}
	}
	if !found {
		t.Fatal("fresh FQDN grant absent")
	}
	qs := f.client.requests
	if len(qs) < 2 || qs[len(qs)-1].Nonce == qs[len(qs)-2].Nonce || qs[len(qs)-1].PolicyHash != a.Identity.PolicyHash {
		t.Fatal("catch-up reused nonce or policy")
	}
}

func (f *FQDNDeferredPollFixture) ExpireOriginal() { *f.rig.now = f.deadline }
func (f *FQDNDeferredPollFixture) ChangeOriginal() {
	a := f.rig.c.active[f.rig.target]
	a.Environment.Underlays[0].InterfaceIndex++
	f.rig.c.active[f.rig.target] = a
}
func (f *FQDNDeferredPollFixture) AssertDenied(t *testing.T) {
	t.Helper()
	if f.ACKs != 0 {
		t.Fatal("invalid original acknowledged")
	}
	for _, n := range []string{guardLeaseName(f.rig.target), guardReplyLeaseName(f.rig.target), guardSALeaseName(f.rig.target)} {
		if f.rig.installed[n] > *f.rig.now {
			t.Fatal("invalid original retained native authority")
		}
	}
	if f.before.Authority.deadline != f.deadline {
		t.Fatal("old authority changed")
	}
}

// ValidateCore executes the production wrapper's already-qualified reconciliation
// and guard assembly. Platform qualification remains modeled by this fixture.
func (f *FQDNDeferredPollFixture) ValidateCore(t *testing.T) {
	t.Helper()
	c := f.rig.c
	c.mu.Lock()
	defer c.mu.Unlock()
	entries, err := c.journal.Entries()
	if err != nil {
		t.Fatal(err)
	}
	if err = c.reconcileActiveBGP(context.Background(), entries); err != nil {
		t.Fatal("Validate route reconciliation", err)
	}
	entries, err = c.journal.Entries()
	if err != nil {
		t.Fatal(err)
	}
	if err = c.installActive(context.Background(), entries); err != nil {
		t.Fatal("Validate canonical native assembly", err)
	}
}
