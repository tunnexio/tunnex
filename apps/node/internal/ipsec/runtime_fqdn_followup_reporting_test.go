package ipsec

import (
	"context"
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
)

// Reuses the real dual-owner material/kernel setup of the cutoff recollection
// regression. Only post-report authority invalidation is injected here.
func TestFQDNFollowupFinalReportFencesAllCandidates(t *testing.T) {
	r, first := fqdnExpiryTurnoverRig(t)
	r.c.config.JournalDir = r.c.journal.dir
	// Native and lease time use the virtual clock; the bounded late-material
	// wait must advance that same clock before reaching the reporting fence.
	r.c.fqdnMaterialWait = fqdnTestWait(r)
	firstOld := r.c.active[r.target]
	var secondID uuid.UUID
	var secondMaterial RuntimeMaterial
	for _, m := range r.materials {
		if m.Manifest.BGP != nil && m.Manifest.ConnectionID != r.target {
			secondID = m.Manifest.ConnectionID
			secondMaterial = m
			break
		}
	}
	if secondID == uuid.Nil {
		t.Fatal("missing second BGP owner")
	}
	secondOld := r.c.active[secondID]
	f := firstOld.FQDNLeaseDescriptors[0]
	f.ResourceID, f.RuleID = uuid.NewString(), uuid.NewString()
	f.ConnectionID = secondID.String()
	f.SelectedSiteID = secondMaterial.Manifest.SiteID.String()
	f.Destination = netip.PrefixFrom(secondOld.Entry.Engines[0].RemotePrefixes[0].Addr().Next(), 32).String()
	secondMaterial.Policy.FQDNPolicyVersion = 2
	secondMaterial.Policy.FQDNGrants = []RuntimeFQDNGrant{f}
	_, grants, err := runtimeMaterialEntry(secondMaterial, r.c.config.OrgID, r.c.config.GatewayID, secondOld.Environment.Namespace)
	if err != nil {
		t.Fatal(err)
	}
	grants, err = r.c.observeDesktopGrants(context.Background(), grants)
	if err != nil {
		t.Fatal(err)
	}
	secondOld.Grants = grants
	secondOld.FQDNLeaseDescriptors = runtimeFQDNLeaseDescriptors(secondMaterial.Policy)
	auth := maintenanceAuthority(r)()
	q, err := auth.BeginFQDN(secondOld.Identity, runtimeFQDNLeaseKeys(secondMaterial.Policy))
	if err != nil {
		t.Fatal(err)
	}
	if err = auth.Accept(PermitLeaseResponse{PermitLeaseRequest: q, TTLMillis: 60000, FQDNPermits: []RuntimeFQDNPermit{{GrantDigest: runtimeFQDNGrantDigest(f), TTLMS: 25000}}}); err != nil {
		t.Fatal(err)
	}
	secondOld.Authority = auth
	r.c.active[secondID] = secondOld
	p := r.c.config.FQDNPolicy.view.Load().policy
	p.Mode = nodepolicy.ModeEnforcing
	allow := p.Allow[0]
	allow.RuleID = f.RuleID
	allow.DstCIDR = f.Destination
	p.Allow = append(append([]nodepolicy.AllowEntry(nil), p.Allow...), allow)
	gen := p.FQDNGenerations[0]
	gen.ResourceID = f.ResourceID
	gen.Answers = []string{f.Destination}
	gen.ApplicationIPsecPath = &nodepolicy.FQDNApplicationIPsecPath{ConnectionID: f.ConnectionID, ConfigurationRevision: f.ConfigurationRevision}
	p.FQDNGenerations = append(append([]nodepolicy.FQDNGeneration(nil), p.FQDNGenerations...), gen)
	r.c.config.FQDNPolicy.CommittedPolicy(&p)
	for id := range r.c.active {
		if id != r.target && id != secondID {
			delete(r.c.active, id)
		}
	}
	// Isolate the all-candidate reporting fence from native timing; the separate
	// late-publication regression covers the actual six-second window.
	r.c.prove = func(context.Context, RuntimeJournalEntry, RuntimeEnvironment) error { return nil }
	r.c.recoveryObserve = func(context.Context, RuntimeJournalEntry) [2]string { return [2]string{"up", "up"} }
	// Reuse the complete kernel fixture parser for both real owned tuples;
	// the original desktop fixture's kernel inventory names only owner1.
	var kernels []*recoveryKernelFixture
	for _, entry := range []RuntimeJournalEntry{firstOld.Entry, secondOld.Entry} {
		kernel := newRecoveryKernelFixture()
		kernel.p = entry.Allocation
		kernel.owned = entry.Observed
		kernel.mtu = [2]uint64{1382, 1382}
		kernel.routes = [2]map[string]bool{{}, {}}
		for i, tunnel := range entry.Allocation.Tunnels {
			kernel.routes[i][tunnel.BGP.Peer.String()+"/32"] = true
		}
		for _, route := range entry.BGPRoutes.Owned {
			kernel.routes[int(route.Slot)-1][route.Prefix.String()] = true
		}
		kernels = append(kernels, kernel)
	}
	r.c.kernel = &KernelApplier{namespace: r.c.namespace, run: func(ctx context.Context, args ...string) ([]byte, error) {
		objects := []map[string]any{}
		for _, kernel := range kernels {
			raw, err := kernel.run(ctx, args...)
			if err != nil {
				return nil, err
			}
			var part []map[string]any
			if err = json.Unmarshal(raw, &part); err != nil {
				return nil, err
			}
			objects = append(objects, part...)
		}
		return json.Marshal(objects)
	}}
	if err = r.c.installActive(context.Background(), r.entries); err != nil {
		t.Fatal(err)
	}
	secondNext := secondMaterial
	secondNext.Policy.FQDNGrants = append([]RuntimeFQDNGrant(nil), secondMaterial.Policy.FQDNGrants...)
	secondNext.Policy.FQDNGrants[0].ExpiresAt = f.ExpiresAt.Add(15 * time.Second)
	secondNext.Policy.Hash = first.material.Policy.Hash
	secondBase := &fqdnTurnoverClient{base: first.base, material: secondNext, target: secondID, oldHash: secondOld.Identity.PolicyHash}
	r.c.client = twoFQDNOwnerClient{base: first.base, owners: map[uuid.UUID]RuntimeLeaseClient{r.target: first, secondID: secondBase}}
	originals := map[uuid.UUID]runtimeActive{r.target: r.c.active[r.target], secondID: r.c.active[secondID]}
	originalDeadlines := map[uuid.UUID]time.Duration{}
	for id, old := range originals {
		originalDeadlines[id] = old.Authority.deadline
	}
	prepared := map[uuid.UUID]maintenanceItem{}
	for id, material := range map[uuid.UUID]RuntimeMaterial{r.target: first.material, secondID: secondNext} {
		next, err := r.c.prepareFQDNExpiryMaterial(context.Background(), originals[id], material)
		if err != nil {
			t.Fatal("strict expiry-only preparation", err)
		}
		prepared[id] = next
	}
	reports := 0
	var reportedFirst uuid.UUID
	publish := func(_ context.Context, d RuntimeDelivery, report RuntimeStatusReport) error {
		reports++
		id := d.Manifest.ConnectionID
		if report.DeliveryID != d.ID {
			t.Fatal("report delivery mismatch")
		}
		if reports == 1 {
			reportedFirst = id
			return nil
		}
		if reports != 2 || id == reportedFirst {
			t.Fatal("did not reach second unique owner report")
		}
		// Invalidate only the already reported candidate. The currently reported
		// candidate remains valid, so a per-current-owner post-IO check would miss it.
		earlier := r.c.active[reportedFirst]
		current := r.c.active[id]
		earlier.Authority.Invalidate()
		if _, err := current.Authority.RemainingForApply(current.Identity, time.Millisecond); err != nil {
			t.Fatal("fixture invalidated current owner", err)
		}
		return nil
	}
	err = r.c.commitFQDNFollowup(context.Background(), maintenanceAuthority(r), func() bool { return true }, prepared, publish)
	if err == nil || reports != 2 {
		t.Fatalf("late cross-owner invalidation escaped final fence: err=%v reports=%d", err, reports)
	}
	if len(r.c.active) != 0 || len(r.c.fqdnNativeWindows) != 0 {
		t.Fatal("failed final fence retained process authority")
	}
	for id, old := range originals {
		for _, g := range old.Grants {
			if g.FQDNManaged && r.installed[guardFQDNSetName(g)] > *r.now {
				t.Fatal("failed final fence retained old FQDN member", id)
			}
		}
		for _, g := range prepared[id].Grants {
			if g.FQDNManaged && r.installed[guardFQDNSetName(g)] > *r.now {
				t.Fatal("failed final fence retained fresh FQDN member", id)
			}
		}
		if !r.applicationDenied[id] {
			t.Fatal("failed final fence left positive application grant", id)
		}
		if old.Authority.deadline != originalDeadlines[id] {
			t.Fatal("failed final fence altered original authority")
		}
	}
}
