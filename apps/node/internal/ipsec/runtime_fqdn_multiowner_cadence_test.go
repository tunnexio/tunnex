package ipsec

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
)

// Every successful subset reply retains the requested descriptor's absolute
// deadline, including after a same-answer DNS publication. It is not a sliding
// TTL. Material fetches alone return the later expiry and new policy hash.
type fqdnCadenceSubsetClient struct {
	r               *renewalCycleRig
	base            RuntimeLeaseClient
	old, fresh      map[uuid.UUID]RuntimeMaterial
	deadlines       map[string]time.Duration
	publishAt       time.Duration
	reads, requests int
	t               *testing.T
	phase           time.Duration
}

func (c *fqdnCadenceSubsetClient) publication() int {
	if *c.r.now < c.publishAt {
		return 0
	}
	return 1 + int((*c.r.now-c.publishAt)/(15*time.Second))
}
func (c *fqdnCadenceSubsetClient) materialAt(id uuid.UUID, publication int) RuntimeMaterial {
	m := c.old[id]
	if publication == 0 || len(m.Policy.FQDNGrants) == 0 {
		return m
	}
	m.Policy.FQDNGrants = append([]RuntimeFQDNGrant(nil), m.Policy.FQDNGrants...)
	for i := range m.Policy.FQDNGrants {
		prior := m.Policy.FQDNGrants[i]
		m.Policy.FQDNGrants[i].ExpiresAt = prior.ExpiresAt.Add(time.Duration(publication)*15*time.Second - c.phase)
		c.deadlines[runtimeFQDNGrantDigest(m.Policy.FQDNGrants[i])] = c.deadlines[runtimeFQDNGrantDigest(prior)] + time.Duration(publication)*15*time.Second - c.phase
	}
	m.Policy.Hash = stringDigest([]byte(fmt.Sprintf("%s:%s:%d", id, m.Policy.Hash, publication)))
	return m
}

func (c *fqdnCadenceSubsetClient) IPsecMaterial(_ context.Context, id uuid.UUID, rev int64) (RuntimeMaterial, error) {
	c.reads++
	c.r.charge("material_http", 100*time.Millisecond)
	if c.t != nil {
		c.t.Logf("material at=%s publication=%d", *c.r.now, c.publication())
	}
	_, ok := c.old[id]
	m := c.materialAt(id, c.publication())
	if !ok || rev != m.DesiredRevision {
		return RuntimeMaterial{}, ErrRuntimeController
	}
	return m, nil
}

func (c *fqdnCadenceSubsetClient) RenewIPsecLease(ctx context.Context, id uuid.UUID, q RuntimeLeaseRequest) (RuntimeLease, error) {
	c.requests++
	m, ok := c.old[id]
	if !ok {
		return RuntimeLease{}, ErrRuntimeController
	}
	if q.PolicyHash != m.Policy.Hash {
		for i := 1; i <= c.publication(); i++ {
			next := c.materialAt(id, i)
			if q.PolicyHash == next.Policy.Hash {
				m = next
				break
			}
		}
		if q.PolicyHash != m.Policy.Hash {
			return RuntimeLease{}, fqdnTurnoverConflict{}
		}
	}
	if !reflect.DeepEqual(q.FQDNGrants, m.Policy.FQDNGrants) {
		return RuntimeLease{}, fqdnTurnoverConflict{}
	}
	out, err := c.base.RenewIPsecLease(ctx, id, q)
	if err != nil {
		return out, err
	}
	for _, g := range q.FQDNGrants {
		remaining := c.deadlines[runtimeFQDNGrantDigest(g)] - *c.r.now
		if remaining < 0 {
			remaining = 0
		}
		// Match the CP's per-descriptor maximum; the request's absolute
		// expiry still caps this response independently of the whole lease.
		if remaining > time.Minute {
			remaining = time.Minute
		}
		out.FQDNPermits = append(out.FQDNPermits, RuntimeFQDNPermit{GrantDigest: runtimeFQDNGrantDigest(g), TTLMS: remaining.Milliseconds()})
	}
	return out, nil
}

func fqdnMultiOwnerCadenceRig(t *testing.T, variants ...string) (*renewalCycleRig, *fqdnCadenceSubsetClient) {
	t.Helper()
	variant := ""
	if len(variants) > 0 {
		variant = variants[0]
	}
	ids := pulseDeferralIDs()
	r := newRenewalCycleRigWithIDs(t, true, ids, desktopStaticTransportFixture, func(t *testing.T, c *RuntimeController, entries []RuntimeJournalEntry, materials []RuntimeMaterial) ([]RuntimeJournalEntry, []RuntimeMaterial) {
		keep := map[uuid.UUID]bool{ids[0]: true, ids[3]: true, ids[4]: true}
		var es []RuntimeJournalEntry
		var ms []RuntimeMaterial
		for _, e := range entries {
			if keep[e.Allocation.ConnectionID] {
				es = append(es, e)
			} else {
				delete(c.active, e.Allocation.ConnectionID)
				delete(c.bgpProcesses, e.DeliveryID)
			}
		}
		for _, m := range materials {
			if keep[m.Manifest.ConnectionID] {
				ms = append(ms, m)
			}
		}
		return es, ms
	})
	r.c.config.JournalDir = r.c.journal.dir
	r.c.config.Diagnostic = func(d RuntimeDiagnostic) {
		if d.Refused {
			t.Log(d.Operation, d.Stage, d.ConnectionID)
		}
	}
	r.c.kernel = &KernelApplier{namespace: r.c.namespace, run: func(ctx context.Context, args ...string) ([]byte, error) {
		all := []json.RawMessage{}
		for _, e := range r.entries {
			k := newRecoveryKernelFixture()
			k.p, k.owned = e.Allocation, e.Observed
			k.routes = [2]map[string]bool{{}, {}}
			for i, a := range e.Allocation.Tunnels {
				if e.ContractVersion == 3 {
					k.routes[i][netip.PrefixFrom(a.BGP.Peer, 32).String()] = true
				} else if i == 0 {
					for _, p := range a.RemotePrefixes {
						k.routes[i][p.String()] = true
					}
				}
			}
			if e.BGPRoutes != nil {
				for _, route := range e.BGPRoutes.Owned {
					k.routes[route.Slot-1][route.Prefix.String()] = true
				}
			}
			raw, err := k.run(ctx, args...)
			if err != nil {
				return nil, err
			}
			var rows []json.RawMessage
			if err = json.Unmarshal(raw, &rows); err != nil {
				return nil, err
			}
			all = append(all, rows...)
		}
		return json.Marshal(all)
	}}
	r.c.desktopObserve = func(_ context.Context, in []GuardGrant) ([]GuardGrant, error) {
		out := append([]GuardGrant(nil), in...)
		for i := range out {
			if out[i].DesktopDeviceID != uuid.Nil {
				out[i].DesktopIngressIndex = 7777
			}
		}
		return out, nil
	}
	interfaces := r.c.guard.reader.interfaces
	r.c.guard.reader.interfaces = func() ([]GuardInterface, error) {
		out, err := interfaces()
		return append(out, GuardInterface{Name: "wg0", Index: 7777}), err
	}
	policy := &nodepolicy.Compiled{Version: 9, NodeID: r.c.config.GatewayID.String(), Mode: nodepolicy.ModeEnforcing}
	client := &fqdnCadenceSubsetClient{r: r, t: t, base: r.c.client, old: map[uuid.UUID]RuntimeMaterial{}, fresh: map[uuid.UUID]RuntimeMaterial{}, deadlines: map[string]time.Duration{}}
	seed, _, _ := desktopStaticFQDNFixture(t)
	for i, m := range r.materials {
		id := m.Manifest.ConnectionID
		a := r.c.active[id]
		if a.Entry.ContractVersion == 3 && variant == "" {
			client.old[id], client.fresh[id] = m, m
			continue
		}
		f := seed.Policy.FQDNGrants[0]
		f.ResourceID, f.RuleID, f.ResolverProfileID = uuid.NewString(), uuid.NewString(), uuid.NewString()
		f.Name = fmt.Sprintf("service-%d.example.net", i)
		f.ResolverMatchSuffix = f.Name
		f.Destination = netip.PrefixFrom(a.Entry.Engines[0].RemotePrefixes[0].Addr().Next(), 32).String()
		f.ResolverSourceAddress = ""
		f.SelectedSiteID = m.Manifest.SiteID.String()
		f.SelectedGatewayID = m.Manifest.NodeID.String()
		f.ConnectionID = id.String()
		f.ConfigurationRevision = m.Manifest.ConfigurationRevision
		f.ExpiresAt = time.Now().UTC().Add(30 * time.Second)
		if variant == "live" && a.Entry.ContractVersion == 3 {
			f.ExpiresAt = f.ExpiresAt.Add(30 * time.Second)
		}
		m.Policy.FQDNPolicyVersion = 2
		m.Policy.FQDNGrants = []RuntimeFQDNGrant{f}
		answers := []string{f.Destination}
		if variant == "live" {
			answers = append(answers, netip.PrefixFrom(netip.MustParsePrefix(f.Destination).Addr().Next(), 32).String())
			m.Policy.FQDNGrants = nil
			for device, source := range []string{"10.99.0.2/32", "10.99.0.3/32"} {
				g := f
				g.Source, g.DeviceID, g.RuleID = source, fmt.Sprintf("00000000-0000-4000-8000-%012d", device+20), uuid.NewString()
				if device == 1 {
					g.PublicKey = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
				}
				for _, answer := range answers {
					g.Destination = answer
					m.Policy.FQDNGrants = append(m.Policy.FQDNGrants, g)
				}
			}
		}
		_, grants, err := runtimeMaterialEntry(m, r.c.config.OrgID, r.c.config.GatewayID, a.Environment.Namespace)
		if err != nil {
			t.Fatal(err)
		}
		grants, err = r.c.observeDesktopGrants(context.Background(), grants)
		if err != nil {
			t.Fatal(err)
		}
		a.Grants = grants
		a.FQDNLeaseDescriptors = runtimeFQDNLeaseDescriptors(m.Policy)
		for _, grant := range m.Policy.FQDNGrants {
			policy.Allow = append(policy.Allow, nodepolicy.AllowEntry{SrcIP: strings.TrimSuffix(grant.Source, "/32"), SrcDeviceID: grant.DeviceID, FQDNDeviceID: grant.DeviceID, DstCIDR: grant.Destination, Protocol: grant.Protocol, PortLow: int(grant.PortLow), PortHigh: int(grant.PortHigh), RuleID: grant.RuleID, FQDNManaged: true})
		}
		policy.FQDNGenerations = append(policy.FQDNGenerations, nodepolicy.FQDNGeneration{ResourceID: f.ResourceID, Name: f.Name, Generation: f.Generation, ResolverConfigID: f.ResolverConfigID, ResolverConfigVersion: f.ResolverConfigVersion, Answers: answers, ApplicationIPsecPath: &nodepolicy.FQDNApplicationIPsecPath{ConnectionID: f.ConnectionID, ConfigurationRevision: f.ConfigurationRevision}})
		policy.DNSResolverProfiles = append(policy.DNSResolverProfiles, nodepolicy.DNSResolverProfile{ContextConfigID: f.ResolverConfigID, ContextConfigVersion: f.ResolverConfigVersion, ProfileID: f.ResolverProfileID, ZoneSuffixes: []string{f.ResolverMatchSuffix}, StaticRecords: []nodepolicy.DNSStaticRecord{{Name: f.Name, Type: "CNAME", Value: "backend.example.net", TTL: 30}}})
		fresh := m
		fresh.Policy.FQDNGrants = append([]RuntimeFQDNGrant(nil), m.Policy.FQDNGrants...)
		for i := range fresh.Policy.FQDNGrants {
			fresh.Policy.FQDNGrants[i].ExpiresAt = fresh.Policy.FQDNGrants[i].ExpiresAt.Add(15 * time.Second)
		}
		fresh.Policy.Hash = fmt.Sprintf("%064x", i+101)
		client.old[id], client.fresh[id] = m, fresh
		r.materials[i] = m
		r.c.active[id] = a
	}
	r.c.config.FQDNPolicy = &RuntimeFQDNPolicySource{}
	r.c.config.FQDNPolicy.CommittedPolicy(policy)
	r.c.qualification.fqdnExpiry = true
	// Setup starts at one actual rendered commit. Proof hooks still execute;
	// their virtual cost is zero only while seeding its finite native receipt.
	prove, observe := r.c.prove, r.c.recoveryObserve
	r.c.prove = func(context.Context, RuntimeJournalEntry, RuntimeEnvironment) error { return nil }
	r.c.recoveryObserve = func(context.Context, RuntimeJournalEntry) [2]string { return [2]string{"up", "up"} }
	for id, a := range r.c.active {
		auth := maintenanceAuthority(r)()
		q, err := auth.BeginFQDN(a.Identity, runtimeFQDNLeaseKeys(client.old[id].Policy))
		if err != nil {
			t.Fatal(err)
		}
		permits := []RuntimeFQDNPermit{}
		initial := 23 * time.Second
		if variant == "live" && a.Entry.ContractVersion == 3 {
			initial += 30 * time.Second
		}
		for _, f := range a.FQDNLeaseDescriptors {
			key := runtimeFQDNGrantDigest(f)
			permits = append(permits, RuntimeFQDNPermit{GrantDigest: key, TTLMS: initial.Milliseconds()})
			client.deadlines[key] = *r.now + initial
		}
		for _, f := range client.fresh[id].Policy.FQDNGrants {
			client.deadlines[runtimeFQDNGrantDigest(f)] = *r.now + initial + 15*time.Second
		}
		if err = auth.Accept(PermitLeaseResponse{PermitLeaseRequest: q, TTLMillis: 60000, FQDNPermits: permits}); err != nil {
			t.Fatal(err)
		}
		a.Authority = auth
		r.c.active[id] = a
	}
	for _, e := range r.entries {
		if e.ContractVersion == 2 {
			snap, err := r.c.kernel.snapshotSelectionRoutes(context.Background(), e.Allocation, true, nil)
			if err != nil || snap.ownership != e.Observed {
				t.Fatal("seed native ownership", err)
			}
		}
	}
	if err := r.c.installActive(context.Background(), r.entries); err != nil {
		t.Fatal("seed18s", err)
	}
	r.c.prove, r.c.recoveryObserve = prove, observe
	client.publishAt = *r.now + 5*time.Second
	r.c.client = client
	r.c.fqdnMaterialWait = fqdnTestWait(r)
	return r, client
}

func TestFQDNMultiOwnerCadenceSameAnswerSubset(t *testing.T) {
	for phase := time.Duration(0); phase < 15*time.Second; phase += time.Second {
		t.Run(phase.String(), func(t *testing.T) { testFQDNMultiOwnerCadence(t, phase) })
	}
}

func testFQDNMultiOwnerCadence(t *testing.T, phase time.Duration, variants ...string) {
	r, client := fqdnMultiOwnerCadenceRig(t, variants...)
	client.publishAt -= phase
	client.phase = phase
	old := map[uuid.UUID]runtimeActive{}
	for id, a := range r.c.active {
		old[id] = cloneMaintenanceActive(a)
		emitted := 18 * time.Second
		if len(variants) > 0 && variants[0] == "live" && a.Entry.ContractVersion == 3 {
			emitted += 30 * time.Second
		}
		for _, g := range a.Grants {
			if g.FQDNManaged && r.installed[guardFQDNSetName(g)]-*r.now != emitted {
				t.Fatalf("expected %s emitted membership, got %s", emitted, r.installed[guardFQDNSetName(g)]-*r.now)
			}
		}
	}
	r.charge("normal_post_commit_publication", 5*time.Second)
	gap := false
	firstGap := time.Duration(0)
	nativeMembers := map[uuid.UUID][]GuardGrant{}
	for id, a := range old {
		nativeMembers[id] = append([]GuardGrant(nil), a.Grants...)
	}
	check := func() {
		for id, a := range old {
			for _, wanted := range a.Grants {
				if !wanted.FQDNManaged {
					continue
				}
				found := false
				for _, g := range nativeMembers[id] {
					if g.FQDNManaged && g.Source == wanted.Source && g.Destination == wanted.Destination && g.FQDN.RuleID == wanted.FQDN.RuleID && r.installed[guardFQDNSetName(g)] > *r.now {
						found = true
					}
				}
				if !found {
					gap = true
					if firstGap == 0 {
						firstGap = *r.now
					}
				}
			}
		}
	}
	replace := r.c.replace
	firstCommit := time.Duration(0)
	r.c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
		check()
		m, e := replace(ctx, in)
		if e == nil {
			if firstCommit == 0 {
				firstCommit = *r.now
			}
			nativeMembers = map[uuid.UUID][]GuardGrant{}
			for _, owner := range in.Connections {
				nativeMembers[owner.ID] = append([]GuardGrant(nil), owner.Grants...)
			}
			check()
		}
		return m, e
	}
	prove := r.c.prove
	r.c.prove = func(ctx context.Context, e RuntimeJournalEntry, env RuntimeEnvironment) error {
		err := prove(ctx, e, env)
		check()
		return err
	}
	observe := r.c.recoveryObserve
	r.c.recoveryObserve = func(ctx context.Context, e RuntimeJournalEntry) [2]string {
		s := observe(ctx, e)
		r.charge("measured_native_sample", 800*time.Millisecond)
		check()
		return s
	}
	start := *r.now
	installFQDNCadenceStatusReaders(t, r, check)
	readerCalls := map[string]int{}
	assemblyReadsAtCommit := 0
	measuredReplace := r.c.replace
	r.c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
		if pulseDeferralInCall("commitExactRuntimeRefresh") && !pulseDeferralInCall("refuse") {
			if delta := readerCalls["assembly_kernel"] - assemblyReadsAtCommit; delta != 2 {
				t.Fatalf("exact refresh must consume one before/after host pair, got%d", delta)
			}
			assemblyReadsAtCommit = readerCalls["assembly_kernel"]
		}
		return measuredReplace(ctx, in)
	}
	readers := *r.c.statusReaders
	r.c.statusReaders.daemon = func(ctx context.Context) (DaemonInventory, error) { return readers.daemon(ctx) }
	r.c.statusReaders.kernel = func(ctx context.Context) (KernelInventory, error) {
		readerCalls["kernel"]++
		if fqdnCadenceInCall(".beginAssemblySnapshot") || fqdnCadenceInCall(".(*runtimeAssemblySnapshot).finish") {
			readerCalls["assembly_kernel"]++
		}
		return readers.kernel(ctx)
	}
	r.c.statusReaders.xfrm = func(ctx context.Context) (XFRMInventory, error) { readerCalls["xfrm"]++; return readers.xfrm(ctx) }
	pub := func(_ context.Context, d RuntimeDelivery, report RuntimeStatusReport) error {
		if report.DeliveryID != d.ID || report.DesiredRevision != d.DesiredRevision || report.ConfigurationRevision != d.Manifest.ConfigurationRevision {
			return ErrRuntimeController
		}
		if d.Manifest.RecoveryVersion != nil {
			if report.RecoveryVersion == nil || *report.RecoveryVersion != 1 || report.SelectionSequence == nil || *report.SelectionSequence == 0 || report.BGP != nil {
				return ErrRuntimeController
			}
			if report.Tunnels[0].Status != "up" || report.Tunnels[1].Status != "up" || report.ActiveSlot == nil {
				return ErrRuntimeController
			}
			_, seq, e := r.c.journal.guardTemplates()
			if e != nil || *report.SelectionSequence > seq {
				return ErrRuntimeController
			}
		}
		r.charge("status_http", 100*time.Millisecond)
		check()
		return nil
	}
	recovery := func(context.Context, RuntimeRecoveryHeartbeat) error {
		r.charge("recovery_http", 100*time.Millisecond)
		check()
		return nil
	}
	var err error
	for cycle := 0; *r.now-start < 180*time.Second && err == nil; cycle++ {
		cycleStarted := *r.now
		phaseStarted := cycleStarted
		if cycle == 0 {
			for _, a := range r.c.active {
				t.Logf("scope=%t profile=%q manifest=%q supported=%t", r.c.exactPageRefreshScope(), a.Entry.Allocation.ProfileID, a.Delivery.Manifest.ProfileID, runtimeFQDNFollowupEntrySupported(a.Entry))
			}
		}
		for id, w := range r.c.fqdnNativeWindows {
			t.Logf("before cycle=%d owner=%s nativeRemaining=%s", cycle, id, w.deadline-*r.now)
		}
		// Match production priority: urgent short-member work, ordinary renewal,
		// post-renewal followup and independent active status observation.
		err = r.c.followupFQDNMaintenance(context.Background(), maintenanceAuthority(r), func() bool { return true }, pub, recovery, fqdnTestWait(r))
		t.Logf("phase pre_followup elapsed=%s", *r.now-phaseStarted)
		phaseStarted = *r.now
		if err == nil {
			err = r.c.renewActiveIPsecRuntimeObserved(context.Background(), maintenanceAuthority(r), func() bool { return true }, pub, recovery)
		}
		t.Logf("phase priority_renew elapsed=%s", *r.now-phaseStarted)
		phaseStarted = *r.now
		if err == nil {
			err = r.c.followupFQDNMaintenance(context.Background(), maintenanceAuthority(r), func() bool { return true }, pub, recovery, fqdnTestWait(r))
		}
		t.Logf("phase post_followup elapsed=%s", *r.now-phaseStarted)
		phaseStarted = *r.now
		if err == nil {
			seen := map[uuid.UUID]bool{}
			var collected []RuntimeRecoveryHeartbeat
			for i := 0; i < 4; i++ {
				reports, e := r.c.refreshIPsecActiveRecoveryLockedQualified(context.Background(), seen, false, time.Now(), func() bool { return true })
				if e != nil {
					err = e
					break
				}
				if len(reports) == 0 {
					break
				}
				for _, out := range reports {
					seen[out.ConnectionID] = true
					if out.Report.SelectionSequence != nil {
						collected = append(collected, out)
					}
				}
			}
			if err == nil {
				for _, out := range collected {
					r.c.rememberRecoveryReport(context.Background(), out.ConnectionID, out.Delivery, out.Report)
				}
				for _, out := range collected {
					if e := recovery(context.Background(), out); e != nil {
						err = e
						break
					}
				}
			}
		}
		t.Logf("phase standalone_status elapsed=%s", *r.now-phaseStarted)
		phaseStarted = *r.now
		if err == nil {
			// The real agent always discovers/polls after priority. A retained
			// validated set triggers its bounded post-page followup; a genuinely
			// deferred/empty page must still take independent Validate.
			r.charge("discovery_http", 200*time.Millisecond)
			page := make([]RuntimeMaterial, 0, len(r.materials))
			for _, m := range r.materials {
				next, e := client.IPsecMaterial(context.Background(), m.Manifest.ConnectionID, m.DesiredRevision)
				if e != nil {
					err = e
					break
				}
				page = append(page, next)
			}
			if err == nil {
				for _, m := range page {
					a := r.c.active[m.Manifest.ConnectionID]
					t.Logf("normal page scope=%t owner=%s sameHash=%t due=%t", r.c.exactPageRefreshScope(), m.Manifest.ConnectionID, m.Policy.Hash == a.Identity.PolicyHash, r.c.maintenanceRenewalDue(a))
				}
				var results []RuntimeMaintenanceResult
				results, err = r.c.maintainIPsecRuntimeRecoveryObserved(context.Background(), page, maintenanceAuthority(r), func() bool { return true }, pub, recovery)
				if err == nil {
					validated := false
					for _, result := range results {
						validated = validated || result.Retained != nil || result.Acknowledgement.Result == "applied"
						if result.Acknowledgement.Result == "applied" {
							r.charge("ack_http", 100*time.Millisecond)
							check()
						}
					}
					if validated {
						err = r.c.followupFQDNMaintenance(context.Background(), maintenanceAuthority(r), func() bool { return true }, pub, recovery, fqdnTestWait(r))
					} else {
						err = r.c.Validate(context.Background())
					}
				}
			}
		}
		t.Logf("phase normal_page_and_followup elapsed=%s", *r.now-phaseStarted)
		if elapsed := *r.now - cycleStarted; elapsed < 5*time.Second {
			r.charge("agent_ticker_idle", 5*time.Second-elapsed)
			check()
		}
		t.Logf("cycle=%d now=%s gap=%t err=%v", cycle, *r.now-start, gap, err)
	}
	check()
	t.Logf("elapsed=%s err=%v gap=%t firstGap=%s firstCommit=%s reads=%d requests=%d inventoryCalls=%v costs=%v", *r.now-start, err, gap, firstGap-start, firstCommit-start, client.reads, client.requests, readerCalls, r.charged)
	for _, a := range old {
		for _, f := range a.FQDNLeaseDescriptors {
			if a.Authority.fqdnDeadlines[runtimeFQDNGrantDigest(f)] != client.deadlines[runtimeFQDNGrantDigest(f)] {
				t.Fatal("original deadline changed")
			}
		}
	}
	if err != nil || gap {
		t.Fatal("same-answer subset renewal lost finite HTTPS membership")
	}
	if len(r.c.active) != 3 {
		t.Fatal("lost retained owner")
	}
	for id, a := range old {
		current := r.c.active[id]
		if !reflect.DeepEqual(a.Entry, current.Entry) || current.Authority == nil {
			t.Fatal("retained transport changed")
		}
		if _, e := current.Authority.RemainingForApply(current.Identity, time.Millisecond); e != nil {
			t.Fatal("ordinary authority expired", e)
		}
	}
}

func fqdnCadenceInCall(suffix string) bool {
	var pcs [40]uintptr
	n := runtime.Callers(2, pcs[:])
	frames := runtime.CallersFrames(pcs[:n])
	for {
		f, more := frames.Next()
		if strings.HasSuffix(f.Function, suffix) {
			return true
		}
		if !more {
			return false
		}
	}
}
