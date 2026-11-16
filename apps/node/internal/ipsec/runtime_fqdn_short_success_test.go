package ipsec

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
	"net/netip"
	"reflect"
	"testing"
	"time"
)

type shortSuccessfulFQDNLeaseClient struct {
	*fqdnTurnoverClient
	rig                   *renewalCycleRig
	oldDeadline           time.Duration
	published             bool
	fetchAttempts         int
	fetchError            error
	onFetch               func()
	rejectOldAfterPublish bool
	rejectFresh           bool
	oldReplyTTL           time.Duration
}

func (c *shortSuccessfulFQDNLeaseClient) RenewIPsecLease(ctx context.Context, id uuid.UUID, q RuntimeLeaseRequest) (RuntimeLease, error) {
	if id != c.target || q.PolicyHash != c.oldHash {
		if id == c.target && c.rejectFresh {
			c.requests = append(c.requests, q)
			return RuntimeLease{}, fqdnTurnoverConflict{}
		}
		return c.fqdnTurnoverClient.RenewIPsecLease(ctx, id, q)
	}
	c.requests = append(c.requests, q)
	if c.published && c.rejectOldAfterPublish {
		return RuntimeLease{}, fqdnTurnoverConflict{}
	}
	out, err := c.base.RenewIPsecLease(ctx, id, q)
	if err != nil {
		return out, err
	}
	ttl := c.oldDeadline - *c.rig.now
	if c.oldReplyTTL > 0 {
		ttl = c.oldReplyTTL
	}
	for _, g := range q.FQDNGrants {
		out.FQDNPermits = append(out.FQDNPermits, RuntimeFQDNPermit{GrantDigest: runtimeFQDNGrantDigest(g), TTLMS: ttl.Milliseconds()})
	}
	// The CP transaction completed against the old generation. An identical
	// newly resolved generation publishes before native bridge/commit IO.
	c.published = true
	return out, nil
}
func (c *shortSuccessfulFQDNLeaseClient) IPsecMaterial(ctx context.Context, id uuid.UUID, rev int64) (RuntimeMaterial, error) {
	c.fetchAttempts++
	if c.onFetch != nil {
		c.onFetch()
	}
	if !c.published || c.fetchError != nil {
		return RuntimeMaterial{}, ErrRuntimeController
	}
	return c.fqdnTurnoverClient.IPsecMaterial(ctx, id, rev)
}
func TestSuccessfulShortFQDNLeaseRefreshesBeforeSilentGuardCutoff(t *testing.T) {
	for _, priority := range []bool{true, false} {
		name := "normal_page"
		if priority {
			name = "priority"
		}
		t.Run(name, func(t *testing.T) {
			r, base := fqdnExpiryTurnoverRig(t)
			old := r.c.active[r.target]
			process := r.c.bgpProcesses[old.Entry.DeliveryID]
			// The deployed topology has one BGP owner. Retained journal obligations for
			// other fixture owners remain denied; no replacement authority is supplied.
			for id := range r.c.active {
				if id != r.target {
					delete(r.c.active, id)
				}
			}
			var oldName string
			for _, g := range old.Grants {
				if g.FQDNManaged {
					oldName = guardFQDNSetName(g)
				}
			}
			if oldName == "" {
				t.Fatal("missing exact FQDN fixture")
			}
			*r.now = r.installed[oldName] - 6*time.Second
			deadline := old.Authority.fqdnDeadlines[runtimeFQDNGrantDigest(old.FQDNLeaseDescriptors[0])]
			client := &shortSuccessfulFQDNLeaseClient{fqdnTurnoverClient: base, rig: r, oldDeadline: deadline}
			r.c.client = client
			t.Logf("old native remaining=%v original FQDN deadline remaining=%v", r.installed[oldName]-*r.now, deadline-*r.now)
			lost := false
			commits := 0
			replace := r.c.replace
			r.c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
				commits++
				if r.installed[oldName] <= *r.now {
					t.Errorf("old FQDN native membership expired before atomic replacement: remaining=%v", r.installed[oldName]-*r.now)
				}
				found := false
				for _, owner := range in.Connections {
					if owner.ID == r.target {
						for _, g := range owner.Grants {
							if g.FQDNManaged {
								found = true
							}
						}
					}
				}
				if !found {
					lost = true
				}
				return replace(ctx, in)
			}
			var err error
			if priority {
				err = r.c.renewActiveIPsecRuntimeObserved(context.Background(), maintenanceAuthority(r), func() bool { return true }, nil, nil)
			} else {
				material := base.material
				material.Policy.FQDNGrants = append([]RuntimeFQDNGrant(nil), old.FQDNLeaseDescriptors...)
				material.Policy.Hash = old.Identity.PolicyHash
				var out []RuntimeMaintenanceResult
				out, err = r.c.maintainIPsecRuntime(context.Background(), []RuntimeMaterial{material}, maintenanceAuthority(r), func() bool { return true })
				if len(out) != 1 {
					t.Errorf("normal maintenance omitted owner: %d", len(out))
				}
			}
			t.Logf("err=%v commits=%d lost=%t fresh material fetches=%d leases=%d", err, commits, lost, client.fetched, len(client.requests))
			if err != nil || lost || client.fetched != 1 || r.c.active[r.target].Identity.PolicyHash != base.material.Policy.Hash {
				t.Fatal("successful short lease silently removed live FQDN tuple instead of exact fresh rollover")
			}
			after := r.c.active[r.target]
			if len(client.requests) != 2 || client.requests[0].Nonce == client.requests[1].Nonce || !reflect.DeepEqual(after.Entry, old.Entry) || r.c.bgpProcesses[old.Entry.DeliveryID] != process || !process.Alive() {
				t.Fatal("expiry-only recollection changed transport or reused nonce")
			}
			for _, g := range after.Grants {
				if g.FQDNManaged {
					if r.installed[guardFQDNSetName(g)] <= *r.now {
						t.Fatal("fresh exact FQDN member absent after commit")
					}
					if _, err := after.Authority.RemainingFQDNForApply(after.Identity, guardFQDNGrantDigest(g), time.Millisecond); err != nil {
						t.Fatal("fresh FQDN member lacks exact CP permit")
					}
				}
			}
			if old.Authority.fqdnDeadlines[runtimeFQDNGrantDigest(old.FQDNLeaseDescriptors[0])] != deadline {
				t.Fatal("old finite deadline extended")
			}
		})
	}
}

func TestSuccessfulShortFQDNLeaseRetryBoundAndRefusal(t *testing.T) {
	for _, priority := range []bool{true, false} {
		path := "normal_page"
		if priority {
			path = "priority"
		}
		for _, mode := range []string{"unavailable", "unchanged", "changed_answer", "changed_rule", "changed_resolver", "changed_device", "revoked", "expired_material", "wrong_fresh_nonce", "slow_fetch", "second_conflict", "second_cutoff"} {
			t.Run(path+"/"+mode, func(t *testing.T) {
				r, base := fqdnExpiryTurnoverRig(t)
				old := r.c.active[r.target]
				process := r.c.bgpProcesses[old.Entry.DeliveryID].(*bgpSessionFixture)
				for id := range r.c.active {
					if id != r.target {
						delete(r.c.active, id)
					}
				}
				var oldName string
				for _, g := range old.Grants {
					if g.FQDNManaged {
						oldName = guardFQDNSetName(g)
					}
				}
				*r.now = r.installed[oldName] - 6*time.Second
				deadline := old.Authority.fqdnDeadlines[runtimeFQDNGrantDigest(old.FQDNLeaseDescriptors[0])]
				ordinaryDeadline := old.Authority.deadline
				client := &shortSuccessfulFQDNLeaseClient{fqdnTurnoverClient: base, rig: r, oldDeadline: deadline}
				r.c.client = client
				fallback := false
				switch mode {
				case "unavailable":
					client.fetchError = ErrRuntimeController
					fallback = true
				case "unchanged":
					base.material.Policy.Hash = old.Identity.PolicyHash
					base.material.Policy.FQDNGrants = append([]RuntimeFQDNGrant(nil), old.FQDNLeaseDescriptors...)
					fallback = true
				case "changed_answer":
					base.material.Policy.FQDNGrants[0].Destination = netip.PrefixFrom(netip.MustParsePrefix(base.material.Policy.FQDNGrants[0].Destination).Addr().Next(), 32).String()
					client.rejectOldAfterPublish = true
				case "changed_rule":
					base.material.Policy.FQDNGrants[0].RuleID = uuid.NewString()
					client.rejectOldAfterPublish = true
				case "changed_resolver":
					base.material.Policy.FQDNGrants[0].ResolverConfigVersion++
					client.rejectOldAfterPublish = true
				case "changed_device":
					base.material.Policy.FQDNGrants[0].DeviceID = uuid.NewString()
					client.rejectOldAfterPublish = true
				case "revoked":
					base.material.Policy.FQDNGrants = nil
					base.material.Policy.FQDNPolicyVersion = 0
					client.rejectOldAfterPublish = true
				case "expired_material":
					base.material.Policy.FQDNGrants[0].ExpiresAt = time.Now().Add(-time.Second)
					client.rejectOldAfterPublish = true
				case "wrong_fresh_nonce":
					base.mutate = func(l *RuntimeLease) { l.Nonce = "not-the-request" }
				case "slow_fetch":
					client.onFetch = func() { *r.now = ordinaryDeadline + time.Millisecond }
				case "second_conflict":
					client.rejectFresh = true
				case "second_cutoff":
					base.mutate = func(l *RuntimeLease) {
						for i := range l.FQDNPermits {
							l.FQDNPermits[i].TTLMS = 9000
						}
					}
					fallback = true
				}
				var err error
				var results []RuntimeMaintenanceResult
				if priority {
					err = r.c.renewActiveIPsecRuntimeObserved(context.Background(), maintenanceAuthority(r), func() bool { return true }, nil, nil)
				} else {
					material := base.material
					// The normal page was read before the fresh publication, exactly as the
					// priority pass retained its original authenticated descriptor.
					material.Policy.Hash = old.Identity.PolicyHash
					material.Policy.FQDNPolicyVersion = 2
					material.Policy.FQDNGrants = append([]RuntimeFQDNGrant(nil), old.FQDNLeaseDescriptors...)
					results, err = r.c.maintainIPsecRuntime(context.Background(), []RuntimeMaterial{material}, maintenanceAuthority(r), func() bool { return true })
				}
				if client.fetchAttempts != 1 {
					t.Fatalf("unbounded/missing material recollection: %d", client.fetchAttempts)
				}
				if len(client.requests) > 2 {
					t.Fatalf("retried a second turnover: leases=%d", len(client.requests))
				}
				current, present := r.c.active[r.target]
				if fallback {
					if err != nil || !present || current.Authority == nil {
						t.Fatalf("DNS cutoff incorrectly removed ordinary authority: %v", err)
					}
					for _, name := range []string{guardLeaseName(r.target), guardReplyLeaseName(r.target), guardSALeaseName(r.target)} {
						if r.installed[name] <= *r.now {
							t.Fatalf("ordinary finite member missing: %s", name)
						}
					}
					for _, g := range current.Grants {
						if g.FQDNManaged {
							if _, ok := r.installed[guardFQDNSetName(g)]; ok {
								t.Fatal("unavailable or short FQDN permit installed")
							}
						}
					}
				} else {
					if err == nil {
						t.Fatal("unsafe refresh unexpectedly succeeded")
					}
					assertFQDNPublicationDenied(t, r, old, process, results)
				}
				if old.Authority.deadline != ordinaryDeadline || old.Authority.fqdnDeadlines[runtimeFQDNGrantDigest(old.FQDNLeaseDescriptors[0])] != deadline {
					t.Fatal("original authority was extended or replaced")
				}
			})
		}
	}
}

func TestFQDNConflictThenCutoffDoesNotRefreshTwice(t *testing.T) {
	r, client := fqdnExpiryTurnoverRig(t)
	client.mutate = func(l *RuntimeLease) {
		for i := range l.FQDNPermits {
			l.FQDNPermits[i].TTLMS = 9000
		}
	}
	if err := r.c.renewActiveIPsecRuntimeObserved(context.Background(), maintenanceAuthority(r), func() bool { return true }, nil, nil); err != nil {
		t.Fatal(err)
	}
	if client.fetched != 1 || len(client.requests) != 2 {
		t.Fatal("cutoff retried an already refreshed409 owner", client.fetched, len(client.requests))
	}
	a := r.c.active[r.target]
	for _, g := range a.Grants {
		if g.FQDNManaged {
			if _, ok := r.installed[guardFQDNSetName(g)]; ok {
				t.Fatal("short second lease installed")
			}
		}
	}
	if r.installed[guardLeaseName(r.target)] <= *r.now {
		t.Fatal("finite ordinary connection authority missing")
	}
}

func TestShortFQDNCutoffRecollectionKeepsOrdinaryReportCallbacks(t *testing.T) {
	for _, priority := range []bool{true, false} {
		name := "normal_page"
		if priority {
			name = "priority"
		}
		t.Run(name, func(t *testing.T) {
			r, base := fqdnExpiryTurnoverRig(t)
			old := r.c.active[r.target]
			var staticID uuid.UUID
			for id, a := range r.c.active {
				if a.Entry.ContractVersion == 2 {
					staticID = id
					break
				}
			}
			if staticID == uuid.Nil {
				t.Fatal("missing ordinary recovery owner")
			}
			originalStatic := r.c.active[staticID]
			originalStaticDeadline := originalStatic.Authority.deadline
			for id := range r.c.active {
				if id != r.target && id != staticID {
					delete(r.c.active, id)
				}
			}
			// This case isolates callback/snapshot binding. The charged one-owner
			// regression above supplies the real short native deadline/IO boundary.
			r.c.prove = func(context.Context, RuntimeJournalEntry, RuntimeEnvironment) error { return nil }
			r.c.recoveryObserve = func(context.Context, RuntimeJournalEntry) [2]string { return [2]string{"up", "up"} }
			client := &shortSuccessfulFQDNLeaseClient{fqdnTurnoverClient: base, rig: r, oldDeadline: old.Authority.fqdnDeadlines[runtimeFQDNGrantDigest(old.FQDNLeaseDescriptors[0])], oldReplyTTL: 9 * time.Second}
			r.c.client = client
			publications, pulses := 0, 0
			publish := func(context.Context, RuntimeDelivery, RuntimeStatusReport) error { publications++; return nil }
			recovery := func(context.Context, RuntimeRecoveryHeartbeat) error { pulses++; return nil }
			var err error
			if priority {
				err = r.c.renewActiveIPsecRuntimeObserved(context.Background(), maintenanceAuthority(r), func() bool { return true }, publish, recovery)
			} else {
				materials := []RuntimeMaterial{staleFQDNPage(r, base)}
				for _, m := range r.materials {
					if m.Manifest.ConnectionID == staticID {
						materials = append(materials, m)
					}
				}
				_, err = r.c.maintainIPsecRuntimeRecoveryObserved(context.Background(), materials, maintenanceAuthority(r), func() bool { return true }, publish, recovery)
			}
			if err != nil || client.fetchAttempts != 1 || len(client.requests) != 2 || publications != 2 || pulses == 0 || len(r.c.active) != 2 {
				t.Fatalf("mixed recollection failed: err=%v fetch=%d leases=%d pubs=%d pulses=%d active=%d", err, client.fetchAttempts, len(client.requests), publications, pulses, len(r.c.active))
			}
			if originalStatic.Authority.deadline != originalStaticDeadline {
				t.Fatal("mutated original static authority")
			}
			for _, id := range []uuid.UUID{r.target, staticID} {
				for _, set := range []string{guardLeaseName(id), guardReplyLeaseName(id), guardSALeaseName(id)} {
					if r.installed[set] <= *r.now {
						t.Fatal("recollection lost unrelated finite authority", set)
					}
				}
			}
		})
	}
}

type twoFQDNOwnerClient struct {
	base   RuntimeLeaseClient
	owners map[uuid.UUID]RuntimeLeaseClient
}

func (c twoFQDNOwnerClient) RenewIPsecLease(ctx context.Context, id uuid.UUID, q RuntimeLeaseRequest) (RuntimeLease, error) {
	if owner := c.owners[id]; owner != nil {
		return owner.RenewIPsecLease(ctx, id, q)
	}
	return c.base.RenewIPsecLease(ctx, id, q)
}
func (c twoFQDNOwnerClient) IPsecMaterial(ctx context.Context, id uuid.UUID, rev int64) (RuntimeMaterial, error) {
	if owner, ok := c.owners[id].(runtimeCurrentMaterialClient); ok {
		return owner.IPsecMaterial(ctx, id, rev)
	}
	return RuntimeMaterial{}, ErrRuntimeController
}

func TestFQDNCutoffRecollectionPreservesEarlierConflictMaterial(t *testing.T) {
	for _, priority := range []bool{true, false} {
		name := "normal_page"
		if priority {
			name = "priority"
		}
		t.Run(name, func(t *testing.T) {
			r, first := fqdnExpiryTurnoverRig(t)
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
			// Isolate cross-owner metadata/nonce preservation from IO timing, which is
			// covered by the six-second native-member regression above.
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
			second := &shortSuccessfulFQDNLeaseClient{fqdnTurnoverClient: secondBase, rig: r, oldDeadline: auth.fqdnDeadlines[runtimeFQDNGrantDigest(f)], oldReplyTTL: 9 * time.Second}
			r.c.client = twoFQDNOwnerClient{base: first.base, owners: map[uuid.UUID]RuntimeLeaseClient{r.target: first, secondID: second}}
			if priority {
				err = r.c.renewActiveIPsecRuntimeObserved(context.Background(), maintenanceAuthority(r), func() bool { return true }, nil, nil)
			} else {
				_, err = r.c.maintainIPsecRuntime(context.Background(), []RuntimeMaterial{staleFQDNPage(r, first), secondMaterial}, maintenanceAuthority(r), func() bool { return true })
			}
			// Exact current owners may be retained by maintenance; their short FQDN
			// windows are renewed by the follow-up path, and TestFQDNThreeOwnerCadence
			// proves no membership gap across the whole agent cycle. Maintenance must
			// still keep both owners and their live members, and any lease it does
			// request must never revert to superseded material or reuse a nonce.
			if err != nil || len(r.c.active) != 2 {
				t.Fatalf("lost earlier validated material: err=%v firstfetch=%d secondfetch=%d firstleases=%d secondleases=%d active=%d", err, first.fetched, second.fetchAttempts, len(first.requests), len(second.requests), len(r.c.active))
			}
			current := false
			for _, request := range first.requests {
				if request.PolicyHash == first.material.Policy.Hash {
					current = true
				} else if current {
					t.Fatal("recollection reverted first owner to superseded material")
				}
			}
			for _, requests := range [][]RuntimeLeaseRequest{first.requests, second.requests} {
				seen := map[string]bool{}
				for _, request := range requests {
					if request.Nonce == "" || seen[request.Nonce] {
						t.Fatal("recollection reused nonce")
					}
					seen[request.Nonce] = true
				}
			}
			for _, id := range []uuid.UUID{r.target, secondID} {
				a := r.c.active[id]
				for _, g := range a.Grants {
					if g.FQDNManaged && r.installed[guardFQDNSetName(g)] <= *r.now {
						t.Fatal("recollection lost exact live FQDN member", id)
					}
				}
			}
		})
	}
}
