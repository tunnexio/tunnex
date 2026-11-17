package ipsec

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	bgpengine "github.com/tunnexio/tunnex/apps/node/internal/bgp"
	"net/netip"
	"reflect"
	"testing"
	"time"
)

func fqdnRouteSwitchRig(t *testing.T) (*renewalCycleRig, *fqdnTurnoverClient, *recoveryKernelFixture, *bgpSessionFixture) {
	t.Helper()
	r, client := fqdnExpiryTurnoverRig(t)
	old := r.c.active[r.target]
	k := newRecoveryKernelFixture()
	k.p, k.owned = old.Entry.Allocation, old.Entry.Observed
	for i, tunnel := range k.p.Tunnels {
		k.routes[i] = map[string]bool{netip.PrefixFrom(tunnel.BGP.Peer, 32).String(): true}
	}
	for _, route := range old.Entry.BGPRoutes.Owned {
		k.routes[route.Slot-1][route.Prefix.String()] = true
	}
	r.c.kernel = k.applier()
	r.c.guard.apply = func(_ context.Context, raw []byte) error {
		var doc struct {
			Commands []map[string]struct {
				Set map[string]any `json:"set"`
			} `json:"nftables"`
		}
		if json.Unmarshal(raw, &doc) != nil || len(doc.Commands) != 3 {
			t.Fatal("not exact three-set denial")
		}
		names := bgpScopeNames(r.target)
		seen := map[string]bool{}
		for _, cmd := range doc.Commands {
			f, ok := cmd["flush"]
			n, _ := f.Set["name"].(string)
			if !ok || !names[n] || seen[n] || len(f.Set) != 3 || f.Set["table"] != "tunnex_ipsec" || f.Set["family"] != "inet" {
				t.Fatal("foreign denial command")
			}
			seen[n] = true
			r.installed[n] = *r.now
		}
		r.applicationDenied[r.target] = true
		return nil
	}
	return r, client, k, r.c.bgpProcesses[old.Entry.DeliveryID].(*bgpSessionFixture)
}

func routeSwitchNativeLive(r *renewalCycleRig, old runtimeActive) bool {
	for name := range bgpScopeNames(r.target) {
		if r.installed[name] <= *r.now {
			return false
		}
	}
	marked := 0
	for _, g := range old.Grants {
		if g.FQDNManaged {
			marked++
			if r.installed[guardFQDNSetName(g)] <= *r.now {
				return false
			}
		}
	}
	return marked > 0
}

func TestFQDNBGPRouteSwitchPreservesExactNativeAuthority(t *testing.T) {
	r, _, k, p := fqdnRouteSwitchRig(t)
	old := cloneMaintenanceActive(r.c.active[r.target])
	originalWindow := r.c.fqdnNativeWindows[r.target]
	native := map[string]time.Duration{}
	for n, d := range r.installed {
		native[n] = d
	}
	deadline := old.Authority.deadline
	fqdnDeadline := old.Authority.fqdnDeadlines[runtimeFQDNGrantDigest(old.FQDNLeaseDescriptors[0])]
	replacements := 0
	baseReplace := r.c.replace
	r.c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
		replacements++
		return baseReplace(ctx, in)
	}
	for _, slot := range []uint8{2, 1} {
		current := r.c.active[r.target]
		target := routeTupleFixture(current.Entry, slot)
		p.routes = []bgpengine.LearnedRoute{{Prefix: target.Prefix, Slot: int(slot)}}
		actions := []string{}
		base := k.run
		r.c.kernel.run = func(ctx context.Context, args ...string) ([]byte, error) {
			mutation := len(args) == 12 && args[0] == "-4" && args[1] == "route"
			if !routeSwitchNativeLive(r, old) {
				t.Fatal("finite native authority disappeared before route IO")
			}
			if mutation {
				actions = append(actions, args[2])
				if !k.routes[0][target.Prefix.String()] && !k.routes[1][target.Prefix.String()] {
					t.Fatal("no route before mutation")
				}
			}
			out, err := base(ctx, args...)
			if !routeSwitchNativeLive(r, old) {
				t.Fatal("finite native authority disappeared after route IO")
			}
			if mutation && !k.routes[0][target.Prefix.String()] && !k.routes[1][target.Prefix.String()] {
				t.Fatal("no route after mutation")
			}
			return out, err
		}
		entries, err := r.c.journal.Entries()
		if err != nil {
			t.Fatal(err)
		}
		if err = r.c.reconcileActiveBGP(context.Background(), entries); err != nil {
			t.Fatal(err)
		}
		after := r.c.active[r.target]
		if !reflect.DeepEqual(actions, []string{"add", "del"}) || !reflect.DeepEqual(after.Entry.BGPRoutes.Owned, []RuntimeBGPRouteTuple{target}) {
			t.Fatal("not add-before-delete exact switch", actions)
		}
		if !reflect.DeepEqual(after.Grants, old.Grants) || after.Authority != old.Authority || p.closed || replacements != 0 || !reflect.DeepEqual(native, r.installed) {
			t.Fatal("route switch changed finite native authority")
		}
		w := r.c.fqdnNativeWindows[r.target]
		if w.deadline != originalWindow.deadline || !reflect.DeepEqual(w.owner, after) {
			t.Fatal("advice owner/deadline not exact")
		}
	}
	if old.Authority.deadline != deadline || old.Authority.fqdnDeadlines[runtimeFQDNGrantDigest(old.FQDNLeaseDescriptors[0])] != fqdnDeadline {
		t.Fatal("CP authority extended")
	}
	before := k.mutations
	entries, _ := r.c.journal.Entries()
	if err := r.c.reconcileActiveBGP(context.Background(), entries); err != nil || k.mutations != before {
		t.Fatal("identical route mutated", err)
	}
}

func TestFQDNBGPRouteSwitchFailuresRetainDurableDuties(t *testing.T) {
	for _, mode := range []string{"add", "delete", "union_readback", "target_readback", "pending_save", "completed_save", "owner_changed", "second_rib", "transport_lost"} {
		t.Run(mode, func(t *testing.T) {
			r, _, k, p := fqdnRouteSwitchRig(t)
			old := cloneMaintenanceActive(r.c.active[r.target])
			target := routeTupleFixture(old.Entry, 2)
			p.routes = []bgpengine.LearnedRoute{{Prefix: target.Prefix, Slot: 2}}
			ordinaryDeadline := old.Authority.deadline
			fqdnDeadline := old.Authority.fqdnDeadlines[runtimeFQDNGrantDigest(old.FQDNLeaseDescriptors[0])]
			if mode == "add" {
				k.failAt = 1
			}
			if mode == "delete" {
				k.failAt = 2
			}
			save := r.c.journal.syncDirectory
			saves := 0
			r.c.journal.syncDirectory = func() error {
				saves++
				if (mode == "pending_save" && saves == 1) || (mode == "completed_save" && saves == 2) {
					return errors.New("injected directory sync uncertainty")
				}
				return save()
			}
			run := k.run
			r.c.kernel.run = func(ctx context.Context, args ...string) ([]byte, error) {
				out, err := run(ctx, args...)
				if len(args) == 12 && args[1] == "route" && err == nil {
					if (mode == "union_readback" && args[2] == "add") || (mode == "target_readback" && args[2] == "del") {
						k.badMetric = true
					}
					if mode == "owner_changed" && args[2] == "add" {
						a := r.c.active[r.target]
						a.Identity.PolicyHash = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
						r.c.active[r.target] = a
					}
					if mode == "second_rib" && args[2] == "del" {
						p.routes = []bgpengine.LearnedRoute{{Prefix: target.Prefix, Slot: 1}}
					}
					if mode == "transport_lost" && args[2] == "del" {
						r.c.recoveryObserve = func(context.Context, RuntimeJournalEntry) [2]string { return [2]string{"up", "down"} }
					}
				}
				return out, err
			}
			entries, _ := r.c.journal.Entries()
			if err := r.c.reconcileActiveBGP(context.Background(), entries); err == nil {
				t.Fatal("unsafe switch accepted")
			}
			if _, ok := r.c.active[r.target]; ok {
				t.Fatal("failed owner retained")
			}
			for name := range bgpScopeNames(r.target) {
				if r.installed[name] > *r.now {
					t.Fatal("native permit survived refused switch", name)
				}
			}
			if !p.closed {
				t.Fatal("known process not stopped after native denial")
			}
			if old.Authority.deadline != ordinaryDeadline || old.Authority.fqdnDeadlines[runtimeFQDNGrantDigest(old.FQDNLeaseDescriptors[0])] != fqdnDeadline {
				t.Fatal("authority changed")
			}
			dir := r.c.journal.dir
			r.c.journal.Close()
			reopened, err := OpenRuntimeJournal(dir, r.c.config.GatewayID)
			if err != nil {
				t.Fatal("durable obligation cannot reopen", err)
			}
			defer reopened.Close()
			disk, err := reopened.Entries()
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, e := range disk {
				if e.Allocation.ConnectionID == r.target {
					found = true
					stage := "pending"
					if mode == "completed_save" || mode == "second_rib" || mode == "transport_lost" {
						stage = "completed"
					}
					if e.BGPRoutes.Stage != stage {
						t.Fatal("durable stage lost", e.BGPRoutes.Stage, stage)
					}
					duties := bgpRouteUnion(e.BGPRoutes)
					for slot := 0; slot < 2; slot++ {
						if k.routes[slot][target.Prefix.String()] {
							covered := false
							for _, d := range duties {
								covered = covered || d.Prefix == target.Prefix && int(d.Slot) == slot+1
							}
							if !covered {
								t.Fatal("surviving native route lost cleanup duty")
							}
						}
					}
				}
			}
			if !found {
				t.Fatal("entry disappeared")
			}
		})
	}
}

func TestFQDNBGPRouteSwitchRejectsUnsafeContinuity(t *testing.T) {
	for _, mode := range []string{"empty_prefix", "changed_prefix", "down", "unknown", "short_native", "missing_native_member", "native_unknown", "policy_revoked", "ordinary_expired", "fqdn_expired"} {
		t.Run(mode, func(t *testing.T) {
			r, _, k, p := fqdnRouteSwitchRig(t)
			old := r.c.active[r.target]
			target := []RuntimeBGPRouteTuple{routeTupleFixture(old.Entry, 2)}
			health := [2]string{"up", "up"}
			switch mode {
			case "empty_prefix":
				target = nil
			case "changed_prefix":
				target[0].Prefix = netip.MustParsePrefix("192.0.2.0/24")
			case "down":
				health[1] = "down"
			case "unknown":
				health[1] = "unknown"
			case "short_native":
				w := r.c.fqdnNativeWindows[r.target]
				w.deadline = *r.now + 5*time.Second
				r.c.fqdnNativeWindows[r.target] = w
			}
			if mode == "empty_prefix" || mode == "changed_prefix" || mode == "down" || mode == "unknown" || mode == "short_native" {
				if r.c.canPreserveBGPRouteSwitch(old, target, health) {
					t.Fatal("unsafe fast-path admission")
				}
				return
			}
			p.routes = []bgpengine.LearnedRoute{{Prefix: target[0].Prefix, Slot: 2}}
			switch mode {
			case "missing_native_member":
				for _, g := range old.Grants {
					if g.FQDNManaged {
						r.installed[guardFQDNSetName(g)] = *r.now
					}
				}
			case "native_unknown":
				r.c.guard.reader.run = func(context.Context, ...string) ([]byte, error) { return nil, ErrGuardRead }
			case "policy_revoked":
				r.c.config.FQDNPolicy.CommittedPolicy(nil)
			case "ordinary_expired":
				*r.now = old.Authority.deadline
			case "fqdn_expired":
				*r.now = old.Authority.fqdnDeadlines[runtimeFQDNGrantDigest(old.FQDNLeaseDescriptors[0])]
			}
			entries, _ := r.c.journal.Entries()
			if _, err := r.c.preserveBGPRouteSwitch(context.Background(), entries, old, target); err == nil || k.mutations != 0 {
				t.Fatal("unsafe authority used for route mutation", err, k.mutations)
			}
		})
	}
}

func TestFQDNBGPRouteSwitchCapturedDenialRejectsForeignNative(t *testing.T) {
	for _, mode := range []string{"foreign_owner", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			r, _, _, _ := fqdnRouteSwitchRig(t)
			templates, _, err := r.c.journal.guardTemplates()
			if err != nil || len(templates) != 1 {
				t.Fatal("template")
			}
			raw := r.native()
			if mode == "malformed" {
				raw = []byte(`{"nftables":[{"set":{"elem":[false]}}]}`)
			} else {
				raw = bgpScopeEdit(t, raw, func(s map[string]any) {
					if s["name"] == guardLeaseName(r.target) {
						s["name"] = "foreign"
					}
				})
			}
			r.c.guard.reader.run = func(context.Context, ...string) ([]byte, error) { return raw, nil }
			writes := 0
			r.c.guard.apply = func(context.Context, []byte) error { writes++; return nil }
			if err = r.c.guard.withdrawConnectionCaptured(context.Background(), templates[0], r.target); err == nil || writes != 0 {
				t.Fatal("foreign/malformed native was mutated", err, writes)
			}
		})
	}
}

func TestFQDNBGPRouteSwitchRenewalContinuity(t *testing.T) {
	for _, mode := range []string{"normal", "priority"} {
		for _, change := range []bool{false, true} {
			name := "identical"
			if change {
				name = "healthy_slot_switch"
			}
			t.Run(mode+"/"+name, func(t *testing.T) {
				r, client := fqdnExpiryTurnoverRig(t)
				old := r.c.active[r.target]
				deadline := old.Authority.deadline
				fqdnDeadline := old.Authority.fqdnDeadlines[runtimeFQDNGrantDigest(old.FQDNLeaseDescriptors[0])]
				process := r.c.bgpProcesses[old.Entry.DeliveryID].(*bgpSessionFixture)
				originalRoutes := append([]RuntimeBGPRouteTuple{}, old.Entry.BGPRoutes.Owned...)
				if change {
					target := routeTupleFixture(old.Entry, 2)
					process.routes = []bgpengine.LearnedRoute{{Prefix: target.Prefix, Slot: 2}}
				}
				base := r.c.replace
				gap, commits := false, 0
				watched := ""
				for _, g := range old.Grants {
					if g.FQDNManaged {
						watched = guardFQDNSetName(g)
					}
				}
				t.Logf("initial clock=%v nativeDeadline=%v", *r.now, r.installed[watched])
				sample := func() {
					if r.installed[watched] <= *r.now {
						gap = true
						t.Logf("native gap clock=%v deadline=%v", *r.now, r.installed[watched])
					}
				}
				proof := r.c.prove
				r.c.prove = func(ctx context.Context, e RuntimeJournalEntry, env RuntimeEnvironment) error {
					sample()
					err := proof(ctx, e, env)
					sample()
					return err
				}
				observe := r.c.recoveryObserve
				r.c.recoveryObserve = func(ctx context.Context, e RuntimeJournalEntry) [2]string {
					sample()
					v := observe(ctx, e)
					sample()
					return v
				}
				r.c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
					sample()
					m, err := base(ctx, in)
					if err == nil {
						commits++
						for _, connection := range in.Connections {
							if connection.ID == r.target {
								for _, g := range connection.Grants {
									if g.FQDNManaged {
										watched = guardFQDNSetName(g)
									}
								}
							}
						}
						sample()
						marked, ordinary := 0, true
						for _, c := range in.Connections {
							if c.ID == r.target {
								for _, g := range c.Grants {
									if g.FQDNManaged {
										marked++
									}
								}
							}
						}
						for _, n := range []string{guardLeaseName(r.target), guardReplyLeaseName(r.target), guardSALeaseName(r.target)} {
							ordinary = ordinary && r.installed[n] > *r.now
						}
						t.Logf("native commit=%d clock=%v marked=%d ordinary=%t originalFQDNDeadline=%v", commits, *r.now, marked, ordinary, fqdnDeadline)
						if marked == 0 {
							gap = true
						}
					}
					return m, err
				}
				var err error
				if mode == "normal" {
					_, err = r.c.maintainIPsecRuntime(context.Background(), []RuntimeMaterial{staleFQDNPage(r, client)}, maintenanceAuthority(r), func() bool { return true })
				} else {
					err = r.c.renewActiveIPsecRuntimeObserved(context.Background(), maintenanceAuthority(r), func() bool { return true }, nil, nil)
				}
				after, ok := r.c.active[r.target]
				if err != nil || !ok || process.closed {
					t.Fatalf("otherwise healthy renewal failed: err=%v active=%t closed=%t", err, ok, process.closed)
				}
				if old.Authority.deadline != deadline || old.Authority.fqdnDeadlines[runtimeFQDNGrantDigest(old.FQDNLeaseDescriptors[0])] != fqdnDeadline {
					t.Fatal("original authority changed")
				}
				if !change && !reflect.DeepEqual(after.Entry.BGPRoutes.Owned, originalRoutes) {
					t.Fatal("identical route changed")
				}
				if gap {
					t.Fatal("live FQDN application authority removed during healthy same-prefix route reconciliation")
				}
			})
		}
	}
}

func TestFQDNBGPRouteSwitchRenewalStillRefusesFreshProofLoss(t *testing.T) {
	for _, mode := range []string{"second_rib", "native_proof", "policy_revoked", "nonce", "original_ordinary_expired", "fresh_fqdn_expired"} {
		t.Run(mode, func(t *testing.T) {
			r, client, _, p := fqdnRouteSwitchRig(t)
			old := r.c.active[r.target]
			target := routeTupleFixture(old.Entry, 2)
			p.routes = []bgpengine.LearnedRoute{{Prefix: target.Prefix, Slot: 2}}
			oldDeadline := old.Authority.deadline
			fqdnDeadline := old.Authority.fqdnDeadlines[runtimeFQDNGrantDigest(old.FQDNLeaseDescriptors[0])]
			called := false
			client.mutate = func(lease *RuntimeLease) {
				called = true
				switch mode {
				case "second_rib":
					p.routes = []bgpengine.LearnedRoute{{Prefix: target.Prefix, Slot: 1}}
				case "native_proof":
					r.c.prove = func(context.Context, RuntimeJournalEntry, RuntimeEnvironment) error { return ErrRuntimeController }
				case "policy_revoked":
					r.c.config.FQDNPolicy.CommittedPolicy(nil)
				case "nonce":
					lease.Nonce = "invalid"
				case "original_ordinary_expired":
					*r.now = oldDeadline
				case "fresh_fqdn_expired":
					for i := range lease.FQDNPermits {
						lease.FQDNPermits[i].TTLMS = 1
					}
				}
			}
			err := r.c.renewActiveIPsecRuntimeObserved(context.Background(), maintenanceAuthority(r), func() bool { return true }, nil, nil)
			if !called {
				t.Fatal("fresh response injection was not reached")
			}
			if mode == "fresh_fqdn_expired" {
				// The established limiter omits an exhausted FQDN permit while
				// retaining independently authorized ordinary traffic.
				if err != nil {
					t.Fatal("ordinary renewal refused for an exhausted FQDN permit", err)
				}
				for _, a := range []runtimeActive{old, r.c.active[r.target]} {
					for _, g := range a.Grants {
						if g.FQDNManaged && r.installed[guardFQDNSetName(g)] > *r.now {
							t.Fatal("expired FQDN member survived")
						}
					}
				}
				for name := range bgpScopeNames(r.target) {
					if r.installed[name] <= *r.now {
						t.Fatal("valid ordinary permit omitted")
					}
				}
			} else {
				// An exhausted original ordinary lease may be omitted while other
				// owners complete successfully; absence, not the page error, is the fence.
				if mode == "original_ordinary_expired" {
					if _, present := r.c.active[r.target]; present {
						t.Fatal("expired original owner retained")
					}
				}
				if err == nil && mode != "original_ordinary_expired" {
					t.Fatal("post-switch invalid fresh authority not refused")
				}
				for name := range bgpScopeNames(r.target) {
					if r.installed[name] > *r.now {
						t.Fatal("invalid fresh proof retained target permit", name)
					}
				}
			}
			if old.Authority.deadline != oldDeadline || old.Authority.fqdnDeadlines[runtimeFQDNGrantDigest(old.FQDNLeaseDescriptors[0])] != fqdnDeadline {
				t.Fatal("original authority altered")
			}
		})
	}
}

func TestFQDNBGPRouteSwitchMaintenanceContinuationExactInventory(t *testing.T) {
	for _, mode := range []string{"exact", "other_owner", "authority", "delivery", "grant", "entry", "guard", "journal"} {
		t.Run(mode, func(t *testing.T) {
			r, _, _, p := fqdnRouteSwitchRig(t)
			old := r.c.active[r.target]
			target := routeTupleFixture(old.Entry, 2)
			p.routes = []bgpengine.LearnedRoute{{Prefix: target.Prefix, Slot: 2}}
			before := map[uuid.UUID]runtimeActive{}
			for id, a := range r.c.active {
				before[id] = cloneMaintenanceActive(a)
			}
			entries, _ := r.c.journal.Entries()
			templates, _, _ := r.c.journal.guardTemplates()
			if err := r.c.reconcileActiveBGP(context.Background(), entries); err != nil {
				t.Fatal(err)
			}
			after := r.c.active[r.target]
			switch mode {
			case "other_owner":
				for id := range r.c.active {
					if id != r.target {
						delete(r.c.active, id)
						break
					}
				}
			case "authority":
				after.Authority = maintenanceAuthority(r)()
				r.c.active[r.target] = after
			case "delivery":
				after.Delivery.DesiredRevision++
				r.c.active[r.target] = after
			case "grant":
				after.Grants = append([]GuardGrant(nil), after.Grants...)
				after.Grants = after.Grants[:len(after.Grants)-1]
				r.c.active[r.target] = after
			case "entry":
				after.Entry.Phase = RuntimeQuiesced
				r.c.active[r.target] = after
			case "guard":
				templates[0].Revision++
			case "journal":
				entries[0].CoveredDeliveryRevision++
			}
			_, ok := r.c.bgpRouteSwitchMaintenanceCurrent(r.target, before, entries, templates)
			if ok != (mode == "exact") {
				t.Fatal("continuation accepted changed inventory", mode, ok)
			}
		})
	}
}
