package ipsec

import (
	"context"
	"github.com/google/uuid"
	"net/netip"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
)

// Exercise the real ordinary-policy withdrawal and normal-material path. Native
// observations use the existing finite-clock WireGuard/FRR fixture.
func fqdnPolicyTransitionRig(t *testing.T, restore bool) (*renewalCycleRig, *fqdnTurnoverClient) {
	t.Helper()
	r, client := fqdnExpiryTurnoverRig(t)
	source := r.c.config.FQDNPolicy
	original := source.view.Load().policy
	original.Mode = nodepolicy.ModeEnforcing
	withdrawn := original
	withdrawn.Allow = nil
	withdrawn.FQDNGenerations = nil
	source.Attach(r.c)
	if err := source.BeforePolicy(context.Background(), &withdrawn); err != nil {
		t.Fatal("scoped withdrawal", err)
	}
	source.CommittedPolicy(&withdrawn)
	old := r.c.active[r.target]
	for _, g := range old.Grants {
		if g.FQDNManaged {
			t.Fatal("old marked authority survived withdrawal")
		}
	}
	if restore {
		// This models the already-authorized ordinary-only state after a previous
		// withdrawal. Restoring a committed DNS generation does not itself grant it.
		old.FQDNLeaseDescriptors = nil
		r.c.active[r.target] = old
		if err := source.BeforePolicy(context.Background(), &original); err != nil {
			t.Fatal(err)
		}
		source.CommittedPolicy(&original)
	} else {
		client.material.Policy.FQDNGrants = nil
		client.material.Policy.FQDNPolicyVersion = 0
	}
	return r, client
}

func TestFQDNPolicyTransitionPreservesOrdinaryAuthority(t *testing.T) {
	for _, phase := range []string{"servfail", "revoke", "restore"} {
		t.Run(phase, func(t *testing.T) {
			r, client := fqdnPolicyTransitionRig(t, phase == "restore")
			before := r.c.active[r.target]
			deadline := before.Authority.deadline
			process := r.c.bgpProcesses[before.Entry.DeliveryID]
			gap := false
			replace := r.c.replace
			r.c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
				m, err := replace(ctx, in)
				if err == nil {
					for _, name := range []string{guardLeaseName(r.target), guardReplyLeaseName(r.target), guardSALeaseName(r.target)} {
						if r.installed[name] <= *r.now {
							gap = true
						}
					}
				}
				return m, err
			}
			result, err := r.c.maintainIPsecRuntime(context.Background(), []RuntimeMaterial{client.material}, maintenanceAuthority(r), func() bool { return true })
			after, active := r.c.active[r.target]
			t.Logf("phase=%s results=%d error=%v ordinary_gap=%t active=%t lease_requests=%d", phase, len(result), err, gap, active, len(client.requests))
			if err != nil || len(result) != 1 || !active || gap {
				t.Fatal("FQDN-only policy transition interrupted ordinary authority")
			}
			if after.Identity.PolicyHash != client.material.Policy.Hash || after.Authority == before.Authority || before.Authority.deadline != deadline || len(client.requests) != 1 || client.requests[0].PolicyHash != after.Identity.PolicyHash || client.requests[0].Nonce == "" {
				t.Fatal("new policy lacks independent finite authorization")
			}
			if r.c.bgpProcesses[before.Entry.DeliveryID] != process || !reflect.DeepEqual(before.Entry, after.Entry) || !reflect.DeepEqual(before.Environment, after.Environment) {
				t.Fatal("FQDN-only change restarted or changed transport")
			}
			if phase != "restore" {
				for _, g := range after.Grants {
					if g.FQDNManaged {
						t.Fatal("removed FQDN permission transferred")
					}
				}
				for name, deadline := range r.installed {
					if strings.HasPrefix(name, "fqdn_") && deadline > *r.now {
						t.Fatal("removed native FQDN member survived")
					}
				}
				if len(after.FQDNLeaseDescriptors) != 0 {
					t.Fatal("removed descriptor retained")
				}
			} else {
				count := 0
				for _, g := range after.Grants {
					if g.FQDNManaged {
						count++
						if r.installed[guardFQDNSetName(g)] <= *r.now || r.installed[guardFQDNSetName(g)] > after.Authority.fqdnDeadlines[guardFQDNGrantDigest(g)] {
							t.Fatal("restored membership absent")
						}
						if _, err := after.Authority.RemainingFQDNForApply(after.Identity, guardFQDNGrantDigest(g), time.Millisecond); err != nil {
							t.Fatal("restored membership lacks exact fresh permit")
						}
					}
				}
				if count == 0 {
					t.Fatal("restore silently omitted application")
				}
			}
		})
	}
}

func TestFQDNPolicyTransitionPriorityConflictPreservesOrdinaryAuthority(t *testing.T) {
	for _, restore := range []bool{false, true} {
		t.Run(map[bool]string{false: "withdraw", true: "restore"}[restore], func(t *testing.T) {
			r, client := fqdnPolicyTransitionRig(t, restore)
			before := r.c.active[r.target]
			process := r.c.bgpProcesses[before.Entry.DeliveryID]
			gap := false
			replace := r.c.replace
			r.c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
				m, e := replace(ctx, in)
				if e == nil {
					for _, name := range []string{guardLeaseName(r.target), guardReplyLeaseName(r.target), guardSALeaseName(r.target)} {
						if r.installed[name] <= *r.now {
							gap = true
						}
					}
				}
				return m, e
			}
			err := r.c.renewActiveIPsecRuntimeObserved(context.Background(), maintenanceAuthority(r), func() bool { return true }, nil, nil)
			after, ok := r.c.active[r.target]
			t.Logf("error=%v active=%t fetched=%d requests=%d", err, ok, client.fetched, len(client.requests))
			if gap || err != nil || !ok || after.Identity.PolicyHash != client.material.Policy.Hash || r.c.bgpProcesses[before.Entry.DeliveryID] != process {
				t.Fatal("priority policy conflict lost ordinary owner")
			}
			if len(client.requests) != 2 || client.requests[0].Nonce == client.requests[1].Nonce || client.fetched != 1 {
				t.Fatal("missing one bounded fresh material/new nonce handoff")
			}
		})
	}
}

func assertFQDNTransitionDenied(t *testing.T, r *renewalCycleRig, result []RuntimeMaintenanceResult) {
	t.Helper()
	if len(result) != 0 {
		t.Fatal("unsafe transition emitted applied acknowledgement")
	}
	if _, ok := r.c.active[r.target]; ok {
		t.Fatal("unsafe transition retained active owner")
	}
	for _, name := range []string{guardLeaseName(r.target), guardReplyLeaseName(r.target), guardSALeaseName(r.target)} {
		if r.installed[name] > *r.now {
			t.Fatal("unsafe transition left positive native ordinary authority", name)
		}
	}
	for name, deadline := range r.installed {
		if strings.HasPrefix(name, "fqdn_") && deadline > *r.now {
			t.Fatal("unsafe transition left marked authority", name)
		}
	}
}

func TestFQDNPolicyTransitionRejectsChangedOrdinaryOrTransport(t *testing.T) {
	for _, mode := range []string{"ordinary-port", "delivery", "revision", "environment", "unknown-export", "foreign-policy", "uncommitted-restore", "desktop-proof", "bgp-dead", "old-lease-expired"} {
		t.Run(mode, func(t *testing.T) {
			r, client := fqdnPolicyTransitionRig(t, true)
			old := r.c.active[r.target]
			deadline := old.Authority.deadline
			switch mode {
			case "ordinary-port":
				client.material.Policy.DesktopGrants[0].PortLow++
				client.material.Policy.DesktopGrants[0].PortHigh++
			case "delivery":
				client.material.ID = uuid.New()
			case "revision":
				client.material.DesiredRevision++
			case "environment":
				env := r.c.config.Environment.(renewalCycleEnvironment)
				v := env[r.target]
				v.Underlays[0].InterfaceIndex++
				env[r.target] = v
			case "unknown-export":
				r.c.bgpDesktopExports[old.Entry.DeliveryID] = nil
			case "foreign-policy":
				p := r.c.config.FQDNPolicy.view.Load().policy
				p.Mode = nodepolicy.ModeEnforcing
				p.NodeID = uuid.NewString()
				r.c.config.FQDNPolicy.CommittedPolicy(&p)
			case "uncommitted-restore":
				r.c.config.FQDNPolicy.CommittedPolicy(nil)
			case "desktop-proof":
				r.c.desktopObserve = func(context.Context, []GuardGrant) ([]GuardGrant, error) { return nil, ErrRuntimeController }
			case "bgp-dead":
				r.c.bgpProcesses[old.Entry.DeliveryID].(*bgpSessionFixture).closed = true
			case "old-lease-expired":
				*r.now = old.Authority.deadline
			}
			result, _ := r.c.maintainIPsecRuntime(context.Background(), []RuntimeMaterial{client.material}, maintenanceAuthority(r), func() bool { return true })
			assertFQDNTransitionDenied(t, r, result)
			if old.Authority.deadline != deadline {
				t.Fatal("old deadline changed")
			}
		})
	}
}

func TestFQDNPolicyTransitionRejectsInvalidFreshAuthorization(t *testing.T) {
	for _, priority := range []bool{false, true} {
		for _, mode := range []string{"nonce", "hash", "delivery", "revision", "zero-ttl", "missing-fqdn-permit", "old-expires-during-lease", "new-policy-revoked", "owner-changes"} {
			name := map[bool]string{false: "normal", true: "priority"}[priority] + "/" + mode
			t.Run(name, func(t *testing.T) {
				r, client := fqdnPolicyTransitionRig(t, true)
				old := r.c.active[r.target]
				deadline := old.Authority.deadline
				client.mutate = func(l *RuntimeLease) {
					switch mode {
					case "nonce":
						l.Nonce = "wrong"
					case "hash":
						l.PolicyHash = strings.Repeat("f", 64)
					case "delivery":
						l.DeliveryID = uuid.New()
					case "revision":
						l.DesiredRevision++
					case "zero-ttl":
						l.TTLMS = 0
					case "missing-fqdn-permit":
						l.FQDNPermits = nil
					case "old-expires-during-lease":
						*r.now = old.Authority.deadline
					case "new-policy-revoked":
						r.c.config.FQDNPolicy.CommittedPolicy(nil)
					case "owner-changes":
						a := r.c.active[r.target]
						a.Environment.Underlays[0].InterfaceIndex++
						r.c.active[r.target] = a
					}
				}
				var result []RuntimeMaintenanceResult
				if priority {
					_ = r.c.renewActiveIPsecRuntimeObserved(context.Background(), maintenanceAuthority(r), func() bool { return true }, nil, nil)
				} else {
					result, _ = r.c.maintainIPsecRuntime(context.Background(), []RuntimeMaterial{client.material}, maintenanceAuthority(r), func() bool { return true })
				}
				assertFQDNTransitionDenied(t, r, result)
				if old.Authority.deadline != deadline {
					t.Fatal("old authority extended")
				}
			})
		}
	}
}

func TestFQDNPolicyTransitionPriorityConflictIsBounded(t *testing.T) {
	r, client := fqdnPolicyTransitionRig(t, true)
	r.c.client = repeatedFQDNConflictClient{client}
	if err := r.c.renewActiveIPsecRuntimeObserved(context.Background(), maintenanceAuthority(r), func() bool { return true }, nil, nil); err == nil {
		t.Fatal("repeated conflict accepted")
	}
	assertFQDNTransitionDenied(t, r, nil)
	if client.fetched != 1 || len(client.requests) != 2 {
		t.Fatalf("unbounded conflict retry: fetch=%d request=%d", client.fetched, len(client.requests))
	}
}

// BeforePolicy publishes its conservative view before it can acquire c.mu.
// This reproduces a priority owner already holding that mutex at publication.
func TestFQDNPolicyTransitionPendingWithdrawalPreservesOrdinaryAuthority(t *testing.T) {
	r, client := fqdnExpiryTurnoverRig(t)
	old := r.c.active[r.target]
	source := r.c.config.FQDNPolicy
	withdrawn := source.view.Load().policy
	withdrawn.Mode = nodepolicy.ModeEnforcing
	withdrawn.Allow = nil
	withdrawn.FQDNGenerations = nil
	source.view.Store(copyFQDNPolicy(&withdrawn))
	client.material.Policy.FQDNGrants = nil
	client.material.Policy.FQDNPolicyVersion = 0
	gap := false
	replace := r.c.replace
	r.c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
		m, e := replace(ctx, in)
		if e == nil {
			for _, name := range []string{guardLeaseName(r.target), guardReplyLeaseName(r.target), guardSALeaseName(r.target)} {
				if r.installed[name] <= *r.now {
					gap = true
				}
			}
		}
		return m, e
	}
	err := r.c.renewActiveIPsecRuntimeObserved(context.Background(), maintenanceAuthority(r), func() bool { return true }, nil, nil)
	after, ok := r.c.active[r.target]
	t.Logf("pending callback err=%v ordinaryGap=%t active=%t freshCalls=%d", err, gap, ok, len(client.requests))
	if err != nil || gap || !ok || after.Identity.PolicyHash != client.material.Policy.Hash || after.Authority == old.Authority {
		t.Fatal("pending scoped withdrawal caused global permission loss")
	}
	for _, g := range after.Grants {
		if g.FQDNManaged {
			t.Fatal("withdrawn marked authority retained")
		}
	}
}

// Start with an actual completed SERVFAIL withdrawal, rather than manufacturing
// an ordinary-only descriptor snapshot. The egress observation settles later.
func fqdnRestorationPendingRig(t *testing.T) (*renewalCycleRig, *fqdnTurnoverClient, *bool, *int) {
	t.Helper()
	r, client := fqdnExpiryTurnoverRig(t)
	source := r.c.config.FQDNPolicy
	restored := source.view.Load().policy
	restored.Mode = nodepolicy.ModeEnforcing
	material := client.material
	source.Attach(r.c)
	withdrawn := restored
	withdrawn.Allow = nil
	withdrawn.FQDNGenerations = nil
	if e := source.BeforePolicy(context.Background(), &withdrawn); e != nil {
		t.Fatal(e)
	}
	source.CommittedPolicy(&withdrawn)
	client.material.Policy.FQDNGrants = nil
	client.material.Policy.FQDNPolicyVersion = 0
	if e := r.c.renewActiveIPsecRuntimeObserved(context.Background(), maintenanceAuthority(r), func() bool { return true }, nil, nil); e != nil {
		t.Fatal("initial withdrawal", e)
	}
	old := r.c.active[r.target]
	if len(old.FQDNLeaseDescriptors) != 0 {
		t.Fatal("withdrawal not completed")
	}
	client.oldHash = old.Identity.PolicyHash
	material.Policy.Hash = strings.Repeat("f", 64)
	client.material = material
	if e := source.BeforePolicy(context.Background(), &restored); e != nil {
		t.Fatal(e)
	}
	source.CommittedPolicy(&restored)
	ready, observed := false, 0
	raw := []byte(`{"nftables":[{"table":{"family":"ip","name":"tunnex"}},{"chain":{"family":"ip","table":"tunnex","name":"postrouting","type":"nat","hook":"postrouting","prio":99,"policy":"accept"}},{"rule":{"family":"ip","table":"tunnex","chain":"postrouting","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":{"prefix":{"addr":"10.99.0.0","len":24}}}},{"match":{"op":"!=","left":{"meta":{"key":"oifname"}},"right":"wg0"}},{"masquerade":null}]}}]}`)
	observe := r.c.desktopObserve
	r.c.desktopObserve = func(ctx context.Context, grants []GuardGrant) ([]GuardGrant, error) {
		out, e := observe(ctx, grants)
		if e != nil {
			return nil, e
		}
		pending := false
		for _, g := range out {
			if g.FQDNManaged && !ready {
				observed++
				if desktopNATExempt(raw, g.Source, g.Destination) || !desktopNATExemptionPending(raw, g.Source, g.Destination, "wg0") {
					t.Fatal("invalid actual missing-exemption fixture")
				}
				pending = true
			}
		}
		if pending {
			return out, errDesktopNATPending
		}
		return out, nil
	}
	return r, client, &ready, &observed
}

func TestFQDNPolicyTransitionRestorationPendingNATPreservesOrdinary(t *testing.T) {
	for _, path := range []string{"normal", "normal_mixed", "priority"} {
		t.Run(path, func(t *testing.T) {
			r, client, ready, observed := fqdnRestorationPendingRig(t)
			before := r.c.active[r.target]
			deadline := before.Authority.deadline
			process := r.c.bgpProcesses[before.Entry.DeliveryID]
			installed := map[string]time.Duration{}
			for _, name := range []string{guardLeaseName(r.target), guardReplyLeaseName(r.target), guardSALeaseName(r.target)} {
				installed[name] = r.installed[name]
			}
			gap := false
			replace := r.c.replace
			commits := 0
			r.c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
				out, e := replace(ctx, in)
				if e == nil {
					commits++
					for name := range installed {
						gap = gap || r.installed[name] <= *r.now
					}
				}
				return out, e
			}
			materialPage := func() []RuntimeMaterial {
				page := []RuntimeMaterial{client.material}
				if path == "normal_mixed" {
					for _, m := range r.materials {
						if m.Manifest.ConnectionID != r.target && r.c.active[m.Manifest.ConnectionID].Entry.ContractVersion == 2 {
							page = append(page, m)
							break
						}
					}
					if len(page) != 2 {
						t.Fatal("missing mixed owner")
					}
				}
				return page
			}
			pendingDiagnostic := 0
			diag := r.c.config.Diagnostic
			r.c.config.Diagnostic = func(d RuntimeDiagnostic) {
				if d.Stage == "maintenance_desktop_nat_pending" {
					pendingDiagnostic++
				}
				if diag != nil {
					diag(d)
				}
			}
			for n := 0; n < 2; n++ {
				var results []RuntimeMaintenanceResult
				var err error
				if path == "priority" {
					err = r.c.renewActiveIPsecRuntimeObserved(context.Background(), maintenanceAuthority(r), func() bool { return true }, nil, nil)
				} else {
					results, err = r.c.maintainIPsecRuntime(context.Background(), materialPage(), maintenanceAuthority(r), func() bool { return true })
				}
				after, ok := r.c.active[r.target]
				t.Logf("path=%s pending=%d err=%v results=%d commits=%d now=%v original_deadline=%v", path, n, err, len(results), commits, *r.now, deadline)
				if err != nil || !ok || gap || !reflect.DeepEqual(after, before) || before.Authority.deadline != deadline || r.c.bgpProcesses[before.Entry.DeliveryID] != process {
					t.Fatal("pending exemption destroyed or renewed old ordinary owner")
				}
				deferred := 0
				for _, result := range results {
					if result.Acknowledgement.DeliveryID == before.Entry.DeliveryID {
						t.Fatal("pending application ACK")
					}
					if result.Deferred != nil {
						deferred++
						if !reflect.DeepEqual(*result.Deferred, before.Delivery) || result.Acknowledgement != (RuntimeAcknowledgement{}) || !reflect.DeepEqual(result.Report, RuntimeStatusReport{}) {
							t.Fatal("pending result lost exact delivery or carried positive output")
						}
					}
				}
				if path != "priority" && deferred != 1 {
					t.Fatal("pending owner not explicitly deferred", deferred)
				}
				for name, oldNative := range installed {
					t.Logf("native %s original_emission=%v current_emission=%v original_authority=%v", name, oldNative, r.installed[name], deadline)
					if r.installed[name] > deadline || (path == "normal" && r.installed[name] != oldNative) {
						t.Fatal("pending native authority extended", name)
					}
				}
				for name, end := range r.installed {
					if strings.HasPrefix(name, "fqdn_") && end > *r.now {
						t.Fatal("pending marked authority installed")
					}
				}
			}
			if *observed == 0 || pendingDiagnostic != 2 {
				t.Fatal("pending recognition/diagnostic missing", *observed, pendingDiagnostic)
			}
			if path != "normal" && commits == 0 {
				t.Fatal("did not exercise retained required owner during other commit")
			}
			if path == "normal" && commits != 0 {
				t.Fatal("pending-only path rewrote native membership")
			}
			*ready = true
			priorRequests := len(client.requests)
			results, err := r.c.maintainIPsecRuntime(context.Background(), []RuntimeMaterial{client.material}, maintenanceAuthority(r), func() bool { return true })
			after := r.c.active[r.target]
			if err != nil || len(results) != 1 || gap || after.Authority == before.Authority || before.Authority.deadline != deadline || after.Identity.PolicyHash != client.material.Policy.Hash || r.c.bgpProcesses[before.Entry.DeliveryID] != process {
				t.Fatal("async exemption catch-up failed", err)
			}
			if len(client.requests) != priorRequests+1 || client.requests[priorRequests].Nonce == "" || client.requests[priorRequests].PolicyHash != client.material.Policy.Hash {
				t.Fatal("catch-up lacks fresh exact authorization")
			}
			found := false
			for _, g := range after.Grants {
				if g.FQDNManaged {
					found = true
					if r.installed[guardFQDNSetName(g)] <= *r.now || r.installed[guardFQDNSetName(g)] > after.Authority.fqdnDeadlines[guardFQDNGrantDigest(g)] {
						t.Fatal("catch-up lacks finite exact member")
					}
				}
			}
			if !found {
				t.Fatal("catch-up omitted restored tuple")
			}
		})
	}
}

func TestFQDNPolicyTransitionRestorationPendingNATRejectsChangedProof(t *testing.T) {
	for _, path := range []string{"normal", "priority"} {
		for _, mode := range []string{"expired", "ordinary-changed", "delivery-changed", "source-not-exported", "policy-revoked", "observe-error", "owner-changed", "environment-changed", "bgp-dead"} {
			t.Run(path+"/"+mode, func(t *testing.T) {
				r, client, _, _ := fqdnRestorationPendingRig(t)
				old := r.c.active[r.target]
				deadline := old.Authority.deadline
				switch mode {
				case "expired":
					*r.now = deadline
				case "ordinary-changed":
					client.material.Policy.DesktopGrants = append([]RuntimeDesktopGrant(nil), client.material.Policy.DesktopGrants...)
					client.material.Policy.DesktopGrants[0].PortLow++
					client.material.Policy.DesktopGrants[0].PortHigh++
				case "delivery-changed":
					client.material.ID = uuid.New()
				case "source-not-exported":
					r.c.bgpDesktopExports[old.Entry.DeliveryID] = nil
				case "policy-revoked":
					r.c.config.FQDNPolicy.CommittedPolicy(nil)
				case "observe-error":
					r.c.desktopObserve = func(context.Context, []GuardGrant) ([]GuardGrant, error) { return nil, ErrRuntimeController }
				case "owner-changed":
					observe := r.c.desktopObserve
					r.c.desktopObserve = func(ctx context.Context, g []GuardGrant) ([]GuardGrant, error) {
						out, e := observe(ctx, g)
						a := r.c.active[r.target]
						a.Environment.Underlays[0].InterfaceIndex++
						r.c.active[r.target] = a
						return out, e
					}
				case "environment-changed":
					env := r.c.config.Environment.(renewalCycleEnvironment)
					v := env[r.target]
					v.Underlays[0].InterfaceIndex++
					env[r.target] = v
				case "bgp-dead":
					r.c.bgpProcesses[old.Entry.DeliveryID].(*bgpSessionFixture).closed = true
				}
				var results []RuntimeMaintenanceResult
				if path == "priority" {
					_ = r.c.renewActiveIPsecRuntimeObserved(context.Background(), maintenanceAuthority(r), func() bool { return true }, nil, nil)
				} else {
					results, _ = r.c.maintainIPsecRuntime(context.Background(), []RuntimeMaterial{client.material}, maintenanceAuthority(r), func() bool { return true })
				}
				assertFQDNTransitionDenied(t, r, results)
				if old.Authority.deadline != deadline {
					t.Fatal("original deadline changed")
				}
			})
		}
	}
}

func TestFQDNPolicyTransitionRestorationPendingNATExpiresDuringOtherReport(t *testing.T) {
	r, client, _, _ := fqdnRestorationPendingRig(t)
	old := r.c.active[r.target]
	// Establish a genuine shorter original lease so the later fresh owner
	// remains independently live when this retained pending owner expires.
	old.Authority = maintenanceAuthority(r)()
	q, e := old.Authority.Begin(old.Identity)
	if e != nil {
		t.Fatal(e)
	}
	if e = old.Authority.Accept(PermitLeaseResponse{PermitLeaseRequest: q, TTLMillis: 30000}); e != nil {
		t.Fatal(e)
	}
	r.c.active[r.target] = old
	if e = r.c.installActive(context.Background(), r.entries); e != nil {
		t.Fatal(e)
	}
	deadline := old.Authority.deadline
	page := []RuntimeMaterial{client.material}
	for _, m := range r.materials {
		if m.Manifest.ConnectionID != r.target && r.c.active[m.Manifest.ConnectionID].Entry.ContractVersion == 2 {
			page = append(page, m)
			break
		}
	}
	if len(page) != 2 {
		t.Fatal("missing mixed owner")
	}
	calls := 0
	var freshAuthority *PermitLeaseAuthority
	var freshIdentity PermitLeaseIdentity
	results, err := r.c.maintainIPsecRuntimeObserved(context.Background(), page, maintenanceAuthority(r), func() bool { return true }, func(_ context.Context, d RuntimeDelivery, _ RuntimeStatusReport) error {
		if d.Manifest.ConnectionID == r.target {
			t.Fatal("pending owner published as applied")
		}
		calls++
		fresh := r.c.active[d.Manifest.ConnectionID]
		freshAuthority = fresh.Authority
		freshIdentity = fresh.Identity
		t.Logf("report entry=%v pendingDeadline=%v freshDeadline=%v freshLast=%v", *r.now, deadline, fresh.Authority.deadline, fresh.Authority.last)
		if fresh.Authority.deadline <= deadline+5*time.Second {
			t.Fatal("fixture fresh owner cannot outlive pending owner")
		}
		*r.now = deadline
		return nil
	})
	if calls != 1 || err == nil {
		t.Fatal("late report failed to fence pending original deadline", calls, err)
	}
	t.Logf("post refusal now=%v pendingDeadline=%v freshDeadline=%v freshLast=%v", *r.now, deadline, freshAuthority.deadline, freshAuthority.last)
	if _, e := freshAuthority.RemainingForApply(freshIdentity, time.Millisecond); e != nil {
		t.Fatal("fixture fresh owner expired too", e)
	}
	assertFQDNTransitionDenied(t, r, results)
	if old.Authority.deadline != deadline {
		t.Fatal("original authority extended")
	}
}

// Uses the real observation/read sequence and the canonical pendingNATFixture
// from runtime_desktop_nat_pending_test.go; does not invoke kernel commands.
func TestFQDNPolicyTransitionDesktopPendingObservation(t *testing.T) {
	for _, mode := range []string{"pending", "second-peer-missing", "second-key-mismatch", "second-return-route", "second-ingress", "second-link-read", "second-route-read", "second-expired", "second-not-fqdn", "final-peers-drift", "final-peers-read", "final-context-cancel", "initial-context-cancel", "nft-read"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			key1 := desktopGrantFixture().PublicKey
			key2 := strings.Repeat("A", 42) + "E="
			if !validDesktopKey(key1) || !validDesktopKey(key2) || key1 == key2 {
				t.Fatal("invalid fixture keys")
			}
			grants := []GuardGrant{
				{Source: netip.MustParsePrefix("10.99.0.7/32"), Destination: netip.MustParsePrefix("10.182.10.246/32"), DesktopDeviceID: uuid.New(), DesktopPublicKey: key1, FQDNManaged: true, DesktopExpiresAt: time.Now().Add(time.Minute)},
				{Source: netip.MustParsePrefix("10.99.0.8/32"), Destination: netip.MustParsePrefix("10.182.20.166/32"), DesktopDeviceID: uuid.New(), DesktopPublicKey: key2, FQDNManaged: true, DesktopExpiresAt: time.Now().Add(time.Minute)},
			}
			peers := "wg0\t" + key1 + "\t10.99.0.7/32\nwg0\t" + key2 + "\t10.99.0.8/32\n"
			switch mode {
			case "second-peer-missing":
				peers = "wg0\t" + key1 + "\t10.99.0.7/32\n"
			case "second-key-mismatch":
				grants[1].DesktopPublicKey = key1
			case "second-ingress":
				grants[1].DesktopIngressIndex = 8
			case "second-expired":
				grants[1].DesktopExpiresAt = time.Now().Add(-time.Minute)
			case "second-not-fqdn":
				grants[1].FQDNManaged = false
			case "initial-context-cancel":
				cancel()
			}
			original := append([]GuardGrant(nil), grants...)
			c := &RuntimeController{}
			c.config.IPPath, c.config.NFTPath = "ip", "nft"
			wgReads, links, routes := 0, 0, 0
			var trace []string
			read := func(path string, args ...string) ([]byte, error) {
				command := path + " " + strings.Join(args, " ")
				trace = append(trace, command)
				switch command {
				case "wg show all allowed-ips":
					wgReads++
					if wgReads == 2 {
						switch mode {
						case "final-peers-drift":
							return []byte(peers + "wg0\t" + key1 + "\t10.99.0.9/32\n"), nil
						case "final-peers-read":
							return nil, ErrRuntimeController
						case "final-context-cancel":
							cancel()
						}
					}
					return []byte(peers), nil
				case "nft -j list table ip tunnex":
					if mode == "nft-read" {
						return nil, ErrRuntimeController
					}
					return pendingNATJSON(pendingNATFixture()), nil
				case "ip -j -d link show dev wg0":
					links++
					if links == 2 && mode == "second-link-read" {
						return nil, ErrRuntimeController
					}
					return []byte(`[{"ifname":"wg0","ifindex":7,"linkinfo":{"info_kind":"wireguard"},"flags":["UP"]}]`), nil
				case "ip -j -4 route get 10.99.0.7", "ip -j -4 route get 10.99.0.8":
					routes++
					if routes == 2 && mode == "second-route-read" {
						return nil, ErrRuntimeController
					}
					dev := "wg0"
					if routes == 2 && mode == "second-return-route" {
						dev = "eth0"
					}
					return []byte(`[{"dst":"` + args[len(args)-1] + `","dev":"` + dev + `"}]`), nil
				default:
					t.Fatalf("unexpected kernel read %q", command)
					return nil, ErrRuntimeController
				}
			}
			observed, err := c.observeDesktopGrantsWithRead(ctx, grants, "wg", read)
			if !reflect.DeepEqual(grants, original) {
				t.Fatal("observation mutated input grants")
			}
			if mode == "pending" {
				want := append([]GuardGrant(nil), grants...)
				want[0].DesktopIngressIndex, want[1].DesktopIngressIndex = 7, 7
				if err != errDesktopNATPending || !reflect.DeepEqual(observed, want) || wgReads != 2 || links != 2 || routes != 2 || len(trace) != 7 {
					t.Fatalf("pending skipped full identity proof: observed=%v err=%v trace=%v", observed, err, trace)
				}
				// Typed pending must still fail the unchanged positive-proof boundary.
				c.desktopObserve = func(context.Context, []GuardGrant) ([]GuardGrant, error) { return observed, errDesktopNATPending }
				if c.proveDesktopGrants(context.Background(), want) != ErrRuntimeController {
					t.Fatal("pending was treated as positive desktop proof")
				}
				return
			}
			if err != ErrRuntimeController || observed != nil {
				t.Fatalf("pending first tuple hid %s: observed=%v err=%v trace=%v", mode, observed, err, trace)
			}
			if mode == "initial-context-cancel" && len(trace) != 0 {
				t.Fatal("read after cancelled input context")
			}
			if strings.HasPrefix(mode, "second-") && routes < 1 {
				t.Fatal("fixture failed before reaching pending first tuple")
			}
			if strings.HasPrefix(mode, "final-") && (wgReads != 2 || links != 2 || routes != 2) {
				t.Fatal("final failure was not reached after both pending tuples")
			}
		})
	}
}

func TestFQDNPolicyTransitionPrecommitWithdrawalPreservesOrdinary(t *testing.T) {
	for _, withdraw := range []bool{false, true} {
		name := map[bool]string{false: "unchanged_control", true: "withdrawn_view_during_proof"}[withdraw]
		t.Run(name, func(t *testing.T) {
			r, client := fqdnExpiryTurnoverRig(t)
			before := r.c.active[r.target]
			deadline := before.Authority.deadline
			process := r.c.bgpProcesses[before.Entry.DeliveryID]
			injected := false
			var diagnostics []RuntimeDiagnostic
			r.c.config.Diagnostic = func(d RuntimeDiagnostic) {
				if d.Refused {
					diagnostics = append(diagnostics, d)
					t.Logf("DIAGNOSTIC %s/%s at=%s", d.Operation, d.Stage, *r.now)
				}
			}
			prove := r.c.prove
			r.c.prove = func(ctx context.Context, e RuntimeJournalEntry, env RuntimeEnvironment) error {
				err := prove(ctx, e, env)
				if err == nil && !injected && e.Allocation.ConnectionID == r.target && pulseDeferralInCall("installActiveCandidatesFQDN") {
					injected = true
					if !r.c.qualification.current() || !process.Alive() {
						t.Fatal("precondition lost physical qualification/process")
					}
					t.Logf("NATIVE_PROOF_OK original_remaining=%s old_fqdn_current=%t", deadline-*r.now, r.c.fqdnGrantsCurrent(before.Grants))
					if withdraw {
						p := r.c.config.FQDNPolicy.view.Load().policy
						p.Mode = nodepolicy.ModeEnforcing
						p.Allow = nil
						p.FQDNGenerations = nil
						// Exact conservative BeforePolicy publication while the serialized owner
						// is busy in a valid native read; no nil/foreign policy or proof failure.
						r.c.config.FQDNPolicy.view.Store(copyFQDNPolicy(&p))
					}
				}
				return err
			}
			gap := false
			replace := r.c.replace
			r.c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
				m, err := replace(ctx, in)
				if err == nil {
					for _, n := range []string{guardLeaseName(r.target), guardReplyLeaseName(r.target), guardSALeaseName(r.target)} {
						if r.installed[n] <= *r.now {
							gap = true
						}
					}
				}
				return m, err
			}
			result, err := r.c.maintainIPsecRuntime(context.Background(), []RuntimeMaterial{client.material}, maintenanceAuthority(r), func() bool { return true })
			_, active := r.c.active[r.target]
			t.Logf("RESULT injected=%t error=%v result=%d ordinary_gap=%t active=%t bgp_alive=%t qualified=%t original_remaining=%s original_deadline_unchanged=%t diagnostics=%v", injected, err, len(result), gap, active, process.Alive(), r.c.qualification.current(), deadline-*r.now, before.Authority.deadline == deadline, diagnostics)
			if !injected {
				t.Fatal("did not reach intended successful proof boundary")
			}
			if gap || !active || !process.Alive() {
				t.Fatal("valid FQDN-only view retraction destroyed original finite ordinary authority")
			}
		})
	}
}

func TestFQDNPolicyTransitionPrecommitWithdrawalBoundaries(t *testing.T) {
	for _, path := range []string{"priority", "mixed", "retained-mixed", "final-desktop-proof", "after-replace", "stale-page-caller"} {
		t.Run(path, func(t *testing.T) {
			r, client := fqdnExpiryTurnoverRig(t)
			originals := map[uuid.UUID]runtimeActive{}
			deadlines := map[uuid.UUID]time.Duration{}
			for id, a := range r.c.active {
				originals[id] = cloneMaintenanceActive(a)
				deadlines[id] = a.Authority.deadline
			}
			old := originals[r.target]
			process := r.c.bgpProcesses[old.Entry.DeliveryID]
			injected := false
			desktopReads := 0
			published := 0
			gap := false
			retract := func() {
				p := r.c.config.FQDNPolicy.view.Load().policy
				p.Mode = nodepolicy.ModeEnforcing
				p.Allow = nil
				p.FQDNGenerations = nil
				r.c.config.FQDNPolicy.view.Store(copyFQDNPolicy(&p))
				injected = true
			}
			prove := r.c.prove
			r.c.prove = func(ctx context.Context, e RuntimeJournalEntry, env RuntimeEnvironment) error {
				err := prove(ctx, e, env)
				if err == nil && !injected && path != "final-desktop-proof" && path != "after-replace" && e.Allocation.ConnectionID == r.target && pulseDeferralInCall("installActiveCandidatesFQDN") {
					retract()
				}
				return err
			}
			observe := r.c.desktopObserve
			r.c.desktopObserve = func(ctx context.Context, gs []GuardGrant) ([]GuardGrant, error) {
				out, err := observe(ctx, gs)
				if err == nil && !injected && path == "final-desktop-proof" && pulseDeferralInCall("installActiveCandidatesFQDN") {
					for _, g := range gs {
						if g.FQDNManaged {
							desktopReads++
							if desktopReads == 2 {
								retract()
							}
							break
						}
					}
				}
				return out, err
			}
			replace := r.c.replace
			r.c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
				out, err := replace(ctx, in)
				if err == nil && path == "after-replace" && !injected && pulseDeferralInCall("installActiveCandidatesFQDN") {
					retract()
				}
				if err == nil {
					for id := range originals {
						for _, n := range []string{guardLeaseName(id), guardReplyLeaseName(id), guardSALeaseName(id)} {
							if r.installed[n] <= *r.now {
								gap = true
							}
						}
					}
				}
				return out, err
			}
			publish := func(context.Context, RuntimeDelivery, RuntimeStatusReport) error { published++; return nil }
			page := []RuntimeMaterial{client.material}
			if path == "mixed" || path == "retained-mixed" {
				for _, m := range r.materials {
					if m.Manifest.ConnectionID != r.target && r.c.active[m.Manifest.ConnectionID].Entry.ContractVersion == 2 {
						page = append(page, m)
						break
					}
				}
				if len(page) != 2 {
					t.Fatal("missing mixed candidate")
				}
				if path == "retained-mixed" {
					page = page[1:]
				}
			}
			var result []RuntimeMaintenanceResult
			var err error
			if path == "priority" {
				err = r.c.renewActiveIPsecRuntimeObserved(context.Background(), maintenanceAuthority(r), func() bool { return true }, publish, nil)
			} else {
				result, err = r.c.maintainIPsecRuntimeObserved(context.Background(), page, maintenanceAuthority(r), func() bool { return true }, publish)
			}
			assertPreserved := func() {
				t.Helper()
				if gap || !process.Alive() || r.c.bgpProcesses[old.Entry.DeliveryID] != process || len(r.c.active) != len(originals) {
					t.Fatal("ordinary owner/process lost")
				}
				for id, before := range originals {
					after := r.c.active[id]
					expected := cloneMaintenanceActive(before)
					if id == r.target {
						expected.Grants = make([]GuardGrant, 0, len(before.Grants))
						for _, g := range before.Grants {
							if !g.FQDNManaged {
								expected.Grants = append(expected.Grants, g)
							}
						}
					}
					for _, n := range []string{guardLeaseName(id), guardReplyLeaseName(id), guardSALeaseName(id)} {
						if r.installed[n] > deadlines[id] {
							t.Fatal("corrected native timer exceeds original authority", id)
						}
					}
					if !reflect.DeepEqual(after, expected) || before.Authority.deadline != deadlines[id] {
						t.Fatal("original owner or deadline changed", id)
					}
				}
				for name, end := range r.installed {
					if strings.HasPrefix(name, "fqdn_") && end > *r.now {
						t.Fatal("stale marked member survived")
					}
				}
			}
			if !injected || err != nil || len(result) != 0 || published != 0 {
				t.Fatal("retraction not scoped/no-ACK", injected, err, len(result), published)
			}
			assertPreserved()
			if path == "stale-page-caller" {
				// The real normal caller observes status/recovery before falling back to
				// Apply with the stale page. These calls must never restore old grants.
				_, _ = r.c.ObserveIPsecStatus(context.Background(), client.material.RuntimeDelivery)
				_ = r.c.RefreshIPsecRecovery(context.Background())
				stage := ""
				r.c.config.Diagnostic = func(d RuntimeDiagnostic) {
					if d.Operation == "apply" && d.Refused {
						stage = d.Stage
					}
				}
				ack, e := r.c.Apply(context.Background(), client.material)
				if e == nil || ack.Result != "" {
					t.Fatal("stale page acknowledged")
				}
				if runtime.GOOS == "linux" && stage != "material_fqdn_current" {
					t.Fatal("Linux stale Apply did not reach current-policy fence", stage)
				}
				// Validate's already-qualified core uses these same two canonical steps.
				// The model cannot fabricate a native BGP preflight receipt for its public
				// wrapper; actual qualification remains an independent Linux/native gate.
				entries, e := r.c.journal.Entries()
				if e != nil {
					t.Fatal(e)
				}
				if e = r.c.reconcileActiveBGP(context.Background(), entries); e != nil {
					t.Fatal("Validate route reconciliation", e)
				}
				if e = r.c.installActive(context.Background(), entries); e != nil {
					t.Fatal("Validate canonical native assembly", e)
				}
				assertPreserved()
			}
		})
	}
}

func TestFQDNPolicyTransitionPrecommitWithdrawalRejectsUnsafe(t *testing.T) {
	for _, mode := range []string{"native-proof", "desktop-proof", "owner-change", "other-owner-change", "ordinary-expired", "nil-view", "foreign-view", "legacy-view", "qualification-lost", "bgp-lost", "rebuild-view-change", "postcommit-view-and-expiry"} {
		t.Run(mode, func(t *testing.T) {
			r, client := fqdnExpiryTurnoverRig(t)
			old := r.c.active[r.target]
			deadline := old.Authority.deadline
			injected := false
			rebuildChanged := false
			published := 0
			retract := func() {
				p := r.c.config.FQDNPolicy.view.Load().policy
				p.Mode = nodepolicy.ModeEnforcing
				p.Allow = nil
				p.FQDNGenerations = nil
				r.c.config.FQDNPolicy.view.Store(copyFQDNPolicy(&p))
				injected = true
			}
			prove := r.c.prove
			r.c.prove = func(ctx context.Context, e RuntimeJournalEntry, env RuntimeEnvironment) error {
				err := prove(ctx, e, env)
				if err == nil && mode == "rebuild-view-change" && injected && !rebuildChanged && pulseDeferralInCall("retractFQDNOnly") {
					rebuildChanged = true
					r.c.config.FQDNPolicy.view.Store(nil)
				}
				if err == nil && !injected && mode != "postcommit-view-and-expiry" && e.Allocation.ConnectionID == r.target && pulseDeferralInCall("installActiveCandidatesFQDN") {
					retract()
					switch mode {
					case "native-proof":
						return ErrRuntimeController
					case "owner-change":
						a := r.c.active[r.target]
						a.Environment.Underlays[0].InterfaceIndex++
						r.c.active[r.target] = a
					case "other-owner-change":
						for id, a := range r.c.active {
							if id != r.target {
								a.Environment.Underlays[0].InterfaceIndex++
								r.c.active[id] = a
								break
							}
						}
					case "ordinary-expired":
						*r.now = deadline
					case "nil-view":
						r.c.config.FQDNPolicy.view.Store(nil)
					case "foreign-view":
						v := r.c.config.FQDNPolicy.view.Load()
						p := v.policy
						p.NodeID = uuid.NewString()
						r.c.config.FQDNPolicy.view.Store(&runtimeFQDNPolicyView{policy: p})
					case "legacy-view":
						v := r.c.config.FQDNPolicy.view.Load()
						p := v.policy
						p.Version = 8
						r.c.config.FQDNPolicy.view.Store(&runtimeFQDNPolicyView{policy: p})
					case "qualification-lost":
						r.c.qualification.invalid = true
					case "bgp-lost":
						r.c.bgpProcesses[old.Entry.DeliveryID].(*bgpSessionFixture).closed = true
					}
				}
				return err
			}
			observe := r.c.desktopObserve
			r.c.desktopObserve = func(ctx context.Context, gs []GuardGrant) ([]GuardGrant, error) {
				if injected && mode == "desktop-proof" {
					return nil, ErrRuntimeController
				}
				return observe(ctx, gs)
			}
			replace := r.c.replace
			r.c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
				out, err := replace(ctx, in)
				if err == nil && !injected && mode == "postcommit-view-and-expiry" && pulseDeferralInCall("installActiveCandidatesFQDN") {
					retract()
					*r.now = deadline
				}
				return out, err
			}
			result, err := r.c.maintainIPsecRuntimeObserved(context.Background(), []RuntimeMaterial{client.material}, maintenanceAuthority(r), func() bool { return true }, func(context.Context, RuntimeDelivery, RuntimeStatusReport) error { published++; return nil })
			if !injected || err == nil || len(result) != 0 || published != 0 {
				t.Fatal("unsafe retraction accepted or injection missed", injected, err, len(result), published)
			}
			if mode == "rebuild-view-change" && !rebuildChanged {
				t.Fatal("withdrawal rebuild boundary missed")
			}
			assertFQDNTransitionDenied(t, r, result)
			if old.Authority.deadline != deadline {
				t.Fatal("original authority extended")
			}
		})
	}
}

func TestFQDNPolicyTransitionFollowupWithdrawalBoundaries(t *testing.T) {
	for _, phase := range []string{"prepared", "lease-return", "native-proof", "after-replace", "after-status", "after-publication"} {
		t.Run(phase, func(t *testing.T) {
			r, client, _ := fqdnFollowupFixture(t)
			client.publishAt = *r.now - time.Millisecond
			before := cloneMaintenanceActive(r.c.active[r.target])
			deadline := before.Authority.deadline
			process := r.c.bgpProcesses[before.Entry.DeliveryID]
			fresh, err := r.c.prepareFQDNExpiryMaterial(context.Background(), before, client.base.material)
			if err != nil {
				t.Fatal("prepare exact expiry", err)
			}
			injected := false
			gap := false
			published := 0
			var committed runtimeActive
			retract := func() {
				p := r.c.config.FQDNPolicy.view.Load().policy
				p.Mode = nodepolicy.ModeEnforcing
				p.Allow = nil
				p.FQDNGenerations = nil
				r.c.config.FQDNPolicy.view.Store(copyFQDNPolicy(&p))
				injected = true
			}
			if phase == "prepared" {
				retract()
			}
			if phase == "lease-return" {
				client.base.mutate = func(*RuntimeLease) { retract() }
			}
			prove := r.c.prove
			r.c.prove = func(ctx context.Context, e RuntimeJournalEntry, env RuntimeEnvironment) error {
				err := prove(ctx, e, env)
				if err == nil && phase == "native-proof" && !injected && e.Allocation.ConnectionID == r.target && pulseDeferralInCall("installActiveCandidatesFQDN") {
					retract()
				}
				return err
			}
			replace := r.c.replace
			r.c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
				out, err := replace(ctx, in)
				if err == nil {
					if phase == "after-replace" && !injected {
						retract()
					}
					for _, n := range []string{guardLeaseName(r.target), guardReplyLeaseName(r.target), guardSALeaseName(r.target)} {
						if r.installed[n] <= *r.now {
							gap = true
						}
					}
				}
				return out, err
			}
			if phase == "after-status" {
				r.c.config.IPPath = "/usr/bin/true"
				r.c.config.Daemon = &DaemonClient{request: func(context.Context, string, string, viciMessage) (viciMessage, []viciMessage, error) {
					if !injected {
						committed = cloneMaintenanceActive(r.c.active[r.target])
						retract()
					}
					// Advisory native telemetry is honestly unknown; it is not
					// the independent current-proof fixture used by guard assembly.
					return viciMessage{}, nil, ErrRuntimeController
				}}
			}
			publish := func(context.Context, RuntimeDelivery, RuntimeStatusReport) error {
				published++
				if phase == "after-publication" && !injected {
					committed = cloneMaintenanceActive(r.c.active[r.target])
					retract()
				}
				return nil
			}
			err = r.c.commitFQDNFollowup(context.Background(), maintenanceAuthority(r), func() bool { return true }, map[uuid.UUID]maintenanceItem{r.target: fresh}, publish)
			after, exists := r.c.active[r.target]
			if !injected || err != nil || !exists || gap || !process.Alive() || r.c.bgpProcesses[before.Entry.DeliveryID] != process {
				t.Fatal("followup policy-only withdrawal lost ordinary authority", injected, err, exists, gap, published)
			}
			expected := before
			if phase == "after-status" || phase == "after-publication" {
				expected = committed
				if expected.Authority == nil || expected.Authority == before.Authority {
					t.Fatal("late fixture missed candidate adoption")
				}
			}
			priorGrants := expected.Grants
			expected.Grants = make([]GuardGrant, 0, len(priorGrants))
			for _, g := range priorGrants {
				if !g.FQDNManaged {
					expected.Grants = append(expected.Grants, g)
				}
			}
			for _, g := range after.Grants {
				if g.FQDNManaged {
					t.Fatal("marked permission survived")
				}
			}
			if !reflect.DeepEqual(after, expected) || before.Authority.deadline != deadline {
				t.Fatal("ordinary committed/original identity changed")
			}
			if (phase == "after-publication" && published != 1) || (phase != "after-publication" && published != 0) {
				t.Fatal("unexpected transport publication", phase, published)
			}
			for name, end := range r.installed {
				if strings.HasPrefix(name, "fqdn_") && end > *r.now {
					t.Fatal("stale native marked authority")
				}
			}
			for _, n := range []string{guardLeaseName(r.target), guardReplyLeaseName(r.target), guardSALeaseName(r.target)} {
				if r.installed[n] <= *r.now || r.installed[n] > after.Authority.deadline {
					t.Fatal("ordinary native deadline invalid", n)
				}
			}
		})
	}
}

func TestFQDNPolicyTransitionValidationWithdrawal(t *testing.T) {
	for _, withdraw := range []bool{false, true} {
		t.Run(map[bool]string{false: "unchanged_control", true: "withdraw_during_native_proof"}[withdraw], func(t *testing.T) {
			r, _ := fqdnExpiryTurnoverRig(t)
			old := r.c.active[r.target]
			deadline := old.Authority.deadline
			process := r.c.bgpProcesses[old.Entry.DeliveryID]
			injected, gap := false, false
			r.c.config.Diagnostic = func(d RuntimeDiagnostic) {
				if d.Refused {
					t.Logf("DIAGNOSTIC %s/%s", d.Operation, d.Stage)
				}
			}
			prove := r.c.prove
			r.c.prove = func(ctx context.Context, e RuntimeJournalEntry, env RuntimeEnvironment) error {
				err := prove(ctx, e, env)
				if err == nil && !injected && e.Allocation.ConnectionID == r.target && pulseDeferralInCall("installActiveCandidatesFQDN") {
					injected = true
					if !r.c.qualification.current() || !process.Alive() {
						t.Fatal("lost valid original proof")
					}
					t.Logf("VALID_PROOF old_remaining=%v policy_current=%v", deadline-*r.now, r.c.fqdnGrantsCurrent(old.Grants))
					if withdraw {
						p := r.c.config.FQDNPolicy.view.Load().policy
						p.Mode = nodepolicy.ModeEnforcing
						p.Allow = nil
						p.FQDNGenerations = nil
						r.c.config.FQDNPolicy.view.Store(copyFQDNPolicy(&p))
					}
				}
				return err
			}
			replace := r.c.replace
			r.c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
				m, err := replace(ctx, in)
				if err == nil {
					for _, n := range []string{guardLeaseName(r.target), guardReplyLeaseName(r.target), guardSALeaseName(r.target)} {
						if r.installed[n] <= *r.now {
							gap = true
						}
					}
				}
				return m, err
			}
			entries, err := r.c.journal.Entries()
			if err != nil {
				t.Fatal(err)
			}
			err = r.c.installActive(context.Background(), entries)
			_, active := r.c.active[r.target]
			t.Logf("RESULT injected=%v error=%v ordinary_gap=%v active=%v bgp_alive=%v qualification=%v old_remaining=%v old_deadline_unchanged=%v", injected, err, gap, active, process.Alive(), r.c.qualification.current(), deadline-*r.now, old.Authority.deadline == deadline)
			if withdraw {
				current := r.c.active[r.target]
				expected := cloneMaintenanceActive(old)
				expected.Grants = make([]GuardGrant, 0, len(old.Grants))
				for _, g := range old.Grants {
					if !g.FQDNManaged {
						expected.Grants = append(expected.Grants, g)
					}
				}
				if err != nil || !reflect.DeepEqual(current, expected) || old.Authority.deadline != deadline {
					t.Fatal("scoped withdrawal changed original owner")
				}
				for name, end := range r.installed {
					if strings.HasPrefix(name, "fqdn_") && end > *r.now {
						t.Fatal("marked grant survived")
					}
				}
				for _, n := range []string{guardLeaseName(r.target), guardReplyLeaseName(r.target), guardSALeaseName(r.target)} {
					if r.installed[n] <= *r.now || r.installed[n] > deadline {
						t.Fatal("ordinary native authority invalid")
					}
				}
			}
			if !injected {
				t.Fatal("native proof not reached")
			}
			if gap || !active || !process.Alive() {
				t.Fatal("plain install policy retraction destroyed original finite ordinary authority")
			}
		})
	}
}

func TestFQDNPolicyTransitionPreparationWithdrawal(t *testing.T) {
	for _, withdraw := range []bool{false, true} {
		t.Run(map[bool]string{false: "unchanged_control", true: "withdraw_after_desktop_observation"}[withdraw], func(t *testing.T) {
			r, client := fqdnExpiryTurnoverRig(t)
			old := r.c.active[r.target]
			deadline := old.Authority.deadline
			process := r.c.bgpProcesses[old.Entry.DeliveryID]
			injected, gap := false, false
			r.c.config.Diagnostic = func(d RuntimeDiagnostic) {
				if d.Refused {
					t.Logf("DIAGNOSTIC %s/%s", d.Operation, d.Stage)
				}
			}
			observe := r.c.desktopObserve
			r.c.desktopObserve = func(ctx context.Context, gs []GuardGrant) ([]GuardGrant, error) {
				out, err := observe(ctx, gs)
				if err == nil && !injected && !pulseDeferralInCall("installActiveCandidatesFQDN") {
					marked := false
					for _, g := range gs {
						marked = marked || g.FQDNManaged
					}
					if marked {
						injected = true
						t.Logf("DESKTOP_PROOF_OK old_remaining=%v", deadline-*r.now)
						if withdraw {
							p := r.c.config.FQDNPolicy.view.Load().policy
							p.Mode = nodepolicy.ModeEnforcing
							p.Allow = nil
							p.FQDNGenerations = nil
							r.c.config.FQDNPolicy.view.Store(copyFQDNPolicy(&p))
						}
					}
				}
				return out, err
			}
			replace := r.c.replace
			r.c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
				m, err := replace(ctx, in)
				if err == nil {
					for _, n := range []string{guardLeaseName(r.target), guardReplyLeaseName(r.target), guardSALeaseName(r.target)} {
						if r.installed[n] <= *r.now {
							gap = true
						}
					}
				}
				return m, err
			}
			result, err := r.c.maintainIPsecRuntime(context.Background(), []RuntimeMaterial{client.material}, maintenanceAuthority(r), func() bool { return true })
			_, active := r.c.active[r.target]
			t.Logf("RESULT injected=%v error=%v results=%d ordinary_gap=%v active=%v bgp_alive=%v qualification=%v old_remaining=%v old_deadline_unchanged=%v", injected, err, len(result), gap, active, process.Alive(), r.c.qualification.current(), deadline-*r.now, old.Authority.deadline == deadline)
			if withdraw {
				if len(result) != 0 {
					t.Fatal("withdrawn page acknowledged")
				}
				current := r.c.active[r.target]
				expected := cloneMaintenanceActive(old)
				expected.Grants = make([]GuardGrant, 0, len(old.Grants))
				for _, g := range old.Grants {
					if !g.FQDNManaged {
						expected.Grants = append(expected.Grants, g)
					}
				}
				if err != nil || !reflect.DeepEqual(current, expected) || old.Authority.deadline != deadline {
					t.Fatal("scoped withdrawal changed original owner")
				}
				for name, end := range r.installed {
					if strings.HasPrefix(name, "fqdn_") && end > *r.now {
						t.Fatal("marked grant survived")
					}
				}
				for _, n := range []string{guardLeaseName(r.target), guardReplyLeaseName(r.target), guardSALeaseName(r.target)} {
					if r.installed[n] <= *r.now || r.installed[n] > deadline {
						t.Fatal("ordinary native authority invalid")
					}
				}
			}
			if !injected {
				t.Fatal("desktop preparation proof not reached")
			}
			if gap || !active || !process.Alive() {
				t.Fatal("valid preparation view withdrawal destroyed original finite ordinary authority")
			}
		})
	}
}

func TestFQDNPolicyTransitionRestorationRevokedDuringLease(t *testing.T) {
	for _, priority := range []bool{false, true} {
		t.Run(map[bool]string{false: "normal", true: "priority"}[priority], func(t *testing.T) {
			r, client := fqdnPolicyTransitionRig(t, true)
			old := cloneMaintenanceActive(r.c.active[r.target])
			deadline := old.Authority.deadline
			process := r.c.bgpProcesses[old.Entry.DeliveryID]
			injected, gap := false, false
			client.mutate = func(*RuntimeLease) {
				p := r.c.config.FQDNPolicy.view.Load().policy
				p.Mode = nodepolicy.ModeEnforcing
				p.Allow = nil
				p.FQDNGenerations = nil
				r.c.config.FQDNPolicy.view.Store(copyFQDNPolicy(&p))
				injected = true
			}
			replace := r.c.replace
			r.c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
				m, e := replace(ctx, in)
				if e == nil {
					for _, n := range []string{guardLeaseName(r.target), guardReplyLeaseName(r.target), guardSALeaseName(r.target)} {
						if r.installed[n] <= *r.now {
							gap = true
						}
					}
				}
				return m, e
			}
			var result []RuntimeMaintenanceResult
			var err error
			if priority {
				err = r.c.renewActiveIPsecRuntimeObserved(context.Background(), maintenanceAuthority(r), func() bool { return true }, nil, nil)
			} else {
				result, err = r.c.maintainIPsecRuntime(context.Background(), []RuntimeMaterial{client.material}, maintenanceAuthority(r), func() bool { return true })
			}
			if !injected || err != nil || len(result) != 0 || gap || !reflect.DeepEqual(r.c.active[r.target], old) || old.Authority.deadline != deadline || !process.Alive() {
				t.Fatal("revoked restoration affected ordinary authorization", injected, err, len(result), gap)
			}
			for name, end := range r.installed {
				if strings.HasPrefix(name, "fqdn_") && end > *r.now {
					t.Fatal("revoked restoration exposed marked authority")
				}
			}
		})
	}
}

func TestFQDNPolicyTransitionPlainInstallRetainsGenericInvalidation(t *testing.T) {
	r, _ := fqdnExpiryTurnoverRig(t)
	target := r.target
	proofFailed, replacementFailed := false, false
	prove := r.c.prove
	r.c.prove = func(ctx context.Context, e RuntimeJournalEntry, env RuntimeEnvironment) error {
		if e.Allocation.ConnectionID == target {
			proofFailed = true
			return ErrRuntimeController
		}
		return prove(ctx, e, env)
	}
	r.c.replace = func(context.Context, GuardIntent) (GuardManifest, error) {
		replacementFailed = true
		return GuardManifest{}, ErrRuntimeController
	}
	entries, err := r.c.journal.Entries()
	if err != nil {
		t.Fatal(err)
	}
	err = r.c.installActive(context.Background(), entries)
	_, exists := r.c.active[target]
	if err == nil || !proofFailed || !replacementFailed || exists {
		t.Fatal("generic proof invalidation was undone by later error", err, proofFailed, replacementFailed, exists)
	}
}
