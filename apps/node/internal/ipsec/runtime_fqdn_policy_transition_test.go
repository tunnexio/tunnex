package ipsec

import (
	"context"
	"github.com/google/uuid"
	"reflect"
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
		for _, mode := range []string{"nonce", "hash", "delivery", "revision", "zero-ttl", "missing-fqdn-permit", "old-expires-during-lease", "new-policy-revoked", "valid-view-revoked-during-lease", "owner-changes"} {
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
					case "valid-view-revoked-during-lease":
						p := r.c.config.FQDNPolicy.view.Load().policy
						p.Mode = nodepolicy.ModeEnforcing
						p.Allow, p.FQDNGenerations = nil, nil
						r.c.config.FQDNPolicy.CommittedPolicy(&p)
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
