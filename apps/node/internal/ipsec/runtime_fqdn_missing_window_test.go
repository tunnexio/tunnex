package ipsec

import (
	"context"
	"github.com/google/uuid"
	"reflect"
	"testing"
	"time"
)

// Real canonical early cutoff supplies the advice. The test never fabricates an
// emitted timeout or a new lease to stand in for missing native membership.
func fqdnMissingWindowRig(t *testing.T) (*renewalCycleRig, *fqdnCadenceSubsetClient, uuid.UUID) {
	t.Helper()
	r, client := fqdnMultiOwnerCadenceRig(t, "live")
	*r.now = 16 * time.Second
	if err := r.c.installActive(context.Background(), r.entries); err != nil {
		t.Fatal(err)
	}
	var target uuid.UUID
	for id, a := range r.c.active {
		if a.Entry.ContractVersion != 2 {
			continue
		}
		w, ok := r.c.fqdnNativeWindows[id]
		if !ok || !w.omitted || w.deadline != 0 {
			t.Fatal("canonical cutoff did not produce omission-only advice")
		}
		for _, g := range a.Grants {
			if g.FQDNManaged && r.installed[guardFQDNSetName(g)] > *r.now {
				t.Fatal("cutoff unexpectedly retained native membership")
			}
		}
		if target == uuid.Nil || id.String() < target.String() {
			target = id
		}
	}
	if target == uuid.Nil {
		t.Fatal("no omitted static owner")
	}
	return r, client, target
}

func TestFQDNMissingWindowSelectionClosed(t *testing.T) {
	for _, scenario := range []string{"current", "original_fqdn_expired", "ordinary_expired", "owner_replaced", "authority_replaced", "policy_revoked", "descriptor_mismatch", "fictitious_deadline", "backward_clock"} {
		t.Run(scenario, func(t *testing.T) {
			r, client, id := fqdnMissingWindowRig(t)
			before := r.c.active[id]
			owner := cloneMaintenanceActive(before)
			switch scenario {
			case "original_fqdn_expired":
				*r.now = 24 * time.Second
			case "ordinary_expired":
				before.Authority.Invalidate()
			case "owner_replaced":
				owner.Identity.PolicyHash = stringDigest([]byte("foreign"))
				r.c.active[id] = owner
			case "authority_replaced":
				owner.Authority = maintenanceAuthority(r)()
				r.c.active[id] = owner
			case "policy_revoked":
				r.c.config.FQDNPolicy.CommittedPolicy(nil)
			case "descriptor_mismatch":
				owner.FQDNLeaseDescriptors = append([]RuntimeFQDNGrant(nil), owner.FQDNLeaseDescriptors...)
				owner.FQDNLeaseDescriptors[0].RuleID = uuid.NewString()
				r.c.active[id] = owner
			case "fictitious_deadline":
				w := r.c.fqdnNativeWindows[id]
				w.deadline = *r.now + time.Second
				r.c.fqdnNativeWindows[id] = w
			case "backward_clock":
				if _, err := before.Authority.RemainingForApply(before.Identity, time.Millisecond); err != nil {
					t.Fatal(err)
				}
				*r.now -= time.Second
			}
			selected := false
			for _, got := range r.c.shortFQDNNativeOwners() {
				selected = selected || got == id
			}
			if selected != (scenario == "current") {
				t.Fatal("unsafe omission advice selected", scenario, selected)
			}
			if client.requests != 0 || client.reads != 0 {
				t.Fatal("scheduling minted authority")
			}
			if scenario == "current" && (!reflect.DeepEqual(before, r.c.active[id]) || !r.c.fqdnNativeWindows[id].omitted) {
				t.Fatal("advice changed owner")
			}
		})
	}
}

func TestFQDNMissingWindowRequiresKnownCanonicalTransport(t *testing.T) {
	for _, scenario := range []string{"known", "prefix_only", "no_ordinary_permit", "unknown_outbound", "unknown_reply", "still_emitted", "no_descriptors", "expired_original"} {
		t.Run(scenario, func(t *testing.T) {
			r, _, id := fqdnMissingWindowRig(t)
			a := r.c.active[id]
			g := GuardConnection{ID: id, PermitFor: time.Second, PermittedInterfaceIndices: []int{a.Entry.Observed[0].InterfaceIndex}, ReplyIngressIndices: []int{a.Entry.Observed[0].InterfaceIndex}}
			switch scenario {
			case "prefix_only":
				g.PrefixOnly = true
			case "no_ordinary_permit":
				g.PermitFor = 0
			case "unknown_outbound":
				g.PermittedInterfaceIndices = nil
			case "unknown_reply":
				g.ReplyIngressIndices = nil
			case "still_emitted":
				g.Grants = append([]GuardGrant(nil), a.Grants...)
			case "no_descriptors":
				a.FQDNLeaseDescriptors = nil
			case "expired_original":
				*r.now = 24 * time.Second
			}
			if got := r.c.fqdnOmittedWindowEligible(g, a); got != (scenario == "known") {
				t.Fatal("unsafe advice recording", scenario, got)
			}
		})
	}
}

func TestFQDNMissingWindowRefreshHostile(t *testing.T) {
	for _, scenario := range []string{"unavailable", "cancelled", "slow_fetch", "revoked", "wrong_nonce", "unknown_native", "wrong_desktop_owner"} {
		t.Run(scenario, func(t *testing.T) {
			r, client, id := fqdnMissingWindowRig(t)
			before := assemblyClone(r.c.active)
			client.publishAt = *r.now
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			leases := 0
			r.c.client = exactPageConvergenceClient{
				material: func(fetch context.Context, owner uuid.UUID, revision int64) (RuntimeMaterial, error) {
					if scenario == "unavailable" {
						return RuntimeMaterial{}, ErrRuntimeController
					}
					m, err := client.IPsecMaterial(fetch, owner, revision)
					if owner == id {
						switch scenario {
						case "cancelled":
							cancel()
						case "slow_fetch":
							r.charge("slow_material", 3*time.Second)
						case "revoked":
							m.Policy.FQDNGrants = nil
						}
					}
					return m, err
				},
				lease: func(leaseCtx context.Context, owner uuid.UUID, q RuntimeLeaseRequest) (RuntimeLease, error) {
					leases++
					l, err := client.RenewIPsecLease(leaseCtx, owner, q)
					if scenario == "wrong_nonce" {
						l.Nonce = "unbound"
					}
					return l, err
				},
			}
			if scenario == "unknown_native" {
				r.c.recoveryObserve = func(context.Context, RuntimeJournalEntry) [2]string { return [2]string{"unknown", "unknown"} }
			}
			if scenario == "wrong_desktop_owner" {
				r.c.desktopObserve = func(context.Context, []GuardGrant) ([]GuardGrant, error) { return nil, ErrRuntimeController }
			}
			err := r.c.followupFQDNMaintenance(ctx, maintenanceAuthority(r), func() bool { return true }, nil, nil, fqdnTestWait(r))
			if (scenario == "wrong_nonce" || scenario == "unknown_native") && err == nil {
				t.Fatal("unsafe fresh authorization accepted")
			}
			for owner, a := range before {
				for _, g := range a.Grants {
					if g.FQDNManaged && r.installed[guardFQDNSetName(g)] > *r.now && a.Entry.ContractVersion == 2 {
						t.Fatal("old omitted grant revived", owner)
					}
				}
			}
			if scenario == "unavailable" || scenario == "cancelled" || scenario == "slow_fetch" {
				if leases != 0 || !reflect.DeepEqual(r.c.active, before) {
					t.Fatal("failed discovery mutated finite owner")
				}
			}
			if scenario == "revoked" {
				if leases != 0 {
					t.Fatal("revoked material requested lease")
				}
				for _, g := range r.c.active[id].Grants {
					if g.FQDNManaged {
						t.Fatal("revoked marked grant retained")
					}
				}
			}
		})
	}
}
