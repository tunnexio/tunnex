package ipsec

import (
	"context"
	"reflect"
	"testing"
	"time"
)

func TestDesktopAWSStaticFQDNExpiryTurnoverUsesFreshAuthority(t *testing.T) {
	r, client := fqdnExpiryTurnoverRig(t, true)
	before := r.c.active[r.target]
	deadline := before.Authority.deadline
	if err := r.c.renewActiveIPsecRuntimeObserved(context.Background(), maintenanceAuthority(r), func() bool { return true }, nil, nil); err != nil {
		t.Fatal(err)
	}
	after := r.c.active[r.target]
	if !reflect.DeepEqual(after.Entry, before.Entry) || !reflect.DeepEqual(after.Delivery, before.Delivery) || after.Authority == before.Authority || before.Authority.deadline != deadline || after.Identity.PolicyHash != client.material.Policy.Hash || client.fetched != 1 || len(client.requests) != 2 || client.requests[0].Nonce == client.requests[1].Nonce {
		t.Fatal("static expiry refresh changed transport or borrowed old authority")
	}
	for _, g := range after.Grants {
		if !g.FQDNManaged {
			continue
		}
		if g.DesktopIngressIndex != 7777 || r.installed[guardFQDNSetName(g)] <= *r.now {
			t.Fatal("static FQDN membership or WG ownership missing")
		}
		if _, err := after.Authority.RemainingFQDNForApply(after.Identity, guardFQDNGrantDigest(g), time.Millisecond); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDesktopAWSStaticFQDNPolicyRevokeRestorePreservesOrdinary(t *testing.T) {
	for _, restore := range []bool{false, true} {
		name := "revoke"
		if restore {
			name = "restore"
		}
		t.Run(name, func(t *testing.T) {
			r, client := fqdnPolicyTransitionRig(t, restore, true)
			before := r.c.active[r.target]
			deadline := before.Authority.deadline
			result, err := r.c.maintainIPsecRuntime(context.Background(), []RuntimeMaterial{client.material}, maintenanceAuthority(r), func() bool { return true })
			after, ok := r.c.active[r.target]
			if err != nil || len(result) != 1 || !ok || r.applicationDenied[r.target] || !reflect.DeepEqual(after.Entry, before.Entry) || !reflect.DeepEqual(after.Environment, before.Environment) {
				t.Fatal("static policy transition lost selected transport or ordinary permission", err)
			}
			if after.Authority == before.Authority || before.Authority.deadline != deadline || after.Identity.PolicyHash != client.material.Policy.Hash || len(client.requests) != 1 || client.requests[0].Nonce == "" {
				t.Fatal("static permission transition lacks fresh finite proof")
			}
			marked := 0
			for _, g := range after.Grants {
				if !g.FQDNManaged {
					continue
				}
				marked++
				if _, err := after.Authority.RemainingFQDNForApply(after.Identity, guardFQDNGrantDigest(g), time.Millisecond); err != nil {
					t.Fatal(err)
				}
			}
			if (marked > 0) != restore {
				t.Fatal("static revocation/restore membership incorrect")
			}
		})
	}
}

func TestDesktopAWSStaticFQDNFollowupWithoutBGP(t *testing.T) {
	r, client, name := fqdnFollowupFixture(t, true)
	before := r.c.active[r.target]
	deadline, oldNative := before.Authority.deadline, r.installed[name]
	requests := len(client.requests)
	client.publishAt = *r.now - time.Millisecond
	if err := r.c.followupFQDNMaintenance(context.Background(), maintenanceAuthority(r), nil, nil, nil, fqdnTestWait(r)); err != nil {
		t.Fatal("static followup unexpectedly requires BGP", err)
	}
	after, ok := r.c.active[r.target]
	var refreshedEnd time.Duration
	for _, g := range after.Grants {
		if g.FQDNManaged {
			refreshedEnd = r.installed[guardFQDNSetName(g)]
		}
	}
	if !ok || refreshedEnd <= oldNative || after.Authority == before.Authority || before.Authority.deadline != deadline || !reflect.DeepEqual(after.Entry, before.Entry) || len(client.requests) != requests+1 {
		t.Fatal("static followup lost exact recovery owner or fresh lease")
	}
	if after.Entry.BGP != nil || after.Entry.BGPProcess != nil || selectedRuntimeSlot(after.Entry) != selectedRuntimeSlot(before.Entry) {
		t.Fatal("static followup created BGP or moved recovery slot")
	}
}

func TestDesktopAWSStaticFQDNFollowupRejectsOwnershipAndRouteDrift(t *testing.T) {
	for _, scenario := range []string{"peer_revoked", "native_drift", "nonce_mismatch", "recovery_switch"} {
		t.Run(scenario, func(t *testing.T) {
			r, client, name := fqdnFollowupFixture(t, true)
			client.publishAt = *r.now - time.Millisecond
			switch scenario {
			case "peer_revoked":
				r.c.desktopObserve = func(context.Context, []GuardGrant) ([]GuardGrant, error) { return nil, ErrRuntimeController }
			case "native_drift":
				r.c.prove = func(context.Context, RuntimeJournalEntry, RuntimeEnvironment) error { return ErrRuntimeController }
			case "nonce_mismatch":
				client.base.mutate = func(l *RuntimeLease) { l.Nonce = "wrong" }
			case "recovery_switch":
				client.onFetch = func(context.Context) {
					a := r.c.active[r.target]
					recovery := *a.Entry.Recovery
					recovery.Stage = "pending"
					a.Entry.Recovery = &recovery
					r.c.active[r.target] = a
				}
			}
			_ = r.c.followupFQDNMaintenance(context.Background(), maintenanceAuthority(r), nil, nil, nil, fqdnTestWait(r))
			if end := r.installed[name]; end > *r.now {
				t.Fatal("unsafe static followup retained FQDN membership")
			}
		})
	}
}

func TestDesktopAWSStaticFQDNFollowupPreservesMixedBGPQualification(t *testing.T) {
	for _, scenario := range []string{"qualified", "lost", "missing"} {
		t.Run(scenario, func(t *testing.T) {
			r, client := fqdnExpiryTurnoverRig(t, true)
			r.c.config.JournalDir = r.c.journal.dir
			window := r.c.fqdnNativeWindows[r.target]
			window.deadline = *r.now + 9*time.Second // conservative advice, never authority
			r.c.fqdnNativeWindows[r.target] = window
			before := map[string]runtimeActive{}
			for id, owner := range r.c.active {
				if id != r.target {
					before[id.String()] = owner
				}
			}
			current := func() bool { return true }
			if scenario == "lost" {
				current = func() bool { return false }
			}
			if scenario == "missing" {
				current = nil
			}
			err := r.c.followupFQDNMaintenance(context.Background(), maintenanceAuthority(r), current, nil, nil, fqdnTestWait(r))
			if scenario != "qualified" {
				if err == nil || len(client.requests) != 0 || len(r.c.active) != 0 {
					t.Fatal("static followup bypassed retained BGP qualification")
				}
				return
			}
			if err != nil || len(client.requests) != 1 {
				t.Fatal("qualified mixed followup failed", err)
			}
			for id, owner := range r.c.active {
				if id == r.target {
					continue
				}
				prior := before[id.String()]
				if !reflect.DeepEqual(owner, prior) || (owner.Entry.ContractVersion == 3 && !r.c.bgpProcesses[owner.Entry.DeliveryID].Alive()) {
					t.Fatal("static followup changed unrelated owner")
				}
			}
		})
	}
}
