package ipsec

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"
)

// An emitted old FQDN timeout is scheduling advice. An independently accepted
// fresh nonce can authorize the same descriptor after that old member expires;
// no old FQDN deadline or unrelated ordinary authority is extended.
func TestFQDNFollowupFreshAuthorityOutlivesOldNativeWindow(t *testing.T) {
	for _, scenario := range []string{"ordinary_timing", "slow_successful_sa_proof", "fresh_material_read_crosses_window"} {
		t.Run(scenario, func(t *testing.T) {
			r, client, oldName := fqdnFollowupFixture(t)
			old := r.c.active[r.target]
			oldNativeEnd := r.installed[oldName]
			oldOrdinaryEnd := old.Authority.deadline
			oldFQDNEnd := old.Authority.fqdnDeadlines[runtimeFQDNGrantDigest(old.FQDNLeaseDescriptors[0])]
			if oldFQDNEnd <= *r.now {
				t.Fatal("fixture lacks live exact old FQDN authority")
			}
			process := r.c.bgpProcesses[old.Entry.DeliveryID]
			requestCount := len(client.requests)
			crossed := false
			if scenario == "fresh_material_read_crosses_window" {
				*r.now = oldNativeEnd - time.Second
				client.onFetch = func(context.Context) {
					r.charge("bounded_successful_material_read", 1200*time.Millisecond)
					crossed = *r.now >= oldNativeEnd
				}
			}
			observe := r.c.recoveryObserve
			delayed := false
			r.c.recoveryObserve = func(ctx context.Context, e RuntimeJournalEntry) [2]string {
				states := observe(ctx, e)
				if !delayed && scenario == "slow_successful_sa_proof" {
					delayed = true
					r.charge("successful_post_cp_sa_observation", 3*time.Second)
					crossed = *r.now >= oldNativeEnd
				}
				return states
			}
			replace := r.c.replace
			r.c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
				for _, set := range []string{guardLeaseName(r.target), guardReplyLeaseName(r.target), guardSALeaseName(r.target)} {
					if r.installed[set] <= *r.now {
						t.Error("ordinary permit lost before replacement", set)
					}
				}
				for _, connection := range in.Connections {
					if connection.ID == r.target && (connection.PrefixOnly || len(connection.Grants) == 0) {
						t.Error("fresh expiry rollover denied ordinary applications")
					}
				}
				return replace(ctx, in)
			}
			if err := r.c.followupFQDNMaintenance(context.Background(), maintenanceAuthority(r), func() bool { return true }, nil, nil, fqdnTestWait(r)); err != nil {
				t.Fatal("fresh exact authority refused", err)
			}
			after := r.c.active[r.target]
			if scenario != "ordinary_timing" && !crossed {
				t.Fatal("fixture did not cross original native window")
			}
			if old.Authority.deadline != oldOrdinaryEnd || old.Authority.fqdnDeadlines[runtimeFQDNGrantDigest(old.FQDNLeaseDescriptors[0])] != oldFQDNEnd {
				t.Fatal("old authority deadline changed")
			}
			if after.Authority == old.Authority || after.Identity.PolicyHash != client.base.material.Policy.Hash || !reflect.DeepEqual(after.FQDNLeaseDescriptors, client.base.material.Policy.FQDNGrants) {
				t.Fatal("fresh descriptors lack independent authority")
			}
			if len(client.requests) != requestCount+1 {
				t.Fatal("expected exactly one independent fresh lease request", len(client.requests), requestCount)
			}
			request := client.requests[len(client.requests)-1]
			if request.Nonce == "" || request.PolicyHash != after.Identity.PolicyHash || !reflect.DeepEqual(request.FQDNGrants, after.FQDNLeaseDescriptors) {
				t.Fatal("fresh nonce not bound to exact hash and descriptors")
			}
			for _, prior := range client.requests[:len(client.requests)-1] {
				if prior.Nonce == request.Nonce {
					t.Fatal("fresh lease reused nonce")
				}
			}
			if !reflect.DeepEqual(after.Entry, old.Entry) || r.c.bgpProcesses[old.Entry.DeliveryID] != process || !process.Alive() {
				t.Fatal("unchanged BGP transport retired")
			}
			if r.installed[oldName] > *r.now {
				t.Fatal("old finite member was revived")
			}
			marked := 0
			for _, grant := range after.Grants {
				if !grant.FQDNManaged {
					continue
				}
				marked++
				deadline := after.Authority.fqdnDeadlines[guardFQDNGrantDigest(grant)]
				if end := r.installed[guardFQDNSetName(grant)]; end <= *r.now || end > deadline {
					t.Fatal("fresh exact timed member absent or exceeds fresh authority", end, deadline)
				}
				if _, err := after.Authority.RemainingFQDNForApply(after.Identity, guardFQDNGrantDigest(grant), time.Millisecond); err != nil {
					t.Fatal("fresh membership not authorized", err)
				}
			}
			if marked != 1 {
				t.Fatal("unexpected fresh marked grants", marked)
			}
			for _, set := range []string{guardLeaseName(r.target), guardReplyLeaseName(r.target), guardSALeaseName(r.target)} {
				if end := r.installed[set]; end <= *r.now || end > after.Authority.deadline {
					t.Fatal("ordinary finite authority absent or extended", set)
				}
			}
			t.Logf("scenario=%s old-native=%s end=%s crossed=%t original-ordinary=%s fresh-FQDN=%s", scenario, oldNativeEnd, *r.now, crossed, oldOrdinaryEnd, after.Authority.fqdnDeadlines[runtimeFQDNGrantDigest(after.FQDNLeaseDescriptors[0])])
		})
	}
}

func TestFQDNFollowupOldWindowExpiryCannotBypassFreshProof(t *testing.T) {
	for _, scenario := range []string{"sa_unknown", "sa_route_down", "route_drift", "process_dead", "owner_changed", "ordinary_reserve_expired", "missing_fresh_fqdn_permit", "expired_fresh_fqdn_permit", "wrong_fresh_nonce"} {
		t.Run(scenario, func(t *testing.T) {
			r, client, oldName := fqdnFollowupFixture(t)
			old := r.c.active[r.target]
			oldOrdinaryEnd := old.Authority.deadline
			oldFQDNEnd := old.Authority.fqdnDeadlines[runtimeFQDNGrantDigest(old.FQDNLeaseDescriptors[0])]
			if oldFQDNEnd <= *r.now {
				t.Fatal("fixture lacks live exact old FQDN authority")
			}
			process := r.c.bgpProcesses[old.Entry.DeliveryID].(*bgpSessionFixture)
			switch scenario {
			case "route_drift":
				client.onFetch = func(context.Context) { process.routes = nil }
			case "missing_fresh_fqdn_permit":
				client.base.mutate = func(l *RuntimeLease) { l.FQDNPermits = nil }
			case "expired_fresh_fqdn_permit":
				client.base.mutate = func(l *RuntimeLease) {
					for i := range l.FQDNPermits {
						l.FQDNPermits[i].TTLMS = 1
					}
				}
			case "wrong_fresh_nonce":
				client.base.mutate = func(l *RuntimeLease) { l.Nonce = "wrong" }
			}
			observe := r.c.recoveryObserve
			delayed := false
			r.c.recoveryObserve = func(ctx context.Context, e RuntimeJournalEntry) [2]string {
				states := observe(ctx, e)
				if !delayed {
					delayed = true
					r.charge("slow_post_cp_observation", 3*time.Second)
					switch scenario {
					case "sa_unknown":
						states[0] = "unknown"
					case "sa_route_down":
						states[0] = "down"
					case "process_dead":
						process.closed = true
					case "owner_changed":
						a := r.c.active[r.target]
						a.Identity.PolicyHash = strings.Repeat("f", 64)
						r.c.active[r.target] = a
					case "ordinary_reserve_expired":
						r.charge("old_ordinary_reserve_exhausted", oldOrdinaryEnd-*r.now)
					}
				}
				return states
			}
			err := r.c.followupFQDNMaintenance(context.Background(), maintenanceAuthority(r), func() bool { return true }, nil, nil, fqdnTestWait(r))
			if err == nil {
				t.Fatal("invalid independent proof accepted")
			}
			if old.Authority.deadline != oldOrdinaryEnd || old.Authority.fqdnDeadlines[runtimeFQDNGrantDigest(old.FQDNLeaseDescriptors[0])] != oldFQDNEnd {
				t.Fatal("old authority extended")
			}
			if r.installed[oldName] > *r.now {
				t.Fatal("invalid fresh proof retained old marked membership")
			}
			for set, end := range r.installed {
				if strings.HasPrefix(set, "fqdn_") && end > *r.now {
					t.Fatal("invalid fresh proof authorized marked membership", set)
				}
			}
			if len(r.c.active) != 0 || len(r.c.fqdnNativeWindows) != 0 || !r.applicationDenied[r.target] {
				t.Fatal("invalid proof retained active application authority")
			}
		})
	}
}

func TestFQDNFollowupInitiallyExpiredAdviceStartsNoWork(t *testing.T) {
	r, client, name := fqdnFollowupFixture(t)
	old := r.c.active[r.target]
	*r.now = r.installed[name]
	reads, requests := client.oldFetches+client.freshFetches, len(client.requests)
	if err := r.c.followupFQDNMaintenance(context.Background(), maintenanceAuthority(r), func() bool { return true }, nil, nil, fqdnTestWait(r)); err != nil {
		t.Fatal(err)
	}
	if reads != client.oldFetches+client.freshFetches || requests != len(client.requests) || !reflect.DeepEqual(old, r.c.active[r.target]) {
		t.Fatal("expired advice initiated work or altered authority")
	}
	if _, ok := r.c.fqdnNativeWindows[r.target]; ok {
		t.Fatal("expired advice retained")
	}
}
