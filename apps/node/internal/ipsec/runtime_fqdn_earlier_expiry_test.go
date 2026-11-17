package ipsec

import (
	"context"
	"net/netip"
	"reflect"
	"testing"
	"time"
)

// The old and new absolute DNS deadlines are both future, but a cached answer
// can legitimately produce an earlier deadline on its next resolution. Bind the
// modeled CP lease to that new deadline rather than the older fixture's fixed TTL.
func earlierFQDNExpiryRig(t *testing.T, reduction time.Duration) (*renewalCycleRig, *fqdnTurnoverClient, time.Duration) {
	t.Helper()
	r, client := fqdnExpiryTurnoverRig(t)
	old := r.c.active[r.target]
	old.FQDNLeaseDescriptors = append([]RuntimeFQDNGrant(nil), old.FQDNLeaseDescriptors...)
	old.FQDNLeaseDescriptors[0].ExpiresAt = time.Now().UTC().Add(45 * time.Second)
	old.Grants = append([]GuardGrant(nil), old.Grants...)
	for i := range old.Grants {
		if old.Grants[i].FQDNManaged {
			old.Grants[i].FQDN.ExpiresAt = old.FQDNLeaseDescriptors[0].ExpiresAt
			old.Grants[i].DesktopExpiresAt = old.FQDNLeaseDescriptors[0].ExpiresAt
		}
	}
	auth := maintenanceAuthority(r)()
	q, err := auth.BeginFQDN(old.Identity, []string{runtimeFQDNGrantDigest(old.FQDNLeaseDescriptors[0])})
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.Accept(PermitLeaseResponse{PermitLeaseRequest: q, TTLMillis: 60000, FQDNPermits: []RuntimeFQDNPermit{{GrantDigest: earlierFQDNGrantKey(old), TTLMS: 40000}}}); err != nil {
		t.Fatal(err)
	}
	old.Authority = auth
	r.c.active[r.target] = old
	if err := r.c.installActive(context.Background(), r.entries); err != nil {
		t.Fatal(err)
	}
	client.material.Policy.FQDNGrants = append([]RuntimeFQDNGrant(nil), old.FQDNLeaseDescriptors...)
	client.material.Policy.FQDNGrants[0].ExpiresAt = old.FQDNLeaseDescriptors[0].ExpiresAt.Add(-reduction)
	freshDeadline := *r.now + time.Until(client.material.Policy.FQDNGrants[0].ExpiresAt)
	client.mutate = func(l *RuntimeLease) {
		for i := range l.FQDNPermits {
			// Like the CP, subtract time spent collecting this exact response.
			l.FQDNPermits[i].TTLMS = (freshDeadline - *r.now).Milliseconds()
		}
	}
	return r, client, freshDeadline
}

func earlierFQDNGrantKey(a runtimeActive) string {
	return runtimeFQDNGrantDigest(a.FQDNLeaseDescriptors[0])
}

func runEarlierFQDNRenewal(r *renewalCycleRig, client *fqdnTurnoverClient, priority bool) ([]RuntimeMaintenanceResult, error) {
	if priority {
		return nil, r.c.renewActiveIPsecRuntimeObserved(context.Background(), maintenanceAuthority(r), func() bool { return true }, nil, nil)
	}
	return r.c.maintainIPsecRuntime(context.Background(), []RuntimeMaterial{client.material}, maintenanceAuthority(r), func() bool { return true })
}

func TestFQDNEarlierExpiryRenewalKeepsMixedDesktopAuthority(t *testing.T) {
	for _, priority := range []bool{false, true} {
		path := "normal"
		if priority {
			path = "priority"
		}
		for _, reduction := range []time.Duration{904371 * time.Microsecond, 15096443 * time.Microsecond} {
			t.Run(path+"/"+reduction.String(), func(t *testing.T) {
				r, client, freshDeadline := earlierFQDNExpiryRig(t, reduction)
				old := r.c.active[r.target]
				ordinaryDeadline, oldFQDNDeadline := old.Authority.deadline, old.Authority.fqdnDeadlines[earlierFQDNGrantKey(old)]
				process := r.c.bgpProcesses[old.Entry.DeliveryID]
				var ordinary []GuardGrant
				for _, g := range old.Grants {
					if !g.FQDNManaged {
						ordinary = append(ordinary, g)
					}
				}
				desktopOrdinary := false
				for _, g := range ordinary {
					desktopOrdinary = desktopOrdinary || g.DesktopPublicKey != ""
				}
				if !desktopOrdinary {
					t.Fatal("fixture missing ordinary desktop permission")
				}
				denied := false
				renewalPhase := true
				replace := r.c.replace
				r.c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
					for _, owner := range in.Connections {
						if owner.ID == r.target && (owner.PrefixOnly || len(owner.Grants) == 0) {
							denied = true
						}
					}
					out, err := replace(ctx, in)
					if err == nil && renewalPhase {
						fqdnMembers := 0
						for _, owner := range in.Connections {
							if owner.ID != r.target {
								continue
							}
							for _, g := range owner.Grants {
								if g.FQDNManaged {
									fqdnMembers++
									if r.installed[guardFQDNSetName(g)] <= *r.now {
										denied = true
									}
								}
							}
						}
						if fqdnMembers != len(old.FQDNLeaseDescriptors) {
							denied = true
						}
						for _, name := range []string{guardLeaseName(r.target), guardReplyLeaseName(r.target), guardSALeaseName(r.target)} {
							if r.installed[name] <= *r.now {
								denied = true
							}
						}
					}
					return out, err
				}
				results, err := runEarlierFQDNRenewal(r, client, priority)
				after, present := r.c.active[r.target]
				t.Logf("priority=%t reduction=%v results=%d requests=%d fetched=%d denied=%t retained=%t err=%v", priority, reduction, len(results), len(client.requests), client.fetched, denied, present, err)
				if err != nil || !present || denied || r.applicationDenied[r.target] || !process.Alive() || r.c.bgpProcesses[old.Entry.DeliveryID] != process {
					t.Fatal("earlier fresh expiry interrupted existing ordinary/FQDN authority")
				}
				if !priority && len(results) != 1 {
					t.Fatal("normal renewal omitted applied result")
				}
				expectedRequests, expectedFetches := 1, 0
				if priority {
					expectedRequests, expectedFetches = 2, 1
				}
				if len(client.requests) != expectedRequests || client.fetched != expectedFetches {
					t.Fatal("unexpected refresh/retry count")
				}
				if priority && client.requests[0].Nonce == client.requests[1].Nonce {
					t.Fatal("fresh lease reused nonce")
				}
				if after.Authority == old.Authority || after.Identity.PolicyHash != client.material.Policy.Hash || !reflect.DeepEqual(after.FQDNLeaseDescriptors, client.material.Policy.FQDNGrants) || !reflect.DeepEqual(after.Entry, old.Entry) || !reflect.DeepEqual(after.Delivery, old.Delivery) {
					t.Fatal("fresh authority/transport binding changed")
				}
				var afterOrdinary []GuardGrant
				fqdnCount := 0
				for _, g := range after.Grants {
					if !g.FQDNManaged {
						afterOrdinary = append(afterOrdinary, g)
						continue
					}
					fqdnCount++
					deadline := after.Authority.fqdnDeadlines[guardFQDNGrantDigest(g)]
					if deadline <= *r.now || deadline > freshDeadline || r.installed[guardFQDNSetName(g)] <= *r.now || r.installed[guardFQDNSetName(g)] > deadline {
						t.Fatal("native membership exceeded new earlier CP deadline")
					}
				}
				if fqdnCount != len(client.material.Policy.FQDNGrants) {
					t.Fatal("missing fresh exact FQDN grant")
				}
				if !reflect.DeepEqual(ordinary, afterOrdinary) || old.Authority.deadline != ordinaryDeadline || old.Authority.fqdnDeadlines[earlierFQDNGrantKey(old)] != oldFQDNDeadline {
					t.Fatal("old authority or ordinary tuple was altered")
				}
				// Advancing past the NEW deadline leaves ordinary authority live,
				// but cannot recover the old later FQDN authority through rebuild.
				renewalPhase = false
				*r.now = freshDeadline + time.Millisecond
				if err := r.c.installActive(context.Background(), r.entries); err != nil {
					t.Fatal(err)
				}
				for _, g := range after.Grants {
					if g.FQDNManaged && r.installed[guardFQDNSetName(g)] > *r.now {
						t.Fatal("earlier expired authority revived")
					}
				}
				for _, name := range []string{guardLeaseName(r.target), guardReplyLeaseName(r.target), guardSALeaseName(r.target)} {
					if r.installed[name] <= *r.now {
						t.Fatal("FQDN expiry removed ordinary authority")
					}
				}
			})
		}
	}
}

func TestFQDNEarlierExpiryStillRejectsUnsafeScope(t *testing.T) {
	for _, mode := range []string{"expired", "answer", "rule", "device", "profile", "source", "same_hash", "wrong_nonce", "wrong_permit", "missing_permit", "revoked"} {
		t.Run(mode, func(t *testing.T) {
			r, client, _ := earlierFQDNExpiryRig(t, time.Second)
			old := r.c.active[r.target]
			switch mode {
			case "expired":
				client.material.Policy.FQDNGrants[0].ExpiresAt = time.Now().Add(-time.Second)
			case "answer":
				client.material.Policy.FQDNGrants[0].Destination = netip.PrefixFrom(netip.MustParsePrefix(client.material.Policy.FQDNGrants[0].Destination).Addr().Next(), 32).String()
			case "rule":
				client.material.Policy.FQDNGrants[0].RuleID = old.Delivery.ID.String()
			case "device":
				client.material.Policy.FQDNGrants[0].DeviceID = old.Delivery.ID.String()
			case "profile":
				client.material.Policy.FQDNGrants[0].ResolverProfileID = old.Delivery.ID.String()
			case "source":
				client.material.Policy.FQDNGrants[0].Source = "10.99.0.8/32"
			case "same_hash":
				client.material.Policy.Hash = old.Identity.PolicyHash
			case "wrong_nonce":
				client.mutate = func(l *RuntimeLease) { l.Nonce = "wrong" }
			case "wrong_permit":
				client.mutate = func(l *RuntimeLease) { l.FQDNPermits[0].GrantDigest = earlierFQDNGrantKey(old) }
			case "missing_permit":
				client.mutate = func(l *RuntimeLease) { l.FQDNPermits = nil }
			case "revoked":
				r.c.config.FQDNPolicy.CommittedPolicy(nil)
			}
			_, _ = runEarlierFQDNRenewal(r, client, true)
			if after, ok := r.c.active[r.target]; ok && after.Identity.PolicyHash == client.material.Policy.Hash && after.Authority != old.Authority {
				t.Fatal("unsafe earlier-expiry material obtained fresh authority")
			}
			if mode != "same_hash" {
				if _, ok := r.c.active[r.target]; ok {
					t.Fatal("unsafe fresh proof retained target")
				}
				for _, name := range []string{guardLeaseName(r.target), guardReplyLeaseName(r.target), guardSALeaseName(r.target)} {
					if r.installed[name] > *r.now {
						t.Fatal("unsafe fresh proof left native permission")
					}
				}
			}
		})
	}
}
