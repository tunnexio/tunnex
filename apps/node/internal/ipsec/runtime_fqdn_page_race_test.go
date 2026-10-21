package ipsec

import (
	"context"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// A normal page can be fetched before a same-answer DNS publication and reach
// its lease request afterwards. The existing exact expiry-only bridge must be
// used here too; a 409 is never permission to discard or extend old authority.
func staleFQDNPage(r *renewalCycleRig, client *fqdnTurnoverClient) RuntimeMaterial {
	m := client.material
	old := r.c.active[r.target]
	m.Policy.Hash = old.Identity.PolicyHash
	m.Policy.FQDNGrants = append([]RuntimeFQDNGrant(nil), old.FQDNLeaseDescriptors...)
	return m
}

func TestNormalPageFQDNPublicationRaceAtomic(t *testing.T) {
	r, client := fqdnExpiryTurnoverRig(t)
	old := r.c.active[r.target]
	page := staleFQDNPage(r, client)
	denied := false
	replace := r.c.replace
	r.c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
		for _, owner := range in.Connections {
			if owner.ID == r.target && (owner.PrefixOnly || len(owner.Grants) == 0) {
				denied = true
			}
		}
		return replace(ctx, in)
	}
	result, err := r.c.maintainIPsecRuntime(context.Background(), []RuntimeMaterial{page}, maintenanceAuthority(r), func() bool { return true })
	next, ok := r.c.active[r.target]
	if err != nil || len(result) != 1 || denied || !ok || client.fetched != 1 || len(client.requests) != 2 {
		t.Fatalf("normal page raced publication without atomic fresh authorization: err=%v results=%d denied=%t retained=%t fetches=%d leasecalls=%d", err, len(result), denied, ok, client.fetched, len(client.requests))
	}
	if next.Authority == old.Authority || next.Identity.PolicyHash != client.material.Policy.Hash || client.requests[0].Nonce == client.requests[1].Nonce || !reflect.DeepEqual(next.FQDNLeaseDescriptors, client.material.Policy.FQDNGrants) || !reflect.DeepEqual(next.Entry, old.Entry) || !reflect.DeepEqual(next.Delivery, old.Delivery) {
		t.Fatal("handoff changed transport or omitted independent fresh authority")
	}
	for _, grant := range next.Grants {
		if grant.FQDNManaged {
			if _, err := next.Authority.RemainingFQDNForApply(next.Identity, guardFQDNGrantDigest(grant), time.Millisecond); err != nil {
				t.Fatal("fresh exact descriptor permit absent", err)
			}
			if _, ok := r.installed[guardFQDNSetName(grant)]; !ok {
				t.Fatal("fresh timed membership missing")
			}
		}
	}
}

func TestNormalPageFQDNPublicationRaceRejectsUnsafeRefresh(t *testing.T) {
	for name, mutate := range map[string]func(*renewalCycleRig, *fqdnTurnoverClient){
		"answer-b": func(_ *renewalCycleRig, c *fqdnTurnoverClient) {
			c.material.Policy.FQDNGrants[0].Destination = netip.PrefixFrom(netip.MustParsePrefix(c.material.Policy.FQDNGrants[0].Destination).Addr().Next(), 32).String()
		},
		"revoked": func(_ *renewalCycleRig, c *fqdnTurnoverClient) {
			c.material.Policy.FQDNGrants = nil
			c.material.Policy.FQDNPolicyVersion = 0
		},
		"resolver-config": func(_ *renewalCycleRig, c *fqdnTurnoverClient) {
			c.material.Policy.FQDNGrants[0].ResolverConfigVersion++
		},
		"device": func(_ *renewalCycleRig, c *fqdnTurnoverClient) {
			c.material.Policy.FQDNGrants[0].DeviceID = uuid.NewString()
		},
		"rule": func(_ *renewalCycleRig, c *fqdnTurnoverClient) {
			c.material.Policy.FQDNGrants[0].RuleID = uuid.NewString()
		},
		"application-path": func(_ *renewalCycleRig, c *fqdnTurnoverClient) {
			c.material.Policy.FQDNGrants[0].ConnectionID = uuid.NewString()
		},
		"fresh-hash": func(_ *renewalCycleRig, c *fqdnTurnoverClient) {
			c.mutate = func(l *RuntimeLease) { l.PolicyHash = strings.Repeat("f", 64) }
		},
		"stale-original": func(r *renewalCycleRig, _ *fqdnTurnoverClient) { r.c.active[r.target].Authority.deadline = *r.now },
		"generation": func(_ *renewalCycleRig, c *fqdnTurnoverClient) {
			c.material.Policy.FQDNGrants[0].Generation = strings.Repeat("d", 64)
		},
		"shortened-expiry": func(r *renewalCycleRig, c *fqdnTurnoverClient) {
			c.material.Policy.FQDNGrants[0].ExpiresAt = r.c.active[r.target].FQDNLeaseDescriptors[0].ExpiresAt.Add(-time.Second)
		},
		"new-nonce": func(_ *renewalCycleRig, c *fqdnTurnoverClient) {
			c.mutate = func(l *RuntimeLease) { l.Nonce = "wrong" }
		},
		"withdrawn-ordinary": func(r *renewalCycleRig, _ *fqdnTurnoverClient) { r.c.config.FQDNPolicy.CommittedPolicy(nil) },
	} {
		t.Run(name, func(t *testing.T) {
			r, c := fqdnExpiryTurnoverRig(t)
			page := staleFQDNPage(r, c)
			old := r.c.active[r.target]
			process := r.c.bgpProcesses[old.Entry.DeliveryID].(*bgpSessionFixture)
			mutate(r, c)
			results, _ := r.c.maintainIPsecRuntime(context.Background(), []RuntimeMaterial{page}, maintenanceAuthority(r), func() bool { return true })
			assertFQDNPublicationDenied(t, r, old, process, results)
		})
	}
}

// A second publication race cannot turn the bridge into a retry loop.
type repeatedFQDNConflictClient struct{ *fqdnTurnoverClient }

func (c repeatedFQDNConflictClient) RenewIPsecLease(ctx context.Context, id uuid.UUID, q RuntimeLeaseRequest) (RuntimeLease, error) {
	if id == c.target {
		c.requests = append(c.requests, q)
		return RuntimeLease{}, fqdnTurnoverConflict{}
	}
	return c.base.RenewIPsecLease(ctx, id, q)
}
func TestNormalPageFQDNPublicationRaceSecondConflictStops(t *testing.T) {
	r, c := fqdnExpiryTurnoverRig(t)
	page := staleFQDNPage(r, c)
	old := r.c.active[r.target]
	process := r.c.bgpProcesses[old.Entry.DeliveryID].(*bgpSessionFixture)
	r.c.client = repeatedFQDNConflictClient{c}
	results, err := r.c.maintainIPsecRuntime(context.Background(), []RuntimeMaterial{page}, maintenanceAuthority(r), func() bool { return true })
	_, retained := r.c.active[r.target]
	assertFQDNPublicationDenied(t, r, old, process, results)
	if err == nil || retained || c.fetched != 1 || len(c.requests) != 2 || c.requests[0].Nonce == c.requests[1].Nonce {
		t.Fatal("second conflict retried or retained authority", err, retained, c.fetched, len(c.requests))
	}
}
func TestNormalPageFQDNPublicationRaceOriginalExpiresDuringFetch(t *testing.T) {
	r, c := fqdnExpiryTurnoverRig(t)
	page := staleFQDNPage(r, c)
	old := r.c.active[r.target]
	process := r.c.bgpProcesses[old.Entry.DeliveryID].(*bgpSessionFixture)
	r.c.client = expiryDuringMaterialClient{c, r}
	results, err := r.c.maintainIPsecRuntime(context.Background(), []RuntimeMaterial{page}, maintenanceAuthority(r), func() bool { return true })
	_, retained := r.c.active[r.target]
	assertFQDNPublicationDenied(t, r, old, process, results)
	// Ordinary maintenance may complete with the expired owner omitted; the
	// security assertion is absence of authority, not a batch-level error.
	if retained || c.fetched != 1 || len(c.requests) != 2 {
		t.Fatal("slow fetch renewed expired original bridge", err, retained, c.fetched, len(c.requests))
	}
}

func assertFQDNPublicationDenied(t *testing.T, r *renewalCycleRig, old runtimeActive, process *bgpSessionFixture, results []RuntimeMaintenanceResult) {
	t.Helper()
	if _, ok := r.c.active[r.target]; ok {
		t.Fatal("unsafe publication retained active authority")
	}
	if !r.applicationDenied[r.target] {
		t.Fatal("unsafe publication left a positive native target grant")
	}
	if !process.closed || r.c.bgpProcesses[old.Entry.DeliveryID] != nil {
		t.Fatal("withdrawal retained desktop BGP exports")
	}
	for _, result := range results {
		if result.Acknowledgement.DeliveryID == old.Entry.DeliveryID && result.Acknowledgement.Result == "applied" {
			t.Fatal("withdrawn target returned applied acknowledgement")
		}
	}
	for _, name := range []string{guardLeaseName(r.target), guardReplyLeaseName(r.target), guardSALeaseName(r.target)} {
		if until, ok := r.installed[name]; ok && until > *r.now {
			t.Fatal("withdrawal retained ordinary native permit", name)
		}
	}
	for _, g := range old.Grants {
		if g.FQDNManaged {
			if until, ok := r.installed[guardFQDNSetName(g)]; ok && until > *r.now {
				t.Fatal("unsafe publication retained live native timed membership")
			}
		}
	}
}
