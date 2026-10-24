package ipsec

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

type fqdnFollowupTestClient struct {
	*lateFQDNPublicationClient
	mutate   func(*RuntimeMaterial)
	fetchErr bool
	onFetch  func(context.Context)
}

func (c *fqdnFollowupTestClient) IPsecMaterial(ctx context.Context, id uuid.UUID, revision int64) (RuntimeMaterial, error) {
	if c.onFetch != nil {
		c.onFetch(ctx)
	}
	if c.fetchErr {
		return RuntimeMaterial{}, ErrRuntimeController
	}
	m, e := c.lateFQDNPublicationClient.IPsecMaterial(ctx, id, revision)
	m.Policy.FQDNGrants = append([]RuntimeFQDNGrant(nil), m.Policy.FQDNGrants...)
	if c.mutate != nil {
		c.mutate(&m)
	}
	return m, e
}
func fqdnFollowupFixture(t *testing.T, static ...bool) (*renewalCycleRig, *fqdnFollowupTestClient, string) {
	t.Helper()
	r, base, name := lateFQDNPublicationFixture(t, static...)
	r.c.config.JournalDir = r.c.journal.dir
	if err := r.c.renewActiveIPsecRuntimeObserved(context.Background(), maintenanceAuthority(r), func() bool { return true }, nil, nil); err != nil {
		t.Fatal(err)
	}
	c := &fqdnFollowupTestClient{lateFQDNPublicationClient: base}
	r.c.client = c
	return r, c, name
}
func fqdnTestWait(r *renewalCycleRig) func(context.Context, time.Duration) error {
	return func(ctx context.Context, d time.Duration) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		r.charge("followup_wait", d)
		return nil
	}
}
func TestFQDNFollowupNoFreshMaterialLeavesExactFiniteAuthority(t *testing.T) {
	for _, scenario := range []string{"unchanged", "unavailable", "cancel_wait", "slow_fetch"} {
		t.Run(scenario, func(t *testing.T) {
			r, client, name := fqdnFollowupFixture(t)
			client.publishAt = *r.now + time.Hour
			before := r.c.active[r.target]
			nativeEnd := r.installed[name]
			requests := len(client.requests)
			started := *r.now
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			wait := fqdnTestWait(r)
			switch scenario {
			case "unavailable":
				client.fetchErr = true
			case "cancel_wait":
				wait = func(context.Context, time.Duration) error { cancel(); return context.Canceled }
			case "slow_fetch":
				client.onFetch = func(context.Context) { r.charge("slow_fetch", 3*time.Second) }
			}
			_ = r.c.followupFQDNMaintenance(ctx, maintenanceAuthority(r), func() bool { return true }, nil, nil, wait)
			if !reflect.DeepEqual(before, r.c.active[r.target]) || r.installed[name] != nativeEnd || len(client.requests) != requests {
				t.Fatal("unavailable/unchanged refresh changed finite authority")
			}
			if scenario != "slow_fetch" && *r.now-started > 2*time.Second {
				t.Fatal("material wait exceeded total bound")
			}
			if client.oldFetches > 9 {
				t.Fatal("unbounded retries", client.oldFetches)
			}
		})
	}
}
func TestFQDNFollowupChangedMaterialWithdrawsMarkedGrant(t *testing.T) {
	for _, scenario := range []string{"answer", "rule", "device", "profile", "path", "revoked"} {
		t.Run(scenario, func(t *testing.T) {
			r, client, name := fqdnFollowupFixture(t)
			before := r.c.active[r.target]
			originalDeadline := before.Authority.deadline
			ordinary := []GuardGrant{}
			for _, g := range before.Grants {
				if !g.FQDNManaged {
					ordinary = append(ordinary, g)
				}
			}
			client.publishAt = *r.now - time.Millisecond
			client.mutate = func(m *RuntimeMaterial) {
				switch scenario {
				case "answer":
					m.Policy.FQDNGrants[0].Destination = "10.182.20.166/32"
				case "rule":
					m.Policy.FQDNGrants[0].RuleID = uuid.NewString()
				case "device":
					m.Policy.FQDNGrants[0].DeviceID = uuid.NewString()
				case "profile":
					m.Policy.FQDNGrants[0].ResolverProfileID = uuid.NewString()
				case "path":
					m.Policy.FQDNGrants[0].ConfigurationRevision++
				case "revoked":
					m.Policy.FQDNGrants = nil
				}
			}
			_ = r.c.followupFQDNMaintenance(context.Background(), maintenanceAuthority(r), func() bool { return true }, nil, nil, fqdnTestWait(r))
			if end := r.installed[name]; end > *r.now {
				t.Fatal("changed material retained exact native FQDN member")
			}
			if _, ok := r.c.fqdnNativeWindows[r.target]; ok {
				t.Fatal("withdrawn owner retained scheduling advice")
			}
			for _, g := range r.c.active[r.target].Grants {
				if g.FQDNManaged {
					t.Fatal("marked grant remained")
				}
			}
			after := r.c.active[r.target]
			if after.Authority != before.Authority || after.Authority.deadline != originalDeadline || !reflect.DeepEqual(after.Grants, ordinary) {
				t.Fatal("FQDN withdrawal changed ordinary authority")
			}
			for _, set := range []string{guardLeaseName(r.target), guardReplyLeaseName(r.target), guardSALeaseName(r.target)} {
				if end := r.installed[set]; end <= *r.now || end > originalDeadline {
					t.Fatal("ordinary finite permit missing or extended", set, end, *r.now, originalDeadline)
				}
			}
		})
	}
}
func TestFQDNFollowupDirectCommitRefusesUnsafeState(t *testing.T) {
	for _, scenario := range []string{"startup_gate", "wrong_nonce", "native_proof", "native_replace", "journal_lineage", "journal_read", "old_expired", "publish_expired"} {
		t.Run(scenario, func(t *testing.T) {
			r, client, name := fqdnFollowupFixture(t)
			client.publishAt = *r.now - time.Millisecond
			publish := func(context.Context, RuntimeDelivery, RuntimeStatusReport) error { return nil }
			switch scenario {
			case "startup_gate":
				if err := os.WriteFile(filepath.Join(r.c.config.JournalDir, "restoration-startup-gate"), []byte("blocked"), 0600); err != nil {
					t.Fatal(err)
				}
			case "wrong_nonce":
				client.base.mutate = func(l *RuntimeLease) { l.Nonce = "wrong" }
			case "native_proof":
				r.c.prove = func(context.Context, RuntimeJournalEntry, RuntimeEnvironment) error { return errors.New("drift") }
			case "native_replace":
				original := r.c.replace
				first := true
				r.c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
					if first {
						first = false
						return GuardManifest{}, ErrGuardReadback
					}
					return original(ctx, in)
				}
			case "journal_read":
				client.onFetch = func(context.Context) { _ = r.c.journal.Close() }
			case "journal_lineage":
				client.onFetch = func(context.Context) {
					a := r.c.active[r.target]
					a.Entry.Allocation.Generation = uuid.New()
					r.c.active[r.target] = a
				}
			case "old_expired":
				client.onFetch = func(context.Context) { r.charge("old_expired", time.Minute) }
			case "publish_expired":
				publish = func(context.Context, RuntimeDelivery, RuntimeStatusReport) error {
					r.charge("publish_expired", time.Minute)
					return nil
				}
			}
			err := r.c.followupFQDNMaintenance(context.Background(), maintenanceAuthority(r), func() bool { return true }, publish, nil, fqdnTestWait(r))
			if scenario == "old_expired" {
				if r.installed[name] > *r.now {
					t.Fatal("old expiry extended")
				}
				return
			}
			if err == nil {
				t.Fatal("unsafe direct refresh accepted")
			}
			if scenario == "journal_read" {
				if len(r.c.active) != 0 || r.c.dnsView.Load() != nil || len(r.c.fqdnNativeWindows) != 0 {
					t.Fatal("journal failure retained process authority")
				}
				return
			}
			if end := r.installed[name]; end > *r.now {
				t.Fatal("unsafe direct refresh left old native authority")
			}
			if len(r.c.fqdnNativeWindows) != 0 {
				t.Fatal("failed commit retained native scheduling advice")
			}
		})
	}
}
func TestFQDNNativeAdviceUsesRenderedWholeSeconds(t *testing.T) {
	id := uuid.New()
	owner := runtimeActive{Entry: RuntimeJournalEntry{ContractVersion: 3}}
	c := &RuntimeController{}
	g := GuardGrant{FQDN: FQDNGrantBinding{Version: 2}, FQDNPermitFor: 1999 * time.Millisecond}
	c.rememberFQDNNativeWindows(GuardIntent{Connections: []GuardConnection{{ID: id, Grants: []GuardGrant{g}}}}, map[uuid.UUID]runtimeActive{id: owner}, 4*time.Second)
	if c.fqdnNativeWindows[id].deadline != 5*time.Second {
		t.Fatal("advice exceeds emitted whole seconds", c.fqdnNativeWindows[id].deadline)
	}
}

func TestFQDNFollowupTransportReportContract(t *testing.T) {
	for _, profile := range []string{AzureActiveStandbyBGPProfile, AzureActiveActiveBGPProfile} {
		t.Run(profile, func(t *testing.T) {
			m := azureMaterialFixture(profile)
			report, err := runtimeFQDNFollowupReport(m.RuntimeDelivery)
			if err != nil {
				t.Fatal(err)
			}
			count, _ := runtimeTransportContract(m.Manifest)
			if report.DeliveryID != m.ID || report.DesiredRevision != m.DesiredRevision || report.ConfigurationRevision != m.Manifest.ConfigurationRevision {
				t.Fatal("report identity drift")
			}
			if count == 1 {
				if report.TransportVersion == nil || *report.TransportVersion != 1 || report.TunnelCount == nil || *report.TunnelCount != 1 || report.Tunnels[1] != (RuntimeTunnelStatus{}) {
					t.Fatal("one-tunnel report lost canonical envelope", report)
				}
			} else if report.TransportVersion != nil || report.TunnelCount != nil || report.Tunnels[1].ID != m.Manifest.Tunnels[1].ID {
				t.Fatal("dual-tunnel report changed", report)
			}
		})
	}
}
func TestFQDNNativeAdviceBoundaryAndIdentity(t *testing.T) {
	for _, scenario := range []string{"ten", "eleven", "expired", "authority_changed", "owner_changed"} {
		t.Run(scenario, func(t *testing.T) {
			r, _, _ := fqdnFollowupFixture(t)
			window := r.c.fqdnNativeWindows[r.target]
			window.deadline = *r.now + 10*time.Second
			switch scenario {
			case "eleven":
				window.deadline = *r.now + 11*time.Second
			case "expired":
				window.deadline = *r.now
			case "authority_changed":
				owner := r.c.active[r.target]
				owner.Authority = maintenanceAuthority(r)()
				r.c.active[r.target] = owner
			case "owner_changed":
				owner := r.c.active[r.target]
				owner.Entry.Allocation.Generation = uuid.New()
				r.c.active[r.target] = owner
			}
			r.c.fqdnNativeWindows[r.target] = window
			got := r.c.shortFQDNNativeOwners()
			if (scenario == "ten") != (len(got) == 1) {
				t.Fatal("incorrect deadline/owner advice", scenario, got)
			}
		})
	}
}
