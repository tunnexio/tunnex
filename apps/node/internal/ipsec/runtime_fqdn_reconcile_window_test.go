package ipsec

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	bgpengine "github.com/tunnexio/tunnex/apps/node/internal/bgp"
)

// This is an offline characterization of generic route reconciliation, not a
// measured live timing claim. The fixture keeps real accepted finite leases,
// canonical shared guard rendering/readback, and stateful route reconciliation.
// Explicit synthetic command costs expose otherwise uncharged desktop/MTU IO.
func TestFQDNGenericReconcileShortSiblingWindow(t *testing.T) {
	for _, near := range []bool{false, true} {
		t.Run(map[bool]string{false: "early_control", true: "short_sibling_cutoff"}[near], func(t *testing.T) {
			r, client, id, process, kernel := exactPageBGPConvergenceRig(t, false)
			// The shared cadence fixture has no ordinary application grant. Seed a
			// normal TCP/80 desktop grant through its authenticated material normalizer
			// and fresh nonce-bound permit before capturing the original authority.
			// This is setup, not renewal or permission inferred from transport.
			for owner, a := range r.c.active {
				if a.Entry.ContractVersion != 2 {
					continue
				}
				m := client.old[owner]
				f := m.Policy.FQDNGrants[0]
				m.Policy.DesktopGrants = append(m.Policy.DesktopGrants, RuntimeDesktopGrant{RuntimeGrant: RuntimeGrant{Source: f.Source, Destination: m.Manifest.RemotePrefixes[0], Protocol: "tcp", PortLow: 80, PortHigh: 80, RuleID: uuid.NewString()}, DeviceID: f.DeviceID, PublicKey: f.PublicKey})
				m.Policy.Hash = stringDigest([]byte(m.Policy.Hash + owner.String() + ":explicit-http"))
				_, grants, err := runtimeMaterialEntry(m, r.c.config.OrgID, r.c.config.GatewayID, a.Environment.Namespace)
				if err != nil {
					t.Fatal("HTTP material setup", err)
				}
				grants, err = r.c.observeDesktopGrants(context.Background(), grants)
				if err != nil {
					t.Fatal(err)
				}
				a.Identity.PolicyHash = m.Policy.Hash
				auth := maintenanceAuthority(r)()
				q, err := auth.BeginFQDN(a.Identity, runtimeFQDNLeaseKeys(m.Policy))
				if err != nil {
					t.Fatal(err)
				}
				response := PermitLeaseResponse{PermitLeaseRequest: q, TTLMillis: (a.Authority.deadline - *r.now).Milliseconds()}
				for _, g := range m.Policy.FQDNGrants {
					key := runtimeFQDNGrantDigest(g)
					response.FQDNPermits = append(response.FQDNPermits, RuntimeFQDNPermit{GrantDigest: key, TTLMS: (a.Authority.fqdnDeadlines[key] - *r.now).Milliseconds()})
				}
				if err = auth.Accept(response); err != nil {
					t.Fatal(err)
				}
				a.Authority, a.Grants = auth, grants
				r.c.active[owner] = a
				client.old[owner] = m
			}
			// As in the shared fixture's initial seed, setup does not charge the
			// synthetic observation hooks. The measured operation below does.
			seedProof, seedObserve := r.c.prove, r.c.recoveryObserve
			r.c.prove = func(context.Context, RuntimeJournalEntry, RuntimeEnvironment) error { return nil }
			r.c.recoveryObserve = func(context.Context, RuntimeJournalEntry) [2]string { return [2]string{"up", "up"} }
			if err := r.c.installActive(context.Background(), r.entries); err != nil {
				t.Fatal("HTTP native seed", err)
			}
			r.c.prove, r.c.recoveryObserve = seedProof, seedObserve
			originals := assemblyClone(r.c.active)
			ordinaryEnds := map[uuid.UUID]time.Duration{}
			fqdnEnds := map[uuid.UUID]map[string]time.Duration{}
			var static []uuid.UUID
			deadline := time.Duration(0)
			for owner, a := range originals {
				ordinaryEnds[owner] = a.Authority.deadline
				fqdnEnds[owner] = map[string]time.Duration{}
				for k, d := range a.Authority.fqdnDeadlines {
					fqdnEnds[owner][k] = d
				}
				if a.Entry.ContractVersion == 2 {
					static = append(static, owner)
					for _, d := range a.Authority.fqdnDeadlines {
						if deadline == 0 || d < deadline {
							deadline = d
						}
					}
				}
			}
			if len(static) != 2 {
				t.Fatal("requires two static siblings and one BGP owner")
			}
			if near {
				*r.now = deadline - 12*time.Second
			}
			start := *r.now
			for _, owner := range static {
				for _, g := range originals[owner].Grants {
					if g.FQDNManaged && r.installed[guardFQDNSetName(g)] <= start {
						t.Fatal("initial FQDN native membership already absent")
					}
				}
			}
			// Real desktop observer reads WG before/after plus nft and two reads per
			// distinct source/key; this fixture charges the same command multiplicity.
			desktop := r.c.desktopObserve
			desktopCommands, mtuCommands := 0, 0
			r.c.desktopObserve = func(ctx context.Context, gs []GuardGrant) ([]GuardGrant, error) {
				peers := map[string]bool{}
				for _, g := range gs {
					if g.DesktopDeviceID != uuid.Nil {
						peers[g.Source.String()+g.DesktopPublicKey] = true
					}
				}
				if len(peers) > 0 {
					n := 3 + 2*len(peers)
					desktopCommands += n
					r.charge("synthetic_desktop_command", time.Duration(n)*25*time.Millisecond)
				}
				return desktop(ctx, gs)
			}
			read := r.c.kernel.run
			r.c.kernel.run = func(ctx context.Context, args ...string) ([]byte, error) {
				if strings.HasPrefix(strings.Join(args, " "), "-j") && pulseDeferralInCall("guardTunnelMTUs") {
					mtuCommands++
					r.charge("synthetic_mtu_command", 25*time.Millisecond)
				}
				return read(ctx, args...)
			}
			observe := r.c.recoveryObserve
			r.c.recoveryObserve = func(ctx context.Context, e RuntimeJournalEntry) [2]string {
				r.charge("synthetic_second_status_sample", 800*time.Millisecond)
				return observe(ctx, e)
			}
			var emitted GuardIntent
			replace := r.c.replace
			r.c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
				emitted = in
				return replace(ctx, in)
			}
			target := routeTupleFixture(originals[id].Entry, 1)
			process.routes = []bgpengine.LearnedRoute{{Prefix: target.Prefix, Slot: 1}}
			if err := r.c.reconcileActiveBGP(context.Background(), r.entries); err != nil {
				t.Fatal("generic healthy RIB reconciliation failed", err)
			}
			if process.closed || !kernel.routes[0][target.Prefix.String()] || len(r.c.active) != 3 {
				t.Fatal("route/process control not retained")
			}
			ordinary, marked := 0, 0
			for _, c := range emitted.Connections {
				if c.ID == id {
					continue
				}
				for _, g := range c.Grants {
					if g.FQDNManaged {
						marked++
					} else if g.Protocol == "tcp" && g.PortLow == 80 && g.PortHigh == 80 {
						ordinary++
					}
				}
				for _, name := range []string{guardLeaseName(c.ID), guardReplyLeaseName(c.ID), guardSALeaseName(c.ID)} {
					if r.installed[name] <= *r.now {
						t.Fatal("static ordinary native permit missing", name)
					}
				}
			}
			if ordinary == 0 || desktopCommands == 0 || mtuCommands == 0 {
				t.Fatal("ordinary TCP/desktop/MTU controls not exercised", ordinary, desktopCommands, mtuCommands)
			}
			for owner, before := range originals {
				after := r.c.active[owner]
				if after.Authority != before.Authority || after.Authority.deadline != ordinaryEnds[owner] || !reflect.DeepEqual(after.Authority.fqdnDeadlines, fqdnEnds[owner]) || !reflect.DeepEqual(after.Grants, before.Grants) {
					t.Fatal("reconciliation extended or changed authority", owner)
				}
			}
			if near {
				if marked != 0 {
					t.Fatal("expected canonical early cutoff for both short siblings", marked)
				}
				if *r.now >= deadline {
					t.Fatal("fixture crossed absolute FQDN deadline instead of early cutoff", *r.now, deadline)
				}
				for _, owner := range static {
					if _, ok := r.c.fqdnNativeWindows[owner]; ok {
						t.Fatal("omitted grant retained a scheduling window")
					}
				}
				reads, leases := client.reads, client.requests
				if err := r.c.followupFQDNMaintenance(context.Background(), maintenanceAuthority(r), func() bool { return true }, nil, nil, fqdnTestWait(r)); err != nil {
					t.Fatal(err)
				}
				if client.reads != reads || client.requests != leases {
					t.Fatal("missing-window followup unexpectedly requested authority")
				}
				for _, owner := range static {
					for _, g := range originals[owner].Grants {
						if g.FQDNManaged && r.installed[guardFQDNSetName(g)] > *r.now {
							t.Fatal("omitted FQDN tuple revived without lease")
						}
					}
				}
			} else if marked != 8 {
				t.Fatal("early control lost a sibling FQDN tuple", marked)
			}
			t.Logf("near=%t generic_elapsed=%s absolute_remaining=%s ordinary_tcp=%d emitted_fqdn=%d desktop_commands=%d mtu_commands=%d windows=%d material_reads=%d lease_requests=%d", near, *r.now-start, deadline-*r.now, ordinary, marked, desktopCommands, mtuCommands, len(r.c.fqdnNativeWindows), client.reads, client.requests)
			if near {
				*r.now = deadline + time.Second
				for _, owner := range static {
					a := r.c.active[owner]
					for _, g := range a.Grants {
						if g.FQDNManaged {
							if _, err := a.Authority.RemainingFQDNForApply(a.Identity, guardFQDNGrantDigest(g), time.Millisecond); err == nil {
								t.Fatal("absolute expired authority survived")
							}
							if r.installed[guardFQDNSetName(g)] > *r.now {
								t.Fatal("expired tuple reappeared")
							}
						}
					}
					if _, err := a.Authority.RemainingForApply(a.Identity, time.Millisecond); err != nil {
						t.Fatal("ordinary positive control expired with FQDN", err)
					}
				}
				reads, leases := client.reads, client.requests
				if err := r.c.followupFQDNMaintenance(context.Background(), maintenanceAuthority(r), func() bool { return true }, nil, nil, fqdnTestWait(r)); err != nil || client.reads != reads || client.requests != leases {
					t.Fatal("expired missing-window path minted authority", err)
				}
			}
		})
	}
}
