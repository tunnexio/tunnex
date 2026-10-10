package ipsec

import (
	"context"
	"errors"
	"github.com/tunnexio/tunnex/apps/node/internal/fqdnrpc"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDNSDiagnosticClassifiesNativeGuardGrantAndRouteRefusal(t *testing.T) {
	for _, scenario := range []string{"native", "grant", "guard", "route", "epoch"} {
		t.Run(scenario, func(t *testing.T) {
			f := newDNSOwnerViewFixture(t, nil)
			var diagnostic RuntimeDiagnostic
			f.c.config.Diagnostic = func(d RuntimeDiagnostic) { diagnostic = d }
			expected := ""
			switch scenario {
			case "native":
				f.c.prove = func(context.Context, RuntimeJournalEntry, RuntimeEnvironment) error {
					return errors.New("private error must never enter diagnostic")
				}
				f.publish(t)
				expected = "dns_native_proof"
			case "grant":
				f.config.Version++
				expected = "dns_grant"
			case "guard":
				f.observed.Store(`{"private":"never emit"}`)
				expected = "dns_guard_full_read"
			case "route":
				view := *f.c.dnsView.Load()
				view.observer.route = func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("private route") }
				f.c.dnsView.Store(&view)
				expected = "dns_route"
			case "epoch":
				view := *f.c.dnsView.Load()
				old := view.observer.source
				view.observer.source = func(source netip.Addr, indices []int) (int, error) {
					index, err := old(source, indices)
					if f.sourceReads.Load() == 2 {
						for _, owner := range view.entries {
							owner.epoch.revoked.Store(true)
						}
					}
					return index, err
				}
				f.c.dnsView.Store(&view)
				expected = "dns_epoch"
			}
			if _, err := f.c.proveResolverDNSStage(context.Background(), f.config, f.config.Endpoints[0], "dns_after_proof"); err == nil {
				t.Fatal("mandatory refusal changed")
			}
			if diagnostic.Operation != "dns_after_proof" || diagnostic.Stage != expected || !diagnostic.Refused || diagnostic.ContextState != "active" {
				t.Fatalf("wrong fixed stage: %+v", diagnostic)
			}
		})
	}
}
func TestDNSDiagnosticRateIsConcurrentAndDoesNotAlterProof(t *testing.T) {
	f := newDNSOwnerViewFixture(t, nil)
	var calls atomic.Int32
	f.c.config.Diagnostic = func(RuntimeDiagnostic) { calls.Add(1) }
	// Successful proof remains silent and retains every independent read.
	if _, err := f.prove(context.Background()); err != nil || calls.Load() != 0 || f.nativeProofs.Load() != 1 || f.guardReads.Load() != 1 || f.routeReads.Load() != 1 || f.sourceReads.Load() != 2 {
		t.Fatal("successful proof changed")
	}
	start := time.Unix(1000, 0)
	f.c.dnsDiagnosticAfter.Store(0)
	var accepted atomic.Int32
	var wait sync.WaitGroup
	for i := 0; i < 100; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if f.c.claimDNSDiagnostic(start) {
				accepted.Add(1)
			}
		}()
	}
	wait.Wait()
	if accepted.Load() != 1 || f.c.claimDNSDiagnostic(start.Add(time.Second-time.Nanosecond)) || !f.c.claimDNSDiagnostic(start.Add(time.Second)) {
		t.Fatal("DNS diagnostics are not one per second")
	}
	if validRuntimeDiagnostic("dns_proof", "private error or hostname") {
		t.Fatal("arbitrary diagnostic accepted")
	}
}

func TestDNSDiagnosticSocketRefusalPreservesActiveContext(t *testing.T) {
	for _, protocol := range []string{"udp", "tcp"} {
		t.Run(protocol, func(t *testing.T) {
			f := newDNSOwnerViewFixture(t, nil)
			var diagnostic RuntimeDiagnostic
			f.c.config.Diagnostic = func(d RuntimeDiagnostic) { diagnostic = d }
			endpoint := fqdnrpc.ResolverEndpoint{Address: f.config.Endpoints[0].Address, Port: 53, Transport: protocol}
			// Malformed packet rejected before any socket; no real network fixture.
			if _, err := f.c.exchangeResolverDNS(context.Background(), f.config, endpoint, []byte("short")); err == nil {
				t.Fatal("malformed DNS packet accepted")
			}
			if diagnostic.Operation != "dns_exchange" || diagnostic.Stage != "dns_socket_"+protocol || diagnostic.ContextState != "active" || !diagnostic.Refused {
				t.Fatalf("wrong socket refusal or context: %+v", diagnostic)
			}
		})
	}
}

func renewDNSDiagnosticGuard(t *testing.T, f *dnsOwnerViewFixture) {
	t.Helper()
	a := f.c.active[f.material.Manifest.ConnectionID]
	i := guardFixture()
	i.OwnerID = f.material.Manifest.NodeID
	i.Revision = f.manifest.Revision + 1
	i.Connections[0].ID = a.Entry.Allocation.ConnectionID
	i.Connections[0].Tunnels = a.Entry.Observed
	i.Connections[0].Grants = a.Grants
	i.Connections[0].ReplyIngressIndices = []int{10}
	i.Connections[0].EncryptedEgress = []GuardEncryptedEgress{{TunnelInterfaceIndex: 10, ReqID: a.Entry.Engines[0].ReqID, Peer: a.Entry.Engines[0].RemoteAddress, UnderlayInterfaceIndex: 2}}
	g, err := RenderGuard(i)
	if err != nil {
		t.Fatal(err)
	}
	f.manifest = g
	f.observed.Store(g.ExpectedJSON)
	f.publish(t)
}
func TestDNSBenignPublishedGuardRenewalRevalidatesExactCurrentTemplate(t *testing.T) {
	f := newDNSOwnerViewFixture(t, nil)
	original := f.c.dnsView.Load().entries[f.material.Manifest.ConnectionID]
	var diagnostic RuntimeDiagnostic
	f.c.config.Diagnostic = func(d RuntimeDiagnostic) { diagnostic = d }
	// Replace native table and publish exact manifest between view load and guard
	// read. Only guard revision changes; owner and accepted authority are exact.
	f.c.prove = func(context.Context, RuntimeJournalEntry, RuntimeEnvironment) error {
		renewDNSDiagnosticGuard(t, f)
		return nil
	}
	f.publish(t)
	if _, err := f.prove(context.Background()); err != nil {
		t.Fatal("benign exact-authority guard renewal refused", err)
	}
	current := f.c.dnsView.Load().entries[f.material.Manifest.ConnectionID]
	if current.epoch != original.epoch || !sameDNSOwnerInputs(current.active, original.active) {
		t.Fatal("fixture changed authority")
	}
	if diagnostic.Refused || f.guardReads.Load() != 3 {
		t.Fatalf("current template not independently bracketed: %+v reads%d", diagnostic, f.guardReads.Load())
	}
}
func TestDNSDiagnosticRenewalWithWrongNativeTableRemainsRefused(t *testing.T) {
	f := newDNSOwnerViewFixture(t, nil)
	var diagnostic RuntimeDiagnostic
	f.c.config.Diagnostic = func(d RuntimeDiagnostic) { diagnostic = d }
	f.c.prove = func(context.Context, RuntimeJournalEntry, RuntimeEnvironment) error {
		renewDNSDiagnosticGuard(t, f)
		f.observed.Store(`{"nftables":[]}`)
		return nil
	}
	f.publish(t)
	if _, err := f.prove(context.Background()); err == nil || diagnostic.Stage != "dns_guard_full_read" {
		t.Fatalf("wrong native table accepted/misclassified: %+v", diagnostic)
	}
}

func TestDNSGuardRevalidationRefusesChangedAuthorityAndDigestChurn(t *testing.T) {
	for _, name := range []string{"owner_epoch", "grants", "original_lease", "current_lease", "native_table", "digest_churn", "deadline", "original_lease_during", "current_lease_during"} {
		t.Run(name, func(t *testing.T) {
			f := newDNSOwnerViewFixture(t, nil)
			id := f.material.Manifest.ConnectionID
			previous := f.c.dnsView.Load()
			owner := previous.entries[id]
			entry := owner.active.Entry
			renewDNSDiagnosticGuard(t, f)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch name {
			case "owner_epoch":
				f.c.withdrawDNSOwnerView(id)
			case "grants":
				a := f.c.active[id]
				a.Grants = append([]GuardGrant(nil), a.Grants[1:]...)
				f.c.active[id] = a
				f.publish(t)
			case "original_lease", "current_lease":
				a := f.c.active[id]
				a.Authority = dnsTestAuthority(t, a.Identity)
				f.c.active[id] = a
				f.publish(t)
				if name == "original_lease" {
					owner.active.Authority.Invalidate()
				} else {
					a.Authority.Invalidate()
				}
			case "original_lease_during", "current_lease_during":
				a := f.c.active[id]
				a.Authority = dnsTestAuthority(t, a.Identity)
				f.c.active[id] = a
				f.publish(t)
				run := f.c.guard.reader.run
				f.c.guard.reader.run = func(ctx context.Context, args ...string) ([]byte, error) {
					raw, err := run(ctx, args...)
					if name == "original_lease_during" {
						owner.active.Authority.Invalidate()
					} else {
						a.Authority.Invalidate()
					}
					return raw, err
				}
			case "native_table":
				f.observed.Store(`{"nftables":[]}`)
			case "digest_churn":
				run := f.c.guard.reader.run
				f.c.guard.reader.run = func(ctx context.Context, args ...string) ([]byte, error) {
					raw, err := run(ctx, args...)
					renewDNSDiagnosticGuard(t, f)
					return raw, err
				}
			case "deadline":
				cancel()
			}
			if f.c.revalidateDNSGuardSnapshot(ctx, id, owner, previous, entry, entry.Observed[0].InterfaceIndex, entry.Engines[0].ReqID) {
				t.Fatal("changed or expired authority accepted")
			}
			if f.guardReads.Load() > 1 {
				t.Fatal("retry loop exceeded one current-template check", f.guardReads.Load())
			}
		})
	}
}
