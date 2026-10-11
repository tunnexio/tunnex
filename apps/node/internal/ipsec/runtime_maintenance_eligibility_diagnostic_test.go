package ipsec

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMaintenanceEligibilityFirstFailurePreservesShortCircuit(t *testing.T) {
	labels := []string{"eligibility_observe", "eligibility_namespace", "eligibility_phase", "eligibility_contract", "eligibility_entry_current", "eligibility_active_entry", "eligibility_delivery", "eligibility_environment", "eligibility_grants", "eligibility_identity", "eligibility_authority"}
	for fail := -1; fail < len(labels); fail++ {
		stage := "eligibility_active"
		calls := []int{}
		check := func(i int) bool {
			return maintenanceEligibilityTerm(&stage, labels[i], func() bool { calls = append(calls, i); return i != fail })
		}
		got := check(0) && check(1) && check(2) && check(3) && check(4) && check(5) && check(6) && check(7) && check(8) && check(9) && check(10)
		wantCount := len(labels)
		if fail >= 0 {
			wantCount = fail + 1
		}
		if got != (fail < 0) || len(calls) != wantCount || stage != labels[wantCount-1] {
			t.Fatalf("failure %d: outcome=%v calls=%v stage=%s", fail, got, calls, stage)
		}
		for i, call := range calls {
			if i != call {
				t.Fatalf("predicate repeated/reordered: %v", calls)
			}
		}
	}
}

func TestMaintenanceEligibilityClosedDiagnosticVocabulary(t *testing.T) {
	labels := []string{"eligibility_active", "eligibility_current", "eligibility_lineage", "eligibility_observe", "eligibility_namespace", "eligibility_phase", "eligibility_contract", "eligibility_entry_current", "eligibility_active_entry", "eligibility_delivery", "eligibility_environment", "eligibility_grants", "eligibility_identity", "eligibility_authority", "eligibility_recovery", "eligibility_bgp", "eligibility_proof"}
	id := uuid.MustParse("b79d7eda-fafe-41cf-af2c-4115d4ef32c6")
	var events []RuntimeDiagnostic
	sink := func(d RuntimeDiagnostic) { events = append(events, d) }
	for _, stage := range labels {
		if !validRuntimeDiagnostic("maintenance_eligibility", stage) {
			t.Fatal(stage)
		}
		emitRuntimeDiagnostic(sink, context.Background(), "maintenance_eligibility", stage, id, time.Now(), true)
	}
	if len(events) != len(labels) {
		t.Fatalf("event count %d", len(events))
	}
	for i, event := range events {
		if event.Stage != labels[i] || event.ConnectionID != id || !event.Refused || event.ContextState != "active" {
			t.Fatalf("fixed event mismatch: %+v", event)
		}
	}
	for _, stage := range []string{"maintenance_eligibility", "eligibility_secret_material", "eligibility_observe:error", "", "maintenance_current_guard"} {
		if validRuntimeDiagnostic("maintenance_eligibility", stage) {
			t.Fatalf("unexpected vocabulary %q", stage)
		}
		emitRuntimeDiagnostic(sink, context.Background(), "maintenance_eligibility", stage, id, time.Now(), true)
	}
	if len(events) != len(labels) {
		t.Fatal("unknown stages emitted")
	}
}

// This uses the actual restored HA/Classic maintenance fixture and ordinary
// FQDN BeforePolicy withdrawal. It is not a live/native qualification claim.
func TestMaintenanceEligibilityActualClassicRevokeMissingActive(t *testing.T) {
	r := newRenewalCycleRigInput(t, true, gcpMaintenanceRestoredClassic)
	id := r.entries[1].Allocation.ConnectionID
	old := r.c.active[id]
	_, g, policy := fqdnRuntimeFixture(t)
	g.Source = netip.MustParsePrefix("10.84.2.10/32")
	g.Destination = netip.PrefixFrom(old.Entry.Engines[0].RemotePrefixes[0].Addr().Next(), 32)
	g.FQDN.SelectedGatewayID = r.c.config.GatewayID
	g.FQDN.SelectedSiteID = old.Entry.SiteID
	g.FQDN.ConnectionID = id
	g.FQDN.ConfigurationRevision = old.Entry.Engines[0].Binding.ConfigurationRevision
	policy.NodeID = r.c.config.GatewayID.String()
	policy.Allow[0].SrcIP, policy.Allow[0].DstCIDR = g.Source.String(), g.Destination.String()
	policy.FQDNGenerations[0].Answers = []string{g.Destination.String()}
	policy.DNSResolverProfiles[0].IPsecPath.ConnectionID = id.String()
	policy.DNSResolverProfiles[0].IPsecPath.ConfigurationRevision = g.FQDN.ConfigurationRevision
	old.Grants = append(old.Grants, g)
	r.c.active[id] = old
	source := &RuntimeFQDNPolicySource{}
	source.CommittedPolicy(policy)
	source.Attach(r.c)
	r.c.config.FQDNPolicy = source
	if !source.view.Load().matches(g) {
		t.Fatal("marked fixture provenance")
	}
	haID := r.entries[0].Allocation.ConnectionID
	ha := r.c.active[haID]
	policy.Allow = policy.Allow[:0]
	if err := source.BeforePolicy(context.Background(), policy); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.c.active[id]; ok {
		t.Fatal("revoked Classic remained active")
	}
	if _, err := old.Authority.RemainingForApply(old.Identity, time.Millisecond); err == nil {
		t.Fatal("original marked authority survived")
	}
	if r.c.active[haID].Authority != ha.Authority {
		t.Fatal("HA authority altered by scoped withdrawal")
	}
	events := []RuntimeDiagnostic{}
	r.c.config.Diagnostic = func(d RuntimeDiagnostic) { events = append(events, d) }
	r.phase = "maintenance"
	initialLeases := r.leases
	results, err := r.c.maintainIPsecRuntime(context.Background(), r.materials, maintenanceAuthority(r), func() bool { return true })
	if err != nil || len(results) != 1 {
		t.Fatalf("unaffected maintenance result %d: %v", len(results), err)
	}
	found := 0
	for _, d := range events {
		if d.Operation == "maintenance_eligibility" && d.ConnectionID == id && d.Refused {
			if d.Stage != "eligibility_active" {
				t.Fatal(d)
			}
			found++
		}
	}
	if found != 1 || r.leases-initialLeases != 1 {
		t.Fatalf("missing-active=%d leaseRPCs=%d", found, r.leases-initialLeases)
	}
	if _, ok := r.c.active[haID]; !ok {
		t.Fatal("unaffected HA removed")
	}
	if _, ok := r.c.active[id]; ok {
		t.Fatal("maintenance recreated missing Classic authority")
	}
}

type eligibilityChangedEnvironment struct {
	previous RuntimeEnvironmentInspector
	selected uuid.UUID
	calls    int
}

func (e *eligibilityChangedEnvironment) Observe(ctx context.Context, a KernelAllocation, engines [2]EngineTunnel) (RuntimeEnvironment, error) {
	env, err := e.previous.Observe(ctx, a, engines)
	if a.ConnectionID == e.selected {
		e.calls++
		env.LocalIngressIndices = []int{999}
	}
	return env, err
}
func (e *eligibilityChangedEnvironment) Drain(ctx context.Context, entries []RuntimeJournalEntry) error {
	return e.previous.Drain(ctx, entries)
}

func TestMaintenanceEligibilityActualEnvironmentMismatchNoClassicRenewal(t *testing.T) {
	r := newRenewalCycleRigInput(t, true, gcpMaintenanceRestoredClassic)
	id := r.entries[1].Allocation.ConnectionID
	env := &eligibilityChangedEnvironment{previous: r.c.config.Environment, selected: id}
	r.c.config.Environment = env
	events := []RuntimeDiagnostic{}
	r.c.config.Diagnostic = func(d RuntimeDiagnostic) { events = append(events, d) }
	initialLeases := r.leases
	r.phase = "maintenance"
	results, err := r.c.maintainIPsecRuntime(context.Background(), r.materials, maintenanceAuthority(r), func() bool { return true })
	if err != nil || len(results) != 1 {
		t.Fatalf("results %d error %v", len(results), err)
	}
	found := 0
	for _, d := range events {
		if d.Operation == "maintenance_eligibility" && d.ConnectionID == id && d.Refused {
			if d.Stage != "eligibility_environment" {
				t.Fatal(d)
			}
			found++
		}
	}
	if found != 1 || env.calls != 1 || r.leases-initialLeases != 1 {
		t.Fatalf("events=%d observe=%d leaseRPCs=%d", found, env.calls, r.leases-initialLeases)
	}
	if _, ok := r.c.active[id]; ok {
		t.Fatal("mismatched Classic retained")
	}
	if _, ok := r.c.active[r.entries[0].Allocation.ConnectionID]; !ok {
		t.Fatal("unaffected HA removed")
	}
}
