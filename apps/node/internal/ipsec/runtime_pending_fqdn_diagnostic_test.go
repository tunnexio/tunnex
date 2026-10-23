package ipsec

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
)

func TestPendingFQDNDiagnosticClosedVocabulary(t *testing.T) {
	stages := []string{"pending_owner_contract", "pending_owner_profile", "pending_policy_source", "pending_policy_view", "pending_policy_binding", "pending_grant_binding", "pending_guard_rebuild"}
	id := uuid.MustParse("b79d7eda-fafe-41cf-af2c-4115d4ef32c6")
	var events []RuntimeDiagnostic
	sink := func(d RuntimeDiagnostic) { events = append(events, d) }
	for _, stage := range stages {
		emitRuntimeDiagnostic(sink, context.Background(), "maintenance_pending_fqdn", stage, id, time.Now(), true)
		for _, operation := range []string{"maintenance", "apply", "install_active", "maintenance_eligibility"} {
			if validRuntimeDiagnostic(operation, stage) {
				t.Fatalf("leaf stage allowed outside its operation: %s/%s", operation, stage)
			}
		}
	}
	if len(events) != len(stages) {
		t.Fatalf("fixed leaf events: got %d want %d", len(events), len(stages))
	}
	for i, d := range events {
		if d.Operation != "maintenance_pending_fqdn" || d.Stage != stages[i] || d.ConnectionID != id || !d.Refused || d.ContextState != "active" || d.ElapsedMillis < 0 || d.DNSReadTiming != nil {
			t.Fatalf("unexpected diagnostic: %+v", d)
		}
	}
	for _, stage := range []string{"", "pending_policy_view:secret", "pending_grant_binding_psk", "maintenance_namespace", "maintenance_pending_fqdn_withdraw"} {
		emitRuntimeDiagnostic(sink, context.Background(), "maintenance_pending_fqdn", stage, id, time.Now(), true)
	}
	if len(events) != len(stages) {
		t.Fatal("open-ended diagnostic emitted")
	}
	if !validRuntimeDiagnostic("maintenance", "maintenance_pending_fqdn_withdraw") || validRuntimeDiagnostic("apply", "maintenance_pending_fqdn_withdraw") {
		t.Fatal("outer pending boundary must be maintenance-only")
	}
}

// Publish the same conservative view as BeforePolicy while maintenance owns
// the lock. The real finite guard/native seam remains the existing fixture.
func pendingFQDNDiagnosticRig(t *testing.T) *renewalCycleRig {
	t.Helper()
	r, _ := fqdnExpiryTurnoverRig(t)
	source := r.c.config.FQDNPolicy
	p := source.view.Load().policy
	p.Mode = nodepolicy.ModeEnforcing
	p.Allow, p.FQDNGenerations = nil, nil
	source.view.Store(copyFQDNPolicy(&p))
	if r.c.fqdnGrantsCurrent(r.c.active[r.target].Grants) {
		t.Fatal("fixture has no pending marked withdrawal")
	}
	return r
}

func TestPendingFQDNDiagnosticValidationLeavesPreserveRefusal(t *testing.T) {
	cases := []struct {
		name, stage string
		mutate      func(*RuntimeController, *runtimeActive, *GuardGrant)
	}{
		{"contract", "pending_owner_contract", func(_ *RuntimeController, a *runtimeActive, _ *GuardGrant) { a.Entry.ContractVersion = 2 }},
		{"profile", "pending_owner_profile", func(_ *RuntimeController, a *runtimeActive, _ *GuardGrant) {
			a.Entry.Allocation.ProfileID = "unsupported"
		}},
		{"source", "pending_policy_source", func(c *RuntimeController, _ *runtimeActive, _ *GuardGrant) { c.config.FQDNPolicy = nil }},
		{"view", "pending_policy_view", func(c *RuntimeController, _ *runtimeActive, _ *GuardGrant) { c.config.FQDNPolicy.view.Store(nil) }},
		{"node_binding", "pending_policy_binding", func(c *RuntimeController, _ *runtimeActive, _ *GuardGrant) {
			p := c.config.FQDNPolicy.view.Load().policy
			p.Mode = nodepolicy.ModeEnforcing
			p.NodeID = uuid.NewString()
			c.config.FQDNPolicy.view.Store(copyFQDNPolicy(&p))
		}},
		{"grant_version", "pending_grant_binding", func(_ *RuntimeController, _ *runtimeActive, g *GuardGrant) { g.FQDN.Version = 1 }},
		{"grant_kind", "pending_grant_binding", func(_ *RuntimeController, _ *runtimeActive, g *GuardGrant) { g.FQDN.ResolverKind = "unsupported" }},
		{"grant_device", "pending_grant_binding", func(_ *RuntimeController, _ *runtimeActive, g *GuardGrant) { g.DesktopDeviceID = uuid.Nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := pendingFQDNDiagnosticRig(t)
			a := cloneMaintenanceActive(r.c.active[r.target])
			var marked *GuardGrant
			for i := range a.Grants {
				if a.Grants[i].FQDNManaged {
					if marked != nil {
						t.Fatal("ambiguous marked fixture")
					}
					marked = &a.Grants[i]
				}
			}
			if marked == nil {
				t.Fatal("fixture marked-grant binding")
			}
			tc.mutate(r.c, &a, marked)
			r.c.active[r.target] = a
			var events []RuntimeDiagnostic
			r.c.config.Diagnostic = func(d RuntimeDiagnostic) { events = append(events, d) }
			before := cloneMaintenanceActive(a)
			replaced := false
			r.c.replace = func(context.Context, GuardIntent) (GuardManifest, error) {
				replaced = true
				return GuardManifest{}, ErrRuntimeController
			}
			err := r.c.withdrawPendingFQDNPolicyLocked(context.Background())
			if !errors.Is(err, ErrRuntimeController) || replaced || !reflect.DeepEqual(r.c.active[r.target], before) {
				t.Fatal("validation failure changed its refusal or modified native/active authority", err)
			}
			if len(events) != 1 || events[0].Operation != "maintenance_pending_fqdn" || events[0].Stage != tc.stage || events[0].ConnectionID != r.target || !events[0].Refused {
				t.Fatalf("first failed prerequisite not identified: %+v", events)
			}
		})
	}
}

func TestPendingFQDNDiagnosticNativeFailureNamesAffectedOwner(t *testing.T) {
	r := pendingFQDNDiagnosticRig(t)
	var events []RuntimeDiagnostic
	r.c.config.Diagnostic = func(d RuntimeDiagnostic) { events = append(events, d) }
	reached := 0
	r.c.replace = func(context.Context, GuardIntent) (GuardManifest, error) {
		reached++
		return GuardManifest{}, errors.New("untrusted-native-error-must-not-be-logged")
	}
	if err := r.c.withdrawPendingFQDNPolicyLocked(context.Background()); !errors.Is(err, ErrRuntimeController) || reached == 0 {
		t.Fatal("native failure injection not reached/refused", err, reached)
	}
	found := 0
	for _, d := range events {
		if d.Operation == "maintenance_pending_fqdn" {
			found++
			if d.Stage != "pending_guard_rebuild" || d.ConnectionID != r.target || !d.Refused || d.DNSReadTiming != nil {
				t.Fatal("affected-owner native failure event", d)
			}
		}
	}
	if found != 1 {
		t.Fatalf("affected-owner event count %d", found)
	}
}

func TestPendingFQDNDiagnosticMaintenanceBoundary(t *testing.T) {
	for _, namespaceFails := range []bool{true, false} {
		name := "pending_withdrawal"
		if namespaceFails {
			name = "namespace"
		}
		t.Run(name, func(t *testing.T) {
			r := pendingFQDNDiagnosticRig(t)
			want := "maintenance_pending_fqdn_withdraw"
			if namespaceFails {
				want = "maintenance_namespace"
				r.c.namespace = func() (string, error) { return "", errors.New("untrusted-namespace-error") }
			} else {
				r.c.config.FQDNPolicy = nil
			}
			var events []RuntimeDiagnostic
			r.c.config.Diagnostic = func(d RuntimeDiagnostic) { events = append(events, d) }
			leasesBefore := r.leases
			results, err := r.c.maintainIPsecRuntime(context.Background(), r.materials, maintenanceAuthority(r), func() bool { return true })
			if !errors.Is(err, ErrRuntimeController) || len(results) != 0 || len(r.c.active) != 0 || r.leases != leasesBefore {
				t.Fatal("maintenance refusal/absence of fresh authority changed", err)
			}
			outer, leaf := 0, 0
			for _, d := range events {
				if d.Operation == "maintenance" {
					outer++
					if d.Stage != want || !d.Refused {
						t.Fatal("incorrect outer boundary", d)
					}
				}
				if d.Operation == "maintenance_pending_fqdn" {
					leaf++
					if d.Stage != "pending_policy_source" || d.ConnectionID != r.target || !d.Refused {
						t.Fatal("incorrect pending leaf", d)
					}
				}
			}
			if outer != 1 || namespaceFails && leaf != 0 || !namespaceFails && leaf != 1 {
				t.Fatalf("boundary events outer=%d leaf=%d", outer, leaf)
			}
		})
	}
}
