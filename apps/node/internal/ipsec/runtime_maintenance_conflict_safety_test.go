package ipsec

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMaintenanceConflictUnsafeScopeRemainsGlobal(t *testing.T) {
	for _, kind := range []string{"prior_changed_owner", "expired_unrelated", "missing_native_unrelated", "partial_native_withdrawal", "post_withdrawal_expiry", "generic_409", "ineligible_409", "context_race", "qualification_race", "target_binding_race", "journal_race"} {
		t.Run(kind, func(t *testing.T) {
			r, originalID, target, process, _ := matrixConflictRig(t, "aws-bgp-ipv4-v1")
			original := r.c.active[originalID]
			deadline := original.Authority.deadline
			materials := []RuntimeMaterial{target}
			if kind == "prior_changed_owner" {
				for _, m := range r.materials {
					if m.Manifest.ConnectionID == originalID {
						m.Policy.Hash = strings.Repeat("c", 64)
						materials = append([]RuntimeMaterial{m}, materials...)
					}
				}
			}
			apply := r.c.guard.apply
			injected := false
			if kind == "partial_native_withdrawal" {
				r.c.guard.apply = func(context.Context, []byte) error {
					injected = true
					r.installed[guardLeaseName(target.Manifest.ConnectionID)] = 0
					return ErrGuardRead
				}
			}
			if kind == "journal_race" {
				r.c.guard.apply = func(ctx context.Context, raw []byte) error {
					injected = true
					if err := apply(ctx, raw); err != nil {
						return err
					}
					return r.c.journal.Save(r.entries)
				}
			}
			if kind == "post_withdrawal_expiry" {
				r.c.guard.apply = func(ctx context.Context, raw []byte) error {
					injected = true
					err := apply(ctx, raw)
					*r.now = deadline + time.Second
					return err
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			qualified := true
			calls := 0
			r.c.client = maintenanceLeaseFunc(func(_ context.Context, id uuid.UUID, request RuntimeLeaseRequest) (RuntimeLease, error) {
				calls++
				if id != target.Manifest.ConnectionID {
					t.Fatal("unexpected renewal owner")
				}
				switch kind {
				case "expired_unrelated":
					*r.now = deadline + time.Second
				case "missing_native_unrelated":
					r.installed[guardLeaseName(originalID)] = 0
				case "context_race":
					cancel()
				case "qualification_race":
					qualified = false
				case "target_binding_race":
					a := r.c.active[id]
					a.Identity.PolicyHash = strings.Repeat("c", 64)
					r.c.active[id] = a
				case "generic_409":
					return RuntimeLease{}, testLeaseFailure("http_409")
				case "ineligible_409":
					return RuntimeLease{}, testLeaseFailure("http_409_ineligible")
				}
				return RuntimeLease{}, testLeaseFailure("http_409_conflict")
			})
			result, err := r.c.maintainIPsecRuntime(ctx, materials, maintenanceAuthority(r), func() bool { return qualified })
			var aborted interface{ IPsecMaintenanceBatchAborted() bool }
			if !errors.Is(err, ErrRuntimeController) || len(result) != 0 || errors.As(err, &aborted) || calls != 1 {
				t.Fatalf("unsafe failure escaped global refusal: err=%v results=%d calls=%d", err, len(result), calls)
			}
			if len(r.c.active) != 0 || !process.closed || !r.applicationDenied[originalID] || !r.applicationDenied[target.Manifest.ConnectionID] {
				t.Fatal("unknown or lost authority retained application access/exports")
			}
			if (kind == "partial_native_withdrawal" || kind == "post_withdrawal_expiry" || kind == "journal_race") && !injected {
				t.Fatal("native failure injection was not reached")
			}
			if original.Authority.deadline != deadline {
				t.Fatal("original deadline changed")
			}
		})
	}
}

func TestMaintenanceConflictDiscardsEarlierLeaseCandidates(t *testing.T) {
	r, originalID, target, process, _ := matrixConflictRig(t, "aws-bgp-ipv4-v1", true)
	original := r.c.active[originalID]
	var originalMaterial, thirdMaterial RuntimeMaterial
	for _, m := range r.materials {
		if m.Manifest.ConnectionID == originalID {
			originalMaterial = m
		}
		if _, live := r.c.active[m.Manifest.ConnectionID]; live && m.Manifest.ConnectionID != originalID && m.Manifest.ConnectionID != target.Manifest.ConnectionID {
			thirdMaterial = m
		}
	}
	if thirdMaterial.ID == uuid.Nil {
		t.Fatal("missing independently admitted transport owner")
	}
	third := r.c.active[thirdMaterial.Manifest.ConnectionID]
	before := map[string]time.Duration{}
	for key, deadline := range r.installed {
		before[key] = deadline
	}
	base, calls, published := r.c.client, []uuid.UUID{}, 0
	r.c.client = maintenanceLeaseFunc(func(ctx context.Context, id uuid.UUID, request RuntimeLeaseRequest) (RuntimeLease, error) {
		calls = append(calls, id)
		if id == target.Manifest.ConnectionID {
			return RuntimeLease{}, testLeaseFailure("http_409_conflict")
		}
		return base.RenewIPsecLease(ctx, id, request)
	})
	results, err := r.c.maintainIPsecRuntimeObserved(context.Background(), []RuntimeMaterial{originalMaterial, thirdMaterial, target}, maintenanceAuthority(r), func() bool { return true }, func(context.Context, RuntimeDelivery, RuntimeStatusReport) error { published++; return nil })
	var aborted interface{ IPsecMaintenanceBatchAborted() bool }
	if !errors.As(err, &aborted) || !aborted.IPsecMaintenanceBatchAborted() || len(results) != 0 || published != 0 || !reflect.DeepEqual(calls, []uuid.UUID{originalID, thirdMaterial.Manifest.ConnectionID, target.Manifest.ConnectionID}) {
		t.Fatalf("candidate batch escaped: err=%v results=%d published=%d calls=%v", err, len(results), published, calls)
	}
	if process.closed || r.c.active[originalID].Authority != original.Authority || r.c.active[thirdMaterial.Manifest.ConnectionID].Authority != third.Authority {
		t.Fatal("unrelated candidate replaced or closed original authority")
	}
	for _, id := range []uuid.UUID{originalID, thirdMaterial.Manifest.ConnectionID} {
		for _, name := range []string{guardLeaseName(id), guardReplyLeaseName(id), guardSALeaseName(id)} {
			if r.installed[name] != before[name] {
				t.Fatal("earlier candidate extended native authority")
			}
		}
	}
}

func TestMaintenanceConflictTargetCleanupCannotOutliveOtherAuthority(t *testing.T) {
	r, originalID, target, _, _ := matrixConflictRig(t, "aws-bgp-ipv4-v1")
	original := r.c.active[originalID]
	targetActive := r.c.active[target.Manifest.ConnectionID]
	r.c.bgpDesktopExports[target.ID] = []netip.Prefix{netip.MustParsePrefix("10.99.0.8/32")}
	targetProcess := r.c.bgpProcesses[target.ID].(*bgpSessionFixture)
	priorClose := targetProcess.close
	targetProcess.close = func() { priorClose(); *r.now = original.Authority.deadline + time.Second }
	if err := r.c.withdrawMaintenanceConflict(context.Background(), targetActive, r.entries, func() bool { return true }); err == nil {
		t.Fatal("target cleanup consumed unrelated authority but scoped abort remained permitted")
	}
	if !targetProcess.closed || !r.applicationDenied[target.Manifest.ConnectionID] {
		t.Fatal("target cleanup was not deny-first")
	}
}
