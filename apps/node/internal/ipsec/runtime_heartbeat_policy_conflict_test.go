package ipsec

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// A normal maintenance pulse renews only telemetry authority. A typed target
// policy conflict must deny that target without killing unrelated BGP exports.
func TestMaintenanceHeartbeatPolicyConflictPreservesUnrelatedBGP(t *testing.T) {
	r, originalID, target, process, flushes := matrixConflictRig(t, "aws-static-ipv4-v1")
	targetID := target.Manifest.ConnectionID
	original := cloneMaintenanceActive(r.c.active[originalID])
	deadline := original.Authority.deadline
	native := map[string]time.Duration{}
	for _, name := range []string{guardLeaseName(originalID), guardReplyLeaseName(originalID), guardSALeaseName(originalID)} {
		native[name] = r.installed[name]
	}
	before, seq, err := r.c.journal.guardTemplates()
	if err != nil {
		t.Fatal(err)
	}
	originalEpoch, targetEpoch := &runtimeDNSEpoch{}, &runtimeDNSEpoch{}
	r.c.dnsView.Store(&runtimeDNSOwnerView{entries: map[uuid.UUID]runtimeDNSOwnerEntry{
		originalID: {active: original, epoch: originalEpoch},
		targetID:   {active: r.c.active[targetID], epoch: targetEpoch},
	}})
	calls, published := 0, 0
	r.c.client = maintenanceLeaseFunc(func(_ context.Context, id uuid.UUID, req RuntimeLeaseRequest) (RuntimeLease, error) {
		calls++
		if id != targetID || req.DeliveryID != target.ID || req.PolicyHash != r.c.active[targetID].Identity.PolicyHash {
			t.Fatal("conflict was not the exact static heartbeat owner")
		}
		return RuntimeLease{}, testLeaseFailure("http_409_conflict")
	})
	r.charge("heartbeat_due", 2*time.Second)
	results, err := runActiveCadenceMaintenance(r, []RuntimeMaterial{target}, nil, func(context.Context, RuntimeRecoveryHeartbeat) error { published++; return nil })
	var aborted interface{ IPsecMaintenanceBatchAborted() bool }
	if !errors.As(err, &aborted) || !aborted.IPsecMaintenanceBatchAborted() || !errors.Is(err, ErrRuntimeController) || len(results) != 0 || calls != 1 || published != 0 {
		t.Errorf("heartbeat conflict escaped scoped page abort: err=%v results=%d calls=%d published=%d", err, len(results), calls, published)
	}
	if *flushes != 1 || !r.applicationDenied[targetID] || r.c.active[targetID].Authority != nil {
		t.Errorf("target not exactly withdrawn: flushes=%d denied=%v", *flushes, r.applicationDenied[targetID])
	}
	if !reflect.DeepEqual(r.c.active[originalID], original) || process.closed || r.c.bgpProcesses[original.Entry.DeliveryID] != process || r.applicationDenied[originalID] || original.Authority.deadline != deadline {
		t.Error("target heartbeat conflict changed unrelated original authority/process")
	}
	for name, want := range native {
		if r.installed[name] != want {
			t.Error("unrelated native deadline changed", name)
		}
	}
	after, afterSeq, _ := r.c.journal.guardTemplates()
	if !reflect.DeepEqual(before, after) || seq != afterSeq {
		t.Error("shared journal changed")
	}
	view := r.c.dnsView.Load()
	if view == nil || len(view.entries) != 1 || view.entries[originalID].epoch != originalEpoch || originalEpoch.revoked.Load() || !targetEpoch.revoked.Load() {
		t.Error("DNS owner withdrawal escaped target")
	}
}

func TestMaintenanceHeartbeatUnsafeConflictRemainsGlobal(t *testing.T) {
	for _, kind := range []string{"generic", "generic_409", "ineligible_409", "bad_nonce", "bad_ttl", "expired_unrelated", "missing_native", "partial_withdrawal", "post_withdrawal_expiry", "canceled", "qualification", "target_binding", "journal"} {
		t.Run(kind, func(t *testing.T) {
			r, originalID, target, process, _ := matrixConflictRig(t, "aws-static-ipv4-v1")
			targetID := target.Manifest.ConnectionID
			original := r.c.active[originalID]
			deadline := original.Authority.deadline
			apply, injected := r.c.guard.apply, false
			if kind == "partial_withdrawal" || kind == "post_withdrawal_expiry" || kind == "journal" {
				r.c.guard.apply = func(ctx context.Context, raw []byte) error {
					injected = true
					if kind == "partial_withdrawal" {
						r.installed[guardLeaseName(targetID)] = 0
						return ErrGuardRead
					}
					if err := apply(ctx, raw); err != nil {
						return err
					}
					if kind == "post_withdrawal_expiry" {
						*r.now = deadline + time.Second
					}
					if kind == "journal" {
						return r.c.journal.Save(r.entries)
					}
					return nil
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			qualified, calls := true, 0
			r.c.client = maintenanceLeaseFunc(func(_ context.Context, id uuid.UUID, req RuntimeLeaseRequest) (RuntimeLease, error) {
				calls++
				if id != targetID {
					t.Fatal("wrong heartbeat owner")
				}
				switch kind {
				case "generic":
					return RuntimeLease{}, errors.New("unclassified")
				case "generic_409":
					return RuntimeLease{}, testLeaseFailure("http_409")
				case "ineligible_409":
					return RuntimeLease{}, testLeaseFailure("http_409_ineligible")
				case "bad_nonce", "bad_ttl":
					lease := RuntimeLease{RuntimeLeaseRequest: req, TTLMS: 60000}
					if kind == "bad_nonce" {
						lease.Nonce = strings.Repeat("f", 64)
					} else {
						lease.TTLMS = 0
					}
					return lease, nil
				case "expired_unrelated":
					*r.now = deadline + time.Second
				case "missing_native":
					r.installed[guardLeaseName(originalID)] = 0
				case "canceled":
					cancel()
				case "qualification":
					qualified = false
				case "target_binding":
					a := r.c.active[id]
					a.Identity.PolicyHash = strings.Repeat("c", 64)
					r.c.active[id] = a
				}
				return RuntimeLease{}, testLeaseFailure("http_409_conflict")
			})
			r.charge("heartbeat_due", 2*time.Second)
			result, err := r.c.maintainIPsecRuntimeRecoveryObserved(ctx, []RuntimeMaterial{target}, maintenanceAuthority(r), func() bool { return qualified }, nil, func(context.Context, RuntimeRecoveryHeartbeat) error { t.Fatal("failed pulse published"); return nil })
			var aborted interface{ IPsecMaintenanceBatchAborted() bool }
			if !errors.Is(err, ErrRuntimeController) || errors.As(err, &aborted) || len(result) != 0 || calls != 1 || len(r.c.active) != 0 || !process.closed || !r.applicationDenied[originalID] || !r.applicationDenied[targetID] {
				t.Fatalf("unsafe heartbeat failure did not globally deny: err=%v result=%d calls=%d active=%d", err, len(result), calls, len(r.c.active))
			}
			if original.Authority.deadline != deadline {
				t.Fatal("unrelated deadline extended")
			}
			if (kind == "partial_withdrawal" || kind == "post_withdrawal_expiry" || kind == "journal") && !injected {
				t.Fatal("native injection not reached")
			}
		})
	}
}

func TestMaintenanceHeartbeatConflictCannotAbandonPendingDenial(t *testing.T) {
	r, originalID, target, process, _ := matrixConflictRig(t, "aws-static-ipv4-v1")
	var original RuntimeMaterial
	for _, m := range r.materials {
		if m.Manifest.ConnectionID == originalID {
			original = m
		}
	}
	original.Policy.Hash = strings.Repeat("c", 64)
	targetID := target.Manifest.ConnectionID
	r.c.recoveryHistory[targetID].lastNow = *r.now
	earlierDenied, calls := false, 0
	r.c.config.Diagnostic = func(d RuntimeDiagnostic) {
		if d.Operation == "maintenance_eligibility" && d.ConnectionID == originalID && d.Refused {
			earlierDenied = true
			r.charge("next_heartbeat_due", 2*time.Second)
		}
	}
	r.c.client = maintenanceLeaseFunc(func(_ context.Context, id uuid.UUID, _ RuntimeLeaseRequest) (RuntimeLease, error) {
		calls++
		if id != targetID || !earlierDenied {
			t.Fatal("heartbeat did not follow pending original denial")
		}
		return RuntimeLease{}, testLeaseFailure("http_409_conflict")
	})
	result, err := runActiveCadenceMaintenance(r, []RuntimeMaterial{original, target}, nil, func(context.Context, RuntimeRecoveryHeartbeat) error { t.Fatal("failed pulse published"); return nil })
	var aborted interface{ IPsecMaintenanceBatchAborted() bool }
	if !earlierDenied || calls != 1 || err == nil || errors.As(err, &aborted) || len(result) != 0 || len(r.c.active) != 0 || !process.closed || !r.applicationDenied[originalID] {
		t.Fatal("pending original denial escaped scoped heartbeat abort", earlierDenied, calls, err, len(result), len(r.c.active))
	}
}

func TestMaintenanceHeartbeatConflictAfterNativeCommitRemainsGlobal(t *testing.T) {
	r, originalID, target, process, _ := matrixConflictRig(t, "aws-static-ipv4-v1")
	targetID := target.Manifest.ConnectionID
	base, replace := r.c.client, r.c.replace
	committed, conflicts := false, 0
	r.c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
		m, err := replace(ctx, in)
		if err == nil {
			committed = true
			r.charge("post_commit_heartbeat_due", 2*time.Second)
		}
		return m, err
	}
	r.c.client = maintenanceLeaseFunc(func(ctx context.Context, id uuid.UUID, req RuntimeLeaseRequest) (RuntimeLease, error) {
		if committed {
			conflicts++
			if id != targetID {
				t.Fatal("wrong committed heartbeat owner")
			}
			return RuntimeLease{}, testLeaseFailure("http_409_conflict")
		}
		return base.RenewIPsecLease(ctx, id, req)
	})
	result, err := runActiveCadenceMaintenance(r, []RuntimeMaterial{target}, nil, func(context.Context, RuntimeRecoveryHeartbeat) error { return nil })
	var aborted interface{ IPsecMaintenanceBatchAborted() bool }
	if !committed || conflicts != 1 || err == nil || errors.As(err, &aborted) || len(result) != 0 || len(r.c.active) != 0 || !process.closed || !r.applicationDenied[originalID] {
		t.Fatal("post-commit conflict escaped full refusal", committed, conflicts, err, len(result), len(r.c.active))
	}
}

func TestPriorityHeartbeatConflictPreservesOriginalAndAborts(t *testing.T) {
	r, originalID, target, process, flushes := matrixConflictRig(t, "aws-static-ipv4-v1")
	original := cloneMaintenanceActive(r.c.active[originalID])
	deadline := original.Authority.deadline
	calls := 0
	r.c.client = maintenanceLeaseFunc(func(_ context.Context, id uuid.UUID, _ RuntimeLeaseRequest) (RuntimeLease, error) {
		calls++
		if id != target.Manifest.ConnectionID {
			t.Fatal("wrong heartbeat owner")
		}
		return RuntimeLease{}, testLeaseFailure("http_409_conflict")
	})
	r.charge("heartbeat_due", 2*time.Second)
	err := r.c.renewActiveIPsecRuntimeObserved(context.Background(), maintenanceAuthority(r), func() bool { return true }, nil, func(context.Context, RuntimeRecoveryHeartbeat) error { t.Fatal("failed pulse published"); return nil })
	var aborted interface{ IPsecMaintenanceBatchAborted() bool }
	if !errors.As(err, &aborted) || !aborted.IPsecMaintenanceBatchAborted() || calls != 1 || *flushes != 1 || !reflect.DeepEqual(r.c.active[originalID], original) || process.closed || original.Authority.deadline != deadline || !r.applicationDenied[target.Manifest.ConnectionID] {
		t.Fatal("priority heartbeat lost exact target isolation", err, calls, *flushes)
	}
}

func TestPublicHeartbeatConflictRequiresActualBGPQualification(t *testing.T) {
	r, originalID, target, process, flushes := matrixConflictRig(t, "aws-static-ipv4-v1")
	if r.c.bgpQualificationCurrent() {
		t.Fatal("test seam must not qualify native BGP")
	}
	calls := 0
	r.c.client = maintenanceLeaseFunc(func(_ context.Context, id uuid.UUID, _ RuntimeLeaseRequest) (RuntimeLease, error) {
		calls++
		if id != target.Manifest.ConnectionID {
			t.Fatal("wrong heartbeat owner")
		}
		return RuntimeLease{}, testLeaseFailure("http_409_conflict")
	})
	r.charge("heartbeat_due", 2*time.Second)
	reports, err := r.c.RefreshIPsecActiveRecovery(context.Background())
	var aborted interface{ IPsecMaintenanceBatchAborted() bool }
	if err == nil || errors.As(err, &aborted) || len(reports) != 0 || calls != 1 || *flushes != 0 || r.c.active[target.Manifest.ConnectionID].Authority != nil || !process.closed || !r.applicationDenied[originalID] {
		t.Fatal("public heartbeat manufactured BGP qualification", err, calls, *flushes)
	}
}
