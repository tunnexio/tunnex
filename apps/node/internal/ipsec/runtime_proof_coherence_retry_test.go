package ipsec

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Uses the existing exact owned deleted-CHILD/native-pair fixture. These are
// injected independent reader observations, not Linux or cloud acceptance.
type proofCoherenceRig struct {
	c                      *RuntimeController
	e                      RuntimeJournalEntry
	env                    RuntimeEnvironment
	d                      []DaemonInventory
	x                      []XFRMInventory
	k                      KernelInventory
	xReads, dReads, kReads int
	mutateX                func(int, *XFRMInventory)
	mutateK                func(int, *KernelInventory)
	mutateD                func(int, *DaemonInventory)
	afterX                 func(int)
	diagnostics            []RuntimeDiagnostic
}

func newProofCoherenceRig(t *testing.T, churn bool) *proofCoherenceRig {
	t.Helper()
	e, beforeD, k, beforeX := rekeyHandoverFixture()
	afterD := beforeD
	afterD.SAs = append([]DaemonIKE(nil), beforeD.SAs...)
	afterD.SAs[0].Children = append([]DaemonChild(nil), beforeD.SAs[0].Children[1:]...)
	afterX := beforeX
	afterX.States = append([]XFRMState(nil), beforeX.States[1:]...)
	if runtimeInventoryMatches(e, beforeD, k, beforeX) != nil || runtimeInventoryMatches(e, afterD, k, afterX) != nil {
		t.Fatal("both rekey endpoints must independently satisfy the original proof")
	}
	r := &proofCoherenceRig{e: e, k: k, env: RuntimeEnvironment{Namespace: e.Allocation.Namespace}}
	r.d = []DaemonInventory{beforeD, afterD, afterD, afterD}
	r.x = []XFRMInventory{beforeX, afterX, afterX, afterX}
	if churn {
		r.d[2], r.x[2] = beforeD, beforeX
	}
	r.c = &RuntimeController{config: RuntimeControllerConfig{
		OrgID: e.Engines[0].Binding.OrgID, GatewayID: e.Engines[0].Binding.GatewayID,
		DaemonAlive: func() bool { return true }, Environment: &mtuEnvironmentFixture{env: r.env},
		Diagnostic: func(d RuntimeDiagnostic) { r.diagnostics = append(r.diagnostics, d) },
	}}
	return r
}

func (r *proofCoherenceRig) readers(t *testing.T, expected context.Context) runtimeStatusReaders {
	t.Helper()
	check := func(ctx context.Context) {
		if ctx != expected {
			t.Fatal("whole retry changed the original caller context")
		}
		want, ok := expected.Deadline()
		got, same := ctx.Deadline()
		if !ok || !same || got != want {
			t.Fatal("whole retry changed the original caller deadline")
		}
	}
	return runtimeStatusReaders{
		xfrm: func(ctx context.Context) (XFRMInventory, error) {
			check(ctx)
			r.xReads++
			if r.xReads > len(r.x) {
				t.Fatal("more than two complete attempts")
			}
			x := r.x[r.xReads-1]
			x.States = append([]XFRMState(nil), x.States...)
			x.Policies = append([]XFRMPolicy(nil), x.Policies...)
			if r.mutateX != nil {
				r.mutateX(r.xReads, &x)
			}
			if r.afterX != nil {
				r.afterX(r.xReads)
			}
			return x, nil
		},
		daemon: func(ctx context.Context) (DaemonInventory, error) {
			check(ctx)
			r.dReads++
			d := r.d[r.xReads-1]
			d.SAs = append([]DaemonIKE(nil), d.SAs...)
			if r.mutateD != nil {
				r.mutateD(r.dReads, &d)
			}
			return d, nil
		},
		kernel: func(ctx context.Context) (KernelInventory, error) {
			check(ctx)
			r.kReads++
			k := r.k
			k.Links = append([]KernelLink(nil), k.Links...)
			k.Routes = append([]KernelRoute(nil), k.Routes...)
			if r.mutateK != nil {
				r.mutateK(r.kReads, &k)
			}
			return k, nil
		},
	}
}

func TestRuntimeProofOwnedRekeyMovementRetriesWholeProof(t *testing.T) {
	r := newProofCoherenceRig(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := r.c.proveRuntimeWithReaders(ctx, r.e, r.env, r.readers(t, ctx)); err != nil {
		t.Fatal("valid owned rekey settles within the original context but was refused", err)
	}
	if r.xReads != 4 || r.dReads != 4 || r.kReads != 4 {
		t.Fatal("second attempt reused first-attempt native data", r.xReads, r.dReads, r.kReads)
	}
	if len(r.diagnostics) != 1 || r.diagnostics[0].Stage != "native_xfrm_after_equal" || !r.diagnostics[0].Refused {
		t.Fatal("first attempt's genuine coherence refusal was not retained", r.diagnostics)
	}
}

func TestRuntimeProofContinuousOwnedChurnFailsClosed(t *testing.T) {
	r := newProofCoherenceRig(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := r.c.proveRuntimeWithReaders(ctx, r.e, r.env, r.readers(t, ctx)); err != ErrRuntimeController {
		t.Fatal("continuous movement escaped the public refusal contract", err)
	}
	if r.xReads != 4 || r.dReads != 4 || r.kReads != 4 || len(r.diagnostics) != 2 {
		t.Fatal("continuous movement exceeded or skipped complete attempts", r.xReads, r.dReads, r.kReads, r.diagnostics)
	}
}

func TestRuntimeProofOnlyQualifiedMovementRetries(t *testing.T) {
	for _, scenario := range []string{"after namespace", "after foreign reqid", "after foreign ifid", "after unknown SPI", "after missing active pair", "after kernel route", "after daemon owner", "environment", "second before foreign", "canceled movement", "reader error", "expired context"} {
		t.Run(scenario, func(t *testing.T) {
			r := newProofCoherenceRig(t, false)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			wantReads := 2
			switch scenario {
			case "after namespace":
				r.mutateX = func(n int, x *XFRMInventory) {
					if n == 2 {
						x.Namespace = "net:[1234]"
					}
				}
			case "after foreign reqid", "after foreign ifid", "after unknown SPI":
				r.mutateX = func(n int, x *XFRMInventory) {
					if n != 2 {
						return
					}
					s := x.States[0]
					if scenario == "after foreign reqid" {
						s.ReqID++
					} else if scenario == "after foreign ifid" {
						s.IfID++
					} else {
						s.SPI++
					}
					x.States = append(x.States, s)
				}
			case "after missing active pair":
				r.mutateX = func(n int, x *XFRMInventory) {
					if n == 2 {
						x.States = x.States[:len(x.States)-1]
					}
				}
			case "after kernel route":
				r.mutateK = func(n int, k *KernelInventory) {
					if n == 2 {
						k.Routes[0].Metric++
					}
				}
			case "after daemon owner":
				r.mutateD = func(n int, d *DaemonInventory) {
					if n == 2 {
						d.SAs[0].RemoteAddress = d.SAs[0].RemoteAddress.Next()
					}
				}
			case "environment":
				changed := r.env
				changed.Namespace = "net:[1234]"
				r.c.config.Environment = &mtuEnvironmentFixture{env: changed}
				wantReads = 1
			case "second before foreign":
				r.mutateX = func(n int, x *XFRMInventory) {
					if n == 3 {
						x.States[0].ReqID++
					}
				}
				wantReads = 3
			case "canceled movement":
				r.afterX = func(n int) {
					if n == 2 {
						cancel()
					}
				}
			case "reader error":
				wantReads = 1
			case "expired context":
				cancel()
				wantReads = 0
			}
			readers := r.readers(t, ctx)
			if scenario == "reader error" {
				read := readers.xfrm
				readers.xfrm = func(call context.Context) (XFRMInventory, error) {
					_, _ = read(call)
					return XFRMInventory{}, ErrXFRMRead
				}
			}
			if err := r.c.proveRuntimeWithReaders(ctx, r.e, r.env, readers); err != ErrRuntimeController {
				t.Fatal("unsafe observation escaped the public refusal contract", err)
			}
			if r.xReads != wantReads {
				t.Fatal("non-coherence refusal was retried or prior data reused", r.xReads, wantReads)
			}
		})
	}
}

func TestRuntimeProofStableSnapshotNeedsOneAttempt(t *testing.T) {
	r := newProofCoherenceRig(t, false)
	r.d[0], r.x[0] = r.d[1], r.x[1]
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := r.c.proveRuntimeWithReaders(ctx, r.e, r.env, r.readers(t, ctx)); err != nil || r.xReads != 2 || r.dReads != 2 || r.kReads != 2 || len(r.diagnostics) != 0 {
		t.Fatal("stable original proof behavior changed", err, r.xReads, r.dReads, r.kReads, r.diagnostics)
	}
}

func TestRuntimeProofRetryCannotRestoreExpiredLease(t *testing.T) {
	r := newProofCoherenceRig(t, false)
	authority, now, id := leaseFixture()
	id.Binding, id.DeliveryID = r.e.Engines[0].Binding, r.e.DeliveryID
	// Same canonical-hash lease identity fixture as TestPermitLeaseCanonicalPolicyHashIdentity.
	id.PolicyHash = strings.Repeat("a", 64)
	request, err := authority.Begin(id)
	if err != nil || authority.Accept(PermitLeaseResponse{request, 60000}) != nil {
		t.Fatal("lease fixture", err)
	}
	r.afterX = func(n int) {
		if n == 3 {
			*now = 61 * time.Second
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r.c.qualification = testRuntimeQualification(r.e.Allocation.Namespace)
	r.c.namespace = func() (string, error) { return r.e.Allocation.Namespace, nil }
	j, err := OpenRuntimeJournal(journalDir(t), r.c.config.GatewayID)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	r.c.journal = j
	for _, phase := range []RuntimePhase{RuntimeReserved, RuntimeApplying, RuntimeApplied} {
		r.e.Phase = phase
		if err = j.Save([]RuntimeJournalEntry{r.e}); err != nil {
			t.Fatal("original durable reservation/apply progression", phase, err)
		}
	}
	r.c.active = map[uuid.UUID]runtimeActive{r.e.Allocation.ConnectionID: {Entry: r.e, Environment: r.env, Authority: authority, Identity: id}}
	r.c.prove = func(call context.Context, e RuntimeJournalEntry, env RuntimeEnvironment) error {
		if !reflect.DeepEqual(e, r.e) || !reflect.DeepEqual(env, r.env) {
			t.Fatal("active owner changed")
		}
		return r.c.proveRuntimeWithReaders(call, e, env, r.readers(t, call))
	}
	var installed []GuardIntent
	r.c.replace = func(_ context.Context, intent GuardIntent) (GuardManifest, error) {
		installed = append(installed, intent)
		return GuardManifest{}, nil
	}
	if err = r.c.installActive(ctx, []RuntimeJournalEntry{r.e}); err != nil {
		t.Fatal("expired owner should install the original deny-only projection", err)
	}
	if r.xReads != 4 || len(r.c.active) != 0 || len(installed) != 1 || len(installed[0].Connections) != 1 || !installed[0].Connections[0].PrefixOnly {
		t.Fatal("native retry resurrected expired forwarding authority", r.xReads, len(r.c.active), installed)
	}
	if _, err = authority.RemainingForApply(id, 5*time.Second); err == nil {
		t.Fatal("expired lease was extended")
	}
}
