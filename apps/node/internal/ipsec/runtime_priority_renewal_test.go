package ipsec

import (
	"context"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"
)

func priorityRenewalWindow(t *testing.T) (*renewalCycleRig, []RuntimeMaterial) {
	t.Helper()
	r, _ := maintainedMissingStandby(t, 2)
	materials := maintenanceMaterials(r)
	sort.Slice(materials, func(i, j int) bool {
		return materials[i].Manifest.ConnectionID.String() < materials[j].Manifest.ConnectionID.String()
	})
	earliest := time.Duration(1<<63 - 1)
	for _, end := range r.installed {
		if end < earliest {
			earliest = end
		}
	}
	if earliest-*r.now <= 20*time.Second {
		t.Fatal("initial genuine native deadline too short")
	}
	r.charge("forward_to_caller_window", earliest-*r.now-20*time.Second)
	return r, materials
}

func allPriorityMembersLive(r *renewalCycleRig) bool {
	if len(r.c.active) != 5 {
		return false
	}
	for id := range r.c.active {
		for _, name := range []string{guardLeaseName(id), guardReplyLeaseName(id), guardSALeaseName(id)} {
			if end, ok := r.installed[name]; !ok || end <= *r.now {
				return false
			}
		}
	}
	return true
}

// The baseline and priority arms enter with the same real 20s rendered window.
// Optional IO costs 12s in both arms. Only its position changes. Neither arm
// alters a lease TTL, a reserve, a timeout or an existing rendered deadline.
func TestPriorityActiveRenewalCallerContinuity(t *testing.T) {
	for _, priority := range []bool{false, true} {
		t.Run(fmt.Sprintf("priority_%t", priority), func(t *testing.T) {
			r, materials := priorityRenewalWindow(t)
			start := *r.now
			commits := 0
			lapse := false
			firstCommit := time.Duration(0)
			recoveryCallbacks := 0
			beforeFirstCommitCallbacks := 0
			check := func() {
				if !allPriorityMembersLive(r) {
					lapse = true
				}
			}
			proof := r.c.prove
			r.c.prove = func(ctx context.Context, e RuntimeJournalEntry, env RuntimeEnvironment) error {
				err := proof(ctx, e, env)
				check()
				return err
			}
			observe := r.c.recoveryObserve
			r.c.recoveryObserve = func(ctx context.Context, e RuntimeJournalEntry) [2]string {
				out := observe(ctx, e)
				check()
				return out
			}
			replace := r.c.replace
			r.c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
				positive := 0
				for _, g := range in.Connections {
					if !g.PrefixOnly {
						positive++
					}
				}
				if positive > 0 {
					check()
					if commits == 0 {
						firstCommit = *r.now - start
						beforeFirstCommitCallbacks = recoveryCallbacks
					}
				}
				out, err := replace(ctx, in)
				if err == nil && positive > 0 {
					commits++
				}
				return out, err
			}
			publish := func(context.Context, RuntimeDelivery, RuntimeStatusReport) error { return nil }
			pulse := func(context.Context, RuntimeRecoveryHeartbeat) error { recoveryCallbacks++; check(); return nil }
			optional := func() { r.charge("unchanged_optional_status_discovery_material", 12*time.Second); check() }
			rounds := 1
			if priority {
				rounds = 2
			}
			for cycle := 0; cycle < rounds; cycle++ {
				old := map[*PermitLeaseAuthority]time.Duration{}
				for _, a := range r.c.active {
					old[a.Authority] = a.Authority.deadline
				}
				if !priority {
					optional()
				}
				r.phase = "maintenance"
				var err error
				if priority {
					err = r.c.renewActiveIPsecRuntimeObserved(context.Background(), maintenanceAuthority(r), func() bool { return true }, publish, pulse)
				} else {
					_, err = runActiveCadenceMaintenance(r, materials, publish, pulse)
				}
				r.phase = ""
				for a, d := range old {
					if a.deadline != d {
						t.Fatal("original CP deadline changed")
					}
				}
				if priority {
					if err != nil || !allPriorityMembersLive(r) {
						t.Fatalf("priority cycle%d refused/lapsed: %v", cycle, err)
					}
					optional()
					if !allPriorityMembersLive(r) {
						t.Fatal("postrenewal optional IO lapsed finite member")
					}
					// The original authoritative page maintenance still runs
					// after discovery/material IO. Include its real charged
					// callbacks/proofs/commit, not a cached success or ACK.
					r.phase = "maintenance"
					normalResults, normalErr := runActiveCadenceMaintenance(r, materials, publish, pulse)
					r.phase = ""
					check()
					if normalErr != nil || len(normalResults) != 5 || !allPriorityMembersLive(r) {
						t.Fatal("ordinary pass after priority renewal refused/lapsed", normalErr, len(normalResults))
					}

				} else if err == nil && allPriorityMembersLive(r) && !lapse {
					t.Fatal("baseline must expose late arrival native loss")
				}
			}
			t.Logf("priority=%t elapsed=%s firstCommit=%s commits=%d recoveryCallbacksBeforeCommit=%d totalCallbacks=%d all15Live=%t lapse=%t freshNonces=%d costs=%v", priority, *r.now-start, firstCommit, commits, beforeFirstCommitCallbacks, recoveryCallbacks, allPriorityMembersLive(r), lapse, len(r.nonces), r.charged)
			if priority && (lapse || commits != 4 || beforeFirstCommitCallbacks == 0) {
				t.Fatal("priority lost continuity or original early callback ordering")
			}
			if !priority && !lapse {
				t.Fatal("baseline did not reproduce finite loss")
			}
		})
	}
}

type priorityRejectedLease struct {
	base   RuntimeLeaseClient
	mutate string
	calls  *int
}

func (l priorityRejectedLease) RenewIPsecLease(ctx context.Context, id uuid.UUID, q RuntimeLeaseRequest) (RuntimeLease, error) {
	*l.calls++
	if l.mutate == "cleanup" || l.mutate == "revision" || l.mutate == "policy" || l.mutate == "disabled" || l.mutate == "rpc" {
		return RuntimeLease{}, ErrRuntimeController
	}
	out, err := l.base.RenewIPsecLease(ctx, id, q)
	if l.mutate == "nonce" {
		out.Nonce = "wrong"
	}
	return out, err
}

func TestPriorityActiveRenewalRefusesUntrustedCurrentAuthority(t *testing.T) {
	for _, kind := range []string{"cleanup", "revision", "policy", "disabled", "rpc", "nonce", "delivery", "journal", "cancel", "native"} {
		t.Run(kind, func(t *testing.T) {
			r, _ := priorityRenewalWindow(t)
			calls, positive := 0, 0
			base := r.c.client
			r.c.client = priorityRejectedLease{base: base, mutate: kind, calls: &calls}
			switch kind {
			case "delivery":
				for id, a := range r.c.active {
					a.Delivery.OwnershipDigest = "bad"
					r.c.active[id] = a
					break
				}
			case "journal":
				for id, a := range r.c.active {
					a.Entry.SiteID = uuid.New()
					r.c.active[id] = a
					break
				}
			case "native":
				r.c.prove = func(context.Context, RuntimeJournalEntry, RuntimeEnvironment) error { return ErrRuntimeController }
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if kind == "cancel" {
				cancel()
			}
			replace := r.c.replace
			r.c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
				for _, g := range in.Connections {
					if !g.PrefixOnly {
						positive++
					}
				}
				return replace(ctx, in)
			}
			r.phase = "maintenance"
			err := r.c.renewActiveIPsecRuntimeObserved(ctx, maintenanceAuthority(r), func() bool { return true }, nil, nil)
			r.phase = ""
			if positive != 0 {
				t.Fatal("refused/stale authority renewed finite native permits", kind)
			}
			if kind != "journal" && kind != "native" && err == nil {
				t.Fatal("invalid current authority not refused", kind)
			}
			if (kind == "delivery" || kind == "cancel") && calls != 0 {
				t.Fatal("invalid input reached CP", kind)
			}
			t.Logf("kind=%s CPcalls=%d positiveNativeCommits=%d active=%d err=%v", kind, calls, positive, len(r.c.active), err)
		})
	}
}

// Count actual finite native permit publications, even for zero app-grant owners.
// A callback failure must withdraw, never publish a candidate before the refusal.
func TestPriorityActiveCallbackCannotPublishFinitePermits(t *testing.T) {
	for _, kind := range []string{"error", "revoke", "replace", "expired"} {
		t.Run(kind, func(t *testing.T) {
			r, _ := priorityRenewalWindow(t)
			commits, callbacks := 0, 0
			replace := r.c.replace
			r.c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
				for _, g := range in.Connections {
					if !g.PrefixOnly {
						commits++
					}
				}
				return replace(ctx, in)
			}
			r.phase = "maintenance"
			err := r.c.renewActiveIPsecRuntimeObserved(context.Background(), maintenanceAuthority(r), func() bool { return true }, nil, func(_ context.Context, out RuntimeRecoveryHeartbeat) error {
				callbacks++
				id := out.ConnectionID
				switch kind {
				case "error":
					return ErrRuntimeController
				case "revoke":
					r.c.active[id].Authority.Invalidate()
				case "replace":
					delete(r.c.active, id)
				case "expired":
					r.charge("callback_expiration", 61*time.Second)
				}
				return nil
			})
			r.phase = ""
			if err == nil || callbacks != 1 || commits != 0 || len(r.c.active) != 0 {
				t.Fatal("callback failure published finite native authority", kind, err, callbacks, commits, len(r.c.active))
			}
			t.Logf("kind=%s callbacks=%d finiteNativeCommits=%d active=%d", kind, callbacks, commits, len(r.c.active))
		})
	}
}
