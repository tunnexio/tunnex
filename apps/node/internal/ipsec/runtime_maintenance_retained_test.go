package ipsec

import (
	"context"
	"errors"
	"maps"
	"reflect"
	"testing"
	"time"
)

func TestMaintenanceNotDueReturnsValidatedRetention(t *testing.T) {
	r, client := fqdnMultiOwnerCadenceRig(t)
	before := assemblyClone(r.c.active)
	clocks := maps.Clone(r.c.recoveryReportClocks)
	replaced := 0
	replace := r.c.replace
	r.c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) { replaced++; return replace(ctx, in) }
	results, err := r.c.maintainIPsecRuntime(context.Background(), r.materials, maintenanceAuthority(r), func() bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != len(before) || client.requests != 0 || replaced != 0 {
		t.Fatal("not-due owner did not retain exact authority", len(results), client.requests, replaced)
	}
	for _, out := range results {
		if out.Retained == nil || out.Deferred != nil || out.Acknowledgement != (RuntimeAcknowledgement{}) || !reflect.DeepEqual(out.Report, RuntimeStatusReport{}) {
			t.Fatal("fully proven not-due owners force independent Validate instead of validated retention")
		}
	}
	if !reflect.DeepEqual(before, r.c.active) || !reflect.DeepEqual(clocks, r.c.recoveryReportClocks) {
		t.Fatal("retained original authority changed")
	}
}

func TestMaintenancePartialPageDoesNotClaimGlobalRetention(t *testing.T) {
	r, client := fqdnMultiOwnerCadenceRig(t)
	before := assemblyClone(r.c.active)
	results, err := r.c.maintainIPsecRuntime(context.Background(), r.materials[:1], maintenanceAuthority(r), func() bool { return true })
	if err != nil || len(results) != 1 || results[0].Retained != nil || results[0].Deferred == nil || results[0].Acknowledgement != (RuntimeAcknowledgement{}) || !reflect.DeepEqual(results[0].Report, RuntimeStatusReport{}) || client.requests != 0 || !reflect.DeepEqual(before, r.c.active) {
		t.Fatal("partial normal page bypassed independent validation", err)
	}
}

// Call the read-only final fence after the same fixture's complete native seed.
// The final read itself invalidates a previously eligible owner's evidence: the
// fence must reject without rewriting authority or inventing a status clock.
func TestMaintenanceRetainedFinalReadRechecksWholeOwnerSet(t *testing.T) {
	for _, mode := range []string{"control", "authority-expired-during-read", "fqdn-expired-during-read", "current-owner-mutated", "guard-drift", "read-failed", "cancel-during-read", "daemon-lost", "bgp-qualification-lost", "partial-owners"} {
		t.Run(mode, func(t *testing.T) {
			r, client := fqdnMultiOwnerCadenceRig(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			owners := assemblyClone(r.c.active)
			clocks := maps.Clone(r.c.recoveryReportClocks)
			replacements := 0
			r.c.replace = func(context.Context, GuardIntent) (GuardManifest, error) {
				replacements++
				return GuardManifest{}, errors.New("unexpected mutation")
			}
			reads := 0
			run := r.c.guard.reader.run
			bgpOK := true
			r.c.guard.reader.run = func(ctx context.Context, args ...string) ([]byte, error) {
				raw, err := run(ctx, args...)
				reads++
				switch mode {
				case "authority-expired-during-read":
					*r.now += time.Minute
				case "fqdn-expired-during-read":
					*r.now += 24 * time.Second
				case "current-owner-mutated":
					for id, a := range r.c.active {
						a.Identity.PolicyHash = "changed"
						r.c.active[id] = a
						break
					}
				case "guard-drift":
					return []byte(`{"nftables":[]}`), nil
				case "read-failed":
					return nil, errors.New("native read failed")
				case "cancel-during-read":
					cancel()
				case "daemon-lost":
					r.c.config.DaemonAlive = func() bool { return false }
				case "bgp-qualification-lost":
					bgpOK = false
				}
				return raw, err
			}
			if mode == "partial-owners" {
				for id := range owners {
					delete(owners, id)
					break
				}
			}
			err := r.c.retainedMaintenanceCurrent(ctx, owners, func() bool { return bgpOK })
			if mode == "control" {
				if err != nil || reads != 1 {
					t.Fatal("unchanged proof failed", err, reads)
				}
			} else if err == nil {
				t.Fatal("invalid final proof accepted")
			}
			if mode != "partial-owners" && reads == 0 {
				t.Fatal("test did not cross final native read")
			}
			if replacements != 0 || client.requests != 0 || !reflect.DeepEqual(clocks, r.c.recoveryReportClocks) {
				t.Fatal("retained fence fabricated authority or observation")
			}
			if mode != "current-owner-mutated" && mode != "partial-owners" && !reflect.DeepEqual(owners, r.c.active) {
				t.Fatal("final fence mutated original owners")
			}
		})
	}
}
