package ipsec

import (
	"context"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"
)

type fqdnSplitPublicationClient struct {
	RuntimeLeaseClient
	material map[uuid.UUID]RuntimeMaterial
	renewed  map[uuid.UUID]int
	cancel   context.CancelFunc
	first    uuid.UUID
	failID   uuid.UUID
}

func (c *fqdnSplitPublicationClient) IPsecMaterial(_ context.Context, id uuid.UUID, _ int64) (RuntimeMaterial, error) {
	if id == c.failID {
		return RuntimeMaterial{}, ErrRuntimeController
	}
	if id == c.first && c.cancel != nil {
		c.cancel()
	}
	return c.material[id], nil
}
func (c *fqdnSplitPublicationClient) RenewIPsecLease(ctx context.Context, id uuid.UUID, in RuntimeLeaseRequest) (RuntimeLease, error) {
	c.renewed[id]++
	return c.RuntimeLeaseClient.RenewIPsecLease(ctx, id, in)
}

func TestFQDNPartialFollowupValidatesUnchangedSiblingBeforeCommit(t *testing.T) {
	for _, mode := range []string{"fresh_subset", "invalid_later_sibling", "cancel_first_material", "later_fetch_error"} {
		t.Run(mode, func(t *testing.T) {
			r, base := fqdnMultiOwnerCadenceRig(t)
			r.charge("publication", 5*time.Second)
			installFQDNCadenceStatusReaders(t, r, nil)
			ids := []uuid.UUID{}
			for id, a := range r.c.active {
				if len(a.FQDNLeaseDescriptors) > 0 {
					ids = append(ids, id)
				}
			}
			sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
			if len(ids) != 2 {
				t.Fatal("fixture needs two FQDN owners")
			}
			first, unchanged := ids[0], ids[1]
			original := map[uuid.UUID]runtimeActive{}
			for id, a := range r.c.active {
				original[id] = cloneMaintenanceActive(a)
			}
			oldDeadline := r.c.fqdnNativeWindows[unchanged].deadline
			client := &fqdnSplitPublicationClient{RuntimeLeaseClient: base, material: map[uuid.UUID]RuntimeMaterial{first: base.materialAt(first, 1), unchanged: base.old[unchanged]}, renewed: map[uuid.UUID]int{}, first: first}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "invalid_later_sibling" {
				m := client.material[unchanged]
				m.Policy.Hash = stringDigest([]byte("different-policy"))
				client.material[unchanged] = m
			}
			if mode == "cancel_first_material" {
				client.cancel = cancel
			}
			if mode == "later_fetch_error" {
				client.failID = unchanged
			}
			r.c.client = client
			proofs := map[uuid.UUID]int{}
			prove := r.c.prove
			r.c.prove = func(ctx context.Context, e RuntimeJournalEntry, env RuntimeEnvironment) error {
				proofs[e.Allocation.ConnectionID]++
				return prove(ctx, e, env)
			}
			commits := 0
			replace := r.c.replace
			r.c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
				if pulseDeferralInCall("commitExactRuntimeRefresh") && !pulseDeferralInCall("refuse") {
					commits++
				}
				return replace(ctx, in)
			}
			err := r.c.followupFQDNMaintenance(ctx, maintenanceAuthority(r), func() bool { return true }, nil, nil, fqdnTestWait(r))
			if mode != "fresh_subset" {
				if len(client.renewed) != 0 || commits != 0 {
					t.Fatal("incomplete/invalid full material pass committed fresh subset", err, client.renewed, commits)
				}
				if current, ok := r.c.active[first]; ok && current.Authority != original[first].Authority {
					t.Fatal("untested fresh candidate adopted")
				}
				if mode == "invalid_later_sibling" {
					for _, g := range r.c.active[unchanged].Grants {
						if g.FQDNManaged {
							t.Fatal("invalid sibling FQDN authority retained")
						}
					}
					for _, g := range original[unchanged].Grants {
						if g.FQDNManaged && r.installed[guardFQDNSetName(g)] > *r.now {
							t.Fatal("invalid sibling native member retained")
						}
					}
				}
				return
			}
			if err != nil || commits != 1 || client.renewed[first] != 1 || client.renewed[unchanged] != 0 {
				t.Fatal("partial renewal", err, commits, client.renewed)
			}
			if r.c.active[first].Authority == original[first].Authority || r.c.active[unchanged].Authority != original[unchanged].Authority || !reflect.DeepEqual(r.c.active[unchanged], original[unchanged]) {
				t.Fatal("only fresh owner may receive authority")
			}
			if window := r.c.fqdnNativeWindows[unchanged]; window.deadline > oldDeadline {
				t.Fatal("unchanged sibling native authority extended")
			}
			for id, a := range original {
				if proofs[id] == 0 || !reflect.DeepEqual(a.Entry, r.c.active[id].Entry) {
					t.Fatal("complete owner native proof/identity missing", id)
				}
			}
			for _, f := range original[unchanged].FQDNLeaseDescriptors {
				if original[unchanged].Authority.fqdnDeadlines[runtimeFQDNGrantDigest(f)] != base.deadlines[runtimeFQDNGrantDigest(f)] {
					t.Fatal("unchanged original permit deadline changed")
				}
			}
		})
	}
}
