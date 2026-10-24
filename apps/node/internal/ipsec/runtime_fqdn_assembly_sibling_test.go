package ipsec

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"reflect"
	"testing"
	"time"
)

type lateSiblingClient struct {
	base   *fqdnCadenceSubsetClient
	join   uuid.UUID
	reads  int
	mode   string
	cancel context.CancelFunc
	nonces map[uuid.UUID]int
}

func (c *lateSiblingClient) IPsecMaterial(ctx context.Context, id uuid.UUID, rev int64) (RuntimeMaterial, error) {
	c.base.r.charge("material_http", 100*time.Millisecond)
	publication := 2
	if c.mode == "already-fresh" {
		publication = 1
	}
	if id == c.join {
		c.reads++
		if c.mode != "already-fresh" && (c.reads == 1 || c.mode == "unchanged") {
			publication = 0
		}
	}
	m := c.base.materialAt(id, publication)
	raw, _ := json.Marshal(m)
	_ = json.Unmarshal(raw, &m)
	if id == c.join && c.reads > 1 {
		switch c.mode {
		case "changed-key":
			m.Policy.FQDNGrants[0].PublicKey = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
		case "revoked":
			m.Policy.FQDNGrants = nil
		case "canceled":
			c.cancel()
		case "original-expired":
			*c.base.r.now = c.base.r.c.active[id].Authority.deadline
		case "fetch-error":
			return RuntimeMaterial{}, ErrRuntimeController
		}
	}
	return m, nil
}
func (c *lateSiblingClient) RenewIPsecLease(ctx context.Context, id uuid.UUID, q RuntimeLeaseRequest) (RuntimeLease, error) {
	c.nonces[id]++
	out, err := c.base.RenewIPsecLease(ctx, id, q)
	if id == c.join && c.mode == "wrong-nonce" {
		out.Nonce = "wrong"
	}
	return out, err
}

// The final preassembly pass itself straddles a publication: BGP is read
// unchanged first; both static candidates are fresh; only the immediate bounded
// re-read discovers BGP's new expiry. Real postcommit status IO follows.
func TestFQDNAssemblyLateSiblingPublishesJoinedBGP(t *testing.T) {
	for _, mode := range []string{"joined", "already-fresh", "unchanged", "changed-key", "revoked", "canceled", "original-expired", "fetch-error", "wrong-nonce"} {
		t.Run(mode, func(t *testing.T) {
			r, base := fqdnMultiOwnerCadenceRig(t, "three-short")
			installFQDNCadenceStatusReaders(t, r, nil)
			before := assemblyClone(r.c.active)
			var bgp uuid.UUID
			for id, a := range before {
				if a.Entry.ContractVersion == 3 {
					bgp = id
				}
			}
			if bgp == uuid.Nil {
				t.Fatal("BGP owner missing")
			}
			base.publishAt = -15 * time.Second
			page := exactPageTestMaterials(t, r, base, false)
			for i, m := range page {
				if m.Manifest.ConnectionID != bgp || mode == "already-fresh" {
					page[i] = base.materialAt(m.Manifest.ConnectionID, 1)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			client := &lateSiblingClient{base: base, join: bgp, mode: mode, cancel: cancel, nonces: map[uuid.UUID]int{}}
			r.c.client = client
			r.charge("previous_publication", 5*time.Second)
			initial := r.c.fqdnNativeWindows[bgp].deadline - *r.now
			if initial != 13*time.Second {
				t.Fatal("initial native runway changed", initial)
			}
			published := map[uuid.UUID]RuntimeStatusReport{}
			gap := false
			check := func() {
				for _, w := range r.c.fqdnNativeWindows {
					if w.deadline <= *r.now {
						gap = true
					}
				}
			}
			installFQDNCadenceStatusReaders(t, r, check)
			results, handled, err := r.c.tryMaintainExactRuntimePage(ctx, page, maintenanceAuthority(r), func() bool { return true }, func(ctx context.Context, d RuntimeDelivery, out RuntimeStatusReport) error {
				r.charge("actual_publication", 100*time.Millisecond)
				check()
				if out.Tunnels[0].Status != "up" || out.Tunnels[1].Status != "up" {
					t.Fatal("native report not healthy")
				}
				published[d.ID] = out
				return nil
			})
			positive := mode == "joined" || mode == "already-fresh" || mode == "unchanged"
			if !positive {
				if err == nil || !handled || len(results) != 0 || len(published) != 0 {
					t.Fatal("unsafe joined sibling accepted", handled, err, len(results), len(published))
				}
				return
			}
			if err != nil || !handled || len(results) != 3 || gap {
				t.Fatal("late sibling refresh failed or native gap", handled, err, len(results), gap)
			}
			wantReports := 3
			if mode == "unchanged" {
				wantReports = 2
			}
			wantReads := 2
			if mode == "already-fresh" {
				wantReads = 1
			}
			if len(published) != wantReports || client.reads != wantReads {
				t.Fatal("final split pass not exercised", len(published), client.reads)
			}
			for _, out := range results {
				if out.Retained != nil {
					if mode != "unchanged" || out.Retained.Manifest.ConnectionID != bgp || !reflect.DeepEqual(r.c.active[bgp], before[bgp]) {
						t.Fatal("wrong retained sibling")
					}
				} else if _, ok := published[out.Acknowledgement.DeliveryID]; !ok || out.Acknowledgement.Result != "applied" {
					t.Fatal("ACK without real report")
				}
			}
			if mode == "joined" || mode == "already-fresh" {
				publication := 2
				if mode == "already-fresh" {
					publication = 1
				}
				if client.nonces[bgp] != 1 || r.c.active[bgp].Authority == before[bgp].Authority || r.c.active[bgp].Identity.PolicyHash != base.materialAt(bgp, publication).Policy.Hash {
					t.Fatal("joined owner lacks exact new nonce")
				}
			} else if client.nonces[bgp] != 0 {
				t.Fatal("unchanged owner renewed")
			}
			for _, a := range before {
				for _, f := range a.FQDNLeaseDescriptors {
					if a.Authority.fqdnDeadlines[runtimeFQDNGrantDigest(f)] != base.deadlines[runtimeFQDNGrantDigest(f)] {
						t.Fatal("original deadline extended")
					}
				}
			}
		})
	}
}
