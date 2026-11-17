package ipsec

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
)

// This is the production callback seam: a real heartbeat runs between priority
// maintenance items, including before and after the changed hash is committed.
func TestStaticFQDNExpiryTurnoverWithRecoveryPublication(t *testing.T) {
	for _, publish := range []bool{false, true} {
		name := "without_callback"
		if publish {
			name = "with_real_callback"
		}
		t.Run(name, func(t *testing.T) {
			r, client := fqdnExpiryTurnoverRig(t, true)
			r.charge("heartbeat_due", 2*time.Second)
			before := cloneMaintenanceActive(r.c.active[r.target])
			deadline := before.Authority.deadline
			denied := map[uuid.UUID]bool{}
			for id := range r.c.active {
				denied[id] = r.applicationDenied[id]
			}
			publications := 0
			var callback func(context.Context, RuntimeRecoveryHeartbeat) error
			if publish {
				callback = func(context.Context, RuntimeRecoveryHeartbeat) error { publications++; return nil }
			}
			err := r.c.renewActiveIPsecRuntimeObserved(context.Background(), maintenanceAuthority(r), func() bool { return true }, nil, callback)
			after, present := r.c.active[r.target]
			if err != nil || !present || len(r.c.active) != 5 || after.Identity.PolicyHash != client.material.Policy.Hash || after.Authority == before.Authority || before.Authority.deadline != deadline || !reflect.DeepEqual(after.Entry, before.Entry) || !reflect.DeepEqual(after.Delivery, before.Delivery) || r.applicationDenied[r.target] {
				t.Fatal("expiry-only renewal lost finite authority or a sibling with telemetry enabled", err)
			}
			if publish && publications == 0 {
				t.Fatal("production recovery callback was not reached")
			}
			for id, owner := range r.c.active {
				if r.applicationDenied[id] != denied[id] || owner.Authority == nil || (owner.Entry.ContractVersion == 3 && !r.c.bgpProcesses[owner.Entry.DeliveryID].Alive()) {
					t.Fatal("renewal starved unrelated owner")
				}
			}
			// A later independent observation must work under the committed epoch,
			// not borrow the old hash or manufacture a failover recommendation.
			r.charge("next_heartbeat_due", 2*time.Second)
			reports, err := staticFQDNHeartbeat(r, true, func() bool { return true })
			if err != nil || len(reports) != 1 || reports[0].Report.ActiveSlot == nil || *reports[0].Report.ActiveSlot != int(selectedRuntimeSlot(before.Entry)) {
				t.Fatal("committed expiry hash cannot publish a later native heartbeat", err)
			}
		})
	}
}

func staticFQDNHeartbeat(r *renewalCycleRig, sequence bool, bgp func() bool) ([]RuntimeRecoveryHeartbeat, error) {
	seen := map[uuid.UUID]bool{}
	for id := range r.c.active {
		if id != r.target {
			seen[id] = true
		}
	}
	return r.c.refreshIPsecActiveRecoveryLockedQualified(context.Background(), seen, sequence, time.Now(), bgp)
}

type recoveryExpiryClient struct {
	*fqdnTurnoverClient
	onFetch    func()
	freshError error
}

func (c *recoveryExpiryClient) IPsecMaterial(ctx context.Context, id uuid.UUID, rev int64) (RuntimeMaterial, error) {
	if c.onFetch != nil {
		c.onFetch()
	}
	return c.fqdnTurnoverClient.IPsecMaterial(ctx, id, rev)
}
func (c *recoveryExpiryClient) RenewIPsecLease(ctx context.Context, id uuid.UUID, req RuntimeLeaseRequest) (RuntimeLease, error) {
	if id == c.target && req.PolicyHash != c.oldHash && c.freshError != nil {
		c.requests = append(c.requests, req)
		return RuntimeLease{}, c.freshError
	}
	return c.fqdnTurnoverClient.RenewIPsecLease(ctx, id, req)
}

func TestStaticFQDNHeartbeatExpiryRetryIsTelemetryOnly(t *testing.T) {
	r, client := fqdnExpiryTurnoverRig(t, true)
	r.charge("heartbeat_due", 2*time.Second)
	before := cloneMaintenanceActive(r.c.active[r.target])
	deadline := before.Authority.deadline
	native := map[string]time.Duration{}
	for name, end := range r.installed {
		native[name] = end
	}
	entries, _ := r.c.journal.Entries()
	_, sequence, _ := r.c.journal.guardTemplates()
	reports, err := staticFQDNHeartbeat(r, false, func() bool { return true })
	if err != nil || len(reports) != 1 || len(client.requests) != 2 || client.fetched != 1 || client.requests[0].Nonce == client.requests[1].Nonce || client.requests[0].PolicyHash != before.Identity.PolicyHash || client.requests[1].PolicyHash != client.material.Policy.Hash || !reflect.DeepEqual(client.requests[1].FQDNGrants, client.material.Policy.FQDNGrants) {
		t.Fatal("missing bounded exact fresh-nonce telemetry retry", err)
	}
	afterEntries, _ := r.c.journal.Entries()
	_, afterSequence, _ := r.c.journal.guardTemplates()
	if !reflect.DeepEqual(before, r.c.active[r.target]) || before.Authority != r.c.active[r.target].Authority || before.Authority.deadline != deadline || !reflect.DeepEqual(native, r.installed) || !reflect.DeepEqual(entries, afterEntries) || sequence != afterSequence {
		t.Fatal("telemetry adopted fresh authority or changed native/journal state")
	}
}

func TestStaticFQDNExpiryAdoptionNormalAndFollowupKeepRecovery(t *testing.T) {
	for _, mode := range []string{"normal_page", "followup"} {
		t.Run(mode, func(t *testing.T) {
			r, client := fqdnExpiryTurnoverRig(t, true)
			before := r.c.active[r.target]
			h := r.c.recoveryHistory[r.target]
			h.consecutive, h.firstDown = 2, time.Millisecond
			callback := func(context.Context, RuntimeRecoveryHeartbeat) error { return nil }
			var err error
			if mode == "normal_page" {
				_, err = r.c.maintainIPsecRuntimeRecoveryObserved(context.Background(), []RuntimeMaterial{client.material}, maintenanceAuthority(r), func() bool { return true }, nil, callback)
			} else {
				r.c.config.JournalDir = r.c.journal.dir
				window := r.c.fqdnNativeWindows[r.target]
				window.deadline = *r.now + 9*time.Second
				r.c.fqdnNativeWindows[r.target] = window
				err = r.c.followupFQDNMaintenance(context.Background(), maintenanceAuthority(r), func() bool { return true }, nil, callback, fqdnTestWait(r))
			}
			after := r.c.active[r.target]
			if err != nil || after.Identity.PolicyHash != client.material.Policy.Hash || after.Authority == before.Authority || !reflect.DeepEqual(after.Entry, before.Entry) {
				t.Fatal("normal adoption failed", err)
			}
			if h := r.c.recoveryHistory[r.target]; h == nil || h.epoch != recoveryReportEpoch(after) || h.consecutive != 0 || h.firstDown != 0 {
				t.Fatal("committed policy retained old recovery advice")
			}
			r.charge("later_native_sample", 2*time.Second)
			reports, err := staticFQDNHeartbeat(r, true, func() bool { return true })
			if err != nil || len(reports) != 1 || reports[0].Report.ActiveSlot == nil {
				t.Fatal("normal adoption cannot take next native sample", err)
			}
		})
	}
}

func TestStaticFQDNHeartbeatExpiryRetryRejectsUnsafeRefresh(t *testing.T) {
	for _, kind := range []string{"answer", "rule", "revoked", "unchanged_hash", "delivery", "expired_fqdn", "bad_nonce", "second_conflict", "expired_original_during_fetch", "expired_original_during_observation", "lost_bgp"} {
		t.Run(kind, func(t *testing.T) {
			r, base := fqdnExpiryTurnoverRig(t, true)
			client := &recoveryExpiryClient{fqdnTurnoverClient: base}
			r.c.client = client
			before := r.c.active[r.target]
			deadline := before.Authority.deadline
			bgp := func() bool { return true }
			switch kind {
			case "answer":
				client.material.Policy.FQDNGrants[0].Destination = "10.222.33.44/32"
			case "rule":
				client.material.Policy.FQDNGrants[0].RuleID = uuid.NewString()
			case "revoked":
				client.material.Policy.FQDNGrants = nil
			case "unchanged_hash":
				client.material.Policy.Hash = client.oldHash
			case "delivery":
				client.material.ID = uuid.New()
			case "expired_fqdn":
				client.material.Policy.FQDNGrants[0].ExpiresAt = time.Now().Add(-time.Second)
			case "bad_nonce":
				client.mutate = func(lease *RuntimeLease) { lease.Nonce = "wrong" }
			case "second_conflict":
				client.freshError = fqdnTurnoverConflict{}
			case "expired_original_during_fetch":
				client.onFetch = func() { *r.now = deadline + time.Second }
			case "expired_original_during_observation":
				r.c.recoveryObserve = func(context.Context, RuntimeJournalEntry) [2]string {
					*r.now = deadline + time.Second
					return [2]string{"up", "up"}
				}
			case "lost_bgp":
				bgp = func() bool { return false }
				client.material.Policy.FQDNGrants = nil
			}
			r.charge("heartbeat_due", 2*time.Second)
			reports, err := staticFQDNHeartbeat(r, true, bgp)
			if err == nil || len(reports) != 0 || r.c.active[r.target].Authority != nil || before.Authority.deadline != deadline || client.fetched > 1 || len(client.requests) > 2 {
				t.Fatal("unsafe material retried or retained original authority", err, client.fetched, len(client.requests))
			}
		})
	}
}

func TestStaticFQDNHeartbeatRealRevokePreservesUnrelatedOwners(t *testing.T) {
	r, client := fqdnExpiryTurnoverRig(t, true)
	before := map[uuid.UUID]runtimeActive{}
	denied := map[uuid.UUID]bool{}
	native := map[string]time.Duration{}
	for id, owner := range r.c.active {
		if id != r.target {
			before[id] = cloneMaintenanceActive(owner)
			denied[id] = r.applicationDenied[id]
		}
	}
	for name, end := range r.installed {
		native[name] = end
	}
	flushes := 0
	r.c.guard.apply = func(_ context.Context, raw []byte) error {
		var doc struct {
			NFTables []struct {
				Flush struct {
					Set struct {
						Family string `json:"family"`
						Table  string `json:"table"`
						Name   string `json:"name"`
					} `json:"set"`
				} `json:"flush"`
			} `json:"nftables"`
		}
		if json.Unmarshal(raw, &doc) != nil || len(doc.NFTables) != 3 {
			t.Fatal("invalid withdrawal transaction")
		}
		allowed := map[string]bool{guardLeaseName(r.target): true, guardReplyLeaseName(r.target): true, guardSALeaseName(r.target): true}
		for _, cmd := range doc.NFTables {
			set := cmd.Flush.Set
			if set.Family != "inet" || set.Table != "tunnex_ipsec" || !allowed[set.Name] {
				t.Fatal("withdrawal escaped target")
			}
			delete(allowed, set.Name)
			r.installed[set.Name] = 0
		}
		if len(allowed) != 0 {
			t.Fatal("incomplete withdrawal")
		}
		r.applicationDenied[r.target] = true
		flushes++
		return nil
	}
	client.material.Policy.FQDNGrants = nil // real revoke is never an expiry-only bridge
	r.charge("heartbeat_due", 2*time.Second)
	publications := 0
	err := r.c.renewActiveIPsecRuntimeObserved(context.Background(), maintenanceAuthority(r), func() bool { return true }, nil, func(context.Context, RuntimeRecoveryHeartbeat) error { publications++; return nil })
	var aborted interface{ IPsecMaintenanceBatchAborted() bool }
	if !errors.As(err, &aborted) || !aborted.IPsecMaintenanceBatchAborted() || flushes != 1 || publications != 0 || len(client.requests) != 1 || client.fetched != 1 || r.c.active[r.target].Authority != nil {
		t.Fatal("real revoke failed existing scoped withdrawal", err, flushes, publications, client.fetched)
	}
	for id, original := range before {
		if !reflect.DeepEqual(original, r.c.active[id]) || r.applicationDenied[id] != denied[id] || (original.Entry.ContractVersion == 3 && !r.c.bgpProcesses[original.Entry.DeliveryID].Alive()) {
			t.Fatal("target revoke changed unrelated owner")
		}
		for _, name := range []string{guardLeaseName(id), guardReplyLeaseName(id), guardSALeaseName(id)} {
			if r.installed[name] != native[name] {
				t.Fatal("unrelated finite deadline changed")
			}
		}
	}
}
