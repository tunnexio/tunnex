package ipsec

import (
	"context"
	"reflect"
	"sort"
	"time"

	"github.com/google/uuid"
)

// A late, known-current RIB change is reconciled once under the original finite
// authority. No candidate from the abandoned assembly, or its native snapshot,
// survives this boundary. The caller must collect new nonce-bound permits.
func (c *RuntimeController) reconcileExactRefreshBGP(ctx context.Context, entries []RuntimeJournalEntry, original map[uuid.UUID]runtimeActive, refreshed map[uuid.UUID]maintenanceItem, bgpCurrent func() bool) (map[uuid.UUID]runtimeActive, error) {
	client, ok := c.client.(runtimeCurrentMaterialClient)
	healthy := func() bool {
		return ctx.Err() == nil && c.qualification.current() && c.config.DaemonAlive != nil && c.config.DaemonAlive() && bgpCurrent != nil && bgpCurrent()
	}
	if !ok || !healthy() || !reflect.DeepEqual(c.active, original) {
		return nil, ErrRuntimeController
	}
	processes := map[uuid.UUID]runtimeBGPSession{}
	for _, a := range original {
		if a.Authority == nil {
			return nil, ErrRuntimeController
		}
		if _, err := a.Authority.RemainingForApply(a.Identity, 5*time.Second); err != nil {
			return nil, ErrRuntimeController
		}
		if a.Entry.ContractVersion == 3 {
			p := c.bgpProcesses[a.Entry.DeliveryID]
			if p == nil || !p.Alive() {
				return nil, ErrRuntimeController
			}
			processes[a.Entry.DeliveryID] = p
		}
	}
	reconcileCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	err := c.reconcileActiveBGP(reconcileCtx, entries)
	if reconcileCtx.Err() != nil {
		err = ErrRuntimeController
	}
	cancel()
	if err != nil || !healthy() || len(c.active) != len(original) {
		return nil, ErrRuntimeController
	}
	reconciled := map[uuid.UUID]runtimeActive{}
	for id, old := range original {
		next, exists := c.active[id]
		want := cloneMaintenanceActive(old)
		if old.Entry.ContractVersion == 3 {
			p := processes[old.Entry.DeliveryID]
			if p != c.bgpProcesses[old.Entry.DeliveryID] || !p.Alive() || next.Entry.BGPRoutes == nil || next.Entry.BGPRoutes.Stage != "completed" || !validJournalBGP(next.Entry) {
				return nil, ErrRuntimeController
			}
			want.Entry.BGPRoutes = next.Entry.BGPRoutes
		}
		if !exists || !reflect.DeepEqual(want, next) {
			return nil, ErrRuntimeController
		}
		if _, err := old.Authority.RemainingForApply(old.Identity, 5*time.Second); err != nil {
			return nil, ErrRuntimeController
		}
		reconciled[id] = cloneMaintenanceActive(next)
	}
	ids := make([]uuid.UUID, 0, len(refreshed))
	for id := range refreshed {
		if _, exists := reconciled[id]; !exists {
			return nil, ErrRuntimeController
		}
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
	fetchCtx, fetchCancel := context.WithTimeout(ctx, 5*time.Second)
	defer fetchCancel()
	prepared := map[uuid.UUID]maintenanceItem{}
	for _, id := range ids {
		old := reconciled[id]
		m, fetchErr := client.IPsecMaterial(fetchCtx, id, old.Delivery.DesiredRevision)
		var item maintenanceItem
		if fetchErr == nil {
			if len(old.FQDNLeaseDescriptors) > 0 {
				item, fetchErr = c.prepareFQDNFollowupMaterial(fetchCtx, old, m, true)
			} else {
				item, fetchErr = c.prepareExactOrdinaryPageMaterial(fetchCtx, old, m)
			}
		}
		for i := range m.Secrets {
			m.Secrets[i] = RuntimeSecret{}
		}
		if fetchErr != nil || fetchCtx.Err() != nil || !healthy() || !reflect.DeepEqual(c.active, reconciled) {
			return nil, ErrRuntimeController
		}
		prepared[id] = item
	}
	// Keep the caller's report/candidate map identity, but replace its contents
	// only after the complete selected set has passed fresh material validation.
	for id, item := range prepared {
		refreshed[id] = item
	}
	return reconciled, nil
}
