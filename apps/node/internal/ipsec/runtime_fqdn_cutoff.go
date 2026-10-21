package ipsec

import (
	"context"
	"reflect"
	"time"

	"github.com/google/uuid"
)

// This is scheduling advice only. It is emitted after all ordinary precommit
// proofs, before any native mutation, and never authorizes a grant itself.
type runtimeFQDNPrecommitCutoff struct{ connections []uuid.UUID }

func (*runtimeFQDNPrecommitCutoff) Error() string {
	return "required FQDN member reached finite precommit cutoff"
}

func runtimeFQDNRequiredCutoff(before, limited GuardIntent, required map[uuid.UUID]runtimeActive) *runtimeFQDNPrecommitCutoff {
	var ids []uuid.UUID
	for i, owner := range before.Connections {
		if _, ok := required[owner.ID]; !ok || owner.PrefixOnly {
			continue
		}
		present := map[string]bool{}
		for _, g := range limited.Connections[i].Grants {
			if g.FQDN.Version == 2 {
				present[guardFQDNGrantDigest(g)] = true
			}
		}
		for _, g := range owner.Grants {
			if g.FQDN.Version == 2 && !present[guardFQDNGrantDigest(g)] {
				ids = append(ids, owner.ID)
				break
			}
		}
	}
	if len(ids) == 0 {
		return nil
	}
	return &runtimeFQDNPrecommitCutoff{connections: ids}
}

func (c *RuntimeController) prepareFQDNCutoffRetry(ctx context.Context, materials []maintenanceItem, cutoff *runtimeFQDNPrecommitCutoff) ([]maintenanceItem, error) {
	out := append([]maintenanceItem(nil), materials...)
	for _, id := range cutoff.connections {
		old, ok := c.active[id]
		if !ok || old.Authority == nil || ctx.Err() != nil {
			return nil, ErrRuntimeController
		}
		if _, err := old.Authority.RemainingForApply(old.Identity, 5*time.Second); err != nil {
			return nil, err
		}
		index := -1
		for i, m := range out {
			if m.Manifest.ConnectionID == id {
				if index != -1 {
					return nil, ErrRuntimeController
				}
				index = i
			}
		}
		if index < 0 {
			return nil, ErrRuntimeController
		}
		fresh, err := c.refreshFQDNExpiryMaterial(ctx, old)
		// Unavailable or unchanged DNS cannot extend authority. The second pass
		// retains the original finite omission and still obtains current CP leases.
		if err == nil {
			out[index] = fresh
		}
		current, present := c.active[id]
		if !present || !reflect.DeepEqual(current, old) || ctx.Err() != nil || !c.qualification.current() || c.config.DaemonAlive == nil || !c.config.DaemonAlive() {
			return nil, ErrRuntimeController
		}
		if _, err := old.Authority.RemainingForApply(old.Identity, 5*time.Second); err != nil {
			return nil, err
		}
	}
	return out, nil
}
