package ipsec

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"github.com/google/uuid"
	"reflect"
	"time"
)

// A denied transport is process-local continuity only, never permit authority.
// It is captured only at an explicitly scoped late HA freshness refusal.
type runtimeDeniedClassicTransport struct {
	KeyDigest   [32]byte
	Entry       RuntimeJournalEntry
	Delivery    RuntimeDelivery
	Environment RuntimeEnvironment
}

func (c *RuntimeController) rememberDeniedClassicTransports(entries []RuntimeJournalEntry) map[uuid.UUID]runtimeDeniedClassicTransport {
	out := map[uuid.UUID]runtimeDeniedClassicTransport{}
	for id, a := range c.active {
		if a.Entry.ContractVersion != 4 || a.Entry.Allocation.ProfileID != GCPClassicStaticProfile || a.Entry.Phase != RuntimeApplied || !validClassicJournal(a.Entry) || a.Authority == nil {
			continue
		}
		if _, err := a.Authority.RemainingForApply(a.Identity, 5*time.Second); err != nil {
			continue
		}
		found := 0
		for _, e := range entries {
			if e.DeliveryID == a.Entry.DeliveryID {
				if !reflect.DeepEqual(e, a.Entry) {
					found = -1
					break
				}
				found++
			}
		}
		if found != 1 || a.Delivery.ID != a.Entry.DeliveryID || a.StaticKeyDigest == ([32]byte{}) {
			continue
		}
		// JSON copy preserves all secret-free committed/delivery/environment fields.
		raw, err := json.Marshal(runtimeDeniedClassicTransport{a.StaticKeyDigest, a.Entry, a.Delivery, a.Environment})
		if err != nil {
			continue
		}
		var copied runtimeDeniedClassicTransport
		if json.Unmarshal(raw, &copied) != nil {
			continue
		}
		out[id] = copied
	}
	return out
}

func (c *RuntimeController) deniedClassicTransportMatches(ctx context.Context, m RuntimeMaterial, e RuntimeJournalEntry, env RuntimeEnvironment, entries []RuntimeJournalEntry) (bool, error) {
	hint, ok := c.deniedClassicTransports[e.Allocation.ConnectionID]
	delete(c.deniedClassicTransports, e.Allocation.ConnectionID) // single-use; any failed attempt loses continuity
	if !ok {
		return false, nil
	}
	if e.ContractVersion != 4 || e.Allocation.ProfileID != GCPClassicStaticProfile || !reflect.DeepEqual(hint.Entry, e) || !reflect.DeepEqual(hint.Delivery, m.RuntimeDelivery) || !reflect.DeepEqual(hint.Environment, env) {
		return false, nil
	}
	if hint.KeyDigest != sha256.Sum256([]byte(m.Secrets[0].PSK)) {
		return false, ErrRuntimeController
	}
	if ctx.Err() != nil || !c.qualification.current() || c.config.DaemonAlive == nil || !c.config.DaemonAlive() {
		return false, ErrRuntimeController
	}
	// A complete fresh daemon census must contain only current applied journal
	// configurations, keys and SAs. The target must actually remain loaded.
	inventory, err := c.config.Daemon.Inspect(ctx)
	if err != nil {
		return false, ErrRuntimeController
	}
	allowed := map[string]bool{}
	for _, current := range entries {
		if current.Phase != RuntimeApplied || current.Allocation.Namespace != e.Allocation.Namespace {
			continue
		}
		for _, engine := range current.Engines[:current.Allocation.activeTunnelCount()] {
			allowed[engineName(engine)] = true
		}
	}
	for _, name := range inventory.Connections {
		if !allowed[name] {
			return false, ErrRuntimeController
		}
	}
	for _, name := range inventory.SharedKeys {
		if !allowed[name] {
			return false, ErrRuntimeController
		}
	}
	for _, sa := range inventory.SAs {
		if !allowed[sa.Name] {
			return false, ErrRuntimeController
		}
	}
	name := engineName(e.Engines[0])
	if !containsString(inventory.Connections, name) || !containsString(inventory.SharedKeys, name) {
		return false, ErrRuntimeController
	}
	// The ordinary caller still obtains fresh CP authority and re-proves current
	// VICI/keyless-kernel/environment before publication. No cached lease survives.
	if c.proveCurrent(ctx, e, env) != nil {
		return false, ErrRuntimeController
	}
	return true, nil
}
