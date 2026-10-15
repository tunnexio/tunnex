package ipsec

import (
	"context"
	"reflect"
	"time"
)

// An Applied journal and surviving links do not prove that a fresh daemon has
// loaded configuration. This path only restages absent AWS BGP or GCP HA
// configurations in the same independently observed namespace and boot; it
// cannot recreate lost links. AWS retains its legacy empty runtime profile.
func (c *RuntimeController) bgpOrdinaryDaemonAbsent(ctx context.Context, e RuntimeJournalEntry, entries []RuntimeJournalEntry, authority *PermitLeaseAuthority, identity PermitLeaseIdentity, environment RuntimeEnvironment) (bool, bool, error) {
	refuse := func() (bool, bool, error) { return false, false, ErrRuntimeController }
	if ctx.Err() != nil || e.ContractVersion != 3 || (e.Allocation.ProfileID != "" && e.Allocation.ProfileID != GCPHABGPProfile) || e.Phase != RuntimeApplied || e.AbsenceOnly || !validJournalBGP(e) || c.config.Environment == nil || c.config.Daemon == nil || !c.qualification.current() || c.config.DaemonAlive == nil || !c.config.DaemonAlive() {
		return refuse()
	}
	namespace, err := c.namespace()
	if err != nil || namespace != e.Allocation.Namespace || environment.Namespace != namespace {
		return refuse()
	}
	if !validRestoration(e) {
		return refuse()
	}
	if e.Restoration != nil {
		boot, err := resetBootID()
		if err != nil || boot != e.Restoration.BootID {
			return refuse()
		}
	}
	allowed := map[string]bool{}
	engines := map[string]EngineTunnel{engineName(e.Engines[0]): e.Engines[0], engineName(e.Engines[1]): e.Engines[1]}
	for _, other := range entries {
		if other.DeliveryID == e.DeliveryID {
			continue
		}
		if other.Phase != RuntimeApplied || other.Allocation.Namespace != e.Allocation.Namespace {
			continue
		}
		for i := 0; i < other.Allocation.activeTunnelCount(); i++ {
			allowed[engineName(other.Engines[i])] = true
			engines[engineName(other.Engines[i])] = other.Engines[i]
		}
	}
	inspect := func() (DaemonInventory, error) {
		inv, err := c.config.Daemon.Inspect(ctx)
		if err != nil {
			return inv, err
		}
		for _, name := range inv.Connections {
			if !allowed[name] && name != engineName(e.Engines[0]) && name != engineName(e.Engines[1]) {
				return inv, ErrRuntimeController
			}
		}
		for _, name := range inv.SharedKeys {
			if !allowed[name] && name != engineName(e.Engines[0]) && name != engineName(e.Engines[1]) {
				return inv, ErrRuntimeController
			}
		}
		for _, sa := range inv.SAs {
			if !allowed[sa.Name] && sa.Name != engineName(e.Engines[0]) && sa.Name != engineName(e.Engines[1]) {
				return inv, ErrRuntimeController
			}
		}
		for _, engine := range engines {
			if _, _, _, err := ownedRuntimeChildren(engine, inv); err != nil {
				return inv, ErrRuntimeController
			}
		}
		return inv, nil
	}
	before, err := inspect()
	if err != nil {
		return refuse()
	}
	loaded := 0
	for _, engine := range e.Engines {
		name := engineName(engine)
		conn := containsString(before.Connections, name)
		key := containsString(before.SharedKeys, name)
		if conn != key {
			return refuse()
		}
		if conn {
			loaded++
		}
		for _, sa := range before.SAs {
			if sa.Name == name && !conn {
				return refuse()
			}
		}
	}
	if loaded == 2 {
		return false, false, nil
	}
	if loaded != 0 {
		return refuse()
	}
	delete(c.active, e.Allocation.ConnectionID)
	if c.installActive(ctx, entries) != nil {
		return refuse()
	}
	for round := 0; round < 2; round++ {
		if _, err := authority.RemainingForApply(identity, 5*time.Second); err != nil {
			return refuse()
		}
		observed, err := c.config.Environment.Observe(ctx, e.Allocation, e.Engines)
		if err != nil || !reflect.DeepEqual(observed, environment) {
			return refuse()
		}
		missing, err := c.restartNeedsRecreation(ctx, e)
		if err != nil || missing {
			return refuse()
		}
		if c.observeRecovery(ctx, e) != [2]string{"down", "down"} {
			return refuse()
		}
	}
	after, err := inspect()
	if err != nil || !reflect.DeepEqual(bgpDaemonIdentity(before), bgpDaemonIdentity(after)) || ctx.Err() != nil || !c.qualification.current() || c.config.DaemonAlive == nil || !c.config.DaemonAlive() {
		return refuse()
	}
	namespace, err = c.namespace()
	if err != nil || namespace != e.Allocation.Namespace {
		return refuse()
	}
	if e.Restoration != nil {
		boot, err := resetBootID()
		if err != nil || boot != e.Restoration.BootID {
			return refuse()
		}
	}
	return true, false, nil
}

// CHILD byte counters are traffic, not daemon ownership identity. Copy every
// remaining field so configuration, peer, generation and rekey changes refuse.
func bgpDaemonIdentity(in DaemonInventory) DaemonInventory {
	out := in
	out.SAs = append([]DaemonIKE(nil), in.SAs...)
	for i := range out.SAs {
		out.SAs[i].Children = append([]DaemonChild(nil), in.SAs[i].Children...)
		for j := range out.SAs[i].Children {
			out.SAs[i].Children[j].BytesIn = 0
			out.SAs[i].Children[j].BytesOut = 0
		}
	}
	return out
}
