package ipsec

import "reflect"

// runtimeTransportContract validates cardinality independently of activation.
// Classic's second wire slot is empty; it never represents a second SA, link,
// inside address, PSK or cloud resource. Profile ownership bounds all shared
// lifecycle and authority observers to the single active slot.
func runtimeTransportContract(m RuntimeManifest) (int, error) {
	if m.ProfileID != GCPClassicStaticProfile {
		if m.TransportVersion != nil || m.TunnelCount != nil {
			return 0, ErrRuntimeController
		}
		return 2, nil
	}
	if m.TransportVersion == nil || *m.TransportVersion != 1 || m.TunnelCount == nil || *m.TunnelCount != 1 || m.BGP != nil || m.BGPVersion != nil || m.RecoveryVersion != nil || m.Tunnels[1] != (RuntimeTunnel{}) {
		return 0, ErrRuntimeController
	}
	if m.Tunnels[0].ID == ([16]byte{}) || m.Tunnels[0].Slot != 1 || !m.Tunnels[0].Selected {
		return 0, ErrRuntimeController
	}
	return 1, nil
}
func runtimeMaterialTransportContract(m RuntimeMaterial) (int, error) {
	count, err := runtimeTransportContract(m.Manifest)
	if err != nil || count == 1 && m.Secrets[1] != (RuntimeSecret{}) {
		return 0, ErrRuntimeController
	}
	return count, nil
}

// Exact zero means no inactive resources can be smuggled through a one-slot
// intent. These predicates are also used by the single-slot journal migration.
func emptyKernelTunnel(t KernelTunnelAllocation) bool {
	return reflect.DeepEqual(t, KernelTunnelAllocation{})
}
func emptyEngineTunnel(t EngineTunnel) bool { return reflect.DeepEqual(t, EngineTunnel{}) }

func validClassicJournal(e RuntimeJournalEntry) bool {
	if e.Allocation.ProfileID != GCPClassicStaticProfile {
		return e.ContractVersion != 4
	}
	return e.ContractVersion == 4 && !e.Allocation.BGP && e.BGP == nil && e.Recovery == nil && emptyKernelTunnel(e.Allocation.Tunnels[1]) && emptyEngineTunnel(e.Engines[1]) && e.Observed[1] == (Ownership{}) && e.Engines[0].ProfileID == GCPClassicStaticProfile
}
