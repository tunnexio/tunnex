package ipsec

import (
	"encoding/json"
	"reflect"
)

func runtimeRecoveryEligible(m RuntimeManifest, capable bool) bool {
	return m.RecoveryVersion == nil || (capable && *m.RecoveryVersion == 1)
}
func validRecoveryStatus(m RuntimeManifest, r RuntimeStatusReport) bool {
	if m.RecoveryVersion == nil {
		return r.RecoveryVersion == nil && r.SelectionSequence == nil && r.ActiveSlot == nil
	}
	return *m.RecoveryVersion == 1 && r.RecoveryVersion != nil && *r.RecoveryVersion == 1 && r.SelectionSequence != nil && *r.SelectionSequence > 0 && *r.SelectionSequence <= 9007199254740991 && (r.ActiveSlot == nil || *r.ActiveSlot == 1 || *r.ActiveSlot == 2)
}

// Keep schema 161's two-tunnel array shape. Repeated metadata must agree; it
// describes a connection observation, not either tunnel's transport state.
type recoveryStoredTunnel struct {
	RuntimeTunnelStatus
	RecoveryVersion   *int    `json:"recovery_version,omitempty"`
	SelectionSequence *uint64 `json:"selection_sequence,omitempty"`
	ActiveSlot        *int    `json:"active_slot,omitempty"`
}

func recoveryStoredTunnels(r RuntimeStatusReport) [2]recoveryStoredTunnel {
	var out [2]recoveryStoredTunnel
	for i, t := range r.Tunnels {
		out[i] = recoveryStoredTunnel{t, r.RecoveryVersion, r.SelectionSequence, r.ActiveSlot}
	}
	return out
}
func decodeRecoveryStored(raw []byte, r *RuntimeStatusReport) bool {
	var stored []recoveryStoredTunnel
	if json.Unmarshal(raw, &stored) != nil || len(stored) != 2 {
		return false
	}
	a, b := stored[0], stored[1]
	if !reflect.DeepEqual(a.RecoveryVersion, b.RecoveryVersion) || !reflect.DeepEqual(a.SelectionSequence, b.SelectionSequence) || !reflect.DeepEqual(a.ActiveSlot, b.ActiveSlot) {
		return false
	}
	r.RecoveryVersion, r.SelectionSequence, r.ActiveSlot = a.RecoveryVersion, a.SelectionSequence, a.ActiveSlot
	r.Tunnels = [2]RuntimeTunnelStatus{a.RuntimeTunnelStatus, b.RuntimeTunnelStatus}
	one := 1
	return validRecoveryStatus(RuntimeManifest{RecoveryVersion: &one}, *r)
}
