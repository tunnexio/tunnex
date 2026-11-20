//go:build !linux

package reconcile

// NewHostNetworkProbe returns nil off Linux: there is no kernel WireGuard backend to plan routes for, and a
// nil probe keeps the reconciler on its address-containment path (SSI-7).
func NewHostNetworkProbe(_ ...string) *HostNetworkProbe { return nil }
