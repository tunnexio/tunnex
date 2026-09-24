// Package ipsec qualifies normalized evidence only. It does not discover kernel
// state, advertise capability, select a path, activate traffic or acknowledge cleanup.
package ipsec

import (
	"net/netip"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
)

type Binding struct {
	OrgID, GatewayID, ConnectionID                         uuid.UUID
	DesiredRevision, ConfigurationRevision, PolicyRevision int64
}
type Ownership struct {
	Namespace, InterfaceName string
	InterfaceIndex           int
	XFRMID                   uint32
}
type RouteTuple struct {
	Destination     netip.Prefix
	Table           uint32
	Protocol        uint8
	Metric          uint32
	OutputInterface int
	// An invalid (zero) address means no next-hop gateway.
	Gateway netip.Addr
}
type TunnelAssignment struct {
	TunnelID       uuid.UUID
	Slot           uint8
	SecretRevision int64
	Ownership      Ownership
	Routes         []RouteTuple
}
type ExpectedAssignment struct {
	Binding Binding
	Tunnels [2]TunnelAssignment
}
type ChildSA struct {
	// ID is a unique daemon-instance SA identity within the complete snapshot,
	// never a reusable configuration name.
	ID                                                     string
	TunnelID                                               uuid.UUID
	DesiredRevision, ConfigurationRevision, SecretRevision int64
	Established                                            bool
}
type TunnelObservation struct {
	Binding                                              Binding
	Tunnel                                               TunnelAssignment
	CollectionID                                         string
	InterfaceOwnershipConfirmed, RouteOwnershipConfirmed bool
	ChildSAInventoryComplete                             bool
	ChildSAs                                             []ChildSA
	PolicyEnforced                                       bool
	EnforcedPolicyRevision                               int64
	AntiSpoofEnforced, UnderlaySeparated                 bool
}
type Snapshot struct {
	Binding                                                                     Binding
	CollectionID                                                                string
	CollectedAt                                                                 time.Time
	Complete, Consistent                                                        bool
	DaemonIdentityConfirmed, OwnershipInventoryComplete, OwnershipCollisionFree bool
	ForwardedTrafficRefused, HostTrafficRefused, EstablishedTrafficRefused      bool
	Tunnels                                                                     []TunnelObservation
}
type Reason string

const (
	ReasonCandidate            Reason = "candidate"
	ReasonInvalidAssignment    Reason = "invalid_assignment"
	ReasonInvalidFreshness     Reason = "invalid_freshness"
	ReasonIncompleteInventory  Reason = "incomplete_inventory"
	ReasonGlobalRefusalMissing Reason = "global_refusal_missing"
	ReasonOwnershipUnconfirmed Reason = "ownership_unconfirmed"
	ReasonInvalidInventory     Reason = "invalid_inventory"
	ReasonMissingTunnel        Reason = "missing_tunnel"
	ReasonBindingMismatch      Reason = "binding_mismatch"
	ReasonObjectMismatch       Reason = "object_mismatch"
	ReasonSAUnconfirmed        Reason = "sa_unconfirmed"
	ReasonPolicyUnconfirmed    Reason = "policy_unconfirmed"
)

type TunnelEvidence struct {
	TunnelID  uuid.UUID
	Slot      uint8
	Candidate bool
	Reason    Reason
}

// EvaluateEvidence evaluates adapter assertions, not actual kernel readback.
// A candidate is only a prerequisite; no result grants runtime capability.
// Refusals are deterministic: assignment, freshness, global inventory/refusal,
// observed identity inventory, then the individual tunnel's evidence.
func EvaluateEvidence(expected ExpectedAssignment, observed Snapshot, now time.Time, maxAge time.Duration) [2]TunnelEvidence {
	result := [2]TunnelEvidence{}
	for i, t := range expected.Tunnels {
		result[i] = TunnelEvidence{TunnelID: t.TunnelID, Slot: t.Slot}
	}
	refuseAll := func(reason Reason) [2]TunnelEvidence {
		for i := range result {
			result[i].Reason = reason
		}
		return result
	}
	if !validExpected(expected) {
		return refuseAll(ReasonInvalidAssignment)
	}
	if maxAge <= 0 || now.IsZero() || observed.CollectedAt.IsZero() || observed.CollectedAt.After(now) || observed.CollectedAt.Before(now.Add(-maxAge)) {
		return refuseAll(ReasonInvalidFreshness)
	}
	if !validToken(observed.CollectionID) || !observed.Complete || !observed.Consistent || !observed.OwnershipInventoryComplete {
		return refuseAll(ReasonIncompleteInventory)
	}
	if !observed.DaemonIdentityConfirmed || !observed.OwnershipCollisionFree {
		return refuseAll(ReasonOwnershipUnconfirmed)
	}
	if !observed.ForwardedTrafficRefused || !observed.HostTrafficRefused || !observed.EstablishedTrafficRefused {
		return refuseAll(ReasonGlobalRefusalMissing)
	}
	if observed.Binding != expected.Binding {
		return refuseAll(ReasonBindingMismatch)
	}
	var found [2]*TunnelObservation
	for i := range observed.Tunnels {
		o := &observed.Tunnels[i]
		slot := -1
		for j, e := range expected.Tunnels {
			if e.TunnelID == o.Tunnel.TunnelID {
				slot = j
				break
			}
		}
		if slot < 0 || found[slot] != nil || o.CollectionID != observed.CollectionID || o.Binding.OrgID != expected.Binding.OrgID || o.Binding.GatewayID != expected.Binding.GatewayID || o.Binding.ConnectionID != expected.Binding.ConnectionID {
			return refuseAll(ReasonInvalidInventory)
		}
		found[slot] = o
	}

	if found[0] != nil && found[1] != nil {
		a, b := found[0], found[1]
		if a.Tunnel.Ownership.Namespace == b.Tunnel.Ownership.Namespace && (a.Tunnel.Ownership.InterfaceName == b.Tunnel.Ownership.InterfaceName || a.Tunnel.Ownership.InterfaceIndex == b.Tunnel.Ownership.InterfaceIndex || a.Tunnel.Ownership.XFRMID == b.Tunnel.Ownership.XFRMID) {
			return refuseAll(ReasonInvalidInventory)
		}
		for _, sa := range a.ChildSAs {
			for _, other := range b.ChildSAs {
				if sa.ID != "" && sa.ID == other.ID {
					return refuseAll(ReasonInvalidInventory)
				}
			}
		}
	}
	for i, e := range expected.Tunnels {
		result[i].Reason = evaluateTunnel(expected.Binding, e, found[i])
		result[i].Candidate = result[i].Reason == ReasonCandidate
	}
	return result
}
func evaluateTunnel(binding Binding, e TunnelAssignment, o *TunnelObservation) Reason {
	if o == nil {
		return ReasonMissingTunnel
	}
	if o.Binding != binding || o.Tunnel.TunnelID != e.TunnelID || o.Tunnel.Slot != e.Slot || o.Tunnel.SecretRevision != e.SecretRevision {
		return ReasonBindingMismatch
	}
	if o.Tunnel.Ownership != e.Ownership || !o.InterfaceOwnershipConfirmed || !o.RouteOwnershipConfirmed || !sameRoutes(e.Routes, o.Tunnel.Routes) {
		return ReasonObjectMismatch
	}
	if !o.ChildSAInventoryComplete || len(o.ChildSAs) != 1 {
		return ReasonSAUnconfirmed
	}
	sa := o.ChildSAs[0]
	if !validToken(sa.ID) || !sa.Established || sa.TunnelID != e.TunnelID || sa.DesiredRevision != binding.DesiredRevision || sa.ConfigurationRevision != binding.ConfigurationRevision || sa.SecretRevision != e.SecretRevision {
		return ReasonSAUnconfirmed
	}
	if !o.PolicyEnforced || o.EnforcedPolicyRevision != binding.PolicyRevision || !o.AntiSpoofEnforced || !o.UnderlaySeparated {
		return ReasonPolicyUnconfirmed
	}
	return ReasonCandidate
}
func validExpected(e ExpectedAssignment) bool {
	b := e.Binding
	if b.OrgID == uuid.Nil || b.GatewayID == uuid.Nil || b.ConnectionID == uuid.Nil || b.DesiredRevision <= 0 || b.ConfigurationRevision <= 0 || b.PolicyRevision <= 0 {
		return false
	}
	for i, t := range e.Tunnels {
		o := t.Ownership
		if t.TunnelID == uuid.Nil || t.Slot != uint8(i+1) || t.SecretRevision <= 0 || !validToken(o.Namespace) || !validToken(o.InterfaceName) || len(o.InterfaceName) > 15 || o.InterfaceName == "." || o.InterfaceName == ".." || strings.ContainsAny(o.InterfaceName, "/:") || o.InterfaceIndex <= 0 || o.XFRMID == 0 || len(t.Routes) == 0 {
			return false
		}
		seen := make(map[RouteTuple]bool, len(t.Routes))
		for _, r := range t.Routes {
			if !r.Destination.IsValid() || !r.Destination.Addr().Is4() || r.Destination != r.Destination.Masked() || r.Table == 0 || r.Protocol == 0 || r.OutputInterface != o.InterfaceIndex || (r.Gateway.IsValid() && (!r.Gateway.Is4() || r.Gateway.IsUnspecified() || r.Gateway.IsMulticast())) || seen[r] {
				return false
			}
			seen[r] = true
		}
	}
	a, bTunnel := e.Tunnels[0], e.Tunnels[1]
	return a.TunnelID != bTunnel.TunnelID && a.Ownership.InterfaceName != bTunnel.Ownership.InterfaceName && a.Ownership.InterfaceIndex != bTunnel.Ownership.InterfaceIndex && a.Ownership.XFRMID != bTunnel.Ownership.XFRMID
}
func validToken(value string) bool {
	return value != "" && strings.TrimSpace(value) == value && !strings.ContainsFunc(value, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) })
}
func sameRoutes(expected, actual []RouteTuple) bool {
	if len(expected) != len(actual) {
		return false
	}
	remaining := make(map[RouteTuple]bool, len(expected))
	for _, r := range expected {
		remaining[r] = true
	}
	for _, r := range actual {
		if !remaining[r] {
			return false
		}
		delete(remaining, r)
	}
	return len(remaining) == 0
}
