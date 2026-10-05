package policy

import (
	"fmt"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxscope"
	"net/netip"
)

// SandboxProjection comes from enabled unexpired records with a same-org peer
// and active creator membership. Current entitlements are always recompiled.
type SandboxProjection struct {
	RemoteTerminalGatewayID, RemoteRuntimeGatewayID uuid.UUID
	SandboxID                                       uuid.UUID
	DeviceID                                        uuid.UUID
	CreatorID                                       uuid.UUID
	TerminalDeviceID                                uuid.UUID
	LocalTerminalGatewayID                          uuid.UUID
	Requested                                       []sandboxscope.Scope
	TemplateCap                                     []sandboxscope.Scope
}

// CreatorStaticScope resolves supported current user/group static grants.
func CreatorStaticScope(s Snapshot, creator uuid.UUID) []sandboxscope.Scope {
	if creator == uuid.Nil || s.Mode != ModeEnforcing {
		return nil
	}
	groups := map[uuid.UUID]bool{}
	for _, m := range s.Memberships {
		if m.UserID == creator {
			groups[m.GroupID] = true
		}
	}
	resources := map[uuid.UUID]Resource{}
	for _, r := range s.Resources {
		resources[r.ID] = r
	}
	unique := map[sandboxscope.Scope]bool{}
	add := func(scope sandboxscope.Scope) {
		if scope.Validate() == nil {
			unique[scope] = true
		}
	}
	for _, r := range s.Rules {
		if r.Disabled {
			continue
		}
		matches := false
		switch r.SrcKind {
		case "user":
			matches = r.SrcUserID == creator
		case "group", "":
			matches = groups[r.SrcGroupID]
		}
		if !matches {
			continue
		}
		switch r.DstKind {
		case "resource":
			if res, ok := resources[r.DstResourceID]; ok && res.PortLow >= 0 && res.PortLow <= 65535 && res.PortHigh >= 0 && res.PortHigh <= 65535 {
				add(sandboxscope.Scope{CIDR: res.CIDR, Protocol: res.Protocol, PortLow: uint16(res.PortLow), PortHigh: uint16(res.PortHigh)})
			}
		case "site":
			for _, subnet := range s.SiteSubnets {
				if subnet.SiteID == r.DstSiteID {
					add(sandboxscope.Scope{CIDR: subnet.CIDR, Protocol: "any"})
				}
			}
		}
	}
	out := make([]sandboxscope.Scope, 0, len(unique))
	for tuple := range unique {
		out = append(out, tuple)
	}
	normalized, err := sandboxscope.NormalizeScope(out)
	if err != nil {
		return nil
	}
	return normalized
}

func expandSandboxProjection(s Snapshot) Snapshot {
	if s.Mode != ModeEnforcing || len(s.Sandboxes) == 0 {
		return s
	}
	s.Rules = append([]Rule(nil), s.Rules...)
	s.Resources = append([]Resource(nil), s.Resources...)
	peers := map[uuid.UUID]Device{}
	for _, d := range s.Devices {
		peers[d.ID] = d
	}
	ambiguous := map[uuid.UUID]bool{}
	seen := map[uuid.UUID]bool{}
	for _, p := range s.Sandboxes {
		if seen[p.DeviceID] {
			ambiguous[p.DeviceID] = true
		}
		seen[p.DeviceID] = true
	}
	for _, p := range s.Sandboxes {
		d, ok := peers[p.DeviceID]
		if !ok || ambiguous[p.DeviceID] || d.Kind != "sandbox" || d.UserID != p.CreatorID || p.SandboxID == uuid.Nil || p.CreatorID == uuid.Nil {
			continue
		}
		if p.RemoteTerminalGatewayID != uuid.Nil && (p.LocalTerminalGatewayID != uuid.Nil || p.RemoteRuntimeGatewayID == uuid.Nil || p.RemoteRuntimeGatewayID != d.NodeID || len(p.Requested) != 0) {
			continue
		}
		if p.LocalTerminalGatewayID != uuid.Nil && (p.TerminalDeviceID == uuid.Nil || len(p.Requested) != 0 || d.NodeID != p.LocalTerminalGatewayID) {
			continue
		}
		entitlement := CreatorStaticScope(s, p.CreatorID)
		for _, tuple := range sandboxscope.EffectiveScope(p.Requested, entitlement, p.TemplateCap) {
			id := uuid.NewSHA1(p.SandboxID, []byte(fmt.Sprintf("%s/%s/%d/%d", tuple.CIDR, tuple.Protocol, tuple.PortLow, tuple.PortHigh)))
			s.Resources = append(s.Resources, Resource{ID: id, CIDR: tuple.CIDR, Protocol: tuple.Protocol, PortLow: int(tuple.PortLow), PortHigh: int(tuple.PortHigh)})
			s.Rules = append(s.Rules, Rule{ID: id, SrcKind: "sandbox", SrcDeviceID: d.ID, DstKind: "resource", DstResourceID: id, sandboxProjected: true})
		}
		address, err := netip.ParseAddr(d.AssignedIP)
		if err != nil || !address.Is4() || !address.IsPrivate() || d.NodeID == uuid.Nil {
			continue
		}
		for _, human := range s.Devices {
			if (p.TerminalDeviceID != uuid.Nil && human.ID != p.TerminalDeviceID) || human.Kind != "human" || human.UserID != p.CreatorID || human.NodeID == uuid.Nil {
				continue
			}
			if p.LocalTerminalGatewayID != uuid.Nil && human.NodeID != p.LocalTerminalGatewayID {
				continue
			}
			if p.RemoteTerminalGatewayID != uuid.Nil && (human.NodeID != p.RemoteTerminalGatewayID || !s.CrossGatewayGraph.AllowsSandboxTerminal(human.NodeID, d.NodeID, human.AssignedIP, d.AssignedIP)) {
				continue
			}
			id := uuid.NewSHA1(p.SandboxID, []byte("terminal/"+human.ID.String()))
			s.Resources = append(s.Resources, Resource{ID: id, CIDR: address.String() + "/32", Protocol: "tcp", PortLow: 22, PortHigh: 22})
			s.Rules = append(s.Rules, Rule{ID: id, SrcKind: "sandbox_terminal", SrcDeviceID: human.ID, DstKind: "resource", DstResourceID: id, sandboxProjected: true, sandboxTerminalNode: d.NodeID, sandboxLocalTerminal: p.LocalTerminalGatewayID != uuid.Nil, sandboxScopedTerminal: p.RemoteTerminalGatewayID != uuid.Nil})
		}
	}
	return s
}
