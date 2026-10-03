package nodes

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/gatewaymesh"
	"github.com/tunnexio/tunnex/apps/api/internal/policy"
)

// Export the actual compiler/finalizer projections for an explicitly supplied
// disposable live fixture. Private keys never enter the control-plane fixture.
func TestCrossGatewayExportLiveFixture(t *testing.T) {
	input := os.Getenv("TUNNEX_GATEWAY_FIXTURE_INPUT")
	output := os.Getenv("TUNNEX_GATEWAY_FIXTURE_OUTPUT")
	if input == "" || output == "" {
		t.Skip("requires explicit live fixture paths")
	}
	var cfg struct {
		Gateways []struct{ Role, ID, Key, Endpoint, Address string }
		Clients  []struct{ Role, Key, Kind, Address, IPv6Address, Gateway, Transport string }
	}
	body, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, &cfg); err != nil {
		t.Fatal(err)
	}
	var carriers []gatewaymesh.Gateway
	ids := map[string]uuid.UUID{}
	for _, g := range cfg.Gateways {
		id := uuid.MustParse(g.ID)
		ids[g.Role] = id
		carriers = append(carriers, gatewaymesh.Gateway{ID: id, PublicKey: g.Key, Endpoint: g.Endpoint})
	}
	result := map[string]map[string]DesiredState{}
	for _, stage := range []string{"off", "deny", "allow", "grant_removed", "revoked", "moved", "no_carrier"} {
		clients := []gatewaymesh.Client{}
		devices := []policy.Device{}
		deviceKeys := map[uuid.UUID]string{}
		sourceUser, sourceDevice, resource := uuid.New(), uuid.New(), uuid.New()
		for i, c := range cfg.Clients {
			if i == 1 && stage == "revoked" {
				continue
			}
			owner := ids[c.Gateway]
			if stage == "moved" && i == 1 {
				owner = ids[cfg.Clients[0].Gateway]
			}
			id, user := uuid.New(), uuid.New()
			if i == 0 {
				id = sourceDevice
				user = sourceUser
			}
			clients = append(clients, gatewaymesh.Client{NodeID: owner, Address: c.Address, IPv6Address: c.IPv6Address})
			devices = append(devices, policy.Device{ID: id, UserID: user, NodeID: owner, AssignedIP: c.Address, Kind: c.Kind})
			deviceKeys[id] = c.Key
		}
		gateways := append([]gatewaymesh.Gateway(nil), carriers...)
		if stage == "no_carrier" {
			for i := range gateways {
				gateways[i].Endpoint = ""
			}
		}
		graph, err := gatewaymesh.Build(stage != "off", gateways, clients, nil)
		if err != nil {
			t.Fatal(err)
		}
		snapshot := policy.Snapshot{Mode: policy.ModeEnforcing, CrossGatewayGraph: graph, Devices: devices, Resources: []policy.Resource{{ID: resource, CIDR: cfg.Clients[1].Address + "/32", Protocol: "tcp", PortLow: 8080, PortHigh: 8080}}}
		if stage == "off" {
			snapshot.Mode = policy.ModeOff
		}
		if stage == "allow" || stage == "moved" || stage == "revoked" || stage == "no_carrier" {
			rule := policy.Rule{ID: uuid.New(), SrcKind: "user", SrcUserID: sourceUser, DstKind: "resource", DstResourceID: resource}
			if cfg.Clients[0].Kind == "agent" {
				rule.SrcKind = "agent"
				rule.SrcUserID = uuid.Nil
				rule.SrcDeviceID = sourceDevice
			}
			snapshot.Rules = []policy.Rule{rule}
			if cfg.Clients[0].IPv6Address != "" && cfg.Clients[1].IPv6Address != "" {
				v6Resource := uuid.New()
				snapshot.Resources = append(snapshot.Resources, policy.Resource{ID: v6Resource, CIDR: cfg.Clients[1].IPv6Address + "/128", Protocol: "tcp", PortLow: 8080, PortHigh: 8080})
				v6Rule := rule
				v6Rule.ID = uuid.New()
				v6Rule.DstResourceID = v6Resource
				snapshot.Rules = append(snapshot.Rules, v6Rule)
			}

		}
		compiled := policy.Compile(snapshot)
		states := map[string]DesiredState{}
		for _, g := range cfg.Gateways {
			id := ids[g.Role]
			pol := compiled[id]
			if pol.NodeID == "" {
				pol.NodeID = id.String()
				pol.Mode = snapshot.Mode
				pol.Mesh = snapshot.Mode == policy.ModeOff
			}
			final := (&Service{}).finalizeArtifact(siteTopology{clientGraph: graph, poolCIDR: "10.99.0.0/24"}, sqlc.Node{ID: id}, &pol)
			ds := DesiredState{NodeID: id.String(), ListenPort: 51820, MTU: 1380, InterfaceAddress: g.Address, Policy: final, ProtocolVersion: ProtocolVersion}
			for _, d := range devices {
				if d.NodeID == id {
					prefixes := []string{d.AssignedIP + "/32"}
					for _, c := range clients {
						if c.Address == d.AssignedIP && c.IPv6Address != "" {
							prefixes = append(prefixes, c.IPv6Address+"/128")
						}
					}
					if deviceKeys[d.ID] != "" {
						ds.Peers = append(ds.Peers, Peer{PublicKey: deviceKeys[d.ID], AllowedIPs: prefixes})
					}
				}
			}
			for _, c := range cfg.Clients {
				if c.Transport == "openvpn" {
					owner := ids[c.Gateway]
					if stage == "moved" && c.Role == cfg.Clients[1].Role {
						owner = ids[cfg.Clients[0].Gateway]
					}
					if owner == id {
						ds.OVPNEnabled = true
						if stage != "revoked" || c.Role != cfg.Clients[1].Role {
							ds.OVPNClients = append(ds.OVPNClients, OVPNClient{CommonName: c.Role, IP: c.Address})
						}
					}
				}
			}
			for _, p := range graph.Peers(id) {
				ds.Peers = append(ds.Peers, Peer{PublicKey: p.PublicKey, Endpoint: p.Endpoint, AllowedIPs: p.Prefixes, SiteLink: true, PersistentKeepalive: 25})
			}
			states[g.Role] = ds
		}
		result[stage] = states
	}
	body, err = json.MarshalIndent(result, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output, body, 0600); err != nil {
		t.Fatal(err)
	}
}
