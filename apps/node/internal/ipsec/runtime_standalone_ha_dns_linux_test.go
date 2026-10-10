//go:build linux

package ipsec

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

// Opt-in component-only addition: exactly one host's UDP/TCP DNS pair. Default
// HA and AWS configurations still refuse additional services and reverse grants.
func validStandaloneHADNSComponent(c standalonePeerConfig) bool {
	if !c.DNSOwnerComponent {
		return len(c.Services) == 0
	}
	if c.ProfileID != GCPHABGPProfile || len(c.Services) != 2 || !validStandaloneServices(c) {
		return false
	}
	a, b := c.Services[0], c.Services[1]
	return a.Source == b.Source && a.Destination == b.Destination && a.Port == 53 && b.Port == 53 && ((a.Protocol == "udp" && b.Protocol == "tcp") || (a.Protocol == "tcp" && b.Protocol == "udp"))
}

func standaloneHADNSServiceRules(c standalonePeerConfig, tunnels [2]Ownership, healthy [2]bool, selected, lan, underlay int) string {
	if !validStandaloneHADNSComponent(c) || !c.DNSOwnerComponent || selected < 0 || selected > 1 || !healthy[selected] {
		return ""
	}
	// Exact return route chooses one child. Incoming requests may arrive on either
	// independently observed healthy child; replies use only that owned route.
	out := standaloneStaticServiceRules(c.Services, tunnels[selected].InterfaceIndex, lan, underlay, c.CustomTunnels[selected].ReqID, c.CustomTunnels[selected].RemoteAddress)
	for slot, up := range healthy {
		if !up || slot == selected {
			continue
		}
		for _, service := range c.Services {
			out += fmt.Sprintf("insert rule inet tunnex_ipsec forward_guard meta iif %d meta oif %d ip saddr %s ip daddr %s %s dport 53 ipsec in reqid %d accept\n", tunnels[slot].InterfaceIndex, lan, service.Source, service.Destination, service.Protocol, c.CustomTunnels[slot].ReqID)
		}
	}
	return out
}

func standaloneHADNSFixture() standalonePeerConfig {
	c := standaloneGCPHAFixture()
	c.DNSOwnerComponent = true
	c.Services = []standalonePeerService{{Source: netip.MustParseAddr("10.10.0.1"), Destination: c.LocalTarget, Protocol: "udp", Port: 53}, {Source: netip.MustParseAddr("10.10.0.1"), Destination: c.LocalTarget, Protocol: "tcp", Port: 53}}
	return c
}
func TestStandaloneHADNSComponentContract(t *testing.T) {
	c := standaloneHADNSFixture()
	if !validStandalonePeer(c) || !validStandalonePeer(standaloneGCPHAFixture()) {
		t.Fatal("exact DNS component or default HA refused")
	}
	for name, mutate := range map[string]func(*standalonePeerConfig){
		"missing optin":    func(c *standalonePeerConfig) { c.DNSOwnerComponent = false },
		"single transport": func(c *standalonePeerConfig) { c.Services = c.Services[:1] },
		"duplicate":        func(c *standalonePeerConfig) { c.Services[1] = c.Services[0] },
		"other port":       func(c *standalonePeerConfig) { c.Services[0].Port = 9000 },
		"other source":     func(c *standalonePeerConfig) { c.Services[0].Source = netip.MustParseAddr("10.10.0.3") },
		"outside source": func(c *standalonePeerConfig) {
			for i := range c.Services {
				c.Services[i].Source = netip.MustParseAddr("10.99.0.1")
			}
		},
		"outside target": func(c *standalonePeerConfig) { c.Services[0].Destination = netip.MustParseAddr("10.99.0.1") },
		"reverse":        func(c *standalonePeerConfig) { c.ReverseServices = c.Services },
		"empty":          func(c *standalonePeerConfig) { c.Services = nil },
	} {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(c)
			var changed standalonePeerConfig
			_ = json.Unmarshal(raw, &changed)
			mutate(&changed)
			if validStandalonePeer(changed) {
				t.Fatal("widened component accepted")
			}
		})
	}
	classic := standaloneGCPClassicFixture()
	classic.DNSOwnerComponent = true
	if validStandalonePeer(classic) {
		t.Fatal("HA opt-in accepted by Classic")
	}
	aws := standaloneGCPHAFixture()
	aws.ProfileID, aws.Scenario = "", ""
	for i := range aws.CustomTunnels {
		aws.CustomTunnels[i].ProfileID = ""
	}
	if !validStandalonePeer(aws) {
		t.Fatal("default AWS fixture refused")
	}
	aws.DNSOwnerComponent = true
	if validStandalonePeer(aws) {
		t.Fatal("HA opt-in accepted by AWS")
	}
}
func TestStandaloneHADNSRulesUseSelectedReturnAndHealthyIngress(t *testing.T) {
	c := standaloneHADNSFixture()
	tunnels := [2]Ownership{{InterfaceIndex: 8}, {InterfaceIndex: 9}}
	for selected := 0; selected < 2; selected++ {
		rules := standaloneHADNSServiceRules(c, tunnels, [2]bool{true, true}, selected, 10, 11)
		for _, slot := range []int{0, 1} {
			for _, protocol := range []string{"udp", "tcp"} {
				want := fmt.Sprintf("meta iif %d meta oif 10 ip saddr 10.10.0.1 ip daddr 10.20.0.2 %s dport 53 ipsec in reqid %d", tunnels[slot].InterfaceIndex, protocol, c.CustomTunnels[slot].ReqID)
				if !strings.Contains(rules, want) {
					t.Fatal("missing healthy exact ingress", want)
				}
			}
		}
		if strings.Contains(rules, fmt.Sprintf("ipsec out reqid %d", c.CustomTunnels[1-selected].ReqID)) {
			t.Fatal("reply allowed on unselected child")
		}
		if !strings.Contains(rules, fmt.Sprintf("ipsec out reqid %d ipsec out ip daddr %s", c.CustomTunnels[selected].ReqID, c.CustomTunnels[selected].RemoteAddress)) {
			t.Fatal("missing exact selected encrypted return")
		}
		only := [2]bool{}
		only[selected] = true
		rules = standaloneHADNSServiceRules(c, tunnels, only, selected, 10, 11)
		if strings.Contains(rules, fmt.Sprintf("meta iif %d meta oif 10", tunnels[1-selected].InterfaceIndex)) {
			t.Fatal("down child allowed DNS ingress")
		}
	}
	if standaloneHADNSServiceRules(c, tunnels, [2]bool{}, 0, 10, 11) != "" {
		t.Fatal("no healthy route yielded rules")
	}
}

// DNS-only peer control and services share the production atomic typed renderer.
func standaloneHADNSManifest(c standalonePeerConfig, base GuardIntent, healthy [2]bool, selected, lan, underlay int) (GuardManifest, error) {
	if !validStandaloneHADNSComponent(c) || !c.DNSOwnerComponent || len(base.Connections) != 1 || selected < 0 || selected > 1 || !healthy[selected] || lan <= 0 || underlay <= 0 {
		return GuardManifest{}, ErrGuardIntent
	}
	base.Connections = append([]GuardConnection(nil), base.Connections...)
	g := &base.Connections[0]
	g.PermittedInterfaceIndices = []int{g.Tunnels[0].InterfaceIndex, g.Tunnels[1].InterfaceIndex}
	g.LocalIngressIndices = []int{lan}
	g.ReplyIngressIndices = nil
	for slot, up := range healthy {
		if up {
			g.ReplyIngressIndices = append(g.ReplyIngressIndices, g.Tunnels[slot].InterfaceIndex)
		}
	}
	g.EncryptedEgress = []GuardEncryptedEgress{{TunnelInterfaceIndex: g.Tunnels[selected].InterfaceIndex, ReqID: c.CustomTunnels[selected].ReqID, Peer: c.CustomTunnels[selected].RemoteAddress, UnderlayInterfaceIndex: underlay}}
	g.Grants = nil
	for _, service := range c.Services {
		g.Grants = append(g.Grants, GuardGrant{Source: netip.PrefixFrom(service.Source, 32), Destination: netip.PrefixFrom(service.Destination, 32), Protocol: GuardProtocol(service.Protocol), PortLow: 53, PortHigh: 53})
	}
	manifest, err := RenderGuard(base)
	if err != nil {
		return GuardManifest{}, err
	}
	// Both BGP controls remain permitted. DNS reply and remote LAN egress are
	// restricted to the exact independently verified selected return route.
	unwanted := g.Tunnels[1-selected].InterfaceIndex
	keep := func(rule map[string]any) bool {
		expr, _ := rule["expr"].([]any)
		oif, dnsReply, lanDestination := false, false, false
		for _, item := range expr {
			object, _ := item.(map[string]any)
			match, _ := object["match"].(map[string]any)
			left, _ := match["left"].(map[string]any)
			meta, _ := left["meta"].(map[string]any)
			if meta["key"] == "oif" && match["op"] == "==" && match["right"] == float64(unwanted) {
				oif = true
			}
			payload, _ := left["payload"].(map[string]any)
			if payload["field"] == "sport" && match["right"] == float64(53) {
				dnsReply = true
			}
			if payload["protocol"] == "ip" && payload["field"] == "daddr" {
				right, _ := match["right"].(map[string]any)
				prefix, _ := right["prefix"].(map[string]any)
				if prefix["addr"] == g.Remote[0].Addr().String() && prefix["len"] == float64(g.Remote[0].Bits()) {
					lanDestination = true
				}
			}
		}
		return !(oif && (dnsReply || rule["chain"] == "postrouting_guard" && lanDestination))
	}
	prune := func(raw string, transaction bool) (string, error) {
		var doc map[string][]map[string]any
		if err := json.Unmarshal([]byte(raw), &doc); err != nil {
			return "", err
		}
		out := doc["nftables"][:0]
		for _, object := range doc["nftables"] {
			value := object
			if transaction {
				if add, ok := object["add"].(map[string]any); ok {
					value = add
				}
			}
			rule, ok := value["rule"].(map[string]any)
			if !ok || keep(rule) {
				out = append(out, object)
			}
		}
		doc["nftables"] = out
		encoded, err := json.Marshal(doc)
		return string(encoded), err
	}
	manifest.NFT = "" // Only the pruned atomic JSON transaction is safe to apply.
	manifest.NFTJSON, err = prune(manifest.NFTJSON, true)
	if err != nil {
		return GuardManifest{}, err
	}
	manifest.ExpectedJSON, err = prune(manifest.ExpectedJSON, false)
	return manifest, err
}

func TestStandaloneHADNSAtomicManifestSelection(t *testing.T) {
	c := standaloneHADNSFixture()
	base := guardFixture()
	g := &base.Connections[0]
	g.Local, g.Remote = c.BGPConfig.LocalPrefixes, c.BGPConfig.RemotePrefixes
	g.Grants = nil
	g.BGPPeers = []GuardBGPPeer{{Local: c.BGPConfig.Peers[0].Local, Remote: c.BGPConfig.Peers[0].Remote, InterfaceIndex: g.Tunnels[0].InterfaceIndex}, {Local: c.BGPConfig.Peers[1].Local, Remote: c.BGPConfig.Peers[1].Remote, InterfaceIndex: g.Tunnels[1].InterfaceIndex}}
	for selected := 0; selected < 2; selected++ {
		m, err := standaloneHADNSManifest(c, base, [2]bool{true, true}, selected, 2, 3)
		if err != nil {
			t.Fatal(err)
		}
		if VerifyGuardReadback([]byte(m.ExpectedJSON), []byte(m.ExpectedJSON)) != nil {
			t.Fatal("invalid full expected guard")
		}
		var doc map[string][]map[string]any
		if json.Unmarshal([]byte(m.ExpectedJSON), &doc) != nil {
			t.Fatal("invalid manifest")
		}
		controls, replies, encrypted := 0, 0, 0
		for _, object := range doc["nftables"] {
			rule, ok := object["rule"].(map[string]any)
			if !ok {
				continue
			}
			expr, _ := rule["expr"].([]any)
			reply, oif, remoteLAN := false, float64(0), false
			reqid, outerPeer := false, false
			for _, item := range expr {
				object, _ := item.(map[string]any)
				match, _ := object["match"].(map[string]any)
				left, _ := match["left"].(map[string]any)
				meta, _ := left["meta"].(map[string]any)
				if meta["key"] == "oif" {
					if n, ok := match["right"].(float64); ok {
						oif = n
					}
				}
				payload, _ := left["payload"].(map[string]any)
				ipsec, _ := left["ipsec"].(map[string]any)
				if ipsec["dir"] == "out" && ipsec["key"] == "reqid" && match["right"] == float64(c.CustomTunnels[selected].ReqID) {
					reqid = true
				}
				if ipsec["dir"] == "out" && ipsec["key"] == "daddr" && match["right"] == c.CustomTunnels[selected].RemoteAddress.String() {
					outerPeer = true
				}
				if payload["protocol"] == "ip" && payload["field"] == "daddr" {
					right, _ := match["right"].(map[string]any)
					prefix, _ := right["prefix"].(map[string]any)
					remoteLAN = remoteLAN || prefix["addr"] == g.Remote[0].Addr().String() && prefix["len"] == float64(g.Remote[0].Bits())
				}

				if payload["field"] == "sport" && match["right"] == float64(53) {
					reply = true
				}
				if (payload["field"] == "sport" || payload["field"] == "dport") && match["right"] == float64(179) {
					controls++
				}
			}
			if rule["chain"] == "postrouting_guard" && remoteLAN && oif == float64(g.Tunnels[1-selected].InterfaceIndex) {
				t.Fatal("unselected remote LAN postrouting permission retained")
			}
			if reqid && outerPeer {
				encrypted++
			}
			if reply {
				replies++
				if oif != float64(g.Tunnels[selected].InterfaceIndex) {
					t.Fatal("DNS reply escaped selected route")
				}
			}
		}
		if replies != 2 || controls != 8 || encrypted != 1 {
			t.Fatalf("exact UDP/TCP replies and both BGP controls required: %d %d", replies, controls)
		}

		healthy := [2]bool{}
		healthy[selected] = true
		only, err := standaloneHADNSManifest(c, base, healthy, selected, 2, 3)
		if err != nil {
			t.Fatal(err)
		}
		if json.Unmarshal([]byte(only.ExpectedJSON), &doc) != nil {
			t.Fatal("invalid one-healthy guard")
		}
		for _, object := range doc["nftables"] {
			rule, _ := object["rule"].(map[string]any)
			expr, _ := rule["expr"].([]any)
			dnsRequest, downIngress := false, false
			for _, item := range expr {
				object, _ := item.(map[string]any)
				match, _ := object["match"].(map[string]any)
				left, _ := match["left"].(map[string]any)
				meta, _ := left["meta"].(map[string]any)
				payload, _ := left["payload"].(map[string]any)
				downIngress = downIngress || meta["key"] == "iif" && match["right"] == float64(g.Tunnels[1-selected].InterfaceIndex)
				dnsRequest = dnsRequest || payload["field"] == "dport" && match["right"] == float64(53)
			}
			if dnsRequest && downIngress {
				t.Fatal("down child admitted DNS request")
			}
		}
	}
	if len(base.Connections[0].Grants) != 0 {
		t.Fatal("base control guard mutated")
	}
	if _, err := standaloneHADNSManifest(c, base, [2]bool{}, 0, 2, 3); err == nil {
		t.Fatal("down selected route accepted")
	}
}
