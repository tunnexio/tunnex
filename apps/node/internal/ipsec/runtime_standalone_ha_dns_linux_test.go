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
