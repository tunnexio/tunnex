//go:build linux

package ipsec

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Peer-emulator new flows only. These tuples do not authorize the enrolled gateway.
func validStandaloneReverseServices(c standalonePeerConfig) bool {
	if len(c.ReverseServices) == 0 {
		return true
	}
	if c.ProfileID != GCPClassicStaticProfile || len(c.ReverseServices) > 16 || len(c.CustomTunnels) != 1 || len(c.CustomTunnels[0].RemotePrefixes) != 1 {
		return false
	}
	seen := map[standalonePeerService]bool{}
	for _, s := range c.ReverseServices {
		if s.Source != c.LocalTarget || s.Destination != c.RemoteTarget || !s.Source.Is4() || !s.Destination.Is4() || !c.CustomTunnels[0].RemotePrefixes[0].Contains(s.Destination) || (s.Protocol != "tcp" && s.Protocol != "udp") || s.Port == 0 || seen[s] {
			return false
		}
		seen[s] = true
	}
	return true
}

func standaloneStaticReverseServiceRules(services []standalonePeerService, xfrm, lan, underlay int, reqid uint32, peer netip.Addr) string {
	var rules strings.Builder
	for _, s := range services {
		fmt.Fprintf(&rules, "insert rule inet tunnex_ipsec forward_guard meta iif %d meta oif %d ip saddr %s ip daddr %s %s dport %d accept\n", lan, xfrm, s.Source, s.Destination, s.Protocol, s.Port)
		fmt.Fprintf(&rules, "insert rule inet tunnex_ipsec forward_guard meta iif %d meta oif %d ip saddr %s ip daddr %s %s sport %d ipsec in reqid %d ct state established accept\n", xfrm, lan, s.Destination, s.Source, s.Protocol, s.Port, reqid)
		fmt.Fprintf(&rules, "insert rule inet tunnex_ipsec postrouting_guard meta oif %d ip saddr %s ip daddr %s %s dport %d ipsec out reqid %d accept\n", xfrm, s.Source, s.Destination, s.Protocol, s.Port, reqid)
		fmt.Fprintf(&rules, "insert rule inet tunnex_ipsec postrouting_guard meta oif %d ip saddr %s ip daddr %s %s dport %d ipsec out reqid %d ipsec out ip daddr %s counter accept\n", underlay, s.Source, s.Destination, s.Protocol, s.Port, reqid, peer)
	}
	return rules.String()
}

func TestStandaloneClassicReverseServices(t *testing.T) {
	c := standaloneGCPClassicFixture()
	c.ReverseServices = []standalonePeerService{{Source: c.LocalTarget, Destination: c.RemoteTarget, Protocol: "tcp", Port: 18081}, {Source: c.LocalTarget, Destination: c.RemoteTarget, Protocol: "udp", Port: 18082}}
	if !validStandalonePeer(c) {
		t.Fatal("exact reverse tuples refused")
	}
	for name, change := range map[string]func(*standalonePeerConfig){
		"different source":      func(c *standalonePeerConfig) { c.ReverseServices[0].Source = netip.MustParseAddr("10.20.0.3") },
		"different destination": func(c *standalonePeerConfig) { c.ReverseServices[0].Destination = netip.MustParseAddr("10.10.0.3") },
		"outside approved remote": func(c *standalonePeerConfig) {
			c.RemoteTarget = netip.MustParseAddr("10.99.0.2")
			c.ReverseServices[0].Destination = c.RemoteTarget
		},
		"IPv6":         func(c *standalonePeerConfig) { c.ReverseServices[0].Source = netip.MustParseAddr("2001:db8::1") },
		"any protocol": func(c *standalonePeerConfig) { c.ReverseServices[0].Protocol = "any" },
		"zero port":    func(c *standalonePeerConfig) { c.ReverseServices[0].Port = 0 },
		"duplicate":    func(c *standalonePeerConfig) { c.ReverseServices = append(c.ReverseServices, c.ReverseServices[0]) },
		"too many":     func(c *standalonePeerConfig) { c.ReverseServices = make([]standalonePeerService, 17) },
		"AWS":          func(c *standalonePeerConfig) { c.ProfileID = "" },
		"HA":           func(c *standalonePeerConfig) { c.ProfileID = GCPHABGPProfile },
	} {
		t.Run(name, func(t *testing.T) {
			changed := c
			changed.ReverseServices = append([]standalonePeerService(nil), c.ReverseServices...)
			change(&changed)
			if validStandalonePeer(changed) {
				t.Fatal("unscoped reverse tuple accepted")
			}
		})
	}
	bounded := c
	bounded.ReverseServices = make([]standalonePeerService, 16)
	for i := range bounded.ReverseServices {
		bounded.ReverseServices[i] = standalonePeerService{Source: c.LocalTarget, Destination: c.RemoteTarget, Protocol: "tcp", Port: uint16(10000 + i)}
	}
	if !validStandalonePeer(bounded) {
		t.Fatal("16 distinct exact tuples refused")
	}
	bounded.ReverseServices = append(bounded.ReverseServices, standalonePeerService{Source: c.LocalTarget, Destination: c.RemoteTarget, Protocol: "tcp", Port: 10016})
	if validStandalonePeer(bounded) {
		t.Fatal("17 distinct tuples accepted")
	}
	ha := standaloneGCPHAFixture()
	if !validStandalonePeer(ha) {
		t.Fatal("baseline HA refused")
	}
	ha.ReverseServices = []standalonePeerService{{Source: ha.LocalTarget, Destination: ha.RemoteTarget, Protocol: "tcp", Port: 18081}}
	if validStandalonePeer(ha) {
		t.Fatal("HA gained reverse fixture permission")
	}
	rules := standaloneStaticReverseServiceRules(c.ReverseServices, 8, 9, 10, c.CustomTunnels[0].ReqID, c.CustomTunnels[0].RemoteAddress)
	for _, want := range []string{"meta iif 9 meta oif 8 ip saddr 10.20.0.2 ip daddr 10.10.0.2 tcp dport 18081 accept", "udp dport 18082 ipsec out reqid", "tcp sport 18081 ipsec in reqid", "ct state established accept"} {
		if !strings.Contains(rules, want) {
			t.Fatal("reverse rule scope missing", want)
		}
	}
	if strings.Contains(rules, "10.10.0.0/24") || strings.Contains(rules, "10.20.0.0/24") {
		t.Fatal("reverse tuple widened to prefix")
	}
	if standaloneStaticReverseServiceRules(nil, 8, 9, 10, 1, c.CustomTunnels[0].RemoteAddress) != "" {
		t.Fatal("default reverse authority changed")
	}
}

// Native nft syntax/readback/restored permanent denial only; no packet proof claim.
func TestStandaloneClassicReverseServicesNative(t *testing.T) {
	if os.Getenv("TUNNEX_GCP_STANDALONE_REVERSE_SERVICES_LAB") != "1" {
		t.Skip("disposable native namespace only")
	}
	c := standaloneGCPClassicFixture()
	c.ReverseServices = []standalonePeerService{{Source: c.LocalTarget, Destination: c.RemoteTarget, Protocol: "tcp", Port: 18081}, {Source: c.LocalTarget, Destination: c.RemoteTarget, Protocol: "udp", Port: 18082}}
	if !validStandalonePeer(c) {
		t.Fatal("reverse tuple contract")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ns, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	guard, err := RenderGuard(GuardIntent{Namespace: ns, OwnerID: c.PeerGatewayID, Revision: 1, Connections: []GuardConnection{{ID: c.CustomTunnels[0].Binding.ConnectionID, PrefixOnly: true, Local: c.CustomTunnels[0].LocalPrefixes, Remote: c.CustomTunnels[0].RemotePrefixes}}})
	if err != nil {
		t.Fatal(err)
	}
	nft := func(text string) {
		t.Helper()
		cmd := exec.CommandContext(ctx, "/usr/sbin/nft", "-f", "-")
		cmd.Stdin = strings.NewReader(text)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("reverse nft: %v %s", err, out)
		}
	}
	nft(guard.NFT)
	nft(standaloneStaticReverseServiceRules(c.ReverseServices, 1, 1, 1, c.CustomTunnels[0].ReqID, c.CustomTunnels[0].RemoteAddress))
	raw, err := exec.CommandContext(ctx, "/usr/sbin/nft", "-nn", "list", "table", "inet", "tunnex_ipsec").Output()
	if err != nil || !bytes.Contains(raw, []byte("ip saddr 10.20.0.2 ip daddr 10.10.0.2 tcp dport 18081")) || !bytes.Contains(raw, []byte("udp dport 18082")) || !bytes.Contains(raw, []byte("tcp sport 18081 ipsec in reqid")) {
		t.Fatal("native reverse tuple readback")
	}
	nft(guard.NFT)
	reader, err := NewGuardReader("/usr/sbin/nft")
	if err != nil || reader.Check(ctx, guard) != nil {
		t.Fatal("reverse permission removal did not restore exact permanent denial")
	}
}
