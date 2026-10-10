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

// Exact peer-emulator requests, never enrolled-gateway policy authority.
type standalonePeerService struct {
	Source      netip.Addr `json:"source"`
	Destination netip.Addr `json:"destination"`
	Protocol    string     `json:"protocol"`
	Port        uint16     `json:"port"`
}

func validStandaloneServices(c standalonePeerConfig) bool {
	if len(c.Services) > 16 {
		return false
	}
	seen := map[standalonePeerService]bool{}
	seen[standalonePeerService{Source: c.RemoteTarget, Destination: c.LocalTarget, Protocol: "tcp", Port: 18080}] = true
	for _, s := range c.Services {
		if !s.Source.Is4() || s.Source.IsUnspecified() || s.Source.IsMulticast() || !c.CustomTunnels[0].RemotePrefixes[0].Contains(s.Source) || s.Source == c.CustomTunnels[0].RemotePrefixes[0].Addr() || s.Destination != c.LocalTarget || (s.Protocol != "tcp" && s.Protocol != "udp") || s.Port == 0 || seen[s] {
			return false
		}
		seen[s] = true
	}
	return validStandaloneReverseServices(c)
}

// This bit is local to the disposable peer namespace. XFRM scrubs conntrack
// before recursive physical egress, but preserves skb marks and copies them to
// fragments. Associate a UDP reply before that scrub, never from fragment bytes.
const standaloneUDPReplyBit = "0x40000000"

func standaloneStaticServiceRules(services []standalonePeerService, xfrm, lan, underlay int, reqid uint32, peer netip.Addr) string {
	var rules strings.Builder
	for _, s := range services {
		fmt.Fprintf(&rules, "insert rule inet tunnex_ipsec forward_guard meta iif %d meta oif %d ip saddr %s ip daddr %s %s dport %d ipsec in reqid %d accept\n", xfrm, lan, s.Source, s.Destination, s.Protocol, s.Port, reqid)
		fmt.Fprintf(&rules, "insert rule inet tunnex_ipsec forward_guard meta iif %d meta oif %d ip saddr %s ip daddr %s %s sport %d ct state established accept\n", lan, xfrm, s.Destination, s.Source, s.Protocol, s.Port)
		if s.Protocol == "udp" {
			fmt.Fprintf(&rules, "insert rule inet tunnex_ipsec postrouting_guard meta oif %d ip saddr %s ip daddr %s ct direction reply ct state established ct protocol udp ct original ip saddr %s ct original ip daddr %s ct original proto-dst %d meta mark set meta mark | %s accept\n", xfrm, s.Destination, s.Source, s.Source, s.Destination, s.Port, standaloneUDPReplyBit)
			fmt.Fprintf(&rules, "insert rule inet tunnex_ipsec postrouting_guard meta oif %d ip saddr %s ip daddr %s meta mark & %s == %s ipsec out reqid %d ipsec out ip daddr %s counter accept\n", underlay, s.Destination, s.Source, standaloneUDPReplyBit, standaloneUDPReplyBit, reqid, peer)
			// Insert executes in reverse emission order: clear before any service accepts.
			// This prevents a prior mark from authorizing an unrelated reply tuple.
			fmt.Fprintf(&rules, "insert rule inet tunnex_ipsec forward_guard meta iif %d meta oif %d ip saddr %s ip daddr %s meta mark set meta mark & 0xbfffffff\n", lan, xfrm, s.Destination, s.Source)
		} else {
			fmt.Fprintf(&rules, "insert rule inet tunnex_ipsec postrouting_guard meta oif %d ip saddr %s ip daddr %s %s sport %d ipsec out reqid %d accept\n", xfrm, s.Destination, s.Source, s.Protocol, s.Port, reqid)
			fmt.Fprintf(&rules, "insert rule inet tunnex_ipsec postrouting_guard meta oif %d ip saddr %s ip daddr %s %s sport %d ipsec out reqid %d ipsec out ip daddr %s counter accept\n", underlay, s.Destination, s.Source, s.Protocol, s.Port, reqid, peer)
		}
	}
	return rules.String()
}

func TestStandaloneClassicUDPReplyFragmentScope(t *testing.T) {
	service := standalonePeerService{Source: netip.MustParseAddr("10.10.0.3"), Destination: netip.MustParseAddr("10.20.0.2"), Protocol: "udp", Port: 9000}
	rules := standaloneStaticServiceRules([]standalonePeerService{service}, 8, 9, 10, 701, netip.MustParseAddr("198.51.100.10"))
	var post []string
	for _, line := range strings.Split(rules, "\n") {
		if strings.Contains(line, "postrouting_guard") {
			post = append(post, line)
		}
	}
	if len(post) != 2 {
		t.Fatal("exact XFRM/underlay reply predicates required")
	}
	for _, wanted := range []string{"meta oif 8", "ip saddr 10.20.0.2 ip daddr 10.10.0.3", "ct direction reply", "ct state established", "ct protocol udp", "ct original ip saddr 10.10.0.3", "ct original ip daddr 10.20.0.2", "ct original proto-dst 9000", "meta mark set meta mark | 0x40000000"} {
		if !strings.Contains(post[0], wanted) {
			t.Fatalf("pre-XFRM service association missing %s", wanted)
		}
	}
	for _, wanted := range []string{"meta oif 10", "ip saddr 10.20.0.2 ip daddr 10.10.0.3", "meta mark & 0x40000000 == 0x40000000", "ipsec out reqid 701", "ipsec out ip daddr 198.51.100.10"} {
		if !strings.Contains(post[1], wanted) {
			t.Fatalf("encrypted fragment association missing %s", wanted)
		}
	}
	for _, line := range post {
		if strings.Contains(line, "udp sport") || strings.Contains(line, "frag-off") {
			t.Fatal("fragment payload or blanket fragment permission")
		}
	}
	if !strings.HasSuffix(strings.TrimSpace(rules), "meta mark set meta mark & 0xbfffffff") {
		t.Fatal("association must clear before reverse-inserted forward acceptance")
	}
	service.Protocol = "tcp"
	service.Port = 18080
	tcp := standaloneStaticServiceRules([]standalonePeerService{service}, 8, 9, 10, 701, netip.MustParseAddr("198.51.100.10"))
	if strings.Contains(tcp, "meta mark") || strings.Contains(tcp, "ct original") || !strings.Contains(tcp, "tcp sport 18080 ipsec out reqid 701") {
		t.Fatal("legacy TCP default changed")
	}
}

func TestStandaloneClassicExactServices(t *testing.T) {
	c := standaloneGCPClassicFixture()
	c.Services = []standalonePeerService{{Source: netip.MustParseAddr("10.10.0.3"), Destination: c.LocalTarget, Protocol: "udp", Port: 53}, {Source: netip.MustParseAddr("10.10.0.3"), Destination: c.LocalTarget, Protocol: "tcp", Port: 53}}
	if !validStandalonePeer(c) {
		t.Fatal("exact DNS source services refused")
	}
	rules := standaloneStaticServiceRules(c.Services, 8, 9, 10, c.CustomTunnels[0].ReqID, c.CustomTunnels[0].RemoteAddress)
	if !strings.Contains(rules, "ip saddr 10.10.0.3 ip daddr 10.20.0.2 udp dport 53 ipsec in reqid") || !strings.Contains(rules, "tcp dport 53") || strings.Contains(rules, "10.10.0.0/24") || strings.Contains(rules, "10.20.0.0/24") {
		t.Fatal("exact source/target/protocol/port scope changed")
	}
	for name, change := range map[string]func(*standalonePeerConfig){
		"outside source": func(c *standalonePeerConfig) { c.Services[0].Source = netip.MustParseAddr("10.99.0.2") },
		"wrong target":   func(c *standalonePeerConfig) { c.Services[0].Destination = netip.MustParseAddr("10.20.0.3") },
		"IPv6":           func(c *standalonePeerConfig) { c.Services[0].Source = netip.MustParseAddr("2001:db8::1") },
		"any protocol":   func(c *standalonePeerConfig) { c.Services[0].Protocol = "any" },
		"zero port":      func(c *standalonePeerConfig) { c.Services[0].Port = 0 },
		"duplicate":      func(c *standalonePeerConfig) { c.Services = append(c.Services, c.Services[0]) },
		"unbounded":      func(c *standalonePeerConfig) { c.Services = make([]standalonePeerService, 17) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := c
			changed.Services = append([]standalonePeerService(nil), c.Services...)
			change(&changed)
			if validStandalonePeer(changed) {
				t.Fatal("unscoped peer service accepted")
			}
		})
	}
}

// Syntax/readback component only, with no SAs or application-traffic claim.
func TestStandaloneClassicServicesNative(t *testing.T) {
	if os.Getenv("TUNNEX_GCP_STANDALONE_SERVICES_LAB") != "1" {
		t.Skip("disposable native namespace only")
	}
	c := standaloneGCPClassicFixture()
	c.Services = []standalonePeerService{{Source: netip.MustParseAddr("10.10.0.3"), Destination: c.LocalTarget, Protocol: "udp", Port: 53}, {Source: netip.MustParseAddr("10.10.0.3"), Destination: c.LocalTarget, Protocol: "tcp", Port: 53}}
	if !validStandalonePeer(c) {
		t.Fatal("exact services")
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
	runNFT := func(text string) {
		t.Helper()
		cmd := exec.CommandContext(ctx, "/usr/sbin/nft", "-f", "-")
		cmd.Stdin = bytes.NewBufferString(text)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("scoped service nft: %v %s", err, out)
		}
	}
	runNFT(guard.NFT)
	runNFT(standaloneStaticServiceRules(c.Services, 1, 1, 1, c.CustomTunnels[0].ReqID, c.CustomTunnels[0].RemoteAddress))
	raw, err := exec.CommandContext(ctx, "/usr/sbin/nft", "-nn", "list", "table", "inet", "tunnex_ipsec").Output()
	if err != nil || !bytes.Contains(raw, []byte("ip saddr 10.10.0.3 ip daddr 10.20.0.2 udp dport 53")) || !bytes.Contains(raw, []byte("ip saddr 10.10.0.3 ip daddr 10.20.0.2 tcp dport 53")) {
		t.Fatal("native exact DNS tuple readback")
	}
	// Readback verifies real nft evaluation order and association constraints;
	// packet-level SA/fragment negatives belong to the managed peer lab.
	text := string(raw)
	clearAt := strings.Index(text, "meta mark set meta mark & 0xbfffffff")
	forwardAcceptAt := strings.Index(text, "udp sport 53 ct state 0x2 accept")
	if clearAt < 0 || forwardAcceptAt < 0 || clearAt > forwardAcceptAt {
		t.Fatal("native premasked reply must clear association before acceptance")
	}
	for _, required := range []string{"ct direction 1 ct state 0x2 ct protocol 17", "ct original ip saddr 10.10.0.3 ct original ip daddr 10.20.0.2 ct original proto-dst 53", "meta mark set meta mark | 0x40000000", "meta mark & 0x40000000 == 0x40000000", fmt.Sprintf("ipsec out reqid %d ipsec out ip daddr %s", c.CustomTunnels[0].ReqID, c.CustomTunnels[0].RemoteAddress)} {
		if !strings.Contains(text, required) {
			t.Fatalf("native association constraint missing %s", required)
		}
	}
	if strings.Count(text, "meta mark set meta mark | 0x40000000") != 1 || strings.Contains(guard.NFT, "meta mark") {
		t.Fatal("association writer must be unique, exact CT service only")
	}
	runNFT(guard.NFT)
	reader, err := NewGuardReader("/usr/sbin/nft")
	if err != nil || reader.Check(ctx, guard) != nil {
		t.Fatal("native service denial restoration")
	}
}
