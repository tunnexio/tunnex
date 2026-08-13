package devices

import (
	"reflect"
	"strings"
	"testing"
)

// TestAllowedIPsForNeverBakesRoutedRanges (S8.5 D5 twin-golden, ruling A) — the mint-time device config is
// the STABLE CORE ONLY: split = [pool], full = [0.0.0.0/0, ::/0]. Routed ranges are NEVER baked at mint —
// they ride the RoutedRangesMonitor poll. So allowedIPsFor is byte-identical for ALL orgs, CATEGORICALLY:
// its signature has no ranges input, so it structurally cannot include them. The feature is config-tier-
// free (the two-tier model — identity baked, routes polled — holds at the mint seam). Gateway-artifact
// hash-blindness (the golden's other side) is covered by TestRequiredVersionRoutesTriggerV5 (a routed
// range IS an approved site subnet → a Route → hash-blind).
func TestAllowedIPsForNeverBakesRoutedRanges(t *testing.T) {
	if got := allowedIPsFor(false, false, "10.99.0.0/24"); !reflect.DeepEqual(got, []string{"10.99.0.0/24"}) {
		t.Fatalf("split-tunnel mint must be the pool ONLY (no baked ranges): got %v", got)
	}
	if got := allowedIPsFor(true, true, "10.99.0.0/24"); !reflect.DeepEqual(got, []string{"0.0.0.0/0", "::/0"}) {
		t.Fatalf("full-tunnel mint must be the default routes only: got %v", got)
	}
}

func TestDeviceAddressCIDRMatchesFreshProfileAddress(t *testing.T) {
	if got := deviceAddressCIDR("10.99.0.2"); got != "10.99.0.2/32" {
		t.Fatalf("mode response address = %q, want host CIDR", got)
	}
	if got := deviceAddressCIDR(""); got != "" {
		t.Fatalf("empty allocation address = %q, want empty", got)
	}
}

func TestBuildConfigSplitTunnel(t *testing.T) {
	conf := buildConfig(configParams{
		address:      "10.99.0.2",
		privateKey:   "PRIVKEY==",
		serverPubKey: "SERVERPUB==",
		endpoint:     "gw.example.com:51820",
		allowedIPs:   allowedIPsFor(false, false, "10.99.0.0/24"),
	})
	for _, want := range []string{
		"[Interface]", "PrivateKey = PRIVKEY==", "Address = 10.99.0.2/32", "MTU = 1420",
		"[Peer]", "PublicKey = SERVERPUB==", "Endpoint = gw.example.com:51820",
		"AllowedIPs = 10.99.0.0/24", "PersistentKeepalive = 25",
	} {
		if !strings.Contains(conf, want) {
			t.Fatalf("config missing %q:\n%s", want, conf)
		}
	}
	if strings.Contains(conf, "0.0.0.0/0") {
		t.Fatal("split-tunnel config must not route all traffic")
	}
	if strings.Contains(conf, "DNS =") {
		t.Fatal("split-tunnel config should not force a DNS server")
	}
}

func TestBuildConfigFullTunnel(t *testing.T) {
	conf := buildConfig(configParams{
		address: "10.99.0.2", privateKey: "k", serverPubKey: "s",
		endpoint: "h:51820", allowedIPs: allowedIPsFor(true, true, "10.99.0.0/24"),
		dns: dnsFor(true),
	})
	// Full-tunnel MUST cover BOTH families or IPv6 leaks (and the client kill-switch
	// rejects it as incomplete_full_tunnel).
	if !strings.Contains(conf, "AllowedIPs = 0.0.0.0/0, ::/0") {
		t.Fatalf("full-tunnel config must route BOTH 0.0.0.0/0 AND ::/0:\n%s", conf)
	}
	if !strings.Contains(conf, "DNS = "+fullTunnelDNS) {
		t.Fatalf("full-tunnel config must set a DNS server:\n%s", conf)
	}
}

func TestBuildConfigIPv4OnlyFullTunnel(t *testing.T) {
	conf := buildConfig(configParams{
		address: "10.99.0.2", privateKey: "k", serverPubKey: "s",
		endpoint: "h:51820", allowedIPs: allowedIPsFor(true, false, "10.99.0.0/24"),
		dns: dnsFor(true),
	})
	if !strings.Contains(conf, "AllowedIPs = 0.0.0.0/0") || strings.Contains(conf, "AllowedIPs = 0.0.0.0/0, ::/0") {
		t.Fatalf("IPv4-only full-tunnel must carry only the IPv4 default route:\n%s", conf)
	}
}
