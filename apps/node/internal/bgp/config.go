package bgp

import (
	"fmt"
	"net/netip"
	"strings"
)

type Peer struct {
	LinkName      string
	XFRMID        uint32
	Slot          int
	Local, Remote netip.Addr
}
type Config struct {
	LocalASN, RemoteASN           uint32
	RouterID                      netip.Addr
	MaximumPrefixes               int
	LocalPrefixes, RemotePrefixes []netip.Prefix
	PeerCount                     int // zero preserves the legacy two-peer contract
	Peers                         [2]Peer
}

func (c Config) activePeerCount() int {
	if c.PeerCount == 1 {
		return 1
	}
	return 2
}
func (c Config) valid() bool {
	if c.PeerCount != 0 && c.PeerCount != 1 || c.PeerCount == 1 && c.Peers[1] != (Peer{}) {
		return false
	}
	private := func(a uint32) bool { return a >= 64512 && a <= 65534 || a >= 4200000000 && a <= 4294967294 }
	if !private(c.LocalASN) || !(private(c.RemoteASN) || c.RemoteASN == 7224) || c.LocalASN == c.RemoteASN || !c.RouterID.Is4() || c.RouterID.As4()[0] == 0 || c.RouterID.IsLoopback() || c.RouterID.IsLinkLocalUnicast() || c.RouterID.As4()[0] >= 224 || c.MaximumPrefixes < 1 || c.MaximumPrefixes > 64 {
		return false
	}
	seen := []netip.Prefix{}
	for _, side := range [][]netip.Prefix{c.LocalPrefixes, c.RemotePrefixes} {
		if len(side) == 0 || len(side) > 64 {
			return false
		}
		for _, p := range side {
			if !p.IsValid() || !p.Addr().Is4() || p != p.Masked() || p.Bits() == 0 || p.Overlaps(netip.MustParsePrefix("169.254.0.0/16")) {
				return false
			}
			for _, old := range seen {
				if p.Overlaps(old) {
					return false
				}
			}
			seen = append(seen, p)
		}
	}
	for i, p := range c.Peers[:c.activePeerCount()] {
		if p.Slot != i+1 || !p.Local.Is4() || !p.Remote.Is4() || p.Local == p.Remote || !netip.MustParsePrefix("169.254.0.0/16").Contains(p.Local) || !netip.PrefixFrom(p.Local, 30).Contains(p.Remote) {
			return false
		}
		l, r := p.Local.As4(), p.Remote.As4()
		if l[3]&3 == 0 || l[3]&3 == 3 || r[3]&3 == 0 || r[3]&3 == 3 {
			return false
		}
	}
	return c.activePeerCount() == 1 || netip.PrefixFrom(c.Peers[0].Local, 30).Masked() != netip.PrefixFrom(c.Peers[1].Local, 30).Masked()
}

// RenderConfig emits bounded deterministic commands from typed intent only.
func RenderConfig(c Config) (string, error) {
	if !c.valid() {
		return "", ErrPackage
	}
	var b strings.Builder
	b.WriteString("hostname tunnex-bgp\n")
	for _, policy := range []struct {
		name     string
		prefixes []netip.Prefix
	}{{"TNX-IN", c.RemotePrefixes}, {"TNX-OUT", c.LocalPrefixes}} {
		name, prefixes := policy.name, policy.prefixes
		for i, p := range prefixes {
			fmt.Fprintf(&b, "ip prefix-list %s seq %d permit %s\n", name, (i+1)*10, p)
		}
		fmt.Fprintf(&b, "ip prefix-list %s seq 1000 deny 0.0.0.0/0 le 32\n", name)
	}
	b.WriteString("route-map TNX-IN permit 10\n match ip address prefix-list TNX-IN\nroute-map TNX-OUT permit 10\n match ip address prefix-list TNX-OUT\n")
	fmt.Fprintf(&b, "router bgp %d\n bgp router-id %s\n no bgp default ipv4-unicast\n", c.LocalASN, c.RouterID)
	for _, p := range c.Peers[:c.activePeerCount()] {
		fmt.Fprintf(&b, " neighbor %s remote-as %d\n neighbor %s update-source %s\n neighbor %s timers 10 30\n neighbor %s disable-connected-check\n", p.Remote, c.RemoteASN, p.Remote, p.Local, p.Remote, p.Remote)
	}
	b.WriteString(" address-family ipv4 unicast\n")
	for _, p := range c.LocalPrefixes {
		fmt.Fprintf(&b, "  network %s\n", p)
	}
	for _, p := range c.Peers[:c.activePeerCount()] {
		fmt.Fprintf(&b, "  neighbor %s activate\n  neighbor %s route-map TNX-IN in\n  neighbor %s route-map TNX-OUT out\n  neighbor %s maximum-prefix %d restart 1\n", p.Remote, p.Remote, p.Remote, p.Remote, c.MaximumPrefixes)
	}
	b.WriteString(" exit-address-family\n!\n")
	return b.String(), nil
}
