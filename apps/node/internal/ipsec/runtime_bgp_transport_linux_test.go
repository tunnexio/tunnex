//go:build linux

package ipsec

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestBGPTransportLinuxOwnedPeers(t *testing.T) {
	if os.Getenv("TUNNEX_IPSEC_BGP_TRANSPORT_LAB") != "1" {
		t.Skip("disconnected disposable namespace only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	e := bgpEntryFixture(t)
	p := e.Allocation
	p.Namespace, _ = os.Readlink("/proc/self/ns/net")
	a, err := NewKernelApplier("/sbin/ip")
	if err != nil {
		t.Fatal(err)
	}
	own, err := a.Apply(ctx, p, [2]Ownership{})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := a.snapshot(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	for i, tunnel := range p.Tunnels {
		if len(snapshot.routes[i]) != 1 || !snapshot.routes[i][netip.PrefixFrom(tunnel.BGP.Peer, 32)] {
			t.Fatal("payload route installed or peer missing")
		}
	}
	if a.ReconcileSelection(ctx, p, own, 1) == nil {
		t.Fatal("static selection admitted BGP")
	}
	guard := GuardIntent{Namespace: p.Namespace, OwnerID: e.Engines[0].Binding.GatewayID, Revision: 1, Connections: []GuardConnection{{ID: p.ConnectionID, Local: e.Engines[0].LocalPrefixes, Remote: e.Engines[0].RemotePrefixes, Tunnels: own, PermitFor: 30 * time.Second, PermittedInterfaceIndices: []int{own[0].InterfaceIndex, own[1].InterfaceIndex}}}}
	for i, tunnel := range p.Tunnels {
		guard.Connections[0].BGPPeers = append(guard.Connections[0].BGPPeers, GuardBGPPeer{Local: tunnel.InsideAddress.Addr(), Remote: tunnel.BGP.Peer, InterfaceIndex: own[i].InterfaceIndex})
	}
	rendered, err := RenderGuard(guard)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, "/usr/sbin/nft", "-f", "-")
	cmd.Stdin = bytes.NewBufferString(rendered.NFT)
	raw, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("native nft control rules: %v %s", err, raw)
	}
	cmd = exec.CommandContext(ctx, "/usr/sbin/nft", "-j", "list", "table", "inet", "tunnex_ipsec")
	raw, err = cmd.CombinedOutput()
	if err != nil || VerifyGuardReadbackWithInterfaces([]byte(rendered.ExpectedJSON), raw, []GuardInterface{{Name: own[0].InterfaceName, Index: own[0].InterfaceIndex}, {Name: own[1].InterfaceName, Index: own[1].InterfaceIndex}}) != nil {
		t.Fatalf("native guard readback: %v %s", err, raw)
	}
	if _, err = a.Remove(ctx, p, own); err != nil {
		t.Fatal(err)
	}
	t.Log("native peer-only kernel routes, leased exact TCP179 NFT/readback, static-selection refusal and owned cleanup verified")
}

// Synthetic two-peer helper uses real VICI and independent kernel inventories.
func engineLabBGPTransport(t *testing.T, client *DaemonClient, configs [2]EngineTunnel, role string, permit bool, appGrant bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	inventory, err := client.Inspect(ctx)
	if err != nil || len(inventory.SAs) != 2 {
		t.Fatal("two BGP transport SAs absent", err)
	}
	reader, err := NewKernelReader("/sbin/ip")
	if err != nil {
		t.Fatal(err)
	}
	kernel, err := reader.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	xr, err := NewXFRMReader("/sbin/ip")
	if err != nil {
		t.Fatal(err)
	}
	xfrm, err := xr.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	guard := GuardIntent{Namespace: kernel.Namespace, OwnerID: configs[0].Binding.GatewayID, Revision: 1, Connections: []GuardConnection{{ID: configs[0].Binding.ConnectionID, Local: configs[0].LocalPrefixes, Remote: configs[0].RemotePrefixes, PermitFor: 30 * time.Second}}}
	c := &guard.Connections[0]
	for i, cfg := range configs {
		found := false
		for _, sa := range inventory.SAs {
			if sa.Name == engineName(cfg) && sa.Established && len(sa.Children) == 1 {
				child := sa.Children[0]
				if child.Installed && child.IfIDIn == cfg.XFRMID && child.IfIDOut == cfg.XFRMID && sameEnginePrefixes(child.LocalPrefixes, engineTransportPrefixes(cfg, true)) && sameEnginePrefixes(child.RemotePrefixes, engineTransportPrefixes(cfg, false)) {
					engineLabKernelSA(t, cfg, child, xfrm)
					if !permit && (child.BytesIn == 0 || child.BytesOut == 0) {
						t.Fatal("encrypted TCP179 byte proof absent")
					}
					found = true
				}
			}
		}
		if !found {
			t.Fatal("actual broad CHILD selector ownership mismatch")
		}
		links := 0
		for _, link := range kernel.Links {
			if link.XFRMID == cfg.XFRMID && link.Up {
				c.Tunnels[i] = Ownership{Namespace: kernel.Namespace, InterfaceName: link.Name, InterfaceIndex: link.Index, XFRMID: link.XFRMID}
				links++
			}
		}
		if links != 1 {
			t.Fatal("BGP XFRM link ownership mismatch")
		}
		local, remote := netip.MustParseAddr("169.254.20.1"), netip.MustParseAddr("169.254.20.2")
		if i == 1 {
			local, remote = netip.MustParseAddr("169.254.20.5"), netip.MustParseAddr("169.254.20.6")
		}
		if role == "peer" {
			local, remote = remote, local
		}
		c.BGPPeers = append(c.BGPPeers, GuardBGPPeer{Local: local, Remote: remote, InterfaceIndex: c.Tunnels[i].InterfaceIndex})
		c.PermittedInterfaceIndices = append(c.PermittedInterfaceIndices, c.Tunnels[i].InterfaceIndex)
	}
	if appGrant {
		lan, e := net.InterfaceByName("eth0")
		if e != nil {
			t.Fatal(e)
		}
		c.LocalIngressIndices = []int{lan.Index}
		c.ReplyIngressIndices = append([]int{}, c.PermittedInterfaceIndices...)
		source, destination := netip.MustParsePrefix("10.10.0.2/32"), netip.MustParsePrefix("10.20.0.2/32")
		c.Grants = []GuardGrant{{Source: source, Destination: destination, Protocol: GuardTCP, PortLow: 18080, PortHigh: 18080}}
		for i, cfg := range configs {
			reqid := uint32(0)
			for _, sa := range inventory.SAs {
				if sa.Name == engineName(cfg) && len(sa.Children) == 1 {
					reqid = sa.Children[0].ReqID
				}
			}
			if reqid == 0 {
				t.Fatal("owned CHILD reqid absent")
			}
			c.EncryptedEgress = append(c.EncryptedEgress, GuardEncryptedEgress{TunnelInterfaceIndex: c.Tunnels[i].InterfaceIndex, ReqID: reqid, Peer: cfg.RemoteAddress, UnderlayInterfaceIndex: lan.Index})
		}
	}
	if permit {
		rendered, err := RenderGuard(guard)
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.CommandContext(ctx, "/usr/sbin/nft", "-f", "-")
		cmd.Stdin = bytes.NewBufferString(rendered.NFT)
		raw, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("BGP control guard: %v %s", err, raw)
		}
	}
	t.Log("two actual broad0/0 CHILD selectors + kernel XFRM IDs/reqids/SPIs/policies verified; policy remains narrow")
}

func TestBGPTransportTCPServer(t *testing.T) {
	if os.Getenv("TUNNEX_IPSEC_BGP_TRANSPORT_LAB") != "1" {
		t.Skip("synthetic encrypted transport lab only")
	}
	var listeners []net.Listener
	for _, addr := range []string{"169.254.20.2:179", "169.254.20.6:179"} {
		listener, err := net.Listen("tcp4", addr)
		if err != nil {
			t.Fatal(err)
		}
		listeners = append(listeners, listener)
		go func(l net.Listener) {
			for {
				c, e := l.Accept()
				if e != nil {
					return
				}
				go func() {
					defer c.Close()
					c.SetDeadline(time.Now().Add(3 * time.Second))
					buf := make([]byte, 16)
					n, e := c.Read(buf)
					if e == nil {
						c.Write(buf[:n])
					}
				}()
			}
		}(listener)
	}
	defer func() {
		for _, l := range listeners {
			l.Close()
		}
	}()
	t.Log("TCP179_SYNTHETIC_READY")
	time.Sleep(90 * time.Second)
}
func TestBGPTransportTCPClient(t *testing.T) {
	if os.Getenv("TUNNEX_IPSEC_BGP_TRANSPORT_LAB") != "1" {
		t.Skip("synthetic encrypted transport lab only")
	}
	for _, pair := range [][2]string{{"169.254.20.1", "169.254.20.2"}, {"169.254.20.5", "169.254.20.6"}} {
		d := net.Dialer{Timeout: 3 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(pair[0])}}
		c, e := d.Dial("tcp4", pair[1]+":179")
		if e != nil {
			t.Fatal("encrypted peer179 failed", e)
		}
		c.SetDeadline(time.Now().Add(3 * time.Second))
		token := []byte("bgp-transport")
		if _, e = c.Write(token); e != nil {
			t.Fatal(e)
		}
		reply := make([]byte, len(token))
		if _, e = io.ReadFull(c, reply); e != nil || !bytes.Equal(reply, token) {
			t.Fatal("encrypted179 reply missing", e)
		}
		c.Close()
	}
	for _, pair := range [][2]string{{"198.19.240.10", "169.254.20.2"}, {"169.254.20.1", "169.254.20.6"}, {"198.19.240.10", "198.19.240.20"}} {
		d := net.Dialer{Timeout: 500 * time.Millisecond, LocalAddr: &net.TCPAddr{IP: net.ParseIP(pair[0])}}
		c, e := d.Dial("tcp4", pair[1]+":179")
		if e == nil {
			c.Close()
			t.Fatal("WAN/wrong inside source accepted", pair)
		}
	}
	t.Log("both encrypted peer179 echo paths passed; WAN and wrong-peer sources refused")
}

func TestBGPForwardApplicationServer(t *testing.T) {
	if os.Getenv("TUNNEX_BGP_APP_LAB") != "1" {
		t.Skip("synthetic forward-path lab")
	}
	l, e := net.Listen("tcp4", "10.20.0.2:18080")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	t.Log("BGP_APP_READY")
	for {
		c, e := l.Accept()
		if e != nil {
			return
		}
		go func() {
			defer c.Close()
			c.SetDeadline(time.Now().Add(2 * time.Second))
			b := make([]byte, 32)
			n, e := c.Read(b)
			if e == nil {
				c.Write(b[:n])
			}
		}()
	}
}
func TestBGPForwardApplicationClient(t *testing.T) {
	if os.Getenv("TUNNEX_BGP_APP_LAB") != "1" {
		t.Skip("synthetic forward-path lab")
	}
	d := net.Dialer{Timeout: 2 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP("10.10.0.2")}}
	c, e := d.Dial("tcp4", "10.20.0.2:18080")
	if os.Getenv("TUNNEX_BGP_APP_EXPECT") == "deny" {
		if e == nil {
			c.Close()
			t.Fatal("learned route created application permission")
		}
		t.Log("FORWARDED_APP_DENIED_WITH_LEARNED_ROUTE")
		return
	}
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	payload := []byte("bgp-forwarded-approved")
	if _, e = c.Write(payload); e != nil {
		t.Fatal(e)
	}
	got := make([]byte, len(payload))
	if _, e = io.ReadFull(c, got); e != nil || !bytes.Equal(got, payload) {
		t.Fatal("forwarded response failed", e)
	}
	t.Log("FORWARDED_APP_ALLOWED_WITH_EXPLICIT_GRANT")
}
