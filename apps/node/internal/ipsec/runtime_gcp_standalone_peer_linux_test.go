//go:build linux

package ipsec

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/node/internal/bgp"
)

func validStandaloneGCPPeer(c standalonePeerConfig) bool {
	if c.ProfileID == GCPHABGPProfile {
		return validStandaloneGCPHAPeer(c)
	}
	// This peer is an external emulator. Only the genuine enrolled gateway can
	// obtain a lease, acknowledge a delivery or grant access to its clients.
	if c.ProfileID != GCPClassicStaticProfile || c.Scenario != "gcp-static" || len(c.CustomTunnels) != 1 || len(c.Interfaces) != 1 || len(c.PSKs) != 1 || c.PeerGatewayID == uuid.Nil || c.Generation == uuid.Nil || c.ActivationPerformed || c.GatewayCPAuthority != "real CP only; this standalone peer cannot acknowledge deliveries" || !reflect.DeepEqual(c.BGPConfig, bgp.Config{}) {
		return false
	}
	e, f := c.CustomTunnels[0], c.Interfaces[0]
	if !validEngineTunnel(e) || e.ProfileID != c.ProfileID || e.BGP || e.Binding.GatewayID != c.PeerGatewayID || e.XFRMID != KernelTunnelID(e.TunnelID) || e.ReqID != e.XFRMID || len(e.LocalPrefixes) != 1 || len(e.RemotePrefixes) != 1 || e.LocalAddress != e.LocalIdentity || e.RemoteAddress != e.RemoteIdentity || !validProfileEnginePSK(c.ProfileID, []byte(c.PSKs[0])) {
		return false
	}
	if f.Name != KernelTunnelName(e.TunnelID) || f.XFRMID != e.XFRMID || f.Alias != "tunnex-ipsec:"+c.Generation.String()+":"+e.TunnelID.String() || f.Address != "" || f.RemoteHostRoute != "" || f.Protocol != 242 || f.Metric != 50001 {
		return false
	}
	for i, a := range []netip.Addr{c.LocalTarget, c.RemoteTarget} {
		p := e.LocalPrefixes[0]
		if i == 1 {
			p = e.RemotePrefixes[0]
		}
		if !a.Is4() || a.IsUnspecified() || a.IsMulticast() || !p.Contains(a) || a == p.Addr() {
			return false
		}
	}
	return true
}

func standaloneGCPClassicFixture() standalonePeerConfig {
	e := engineLabTunnels("peer")[0]
	e.ProfileID = GCPClassicStaticProfile
	e.XFRMID = KernelTunnelID(e.TunnelID)
	e.ReqID = e.XFRMID
	c := standalonePeerConfig{ProfileID: GCPClassicStaticProfile, Scenario: "gcp-static", CustomTunnels: []EngineTunnel{e}, PSKs: []string{"0-standalone-GCP-secret!"}, PeerGatewayID: e.Binding.GatewayID, Generation: uuid.New(), GatewayCPAuthority: "real CP only; this standalone peer cannot acknowledge deliveries", LocalTarget: netip.MustParseAddr("10.20.0.2"), RemoteTarget: netip.MustParseAddr("10.10.0.2")}
	c.Interfaces = []standalonePeerInterface{{Name: KernelTunnelName(e.TunnelID), XFRMID: e.XFRMID, Alias: "tunnex-ipsec:" + c.Generation.String() + ":" + e.TunnelID.String(), Protocol: 242, Metric: 50001}}
	return c
}

func TestStandaloneGCPClassicContract(t *testing.T) {
	c := standaloneGCPClassicFixture()
	if !validStandalonePeer(c) {
		t.Fatal("bounded unnumbered Classic peer refused")
	}
	for name, mutate := range map[string]func(*standalonePeerConfig){
		"activation":          func(c *standalonePeerConfig) { c.ActivationPerformed = true },
		"second tunnel":       func(c *standalonePeerConfig) { c.CustomTunnels = append(c.CustomTunnels, c.CustomTunnels[0]) },
		"invented inside":     func(c *standalonePeerConfig) { c.Interfaces[0].Address = "169.254.1.1/30" },
		"invented peer":       func(c *standalonePeerConfig) { c.Interfaces[0].RemoteHostRoute = "169.254.1.2/32" },
		"BGP daemon":          func(c *standalonePeerConfig) { c.BGPConfig.LocalASN = 65001 },
		"BGP transport":       func(c *standalonePeerConfig) { c.CustomTunnels[0].BGP = true },
		"foreign owner":       func(c *standalonePeerConfig) { c.Interfaces[0].Alias = "foreign" },
		"out of scope target": func(c *standalonePeerConfig) { c.LocalTarget = netip.MustParseAddr("10.99.0.2") },
		"unknown profile":     func(c *standalonePeerConfig) { c.ProfileID = "gcp-classic-static-ipv4-v2" },
	} {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(c)
			var changed standalonePeerConfig
			if json.Unmarshal(raw, &changed) != nil {
				t.Fatal("fixture clone")
			}
			mutate(&changed)
			if validStandalonePeer(changed) {
				t.Fatal("changed peer authority accepted")
			}
		})
	}
}

func TestStandaloneGCPClassicNativeStage(t *testing.T) {
	nativeStandaloneGCPStage(t, standaloneGCPClassicFixture())
}

func nativeStandaloneGCPStage(t *testing.T, c standalonePeerConfig) {
	if os.Getenv("TUNNEX_GCP_STANDALONE_STAGE_LAB") != "1" {
		t.Skip("owned disposable daemon namespace only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	daemon, err := StartDaemonProcess(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer daemon.Close()
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.CommandContext(ctx, "/sbin/ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("owned peer setup: %v %s", err, out)
		}
	}
	for _, f := range c.Interfaces {
		run("link", "add", f.Name, "type", "xfrm", "if_id", fmt.Sprint(f.XFRMID))
		defer exec.Command("/sbin/ip", "link", "del", f.Name).Run()
		run("link", "set", "dev", f.Name, "alias", f.Alias)
		run("link", "set", "dev", f.Name, "up")
		if c.ProfileID == GCPHABGPProfile {
			run("addr", "add", f.Address, "dev", f.Name)
			run("route", "add", f.RemoteHostRoute, "dev", f.Name, "proto", "242", "metric", fmt.Sprint(f.Metric))
		}
	}
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "peer.json")
	if os.WriteFile(path, raw, 0600) != nil {
		t.Fatal("owned peer input")
	}
	t.Setenv("TUNNEX_BGP_STANDALONE_PEER_LAB", "1")
	t.Setenv("TUNNEX_BGP_STANDALONE_PEER_CONFIG", path)
	t.Setenv("TUNNEX_BGP_STANDALONE_PEER_PHASE", "stage")
	t.Run("actual owned stage", TestBGPStandalonePeerNative)
	for _, e := range c.CustomTunnels {
		if daemon.Client.removeTunnel(ctx, e) != nil {
			t.Fatal("owned peer stage cleanup")
		}
	}
	inv, err := daemon.Client.Inspect(ctx)
	if err != nil || len(inv.SAs) != 0 || len(inv.Connections) != 0 || len(inv.SharedKeys) != 0 {
		t.Fatal("owned peer negative inventory")
	}
}

func validStandaloneGCPHAPeer(c standalonePeerConfig) bool {
	if c.Scenario != "gcp-ha" || len(c.CustomTunnels) != 2 || len(c.Interfaces) != 2 || len(c.PSKs) != 2 || c.PeerGatewayID == uuid.Nil || c.Generation == uuid.Nil || c.ActivationPerformed || c.GatewayCPAuthority != "real CP only; this standalone peer cannot acknowledge deliveries" || c.BGPConfig.RemoteASN == 7224 {
		return false
	}
	if _, err := bgp.RenderConfig(c.BGPConfig); err != nil {
		return false
	}
	for i, e := range c.CustomTunnels {
		f, p := c.Interfaces[i], c.BGPConfig.Peers[i]
		if !validEngineTunnel(e) || e.ProfileID != GCPHABGPProfile || !e.BGP || e.Binding.GatewayID != c.PeerGatewayID || e.Binding != c.CustomTunnels[0].Binding || e.XFRMID != KernelTunnelID(e.TunnelID) || e.ReqID != e.XFRMID || len(e.LocalPrefixes) != 1 || len(e.RemotePrefixes) != 1 || !reflect.DeepEqual(e.LocalPrefixes, c.BGPConfig.LocalPrefixes) || !reflect.DeepEqual(e.RemotePrefixes, c.BGPConfig.RemotePrefixes) || e.LocalAddress != e.LocalIdentity || e.RemoteAddress != e.RemoteIdentity || !validProfileEnginePSK(c.ProfileID, []byte(c.PSKs[i])) {
			return false
		}
		if p.LinkName != KernelTunnelName(e.TunnelID) || p.XFRMID != e.XFRMID || f.Name != p.LinkName || f.XFRMID != p.XFRMID || f.Alias != "tunnex-ipsec:"+c.Generation.String()+":"+e.TunnelID.String() || f.Address != p.Local.String()+"/30" || f.RemoteHostRoute != p.Remote.String()+"/32" || f.Protocol != 242 || f.Metric != uint32(50001+i) {
			return false
		}
	}
	a, b := c.CustomTunnels[0], c.CustomTunnels[1]
	if a.TunnelID == b.TunnelID || a.LocalAddress == b.LocalAddress || a.RemoteAddress != b.RemoteAddress {
		return false
	}
	for i, target := range []netip.Addr{c.LocalTarget, c.RemoteTarget} {
		prefix := a.LocalPrefixes[0]
		if i == 1 {
			prefix = a.RemotePrefixes[0]
		}
		if !target.Is4() || target.IsUnspecified() || target.IsMulticast() || !prefix.Contains(target) || target == prefix.Addr() {
			return false
		}
	}
	return true
}

func standaloneGCPHAFixture() standalonePeerConfig {
	engines := engineLabTunnels("peer")
	c := standalonePeerConfig{ProfileID: GCPHABGPProfile, Scenario: "gcp-ha", CustomTunnels: engines[:], Interfaces: make([]standalonePeerInterface, 2), PSKs: []string{"0-GCP-HA-peer-one!", "0-GCP-HA-peer-two!"}, PeerGatewayID: engines[0].Binding.GatewayID, Generation: uuid.New(), GatewayCPAuthority: "real CP only; this standalone peer cannot acknowledge deliveries", LocalTarget: netip.MustParseAddr("10.20.0.2"), RemoteTarget: netip.MustParseAddr("10.10.0.2"), BGPConfig: bgp.Config{LocalASN: 65002, RemoteASN: 65001, RouterID: netip.MustParseAddr("10.20.0.1"), MaximumPrefixes: 1, LocalPrefixes: engines[0].LocalPrefixes, RemotePrefixes: engines[0].RemotePrefixes}}
	for i := range c.CustomTunnels {
		e := &c.CustomTunnels[i]
		e.ProfileID = GCPHABGPProfile
		e.BGP = true
		e.XFRMID = KernelTunnelID(e.TunnelID)
		e.ReqID = e.XFRMID
		local, remote := netip.MustParseAddr("169.254.20.2"), netip.MustParseAddr("169.254.20.1")
		if i == 1 {
			local, remote = netip.MustParseAddr("169.254.20.6"), netip.MustParseAddr("169.254.20.5")
		}
		c.BGPConfig.Peers[i] = bgp.Peer{Slot: i + 1, LinkName: KernelTunnelName(e.TunnelID), XFRMID: e.XFRMID, Local: local, Remote: remote}
		c.Interfaces[i] = standalonePeerInterface{Name: KernelTunnelName(e.TunnelID), XFRMID: e.XFRMID, Alias: "tunnex-ipsec:" + c.Generation.String() + ":" + e.TunnelID.String(), Address: local.String() + "/30", RemoteHostRoute: remote.String() + "/32", Protocol: 242, Metric: uint32(50001 + i)}
	}
	return c
}

func TestStandaloneGCPHAContract(t *testing.T) {
	c := standaloneGCPHAFixture()
	if !validStandalonePeer(c) {
		t.Fatal("owned HA peer refused")
	}
	for name, mutate := range map[string]func(*standalonePeerConfig){"single tunnel": func(c *standalonePeerConfig) { c.CustomTunnels = c.CustomTunnels[:1] }, "single outside interface": func(c *standalonePeerConfig) {
		c.CustomTunnels[1].LocalAddress = c.CustomTunnels[0].LocalAddress
		c.CustomTunnels[1].LocalIdentity = c.CustomTunnels[0].LocalIdentity
	}, "AWS ASN": func(c *standalonePeerConfig) { c.BGPConfig.RemoteASN = 7224 }, "unknown peer": func(c *standalonePeerConfig) { c.Interfaces[0].RemoteHostRoute = "169.254.99.1/32" }, "unapproved target": func(c *standalonePeerConfig) { c.RemoteTarget = netip.MustParseAddr("10.99.0.2") }} {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(c)
			var changed standalonePeerConfig
			if json.Unmarshal(raw, &changed) != nil {
				t.Fatal("clone")
			}
			mutate(&changed)
			if validStandalonePeer(changed) {
				t.Fatal("HA changed contract accepted")
			}
		})
	}
}

func TestStandaloneGCPHANativeStage(t *testing.T) {
	nativeStandaloneGCPStage(t, standaloneGCPHAFixture())
}
