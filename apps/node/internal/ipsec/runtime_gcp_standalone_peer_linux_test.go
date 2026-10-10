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
	c := standaloneGCPClassicFixture()
	f := c.Interfaces[0]
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.CommandContext(ctx, "/sbin/ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("owned peer setup: %v %s", err, out)
		}
	}
	run("link", "add", f.Name, "type", "xfrm", "if_id", fmt.Sprint(f.XFRMID))
	defer exec.Command("/sbin/ip", "link", "del", f.Name).Run()
	run("link", "set", "dev", f.Name, "alias", f.Alias)
	run("link", "set", "dev", f.Name, "up")
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
	t.Run("actual unnumbered stage", TestBGPStandalonePeerNative)
	if daemon.Client.removeTunnel(ctx, c.CustomTunnels[0]) != nil {
		t.Fatal("owned peer stage cleanup")
	}
	inv, err := daemon.Client.Inspect(ctx)
	if err != nil || len(inv.SAs) != 0 || len(inv.Connections) != 0 || len(inv.SharedKeys) != 0 {
		t.Fatal("owned peer negative inventory")
	}
}
