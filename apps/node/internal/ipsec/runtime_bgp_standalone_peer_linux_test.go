//go:build linux

package ipsec

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"reflect"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/node/internal/bgp"
)

type standalonePeerInterface struct {
	Name            string `json:"name"`
	XFRMID          uint32 `json:"xfrm_id"`
	Alias           string `json:"alias"`
	Address         string `json:"address"`
	RemoteHostRoute string `json:"remote_host_route"`
	Protocol        uint8  `json:"protocol"`
	Metric          uint32 `json:"metric"`
}
type standalonePeerConfig struct {
	Services                  []standalonePeerService
	ProfileID                 string
	LocalTarget, RemoteTarget netip.Addr
	Scenario                  string
	CustomTunnels             []EngineTunnel
	BGPConfig                 bgp.Config
	Interfaces                []standalonePeerInterface
	PSKs                      []string
	PeerGatewayID             uuid.UUID
	Generation                uuid.UUID
	GatewayCPAuthority        string
	ActivationPerformed       bool
}

func validStandalonePeer(c standalonePeerConfig) bool {
	if c.ProfileID != "" {
		return validStandaloneGCPPeer(c)
	}
	if len(c.Services) != 0 || len(c.CustomTunnels) != 2 || len(c.Interfaces) != 2 || len(c.PSKs) != 2 || c.PeerGatewayID == uuid.Nil || c.Generation == uuid.Nil || c.ActivationPerformed || c.GatewayCPAuthority != "real CP only; this standalone peer cannot acknowledge deliveries" {
		return false
	}
	if _, err := bgp.RenderConfig(c.BGPConfig); err != nil {
		return false
	}
	if c.Scenario == "limits" && c.BGPConfig.MaximumPrefixes != 1 {
		return false
	}
	expectedLocal := []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}
	switch c.Scenario {
	case "":
	case "limits":
		expectedLocal = []netip.Prefix{netip.MustParsePrefix("10.30.0.0/24"), netip.MustParsePrefix("10.31.0.0/24")}
	case "static":
		expectedLocal = []netip.Prefix{netip.MustParsePrefix("10.32.0.0/24")}
	default:
		return false
	}
	if !reflect.DeepEqual(c.BGPConfig.LocalPrefixes, expectedLocal) || !reflect.DeepEqual(c.BGPConfig.RemotePrefixes, []netip.Prefix{netip.MustParsePrefix("10.10.0.0/24")}) {
		return false
	}
	for i, e := range c.CustomTunnels {
		p, f := c.BGPConfig.Peers[i], c.Interfaces[i]
		if !validEngineTunnel(e) || e.ProfileID != "" || e.BGP != (c.Scenario != "static") || e.Binding.GatewayID != c.PeerGatewayID || e.Binding != c.CustomTunnels[0].Binding || e.XFRMID != KernelTunnelID(e.TunnelID) || e.ReqID != e.XFRMID || !reflect.DeepEqual(e.LocalPrefixes, c.BGPConfig.LocalPrefixes) || !reflect.DeepEqual(e.RemotePrefixes, c.BGPConfig.RemotePrefixes) || e.LocalAddress != e.LocalIdentity || e.RemoteAddress != e.RemoteIdentity || len(c.PSKs[i]) < 16 || len(c.PSKs[i]) > 256 {
			return false
		}
		if p.LinkName != KernelTunnelName(e.TunnelID) || p.XFRMID != e.XFRMID || f.Name != p.LinkName || f.XFRMID != p.XFRMID || f.Alias != "tunnex-ipsec:"+c.Generation.String()+":"+e.TunnelID.String() || f.Address != p.Local.String()+"/30" || f.RemoteHostRoute != p.Remote.String()+"/32" || f.Protocol != 242 || f.Metric != uint32(50001+i) {
			return false
		}
	}
	return c.CustomTunnels[0].TunnelID != c.CustomTunnels[1].TunnelID
}
func readStandalonePeer(path string) (standalonePeerConfig, error) {
	var c standalonePeerConfig
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return c, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Sys().(*syscall.Stat_t).Uid != 0 || st.Size() > 32768 {
		return c, fmt.Errorf("private peer input refused")
	}
	d := json.NewDecoder(io.LimitReader(f, 32769))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil || !validStandalonePeer(c) {
		return c, fmt.Errorf("peer input refused")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return c, fmt.Errorf("trailing peer input")
	}
	return c, nil
}

// Test-only remote peer. It never obtains a CP lease, reports a delivery, or
// grants application access on the enrolled gateway.
func TestBGPStandalonePeerNative(t *testing.T) {
	if os.Getenv("TUNNEX_BGP_STANDALONE_PEER_LAB") != "1" {
		t.Skip("explicit standalone owned peer only")
	}
	c, err := readStandalonePeer(os.Getenv("TUNNEX_BGP_STANDALONE_PEER_CONFIG"))
	if err != nil {
		t.Fatal(err)
	}
	phase := os.Getenv("TUNNEX_BGP_STANDALONE_PEER_PHASE")
	if phase != "stage" && phase != "initiate" && phase != "serve" {
		t.Fatal("unsupported peer phase")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	reader, err := NewKernelReader("/sbin/ip")
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := reader.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	guard := GuardIntent{Namespace: inventory.Namespace, OwnerID: c.PeerGatewayID, Revision: 1, Connections: []GuardConnection{{ID: c.CustomTunnels[0].Binding.ConnectionID, Local: c.BGPConfig.LocalPrefixes, Remote: c.BGPConfig.RemotePrefixes, PermitFor: 30 * time.Second}}}
	gc := &guard.Connections[0]
	if c.ProfileID == GCPClassicStaticProfile {
		gc.TunnelCount = 1
		gc.Local, gc.Remote = c.CustomTunnels[0].LocalPrefixes, c.CustomTunnels[0].RemotePrefixes
	}
	for i, f := range c.Interfaces {
		cmd := exec.CommandContext(ctx, "/sbin/ip", "-d", "-j", "link", "show", "dev", f.Name)
		raw, e := cmd.Output()
		if e != nil {
			t.Fatal("owned peer link absent")
		}
		var links []struct {
			IfAlias string `json:"ifalias"`
		}
		if json.Unmarshal(raw, &links) != nil || len(links) != 1 || links[0].IfAlias != f.Alias {
			t.Fatal("peer generation alias mismatch")
		}
		found := false
		for _, link := range inventory.Links {
			if link.Name == f.Name && link.XFRMID == f.XFRMID && link.Up {
				if found {
					t.Fatal("duplicate peer link")
				}
				found = true
				gc.Tunnels[i] = Ownership{Namespace: inventory.Namespace, InterfaceName: link.Name, InterfaceIndex: link.Index, XFRMID: link.XFRMID}
				gc.PermittedInterfaceIndices = append(gc.PermittedInterfaceIndices, link.Index)
				if e := c.CustomTunnels[i]; e.BGP {
					gc.BGPPeers = append(gc.BGPPeers, GuardBGPPeer{Local: c.BGPConfig.Peers[i].Local, Remote: c.BGPConfig.Peers[i].Remote, InterfaceIndex: link.Index})
				}
				if c.ProfileID == GCPClassicStaticProfile {
					continue
				}
				routeFound := false
				for _, r := range inventory.Routes {
					if r.Destination == netip.PrefixFrom(c.BGPConfig.Peers[i].Remote, 32) && r.OutputInterface == link.Index && r.Table == 254 && r.Protocol == 242 && r.Metric == f.Metric && !r.Gateway.IsValid() {
						routeFound = true
					}
				}
				if !routeFound {
					t.Fatal("exact owned peer route absent")
				}
			}
		}
		if !found {
			t.Fatal("peer XFRM identity absent")
		}
		if c.ProfileID == GCPClassicStaticProfile {
			continue
		}
		cmd = exec.CommandContext(ctx, "/sbin/ip", "-j", "address", "show", "dev", f.Name)
		raw, e = cmd.Output()
		if e != nil {
			t.Fatal("peer inside address absent")
		}
		var addresses []struct {
			AddrInfo []struct {
				Local     string `json:"local"`
				PrefixLen int    `json:"prefixlen"`
			} `json:"addr_info"`
		}
		addressOK := false
		if json.Unmarshal(raw, &addresses) == nil && len(addresses) == 1 {
			for _, a := range addresses[0].AddrInfo {
				if a.Local == c.BGPConfig.Peers[i].Local.String() && a.PrefixLen == 30 {
					addressOK = true
				}
			}
		}
		if !addressOK {
			t.Fatal("exact peer inside address absent")
		}
	}
	rendered, err := RenderGuard(guard)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, "/usr/sbin/nft", "-f", "-")
	cmd.Stdin = bytes.NewBufferString(rendered.NFT)
	if cmd.Run() != nil {
		t.Fatal("peer control guard failed")
	}
	client, err := NewDaemonClient("/run/tunnex-ipsec/charon.vici")
	if err != nil {
		t.Fatal(err)
	}
	if c.ProfileID != "" {
		gr, err := NewGuardReader("/usr/sbin/nft")
		if err != nil || gr.Check(ctx, rendered) != nil {
			t.Fatal("GCP peer control refusal readback")
		}
	}
	if phase == "stage" || phase == "initiate" {
		for i, e := range c.CustomTunnels {
			if phase == "stage" {
				err = client.stageTunnel(ctx, e, []byte(c.PSKs[i]))
			} else {
				err = client.initiateTunnel(ctx, e)
			}
			if err != nil {
				t.Fatal("peer phase refused")
			}
		}
		return
	}
	actual, err := client.Inspect(ctx)
	if err != nil || len(actual.SAs) != len(c.CustomTunnels) {
		t.Fatal("peer transport absent")
	}
	for _, e := range c.CustomTunnels {
		verified := false
		for _, sa := range actual.SAs {
			if sa.Name == engineName(e) && sa.Established && sa.LocalAddress == e.LocalAddress && sa.RemoteAddress == e.RemoteAddress && len(sa.Children) == 1 {
				ch := sa.Children[0]
				verified = ch.Installed && ch.IfIDIn == e.XFRMID && ch.IfIDOut == e.XFRMID && ch.ReqID == e.ReqID && sameEnginePrefixes(ch.LocalPrefixes, engineTransportPrefixes(e, true)) && sameEnginePrefixes(ch.RemotePrefixes, engineTransportPrefixes(e, false))
			}
		}
		if !verified {
			t.Fatal("peer actual CHILD binding absent")
		}
	}
	if c.Scenario == "static" || c.Scenario == "gcp-static" {
		standaloneStaticServe(t, c, guard, reader, client)
		return
	}
	p, err := bgp.StartProcess(ctx, "/run/tunnex-bgp-peer", c.BGPConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if p.Close() != nil {
			t.Error("peer cleanup refused")
		}
	}()
	t.Log("STANDALONE_PEER_READY")
	if c.Scenario == "limits" {
		shutdown := make(chan os.Signal, 1)
		signal.Notify(shutdown, syscall.SIGTERM, syscall.SIGINT)
		defer signal.Stop(shutdown)
		for n := 0; n < 3600; n++ {
			select {
			case <-shutdown:
				return
			default:
			}
			if !p.Alive() {
				t.Fatal("limit peer daemon stopped")
			}
			control, e := RenderGuard(guard)
			if e != nil {
				t.Fatal(e)
			}
			refresh, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			cmd := exec.CommandContext(refresh, "/usr/sbin/nft", "-f", "-")
			cmd.Stdin = bytes.NewBufferString(control.NFT)
			e = cmd.Run()
			cancel()
			if e != nil {
				t.Fatal("limit peer control guard refresh refused")
			}
			time.Sleep(time.Second)
		}
		return
	}
	var owned *RouteTuple
	mutate := func(op string, r RouteTuple) error {
		child, stop := context.WithTimeout(context.Background(), 2*time.Second)
		defer stop()
		return exec.CommandContext(child, "/sbin/ip", "route", op, r.Destination.String(), "dev", gc.Tunnels[slotForPeerTuple(r, gc.Tunnels)].InterfaceName, "table", "254", "proto", "242", "metric", strconv.FormatUint(uint64(r.Metric), 10)).Run()
	}
	verify := func() error {
		child, stop := context.WithTimeout(context.Background(), 2*time.Second)
		defer stop()
		v, e := reader.Read(child)
		if e != nil {
			return e
		}
		if v.Namespace != inventory.Namespace {
			return fmt.Errorf("peer namespace changed")
		}
		for _, own := range gc.Tunnels {
			found := false
			for _, link := range v.Links {
				if link.Name == own.InterfaceName && link.Index == own.InterfaceIndex && link.XFRMID == own.XFRMID && link.Up {
					found = true
				}
			}
			if !found {
				return fmt.Errorf("peer link ownership changed")
			}
		}
		seen := 0
		for _, r := range v.Routes {
			if r.Destination == c.BGPConfig.RemotePrefixes[0] && r.Table == 254 {
				if owned == nil || r.RouteTuple != *owned || r.Kind != 1 {
					return fmt.Errorf("foreign peer return route")
				}
				seen++
			}
		}
		if owned != nil && seen != 1 {
			return fmt.Errorf("owned peer route absent")
		}
		return nil
	}
	deny := func() error {
		child, stop := context.WithTimeout(context.Background(), 2*time.Second)
		defer stop()
		cmd := exec.CommandContext(child, "/usr/sbin/nft", "-f", "-")
		cmd.Stdin = bytes.NewBufferString(rendered.NFT)
		return cmd.Run()
	}
	defer func() {
		if deny() != nil {
			t.Error("peer denial failed")
		}
		if owned != nil {
			if verify() != nil || mutate("del", *owned) != nil {
				t.Error("peer owned return cleanup refused")
			} else {
				owned = nil
				if verify() != nil {
					t.Error("peer return absence failed")
				}
			}
		}
	}()
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(shutdown)
	for n := 0; n < 3600; n++ {
		select {
		case <-shutdown:
			return
		default:
		}
		observeCtx, stop := context.WithTimeout(context.Background(), 2*time.Second)
		status, e := p.Observe(observeCtx)
		var routes []bgp.LearnedRoute
		if e == nil {
			routes, e = p.ObserveRoutes(observeCtx, status)
		}
		stop()
		saCtx, saStop := context.WithTimeout(context.Background(), 2*time.Second)
		currentSAs, saErr := client.Inspect(saCtx)
		saStop()
		healthy := [2]bool{}
		if saErr == nil {
			for i, e := range c.CustomTunnels {
				for _, sa := range currentSAs.SAs {
					if sa.Name == engineName(e) && sa.Established && sa.LocalAddress == e.LocalAddress && sa.RemoteAddress == e.RemoteAddress && len(sa.Children) == 1 {
						ch := sa.Children[0]
						healthy[i] = ch.Installed && ch.ReqID == e.ReqID && ch.IfIDIn == e.XFRMID && ch.IfIDOut == e.XFRMID && sameEnginePrefixes(ch.LocalPrefixes, engineTransportPrefixes(e, true)) && sameEnginePrefixes(ch.RemotePrefixes, engineTransportPrefixes(e, false))
					}
				}
			}
		}
		var target *RouteTuple
		if e == nil && len(routes) == 1 {
			r := routes[0]
			if r.Prefix == c.BGPConfig.RemotePrefixes[0] && r.Slot >= 1 && r.Slot <= 2 && healthy[r.Slot-1] {
				tuple := RouteTuple{Destination: r.Prefix, Table: 254, Protocol: 242, Metric: uint32(50001 + r.Slot - 1), OutputInterface: gc.Tunnels[r.Slot-1].InterfaceIndex}
				target = &tuple
			}
		}
		if err := deny(); err != nil {
			t.Fatal("peer denial refused")
		}
		if err := verify(); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(owned, target) {
			if owned != nil {
				if mutate("del", *owned) != nil {
					t.Fatal("peer return withdrawal failed")
				}
				owned = nil
			}
			if target != nil {
				if mutate("add", *target) != nil {
					t.Fatal("peer return add failed")
				}
				owned = target
			}
			if verify() != nil {
				t.Fatal("peer return readback failed")
			}
		}
		if owned != nil {
			lan, err := net.InterfaceByName("eth1")
			if err != nil {
				t.Fatal("peer target LAN absent")
			}
			slot := slotForPeerTuple(*owned, gc.Tunnels)
			xi := gc.Tunnels[slot].InterfaceIndex
			routeCtx, routeStop := context.WithTimeout(context.Background(), 2*time.Second)
			raw, routeErr := exec.CommandContext(routeCtx, "/sbin/ip", "-j", "-4", "route", "get", c.CustomTunnels[slot].RemoteAddress.String(), "from", c.CustomTunnels[slot].LocalAddress.String()).Output()
			routeStop()
			var underlays []struct {
				Dst    string   `json:"dst"`
				Dev    string   `json:"dev"`
				Source string   `json:"from"`
				Flags  []string `json:"flags"`
			}
			if routeErr != nil || json.Unmarshal(raw, &underlays) != nil || len(underlays) != 1 || underlays[0].Dst != c.CustomTunnels[slot].RemoteAddress.String() || underlays[0].Source != c.CustomTunnels[slot].LocalAddress.String() || len(underlays[0].Flags) != 0 {
				t.Fatal("peer exact underlay route refused")
			}
			var routeRows []map[string]json.RawMessage
			if json.Unmarshal(raw, &routeRows) != nil || len(routeRows) != 1 {
				t.Fatal("peer underlay schema refused")
			}
			for key := range routeRows[0] {
				switch key {
				case "dst", "gateway", "dev", "from", "flags", "uid", "cache":
				default:
					t.Fatal("peer unsupported underlay route")
				}
			}
			underlay, routeErr := net.InterfaceByName(underlays[0].Dev)
			if routeErr != nil || underlay.Flags&net.FlagUp == 0 || underlay.Index == xi || underlay.Index == lan.Index || len(underlay.HardwareAddr) != 6 {
				t.Fatal("peer physical underlay refused")
			}
			assigned, routeErr := underlay.Addrs()
			localAssigned := false
			for _, a := range assigned {
				prefix, e := netip.ParsePrefix(a.String())
				if e == nil && prefix.Addr() == c.CustomTunnels[slot].LocalAddress {
					localAssigned = true
				}
			}
			if routeErr != nil || !localAssigned {
				t.Fatal("peer underlay source unassigned")
			}
			localTarget, remoteTarget := netip.MustParseAddr("10.20.0.2"), netip.MustParseAddr("10.10.0.2")
			if c.ProfileID == GCPHABGPProfile {
				localTarget, remoteTarget = c.LocalTarget, c.RemoteTarget
			}
			rules := fmt.Sprintf("insert rule inet tunnex_ipsec forward_guard meta iif %d meta oif %d ip saddr %s ip daddr %s tcp sport 18080 ct state established accept\ninsert rule inet tunnex_ipsec postrouting_guard meta oif %d ip saddr %s ip daddr %s tcp sport 18080 ipsec out reqid %d accept\n", lan.Index, xi, localTarget, remoteTarget, xi, localTarget, remoteTarget, c.CustomTunnels[slot].ReqID)
			rules += fmt.Sprintf("insert rule inet tunnex_ipsec postrouting_guard meta oif %d ip saddr %s ip daddr %s tcp sport 18080 ipsec out reqid %d ipsec out ip daddr %s counter accept\n", underlay.Index, localTarget, remoteTarget, c.CustomTunnels[slot].ReqID, c.CustomTunnels[slot].RemoteAddress)
			for i, ok := range healthy {
				if ok {
					rules += fmt.Sprintf("insert rule inet tunnex_ipsec forward_guard meta iif %d meta oif %d ip saddr %s ip daddr %s tcp dport 18080 ipsec in reqid %d accept\n", gc.Tunnels[i].InterfaceIndex, lan.Index, remoteTarget, localTarget, c.CustomTunnels[i].ReqID)
				}
			}
			child, done := context.WithTimeout(context.Background(), 2*time.Second)
			cmd := exec.CommandContext(child, "/usr/sbin/nft", "-f", "-")
			cmd.Stdin = bytes.NewBufferString(rules)
			err = cmd.Run()
			done()
			if err != nil {
				t.Fatal("explicit peer simulator target permission failed")
			}
		}
		if !p.Alive() {
			t.Fatal("peer daemon stopped")
		}
		time.Sleep(time.Second)
	}

}

func TestStandalonePeerConfigRejectsAuthorityAndIdentityChanges(t *testing.T) {
	engines := engineLabTunnels("peer")
	c := standalonePeerConfig{CustomTunnels: engines[:], Interfaces: make([]standalonePeerInterface, 2), PSKs: []string{"synthetic-test-key-one", "synthetic-test-key-two"}, PeerGatewayID: engines[0].Binding.GatewayID, Generation: uuid.New(), GatewayCPAuthority: "real CP only; this standalone peer cannot acknowledge deliveries", BGPConfig: bgp.Config{LocalASN: 64512, RemoteASN: 65000, RouterID: netip.MustParseAddr("10.20.0.1"), MaximumPrefixes: 1, LocalPrefixes: engines[0].LocalPrefixes, RemotePrefixes: engines[0].RemotePrefixes}}
	for i := range c.CustomTunnels {
		e := &c.CustomTunnels[i]
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
	if !validStandalonePeer(c) {
		t.Fatal("legal standalone config refused")
	}
	for name, mutate := range map[string]func(*standalonePeerConfig){"gateway activation": func(c *standalonePeerConfig) { c.ActivationPerformed = true }, "foreign XFRMID": func(c *standalonePeerConfig) { c.CustomTunnels[0].XFRMID++ }, "generation alias": func(c *standalonePeerConfig) { c.Interfaces[0].Alias = "foreign" }, "unapproved export": func(c *standalonePeerConfig) {
		c.BGPConfig.LocalPrefixes = []netip.Prefix{netip.MustParsePrefix("10.30.0.0/24")}
	}, "missing peer": func(c *standalonePeerConfig) { c.CustomTunnels = c.CustomTunnels[:1] }} {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(c)
			var changed standalonePeerConfig
			json.Unmarshal(raw, &changed)
			mutate(&changed)
			if validStandalonePeer(changed) {
				t.Fatal("mutated identity accepted")
			}
		})
	}
}

func slotForPeerTuple(r RouteTuple, tunnels [2]Ownership) int {
	for i, t := range tunnels {
		if t.InterfaceIndex == r.OutputInterface {
			return i
		}
	}
	panic("unowned peer tuple")
}

func TestStandaloneAdditionalScenarios(t *testing.T) {
	engines := engineLabTunnels("peer")
	for _, scenario := range []string{"limits", "static"} {
		t.Run(scenario, func(t *testing.T) {
			local := []netip.Prefix{netip.MustParsePrefix("10.30.0.0/24"), netip.MustParsePrefix("10.31.0.0/24")}
			if scenario == "static" {
				local = []netip.Prefix{netip.MustParsePrefix("10.32.0.0/24")}
			}
			c := standalonePeerConfig{Scenario: scenario, CustomTunnels: engines[:], Interfaces: make([]standalonePeerInterface, 2), PSKs: []string{"synthetic-test-key-one", "synthetic-test-key-two"}, PeerGatewayID: engines[0].Binding.GatewayID, Generation: uuid.New(), GatewayCPAuthority: "real CP only; this standalone peer cannot acknowledge deliveries", BGPConfig: bgp.Config{LocalASN: 64512, RemoteASN: 65000, RouterID: local[0].Addr().Next(), MaximumPrefixes: 1, LocalPrefixes: local, RemotePrefixes: engines[0].RemotePrefixes}}
			for i := range c.CustomTunnels {
				e := &c.CustomTunnels[i]
				e.BGP = scenario != "static"
				e.LocalPrefixes = local
				e.XFRMID = KernelTunnelID(e.TunnelID)
				e.ReqID = e.XFRMID
				inside := netip.MustParseAddr("169.254.84.2")
				remote := netip.MustParseAddr("169.254.84.1")
				if i == 1 {
					inside = netip.MustParseAddr("169.254.84.6")
					remote = netip.MustParseAddr("169.254.84.5")
				}
				c.BGPConfig.Peers[i] = bgp.Peer{Slot: i + 1, LinkName: KernelTunnelName(e.TunnelID), XFRMID: e.XFRMID, Local: inside, Remote: remote}
				c.Interfaces[i] = standalonePeerInterface{Name: KernelTunnelName(e.TunnelID), XFRMID: e.XFRMID, Alias: "tunnex-ipsec:" + c.Generation.String() + ":" + e.TunnelID.String(), Address: inside.String() + "/30", RemoteHostRoute: remote.String() + "/32", Protocol: 242, Metric: uint32(50001 + i)}
			}
			if !validStandalonePeer(c) {
				t.Fatal("owned additional scenario rejected")
			}
			c.Scenario = ""
			if validStandalonePeer(c) {
				t.Fatal("scenario boundary bypass accepted")
			}
		})
	}
}
