//go:build linux

package ipsec

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"testing"
	"time"
)

// Static simulator only: its return route/ACL grants no enrolled gateway authority.
func standaloneStaticServe(t *testing.T, c standalonePeerConfig, g GuardIntent, r *KernelReader, d *DaemonClient) {
	gc := g.Connections[0]
	owned := RouteTuple{Destination: c.CustomTunnels[0].RemotePrefixes[0], Table: 254, Protocol: 242, Metric: 50001, OutputInterface: gc.Tunnels[0].InterfaceIndex}
	run := func(args ...string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return exec.CommandContext(ctx, "/sbin/ip", args...).Run()
	}
	nft := func(text string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "/usr/sbin/nft", "-f", "-")
		cmd.Stdin = bytes.NewBufferString(text)
		err := cmd.Run()
		if err != nil && ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("peer nft deadline exceeded: %w", err)
		}
		return err
	}
	deny := func() error {
		v, e := RenderGuard(g)
		if e != nil {
			return e
		}
		return nft(v.NFT)
	}
	verify := func(present bool) error {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		v, e := r.Read(ctx)
		if e != nil {
			return e
		}
		if v.Namespace != g.Namespace {
			return fmt.Errorf("static peer namespace changed")
		}
		found := false
		for _, x := range v.Routes {
			if x.Destination == owned.Destination {
				if x.Destination != owned.Destination || x.Table != owned.Table || x.Protocol != owned.Protocol || x.Metric != owned.Metric || x.OutputInterface != owned.OutputInterface || x.Gateway.IsValid() {
					return fmt.Errorf("foreign static return tuple")
				}
				found = true
			}
		}
		if found != present {
			return fmt.Errorf("static return readback mismatch")
		}
		return nil
	}
	if verify(false) != nil {
		t.Fatal("preexisting static return refused")
	}
	if run("route", "add", owned.Destination.String(), "dev", gc.Tunnels[0].InterfaceName, "proto", "242", "metric", "50001") != nil {
		t.Fatal("static return add refused")
	}
	defer func() {
		if deny() != nil {
			t.Error("static denial failed")
		}
		if verify(true) != nil {
			t.Error("static cleanup ownership refused")
			return
		}
		if run("route", "del", owned.Destination.String(), "dev", gc.Tunnels[0].InterfaceName, "proto", "242", "metric", "50001") != nil || verify(false) != nil {
			t.Error("static return cleanup failed")
		}
	}()
	if verify(true) != nil {
		t.Fatal("static return readback failed")
	}
	lan, e := net.InterfaceByName("eth1")
	if e != nil || lan.Flags&net.FlagUp == 0 {
		t.Fatal("static LAN absent")
	}
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(shutdown)
	t.Log("STANDALONE_STATIC_PEER_READY")
	for n := 0; n < 3600; n++ {
		select {
		case <-shutdown:
			return
		default:
		}
		if err := deny(); err != nil {
			t.Fatalf("static simulator denial update failed: %v", err)
		}
		if err := verify(true); err != nil {
			t.Fatalf("static simulator return proof failed: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		sas, e := d.Inspect(ctx)
		cancel()
		if e == nil {
			for _, sa := range sas.SAs {
				tunnel := c.CustomTunnels[0]
				if sa.Name != engineName(tunnel) || !sa.Established || sa.LocalAddress != tunnel.LocalAddress || sa.RemoteAddress != tunnel.RemoteAddress || len(sa.Children) != 1 {
					continue
				}
				ch := sa.Children[0]
				if !ch.Installed || ch.ReqID != tunnel.ReqID || ch.IfIDIn != tunnel.XFRMID || ch.IfIDOut != tunnel.XFRMID || !sameEnginePrefixes(ch.LocalPrefixes, engineTransportPrefixes(tunnel, true)) || !sameEnginePrefixes(ch.RemotePrefixes, engineTransportPrefixes(tunnel, false)) {
					continue
				}
				underlay, e := standalonePeerUnderlay(tunnel)
				if e != nil {
					t.Fatal("static underlay refused")
				}
				localTarget, remoteTarget := netip.MustParseAddr("10.32.0.2"), netip.MustParseAddr("10.10.0.2")
				if c.ProfileID == GCPClassicStaticProfile {
					localTarget, remoteTarget = c.LocalTarget, c.RemoteTarget
				}
				services := []standalonePeerService{{Source: remoteTarget, Destination: localTarget, Protocol: "tcp", Port: 18080}}
				services = append(services, c.Services...)
				rules := standaloneStaticServiceRules(services, gc.Tunnels[0].InterfaceIndex, lan.Index, underlay.Index, tunnel.ReqID, tunnel.RemoteAddress)
				rules += standaloneStaticReverseServiceRules(c.ReverseServices, gc.Tunnels[0].InterfaceIndex, lan.Index, underlay.Index, tunnel.ReqID, tunnel.RemoteAddress)
				if err := nft(rules); err != nil {
					t.Fatalf("static simulator ACL refused: %v", err)
				}
			}
		}
		time.Sleep(time.Second)
	}
}

func standalonePeerUnderlay(e EngineTunnel) (*net.Interface, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	raw, err := exec.CommandContext(ctx, "/sbin/ip", "-j", "-4", "route", "get", e.RemoteAddress.String(), "from", e.LocalAddress.String()).Output()
	if err != nil {
		return nil, err
	}
	var rows []map[string]json.RawMessage
	if json.Unmarshal(raw, &rows) != nil || len(rows) != 1 {
		return nil, fmt.Errorf("underlay schema")
	}
	for k := range rows[0] {
		switch k {
		case "dst", "gateway", "dev", "from", "flags", "uid", "cache":
		default:
			return nil, fmt.Errorf("unsupported underlay")
		}
	}
	var v []struct {
		Dst   string   `json:"dst"`
		Dev   string   `json:"dev"`
		From  string   `json:"from"`
		Flags []string `json:"flags"`
	}
	if json.Unmarshal(raw, &v) != nil || len(v) != 1 || v[0].Dst != e.RemoteAddress.String() || v[0].From != e.LocalAddress.String() || len(v[0].Flags) != 0 {
		return nil, fmt.Errorf("underlay provenance")
	}
	link, err := net.InterfaceByName(v[0].Dev)
	if err != nil || link.Flags&net.FlagUp == 0 || len(link.HardwareAddr) != 6 || link.Name == "eth1" {
		return nil, fmt.Errorf("underlay physical link")
	}
	addresses, err := link.Addrs()
	if err != nil {
		return nil, err
	}
	for _, a := range addresses {
		p, x := netip.ParsePrefix(a.String())
		if x == nil && p.Addr() == e.LocalAddress {
			return link, nil
		}
	}
	return nil, fmt.Errorf("underlay source absent")
}
