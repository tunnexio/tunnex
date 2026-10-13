//go:build linux

package ipsec

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"net/netip"
	"os"
	"reflect"
	"testing"
	"time"
)

// The lab supplies real encrypted transport. CP authority is a synthetic test
// seam: this test does not obtain a production lease or install application grants.
func TestRestartOtherProviderNative(t *testing.T) {
	if os.Getenv("TUNNEX_RESTART_OTHERS_NATIVE") != "1" {
		t.Skip("owned encrypted component only")
	}
	mode := os.Getenv("TUNNEX_RESTART_OTHER_PROFILE")
	if mode != "static" && mode != "bgp" {
		t.Fatal("exact profile required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	daemon, err := NewDaemonClient("/run/tunnex-ipsec/charon.vici")
	if err != nil {
		t.Fatal(err)
	}
	d, err := daemon.Inspect(ctx)
	if err != nil || len(d.SAs) != 2 {
		t.Fatal("exact two real SAs required", err)
	}
	configs := engineLabTunnels("gateway")
	e := bgpEntryFixture(t)
	e.DeliveryID = uuid.MustParse("eeeeeeee-0000-0000-0000-000000000001")
	e.Allocation.Generation = e.DeliveryID
	e.Allocation.Namespace, err = os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	e.Allocation.ConnectionID = configs[0].Binding.ConnectionID
	e.Allocation.BGP = mode == "bgp"
	if mode == "static" {
		e.ContractVersion = 0
		e.BGP = nil
	}
	for i := range configs {
		configs[i].BGP = mode == "bgp"
		configs[i].XFRMID = KernelTunnelID(configs[i].TunnelID)
		matches := 0
		for _, sa := range d.SAs {
			if sa.Name == engineName(configs[i]) && sa.Established && len(sa.Children) == 1 {
				configs[i].ReqID = sa.Children[0].ReqID
				matches++
			}
		}
		if matches != 1 || configs[i].ReqID == 0 {
			t.Fatal("actual CHILD identity missing")
		}
		e.Engines[i] = configs[i]
		local := netip.MustParseAddr("169.254.20.1")
		remote := netip.MustParseAddr("169.254.20.2")
		if i == 1 {
			local = netip.MustParseAddr("169.254.20.5")
			remote = netip.MustParseAddr("169.254.20.6")
		}
		a := KernelTunnelAllocation{TunnelID: configs[i].TunnelID, Slot: uint8(i + 1), Name: KernelTunnelName(configs[i].TunnelID), Alias: KernelTunnelAlias(e.DeliveryID, configs[i].TunnelID), XFRMID: configs[i].XFRMID, InsideAddress: netip.PrefixFrom(local, 30), RemotePrefixes: configs[i].RemotePrefixes, Selected: mode == "static" && i == 0}
		if mode == "bgp" {
			a.BGP = &KernelBGPTransport{Peer: remote}
		}
		e.Allocation.Tunnels[i] = a
	}
	kernel, err := NewKernelApplier("/sbin/ip")
	if err != nil {
		t.Fatal(err)
	}
	snap, err := kernel.snapshot(ctx, e.Allocation)
	if err != nil {
		t.Fatal("actual allocation", err)
	}
	e.Observed = snap.ownership
	kr, err := NewKernelReader("/sbin/ip")
	if err != nil {
		t.Fatal(err)
	}
	k, err := kr.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	xr, err := NewXFRMReader("/sbin/ip")
	if err != nil {
		t.Fatal(err)
	}
	x, err := xr.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for i := range configs {
		if runtimeTunnelStatus(configs[i], e.Observed[i], d, k, x) != "up" {
			t.Fatal("independent actual transport proof", i)
		}
	}
	target := e
	target.DeliveryID = uuid.MustParse("eeeeeeee-0000-0000-0000-000000000002")
	target.Allocation.Generation = target.DeliveryID
	target.Allocation.ConnectionID = uuid.MustParse("cccccccc-0000-0000-0000-000000000002")
	target.Observed = [2]Ownership{}
	for i := range target.Engines {
		id := uuid.MustParse([]string{"dddddddd-0000-0000-0000-000000000003", "dddddddd-0000-0000-0000-000000000004"}[i])
		target.Engines[i].TunnelID = id
		target.Engines[i].Binding.ConnectionID = target.Allocation.ConnectionID
		target.Engines[i].ReqID += 10000
		target.Engines[i].XFRMID = KernelTunnelID(id)
		a := &target.Allocation.Tunnels[i]
		a.TunnelID = id
		a.XFRMID = KernelTunnelID(id)
		a.Name = KernelTunnelName(id)
		a.Alias = KernelTunnelAlias(target.DeliveryID, id)
		a.InsideAddress = netip.PrefixFrom(netip.MustParseAddr([]string{"169.254.21.1", "169.254.21.5"}[i]), 30)
		a.RemotePrefixes = []netip.Prefix{netip.MustParsePrefix("10.30.0.0/24")}
		target.Engines[i].RemotePrefixes = a.RemotePrefixes
		if mode == "bgp" {
			a.BGP = &KernelBGPTransport{Peer: netip.MustParseAddr([]string{"169.254.21.2", "169.254.21.6"}[i])}
		}
	}
	j, err := OpenRuntimeJournal(journalDir(t), configs[0].Binding.GatewayID)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	for _, phase := range []RuntimePhase{RuntimeReserved, RuntimeApplying, RuntimeApplied} {
		e.Phase = phase
		if err = j.Save([]RuntimeJournalEntry{e}); err != nil {
			t.Fatal("actual journal", err)
		}
	}
	if missing, err := kernel.RestartNeedsRecreation(ctx, target.Allocation, target.Observed); err == nil || missing {
		t.Fatal("legacy global census accepted other real SAs")
	}
	environment, err := NewRuntimeEnvironmentInspector("/sbin/ip", "/usr/sbin/nft")
	if err != nil {
		t.Fatal(err)
	}
	ri := environment.(*runtimeEnvironmentInspector)
	originalIP, originalNFT := ri.ip, ri.nft
	ri.ip = func(ctx context.Context, args ...string) ([]byte, error) {
		raw, err := originalIP(ctx, args...)
		t.Log("environment ip", args, "error", err)
		return raw, err
	}
	ri.nft = func(ctx context.Context, args ...string) ([]byte, error) {
		raw, err := originalNFT(ctx, args...)
		t.Log("environment nft", args, "error", err)
		return raw, err
	}
	if _, err := environment.Observe(ctx, e.Allocation, e.Engines); err != nil {
		t.Fatal("actual environment before controller", err)
	}
	if !restartInventoryOwnedByOthers(target, []RuntimeJournalEntry{e}, d, k, x) {
		t.Fatal("actual classifier before controller")
	}
	c := &RuntimeController{journal: j, kernel: kernel, config: RuntimeControllerConfig{IPPath: "/sbin/ip", Daemon: daemon, DaemonAlive: func() bool { _, err := daemon.Inspect(ctx); return err == nil }, Environment: environment}}
	c.prove = func(ctx context.Context, current RuntimeJournalEntry, _ RuntimeEnvironment) error {
		dd, er := daemon.Inspect(ctx)
		if er != nil {
			return er
		}
		kk, er := kr.Read(ctx)
		if er != nil {
			return er
		}
		xx, er := xr.Read(ctx)
		if er != nil {
			return er
		}
		for i, cfg := range current.Engines {
			if runtimeTunnelStatus(cfg, current.Observed[i], dd, kk, xx) != "up" {
				return ErrRuntimeController
			}
		}
		return nil
	}
	if missing, err := c.restartNeedsRecreation(ctx, target); err != nil || !missing {
		t.Fatal("scoped actual controller recreation census", missing, err)
	}
	if !restartInventoryOwnedByOthers(target, []RuntimeJournalEntry{e}, d, k, x) {
		t.Fatal("actual ownership classifier")
	}
	// These are explicitly unit mutations of real snapshots, not injected kernel faults.
	for name, change := range map[string]func(*XFRMInventory){"wrong SPI": func(v *XFRMInventory) { v.States[0].SPI++ }, "wrong ifID": func(v *XFRMInventory) { v.States[0].IfID++ }, "partial": func(v *XFRMInventory) { v.States = v.States[1:] }, "foreign": func(v *XFRMInventory) {
		s := v.States[0]
		s.IfID += 10000
		s.ReqID += 10000
		v.States = append(v.States, s)
	}} {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(x)
			var bad XFRMInventory
			if json.Unmarshal(raw, &bad) != nil {
				t.Fatal("clone")
			}
			change(&bad)
			if restartInventoryOwnedByOthers(target, []RuntimeJournalEntry{e}, d, k, bad) {
				t.Fatal("unproven tuple accepted")
			}
		})
	}
	after, err := xr.Read(ctx)
	if err != nil || !reflect.DeepEqual(x, after) {
		t.Fatal("read-only census changed XFRM")
	}
	entries, err := j.Entries()
	if err != nil || len(entries) != 1 || !reflect.DeepEqual(entries[0], e) {
		t.Fatal("journal changed during census")
	}
	proof, err := json.Marshal(struct {
		Profile                         string
		Other, Target                   RuntimeJournalEntry
		Daemon                          DaemonInventory
		Kernel                          KernelInventory
		XFRM                            XFRMInventory
		JournalUnchanged, XFRMUnchanged bool
	}{mode, e, target, d, k, x, true, true})
	if err != nil || os.WriteFile("/test/native-restart-proof.json", proof, 0600) != nil {
		t.Fatal("private proof capture")
	}
	t.Log("actual two CHILDs; legacy refused; locked journal scoped census permits absent other provider; synthetic CP authority; no application grants")
}
