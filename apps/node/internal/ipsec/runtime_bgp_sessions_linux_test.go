//go:build linux

package ipsec

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	bgpengine "github.com/tunnexio/tunnex/apps/node/internal/bgp"
	"net/netip"
	"os"
	"reflect"
	"runtime"
	"syscall"
	"testing"
	"time"
)

func TestBGPManagedSessionsNative(t *testing.T) {
	if os.Getenv("TUNNEX_IPSEC_BGP_SESSION_LAB") != "1" {
		t.Skip("owned native two-peer encrypted lab only")
	}
	journalDir := os.Getenv("TUNNEX_BGP_LAB_JOURNAL_DIR")
	if journalDir == "" {
		journalDir = "/run/bgp-journal"
	}
	role := os.Getenv("TUNNEX_BGP_LAB_ROLE")
	if role != "gateway" && role != "peer" {
		t.Fatal("role required")
	}
	c := bgpengine.Config{LocalASN: 65000, RemoteASN: 64512, RouterID: netip.MustParseAddr("10.10.0.1"), MaximumPrefixes: 64, LocalPrefixes: []netip.Prefix{netip.MustParsePrefix("10.10.0.0/24")}, RemotePrefixes: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}}
	if role == "peer" {
		c.LocalASN, c.RemoteASN = 64512, 65000
		c.RouterID = netip.MustParseAddr("10.20.0.1")
		c.LocalPrefixes, c.RemotePrefixes = c.RemotePrefixes, c.LocalPrefixes
	}
	for i := range c.Peers {
		local, remote := netip.MustParseAddr("169.254.20.1"), netip.MustParseAddr("169.254.20.2")
		if i == 1 {
			local, remote = netip.MustParseAddr("169.254.20.5"), netip.MustParseAddr("169.254.20.6")
		}
		if role == "peer" {
			local, remote = remote, local
		}
		xid := uint32(701 + i)
		if role == "peer" {
			xid += 100
		}
		link := fmt.Sprintf("tnx-%d", i+1)
		if os.Getenv("TUNNEX_BGP_LAB_ROUTE_WRITER") == "1" {
			id := engineLabTunnels(role)[i].TunnelID
			link = KernelTunnelName(id)
			xid = KernelTunnelID(id)
		}
		c.Peers[i] = bgpengine.Peer{Slot: i + 1, Local: local, Remote: remote, LinkName: link, XFRMID: xid}
	}
	if os.Getenv("TUNNEX_BGP_MED_LAB") == "1" {
		if role == "gateway" {
			c.RemotePrefixes = append(c.RemotePrefixes, netip.MustParsePrefix("10.30.0.0/24"))
		} else {
			c.LocalPrefixes = append(c.LocalPrefixes, netip.MustParsePrefix("10.30.0.0/24"))
		}
	}
	if os.Getenv("TUNNEX_BGP_LAB_MAX_PREFIXES") == "64" {
		c.LocalPrefixes = []netip.Prefix{}
		c.RemotePrefixes = []netip.Prefix{}
		for i := 0; i < 64; i++ {
			local, remote := 10, 20
			if role == "peer" {
				local, remote = remote, local
			}
			c.LocalPrefixes = append(c.LocalPrefixes, netip.MustParsePrefix(fmt.Sprintf("10.%d.%d.0/24", local, i)))
			c.RemotePrefixes = append(c.RemotePrefixes, netip.MustParsePrefix(fmt.Sprintf("10.%d.%d.0/24", remote, i)))
		}
	}
	if os.Getenv("TUNNEX_BGP_LAB_WRONG_ASN") == "1" {
		c.RemoteASN = 65003
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	startManaged := func() (*bgpengine.Process, error) {
		if os.Getenv("TUNNEX_BGP_CRASH_LAB") != "1" {
			return bgpengine.StartProcess(ctx, "/run/tunnex-bgp", c)
		}
		if raw, err := os.ReadFile("/run/bgp-owned-identity.json"); err == nil {
			var old bgpengine.ProcessIdentity
			if json.Unmarshal(raw, &old) != nil || bgpengine.RecoverProcess(old) != nil {
				return nil, ErrRuntimeController
			}
		}
		return bgpengine.StartProcessWithCheckpoint(ctx, "/run/tunnex-bgp", c, func(id bgpengine.ProcessIdentity) error {
			raw, err := json.Marshal(id)
			if err != nil {
				return err
			}
			if err = os.WriteFile("/run/bgp-owned-identity.tmp", raw, 0600); err != nil {
				return err
			}
			return os.Rename("/run/bgp-owned-identity.tmp", "/run/bgp-owned-identity.json")
		})
	}
	var e error
	var process *bgpengine.Process
	var journal *RuntimeJournal
	var kernel *KernelApplier
	var entry RuntimeJournalEntry
	if os.Getenv("TUNNEX_BGP_LAB_ROUTE_WRITER") == "1" {
		configs := engineLabTunnels(role)
		entry = bgpEntryFixture(t)
		entry.DeliveryID = uuid.MustParse("eeeeeeee-0000-0000-0000-000000000001")
		entry.Allocation.Generation = entry.DeliveryID
		entry.Allocation.ConnectionID = configs[0].Binding.ConnectionID
		entry.Allocation.Namespace, _ = os.Readlink("/proc/self/ns/net")
		for i := range configs {
			configs[i].LocalPrefixes = c.LocalPrefixes
			configs[i].RemotePrefixes = c.RemotePrefixes
			configs[i].BGP = true
			configs[i].XFRMID = KernelTunnelID(configs[i].TunnelID)
			entry.Engines[i] = configs[i]
			p := c.Peers[i]
			entry.Allocation.Tunnels[i] = KernelTunnelAllocation{BGP: &KernelBGPTransport{Peer: p.Remote}, TunnelID: configs[i].TunnelID, Slot: uint8(i + 1), Name: p.LinkName, Alias: KernelTunnelAlias(entry.DeliveryID, configs[i].TunnelID), XFRMID: p.XFRMID, InsideAddress: netip.PrefixFrom(p.Local, 30), RemotePrefixes: configs[i].RemotePrefixes}
		}
		kernel, e = NewKernelApplier("/sbin/ip")
		if e != nil {
			t.Fatal(e)
		}
		entry.BGP = &BGPConfig{LocalASN: c.LocalASN, RemoteASN: c.RemoteASN, RouterID: c.RouterID.String(), MaximumPrefixes: c.MaximumPrefixes}
		if e = os.Mkdir(journalDir, 0700); e != nil && !os.IsExist(e) {
			t.Fatal(e)
		}
		journal, e = OpenRuntimeJournal(journalDir, configs[0].Binding.GatewayID)
		if e != nil {
			t.Fatal(e)
		}
		defer journal.Close()
		prior, err := journal.Entries()
		if err != nil {
			t.Fatal(err)
		}
		if len(prior) == 0 {
			snap, err := kernel.snapshot(ctx, entry.Allocation)
			if err != nil {
				t.Fatal(err)
			}
			entry.Observed = snap.ownership
			for _, phase := range []RuntimePhase{RuntimeReserved, RuntimeApplying, RuntimeApplied} {
				entry.Phase = phase
				if e = journal.Save([]RuntimeJournalEntry{entry}); e != nil {
					t.Fatal(e)
				}
			}
		} else {
			if os.Getenv("TUNNEX_BGP_CRASH_LAB") != "1" || len(prior) != 1 {
				t.Fatal("unexpected prior duty")
			}
			entry = prior[0]
			controller := &RuntimeController{config: RuntimeControllerConfig{JournalDir: journalDir}, journal: journal, kernel: kernel, namespace: func() (string, error) { return os.Readlink("/proc/self/ns/net") }}
			oldOwned := bgpRouteUnion(entry.BGPRoutes)
			if e = controller.cleanupBGPDuties(ctx, entry); e != nil {
				t.Fatal(e)
			}
			snapshot, err := kernel.snapshotBGPRoutes(ctx, entry.Allocation, oldOwned)
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range oldOwned {
				if snapshot.routes[r.Slot-1][r.Prefix] {
					t.Fatal("old owned route survived crash cleanup")
				}
			}
			proof, _ := json.Marshal(struct {
				OriginalOwned      []RuntimeBGPRouteTuple
				ExactKernelAbsence bool
				GrantAuthority     string
			}{oldOwned, true, "synthetic component transport-only denial installed before restart"})
			if os.WriteFile("/run/bgp-crash-cleanup-proof.json", proof, 0600) != nil {
				t.Fatal("cleanup receipt")
			}
			prior, e = journal.Entries()
			if e != nil {
				t.Fatal(e)
			}
			entry = prior[0]
		}
		t.Log("BGP_NO_KERNEL_BEFORE_GO_WRITER")
	}
	if journal != nil && os.Getenv("TUNNEX_BGP_CRASH_LAB") == "1" {
		controller := &RuntimeController{config: RuntimeControllerConfig{JournalDir: journalDir}, journal: journal, kernel: kernel, namespace: func() (string, error) { return os.Readlink("/proc/self/ns/net") }}
		point := os.Getenv("TUNNEX_BGP_STARTUP_CRASH_POINT")
		if point != "" && entry.BGPProcess == nil && len(entry.BGPProcessRetired) == 0 {
			controller.bgpCheckpointBeforeSave = func(id bgpengine.ProcessIdentity) error {
				match := id.Stage == "partial" && (point == "spawn" && len(id.Children) == 1 && len(id.Files) == 3 || point == "socket" && len(id.Children) == 2 && len(id.Files) < 8)
				if !match {
					return nil
				}
				daemon := "zebra"
				if point == "socket" {
					daemon = "bgpd"
				}
				for attempt := 0; attempt < 100; attempt++ {
					if info, err := os.Lstat(id.Directory + "/" + daemon + ".vty"); err == nil && info.Mode()&os.ModeSocket != 0 {
						break
					}
					time.Sleep(10 * time.Millisecond)
				}
				if info, err := os.Lstat(id.Directory + "/" + daemon + ".vty"); err != nil || info.Mode()&os.ModeSocket == 0 {
					return ErrRuntimeController
				}
				witness, _ := json.Marshal(id.Children)
				if os.WriteFile("/run/bgp-startup-crash-children.json", witness, 0600) != nil {
					return ErrRuntimeController
				}
				fmt.Println("BGP_STARTUP_CRASH_REQUESTED", point)
				syscall.Kill(os.Getpid(), syscall.SIGKILL)
				return ErrRuntimeController
			}
		}
		if e = controller.startBGPSession(ctx, entry); e != nil {
			t.Fatal(e)
		}
		process = controller.bgpProcesses[entry.DeliveryID].(*bgpengine.Process)
		entries, err := journal.Entries()
		if err != nil {
			t.Fatal(err)
		}
		entry = entries[0]
		raw, _ := json.Marshal(entry.BGPProcess)
		if os.WriteFile("/run/bgp-owned-identity.json", raw, 0600) != nil {
			t.Fatal("identity receipt")
		}
	} else {
		process, e = startManaged()
		if e != nil {
			t.Fatal(e)
		}
	}
	defer func() { _ = process.Close() }()
	t.Log("BGP_MANAGED_READY")
	for ctx.Err() == nil {
		if os.Getenv("TUNNEX_BGP_CRASH_LAB") == "1" {
			// Exercise scheduler/GC churn while locked creator threads stay alive.
			for i := 0; i < 32; i++ {
				done := make(chan struct{})
				go func() { runtime.Gosched(); close(done) }()
				<-done
			}
			runtime.GC()
			if _, err := os.Stat("/run/bgp-supervisor-crash"); err == nil {
				syscall.Kill(os.Getpid(), syscall.SIGKILL)
			}
		}

		if _, err := os.Stat("/run/bgp-restart"); err == nil {
			if process.Alive() {
				t.Fatal("restart requires dead owned child")
			}
			if err := process.Close(); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove("/run/bgp-restart"); err != nil {
				t.Fatal(err)
			}
			process, e = startManaged()
			if e != nil {
				t.Fatal(e)
			}
			t.Log("BGP_MANAGED_RESTARTED")
		}
		status, e := process.Observe(ctx)
		var learned []bgpengine.LearnedRoute
		if e == nil {
			learned, e = process.ObserveRoutes(ctx, status)
			if e == nil && journal != nil {
				target := []RuntimeBGPRouteTuple{}
				for _, r := range learned {
					target = append(target, RuntimeBGPRouteTuple{Prefix: r.Prefix, Slot: uint8(r.Slot), InterfaceIndex: entry.Observed[r.Slot-1].InterfaceIndex, Table: 254, Protocol: 242, Metric: 50000 + uint32(r.Slot)})
				}
				entries, err := journal.Entries()
				if err != nil {
					t.Fatal(err)
				}
				if entries[0].BGPRoutes == nil || !reflect.DeepEqual(entries[0].BGPRoutes.Owned, target) {
					if err = ReconcileBGPRoutes(ctx, journal, kernel, entry.DeliveryID.String(), target); err != nil {
						t.Fatal(err)
					}
				}
			}
		}
		receipt := struct {
			Alive         bool
			Status        bgpengine.Status
			ObservationOK bool
			Learned       []bgpengine.LearnedRoute
			Diagnostics   []string
		}{process.Alive(), status, e == nil, learned, process.Diagnostics()}
		raw, _ := json.Marshal(receipt)
		if os.WriteFile("/run/bgp-status.tmp", raw, 0600) != nil || os.Rename("/run/bgp-status.tmp", "/run/bgp-status.json") != nil {
			t.Fatal("receipt failed")
		}
		select {
		case <-ctx.Done():
		case <-time.After(200 * time.Millisecond):
		}
	}
}
