//go:build linux

package ipsec

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	bgpengine "github.com/tunnexio/tunnex/apps/node/internal/bgp"
)

// The previous boot and stopped-process checkpoint are synthetic. Kernel, daemon,
// process-directory census, namespace/boot reads and nftables are real. This
// proves a cold reservation boundary, not an actual reboot or cloud traffic.
// Run alone in a disconnected disposable root container/namespace.
func TestColdQuiescedRestorationReservationNative(t *testing.T) {
	if os.Getenv("TUNNEX_IPSEC_COLD_QUIESCED_LAB") != "1" {
		t.Skip("disconnected disposable namespace only")
	}
	if os.Geteuid() != 0 {
		t.Fatal("native qualification requires disposable root namespace")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	process, err := StartDaemonProcess(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer process.Close()
	env, err := NewRuntimeEnvironmentInspector("/sbin/ip", "/usr/sbin/nft")
	if err != nil {
		t.Fatal(err)
	}
	ns, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	boot, err := resetBootID()
	if err != nil {
		t.Fatal(err)
	}
	m := bgpMaterialFixture()
	old, _, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, ns)
	if err != nil {
		t.Fatal(err)
	}
	// Reused namespace inode is intentional: only the real boot change may
	// discharge the recorded old PID identity, never namespace equality alone.
	oldBoot := uuid.NewString()
	if oldBoot == boot {
		t.Fatal("synthetic old boot unexpectedly equals current boot")
	}
	// The real process census requires every ancestor to be root-owned and
	// non-writable by other users; the usual testing /tmp ancestor is not valid.
	dir, err := os.MkdirTemp("/run", "tunnex-cold-quiesced-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error("remove owned native fixture directory", err)
		}
	})
	processDir := filepath.Join(dir, "bgp-"+old.DeliveryID.String()+"-g1")
	if err = os.Mkdir(processDir, 0700); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(processDir)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || info.Mode() != os.ModeDir|0700 {
		t.Fatal("process directory is not a real root-private directory")
	}
	priorProcess := *processStateFixture(t).BGPProcess
	priorProcess.BootID, priorProcess.Namespace = oldBoot, ns
	// A reused live PID must never be signalled for an identity from an old boot.
	priorProcess.Supervisor.PID = os.Getpid()
	priorProcess.Directory, priorProcess.Stage = processDir, "cleaned"
	priorProcess.DirectoryFile = bgpengine.FileIdentity{Device: uint64(stat.Dev), Inode: stat.Ino, Mode: uint32(info.Mode())}
	old.BGPProcess = &priorProcess
	old.Phase = RuntimeQuiesced
	old.Restoration = &RuntimeRestoration{BootID: oldBoot}
	old.BGPRoutes = &RuntimeBGPRoutes{Sequence: 1, Stage: "completed", Withdrawal: true, Owned: []RuntimeBGPRouteTuple{}, Target: []RuntimeBGPRouteTuple{}}
	for i, allocation := range old.Allocation.Tunnels {
		old.Observed[i] = Ownership{Namespace: ns, InterfaceName: allocation.Name, InterfaceIndex: 10 + i, XFRMID: allocation.XFRMID}
	}
	payload := runtimeJournalPayload{Version: 12, OwnerID: m.Manifest.NodeID, Sequence: 1, Entries: []RuntimeJournalEntry{old}}
	if !validJournalPayload(payload) {
		t.Fatal("synthetic old-boot negative checkpoint is invalid")
	}
	writeColdQuiescedPayload(t, dir, payload)
	var c *RuntimeController
	var denial GuardManifest
	denials, leases := 0, 0
	nonces := map[string]bool{}
	lease := maintenanceLeaseFunc(func(leaseCtx context.Context, id uuid.UUID, request RuntimeLeaseRequest) (RuntimeLease, error) {
		if c == nil || denials == 0 || c.guard.reader.Check(leaseCtx, denial) != nil || id != old.Allocation.ConnectionID || request.DeliveryID != old.DeliveryID || request.PolicyHash != m.Policy.Hash || len(request.Nonce) != 64 || nonces[request.Nonce] {
			t.Fatal("lease precedes native denial or reuses/mismatches authority")
		}
		nonces[request.Nonce] = true
		leases++
		return RuntimeLease{RuntimeLeaseRequest: request, TTLMS: 60000}, nil
	})
	c, err = NewRuntimeController(RuntimeControllerConfig{OrgID: m.Manifest.OrgID, GatewayID: m.Manifest.NodeID, JournalDir: dir, IPPath: "/sbin/ip", NFTPath: "/usr/sbin/nft", Daemon: process.Client, DaemonAlive: process.Alive, Environment: env}, lease)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	realReplace := c.replace
	c.replace = func(replaceCtx context.Context, in GuardIntent) (GuardManifest, error) {
		if len(in.Connections) != 1 {
			t.Fatal("missing exact prefix refusal")
		}
		for _, connection := range in.Connections {
			if !connection.PrefixOnly || len(connection.Grants) != 0 || connection.PermitFor != 0 || len(connection.PermittedInterfaceIndices) != 0 {
				t.Fatal("cold reservation installed positive authority")
			}
		}
		// Observe intent only; preserve the real native transaction and readback.
		manifest, replaceErr := realReplace(replaceCtx, in)
		if replaceErr == nil {
			denial = manifest
			denials++
		}
		return manifest, replaceErr
	}
	if err = c.Start(ctx); err != nil {
		t.Fatal("real native startup refusal", err)
	}
	candidate, _, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, ns)
	if err != nil {
		t.Fatal(err)
	}
	entries := func() []RuntimeJournalEntry {
		values, readErr := c.journal.Entries()
		if readErr != nil {
			t.Fatal(readErr)
		}
		return values
	}
	if err = c.coldQuiescedRestorationAbsent(ctx, entries()[0], boot, ns); err != nil {
		t.Fatal("clean real-reader baseline", err)
	}
	run := func(args ...string) []byte {
		t.Helper()
		raw, runErr := c.kernel.run(ctx, args...)
		if runErr != nil {
			t.Fatal("owned native fixture command", args[0], runErr)
		}
		return raw
	}
	cleanup := func(args ...string) {
		t.Helper()
		cleanupCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if _, cleanupErr := c.kernel.run(cleanupCtx, args...); cleanupErr != nil {
			t.Error("owned native fixture cleanup", args[0], cleanupErr)
		}
	}
	refused := func(label string) {
		t.Helper()
		before, beforeLeases, beforeDenials := entries(), leases, denials
		reserveErr := c.reserveRestoration(ctx, m, entries(), 0, candidate, boot)
		if reserveErr == nil || !strings.Contains(reserveErr.Error(), "cold quiesced absence") {
			t.Fatalf("%s did not reach/refuse actual absence gate: %v", label, reserveErr)
		}
		if !reflect.DeepEqual(before, entries()) || c.journal.payload.Version != 12 || len(c.active) != 0 || leases != beforeLeases+1 || denials != beforeDenials+1 || c.guard.reader.Check(ctx, denial) != nil {
			t.Fatalf("%s changed checkpoint, lost native refusal or skipped fresh lease", label)
		}
	}
	func() {
		peer := old.Allocation.Tunnels[0].BGP.Peer.String() + "/32"
		run("route", "add", peer, "dev", "lo")
		defer cleanup("route", "del", peer, "dev", "lo")
		refused("foreign peer route")
		rows, parsed := kernelObjects(run("-j", "-4", "route", "show", "exact", peer))
		if !parsed || len(rows) != 1 {
			t.Fatal("foreign peer route was adopted or removed")
		}
	}()
	func() {
		const name = "coldq-xfrm"
		run("link", "add", name, "type", "xfrm", "if_id", fmt.Sprint(old.Allocation.Tunnels[0].XFRMID))
		defer cleanup("link", "delete", name)
		refused("foreign XFRM interface with owned if_id")
		run("-j", "-d", "link", "show", "dev", name)
	}()
	func() {
		path := filepath.Join(processDir, "foreign-survivor")
		if err := os.WriteFile(path, []byte("preserve"), 0600); err != nil {
			t.Fatal(err)
		}
		defer os.Remove(path)
		refused("nonempty cleaned process directory")
		if raw, err := os.ReadFile(path); err != nil || string(raw) != "preserve" {
			t.Fatal("foreign directory file was removed or changed")
		}
	}()
	func() {
		later := filepath.Join(dir, "bgp-"+old.DeliveryID.String()+"-g2")
		if err := os.Mkdir(later, 0700); err != nil {
			t.Fatal(err)
		}
		defer os.Remove(later)
		path := filepath.Join(later, "foreign-survivor")
		if err := os.WriteFile(path, []byte("preserve"), 0600); err != nil {
			t.Fatal(err)
		}
		defer os.Remove(path)
		refused("unrecorded later generation directory")
		if raw, err := os.ReadFile(path); err != nil || string(raw) != "preserve" {
			t.Fatal("unrecorded generation survivor was removed or changed")
		}
	}()
	beforeLeases := leases
	reserved := entries()
	if err = c.reserveRestoration(ctx, m, reserved, 0, candidate, boot); err != nil {
		t.Fatal("real absent cold reservation", err)
	}
	got := reserved[0]
	if got.Phase != RuntimeApplying || got.Allocation.Namespace != ns || got.Allocation.Generation == old.Allocation.Generation || got.Observed != ([2]Ownership{}) || got.BGPProcess != nil || got.BGPRoutes != nil || got.Restoration == nil || got.Restoration.Epoch != 1 || got.Restoration.BootID != boot || len(got.Restoration.Retired) != 1 || c.journal.payload.Version != 14 || len(c.active) != 0 || leases != beforeLeases+1 || c.guard.reader.Check(ctx, denial) != nil {
		t.Fatal("cold reservation lost negative state or gained application authority")
	}
	retired := got.Restoration.Retired[0]
	if !reflect.DeepEqual(retired.Entry, flattenedRestorationEntry(old)) || retired.BootID != oldBoot || retired.NewBootID != boot || retired.Termination != "kernel-boot-change" || !reflect.DeepEqual(got.BGPProcessRetired, []bgpengine.ProcessIdentity{priorProcess}) {
		t.Fatal("cold reservation changed the exact old negative duties")
	}
	if err = c.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenRuntimeJournal(dir, m.Manifest.NodeID)
	if err != nil {
		t.Fatal("reopen version14", err)
	}
	defer reopened.Close()
	durable, err := reopened.Entries()
	if err != nil || reopened.payload.Version != 14 || !reflect.DeepEqual(durable, reserved) {
		t.Fatal("durable reservation lost exact history", err)
	}
	t.Log("PASS real daemon/kernel/nft/process-directory absence; four preserved survivors denied; fresh nonce-bound lease; durable v14 negative history. Prior boot/process metadata synthetic; no reboot/traffic claim.")
}
