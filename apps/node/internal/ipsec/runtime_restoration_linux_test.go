//go:build linux

package ipsec

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// Synthetic prior-boot/namespace evidence, real kernel absence and guard checks.
// This is not evidence of a real host reboot or cloud traffic continuity.
func TestRuntimeRestorationReservationNative(t *testing.T) {
	if os.Getenv("TUNNEX_IPSEC_RESTORATION_LAB") != "1" {
		t.Skip("disconnected disposable namespace only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
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
	m := runtimeMaterialFixture()
	version := 1
	m.Manifest.RecoveryVersion = &version
	runtimeReseal(&m)
	ns, _ := os.Readlink("/proc/self/ns/net")
	boot, _ := resetBootID()
	old, _, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[9999998]")
	if err != nil {
		t.Fatal(err)
	}
	lease := &recoveryTestLease{ttl: 60000}
	dir := journalDir(t)
	c, err := NewRuntimeController(RuntimeControllerConfig{OrgID: m.Manifest.OrgID, GatewayID: m.Manifest.NodeID, JournalDir: dir, IPPath: "/sbin/ip", NFTPath: "/usr/sbin/nft", Daemon: process.Client, DaemonAlive: process.Alive, Environment: env}, lease)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	old = saveAppliedRestorationFixture(t, c.journal, old)
	old.Recovery = &RuntimeRecoveryState{SelectedSlot: 1, Sequence: 1, PendingFrom: 1, PendingTo: 2, Stage: "pending"}
	if err = c.journal.Save([]RuntimeJournalEntry{old}); err != nil {
		t.Fatal(err)
	}
	if err = c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	candidate, _, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, ns)
	if err != nil {
		t.Fatal(err)
	}
	entries := func() []RuntimeJournalEntry {
		v, e := c.journal.Entries()
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	refused := func(label string) {
		t.Helper()
		before := entries()
		if c.reserveRestoration(ctx, m, entries(), 0, candidate, boot) == nil {
			t.Fatalf("%s accepted", label)
		}
		if !reflect.DeepEqual(before, entries()) {
			t.Fatalf("%s changed entries", label)
		}
	}
	refused("no termination proof")
	receipt := runtimeRestorationReceipt{Version: 1, OwnerID: m.Manifest.NodeID, DeliveryID: old.DeliveryID, EntryDigest: restorationEntryDigest(old), BootID: boot, Namespace: ns, Termination: "supervisor-confirmed-runtime-stop", EvidenceDigest: stringDigest([]byte("synthetic native test"))}
	path := filepath.Join(dir, "restore-"+old.DeliveryID.String()+".json")
	write := func(r runtimeRestorationReceipt) {
		b, _ := json.Marshal(r)
		if err := os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	bad := receipt
	bad.EntryDigest = stringDigest([]byte("wrong"))
	write(bad)
	refused("wrong covered entry")
	write(receipt)
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	refused("public receipt")
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".target"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path+".target", path); err != nil {
		t.Fatal(err)
	}
	refused("symlink receipt")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".target", path); err != nil {
		t.Fatal(err)
	}
	bad = receipt
	bad.Namespace = "net:[9999997]"
	write(bad)
	refused("receipt for another namespace")
	bad = receipt
	bad.BootID = "00000000-0000-0000-0000-000000000001"
	write(bad)
	refused("receipt for another boot")
	write(receipt)
	lease.deny = true
	refused("CP denied")
	lease.deny = false
	run := func(args ...string) {
		t.Helper()
		if _, e := c.kernel.run(ctx, args...); e != nil {
			t.Fatal(e)
		}
	}
	run("link", "add", "rest-collision", "type", "dummy")
	run("link", "set", "dev", "rest-collision", "alias", old.Allocation.Tunnels[0].Alias)
	refused("renamed prior alias survives")
	run("link", "delete", "rest-collision")
	if err = c.reserveRestoration(ctx, m, entries(), 0, candidate, boot); err != nil {
		t.Fatal("valid reservation", err)
	}
	e := entries()[0]
	if e.Allocation.Namespace != ns || e.Allocation.Generation == old.Allocation.Generation || e.Restoration.Epoch != 1 || e.Observed != ([2]Ownership{}) || !reflect.DeepEqual(e.Recovery, old.Recovery) {
		t.Fatal("reservation lost identity separation or route duty")
	}
	// Reopen proves a crash after reservation does not depend on an in-memory receipt.
	c.Close()
	c, err = NewRuntimeController(RuntimeControllerConfig{OrgID: m.Manifest.OrgID, GatewayID: m.Manifest.NodeID, JournalDir: dir, IPPath: "/sbin/ip", NFTPath: "/usr/sbin/nft", Daemon: process.Client, DaemonAlive: process.Alive, Environment: env}, lease)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err = c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	missing, err := c.kernel.RestartNeedsRecreation(ctx, e.Allocation, e.Observed)
	if err != nil || !missing {
		t.Fatal("reserved absent generation cannot resume", err)
	}
	// Simulate crash after one exclusive create: never adopt a partial survivor.
	t0 := e.Allocation.Tunnels[0]
	run("link", "add", t0.Name, "type", "xfrm", "if_id", fmtUint(t0.XFRMID))
	run("link", "set", "dev", t0.Name, "alias", t0.Alias, "addrgenmode", "none")
	if _, err = c.kernel.RestartNeedsRecreation(ctx, e.Allocation, e.Observed); err == nil {
		t.Fatal("partial creation adopted")
	}
	run("link", "delete", t0.Name)
	owned, err := c.kernel.Apply(ctx, e.Allocation, [2]Ownership{})
	if err != nil {
		t.Fatal(err)
	}
	current := entries()
	current[0].Observed = owned
	if err = c.journal.Save(current); err != nil {
		t.Fatal("observed generation not durable", err)
	}
	if err = c.kernel.RemoveRecovery(ctx, e.Allocation, owned); err != nil {
		t.Fatal(err)
	}
	t.Log("PASS native exact receipt/lease/absence gates; durable epoch reservation; pending route preserved; partial creation refused")
}
func fmtUint(v uint32) string { return fmt.Sprint(v) }
