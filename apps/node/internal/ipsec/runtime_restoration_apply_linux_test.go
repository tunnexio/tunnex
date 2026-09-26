//go:build linux

package ipsec

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// Exercise the public Apply entry point, physical environment discovery, real
// kernel recreation, daemon staging, durable route-duty completion and reapply.
// Peer health/proof is injected: this disconnected test is controller-wiring
// evidence, not a live IKE negotiation or payload-continuity qualification.
func TestRuntimeRestorationApplyNative(t *testing.T) {
	runRestorationApplyNative(t, false)
}

func TestRuntimeRestorationApplyReusedNamespaceNative(t *testing.T) {
	runRestorationApplyNative(t, true)
}

func runRestorationApplyNative(t *testing.T, reusedNamespace bool) {
	if os.Getenv("TUNNEX_IPSEC_RESTORATION_APPLY_LAB") != "1" {
		t.Skip("disconnected disposable namespace only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
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
	ns, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	boot, err := resetBootID()
	if err != nil {
		t.Fatal(err)
	}
	dir := journalDir(t)
	c, err := NewRuntimeController(RuntimeControllerConfig{OrgID: m.Manifest.OrgID, GatewayID: m.Manifest.NodeID, JournalDir: dir, IPPath: "/sbin/ip", NFTPath: "/usr/sbin/nft", Daemon: process.Client, DaemonAlive: process.Alive, Environment: env}, &recoveryTestLease{ttl: 60000})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	run := func(args ...string) {
		t.Helper()
		if _, err := c.kernel.run(ctx, args...); err != nil {
			t.Fatalf("ip %v: %v", args, err)
		}
	}
	run("link", "add", "rest-underlay", "type", "veth", "peer", "name", "rest-lan")
	defer func() { _, _ = c.kernel.run(context.Background(), "link", "del", "rest-underlay") }()
	run("addr", "add", "192.0.2.1/24", "dev", "rest-underlay")
	run("addr", "add", "10.10.0.1/24", "dev", "rest-lan")
	run("link", "set", "rest-underlay", "up")
	run("link", "set", "rest-lan", "up")
	run("route", "add", "198.51.100.0/24", "dev", "rest-underlay")
	priorNamespace := "net:[9999996]"
	if reusedNamespace {
		priorNamespace = ns
	}
	old, _, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, priorNamespace)
	if err != nil {
		t.Fatal(err)
	}
	old = saveAppliedRestorationFixture(t, c.journal, old)
	old.Recovery = &RuntimeRecoveryState{SelectedSlot: 1, Sequence: 1, PendingFrom: 1, PendingTo: 2, Stage: "pending"}
	if err := c.journal.Save([]RuntimeJournalEntry{old}); err != nil {
		t.Fatal(err)
	}
	if reusedNamespace {
		old.Restoration = &RuntimeRestoration{BootID: boot}
		if err := c.journal.Save([]RuntimeJournalEntry{old}); err != nil {
			t.Fatal(err)
		}
	}
	receipt := runtimeRestorationReceipt{Version: 1, OwnerID: m.Manifest.NodeID, DeliveryID: old.DeliveryID, EntryDigest: restorationEntryDigest(old), BootID: boot, Namespace: ns, Termination: "supervisor-confirmed-runtime-stop", EvidenceDigest: stringDigest([]byte("synthetic controller wiring fixture"))}
	raw, _ := json.Marshal(receipt)
	if err := os.WriteFile(filepath.Join(dir, "restore-"+old.DeliveryID.String()+".json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	c.qualification = testRuntimeQualification(ns)
	c.recoveryObserve = func(context.Context, RuntimeJournalEntry) [2]string { return [2]string{"up", "up"} }
	c.prove = func(context.Context, RuntimeJournalEntry, RuntimeEnvironment) error { return nil }
	if reusedNamespace {
		gate := filepath.Join(dir, "restoration-startup-gate")
		if err := os.WriteFile(gate, []byte("test supervisor owns this startup hold\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Apply(ctx, m); err == nil {
			t.Fatal("startup hold allowed Apply")
		}
		held, err := c.journal.Entries()
		if err != nil {
			t.Fatal(err)
		}
		if len(held) != 1 || !reflect.DeepEqual(held[0], old) || len(c.active) != 0 {
			t.Fatal("startup hold changed restoration duty or retained permits")
		}
		if err := c.proveAbsent(ctx, old); err != nil {
			t.Fatal("startup hold created tunnel objects", err)
		}
		if err := os.Remove(gate); err != nil {
			t.Fatal(err)
		}
	}
	ack, err := c.Apply(ctx, m)
	if err != nil {
		t.Fatal("public Apply failed", err)
	}
	if ack.Result != "applied" {
		t.Fatalf("unexpected acknowledgement: %s", ack.Result)
	}
	entries, err := c.journal.Entries()
	if err != nil {
		t.Fatal(err)
	}
	e := entries[0]
	if e.Restoration == nil || e.Restoration.Epoch != 1 || e.Restoration.BootID != boot || e.Allocation.Namespace != ns || e.Allocation.Generation == old.Allocation.Generation || selectedRuntimeSlot(e) != 2 || e.Recovery.Stage != "completed" {
		t.Fatal("restored Apply lost epoch or pending route duty")
	}
	if e.Observed[0].InterfaceIndex <= 0 || e.Observed[1].InterfaceIndex <= 0 {
		t.Fatal("kernel ownership missing")
	}
	if missing, err := c.kernel.RestartNeedsRecreation(ctx, e.Allocation, e.Observed); err != nil || missing {
		t.Fatal("restored kernel identity unreadable", err)
	}
	if _, err := c.Apply(ctx, m); err != nil {
		t.Fatal("same CP material cannot reapply after local generation changes", err)
	}
	again, _ := c.journal.Entries()
	if again[0].Restoration.Epoch != 1 || again[0].Allocation.Generation != e.Allocation.Generation || selectedRuntimeSlot(again[0]) != 2 {
		t.Fatal("reapply changed restored epoch or route duty")
	}
	if _, err := c.refuse(ctx, again); err != nil {
		t.Fatal(err)
	}
	for _, tunnel := range e.Engines {
		if err := process.Client.removeTunnel(ctx, tunnel); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.kernel.RemoveRecovery(ctx, e.Allocation, e.Observed); err != nil {
		t.Fatal(err)
	}
	t.Log("PASS public Apply, environment census, new kernel epoch, daemon staging, pending slot-two completion, and idempotent reapply; peer health is injected")
}
