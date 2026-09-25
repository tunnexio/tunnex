//go:build linux

package ipsec

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type resetDrainGate struct {
	RuntimeEnvironmentInspector
	refuse bool
}

func (g *resetDrainGate) Drain(c context.Context, e []RuntimeJournalEntry) error {
	if g.refuse {
		return ErrRuntimeEnvironment
	}
	return g.RuntimeEnvironmentInspector.Drain(c, e)
}

func TestRuntimeResetCleanupNative(t *testing.T) {
	if os.Getenv("TUNNEX_IPSEC_RESET_LAB") != "1" {
		t.Skip("disposable privileged Linux namespace only")
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
	gate := &resetDrainGate{RuntimeEnvironmentInspector: env}
	m := runtimeMaterialFixture()
	recoveryVersion := 1
	m.Manifest.RecoveryVersion = &recoveryVersion
	runtimeReseal(&m)
	oldns := "net:[9999999]"
	entry, _, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, oldns)
	if err != nil {
		t.Fatal(err)
	}
	dir := journalDir(t)
	config := RuntimeControllerConfig{OrgID: m.Manifest.OrgID, GatewayID: m.Manifest.NodeID, JournalDir: dir, IPPath: "/sbin/ip", NFTPath: "/usr/sbin/nft", Daemon: process.Client, DaemonAlive: process.Alive, Environment: gate}
	c, err := NewRuntimeController(config, nativeRuntimeLease{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { c.Close() }()
	if err = c.journal.Save([]RuntimeJournalEntry{entry}); err != nil {
		t.Fatal(err)
	}
	entry.Phase = RuntimeApplying
	for i, tunnel := range entry.Allocation.Tunnels {
		entry.Observed[i] = Ownership{Namespace: oldns, InterfaceName: tunnel.Name, InterfaceIndex: 10 + i, XFRMID: tunnel.XFRMID}
	}
	if err = c.journal.Save([]RuntimeJournalEntry{entry}); err != nil {
		t.Fatal(err)
	}
	entry.Phase = RuntimeApplied
	if err = c.journal.Save([]RuntimeJournalEntry{entry}); err != nil {
		t.Fatal(err)
	}
	entry.Recovery = &RuntimeRecoveryState{SelectedSlot: 1, Sequence: 1, PendingFrom: 1, PendingTo: 2, Stage: "pending"}
	if err = c.journal.Save([]RuntimeJournalEntry{entry}); err != nil {
		t.Fatal(err)
	}
	if err = c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	cleanup := RuntimeCleanup{RuntimeDelivery: RuntimeDelivery{ID: uuid.New(), DesiredRevision: m.DesiredRevision + 1, Kind: "cleanup", CoversDeliveryRevision: m.DesiredRevision, Manifest: m.Manifest}, RetainGuard: true, Lineage: []RuntimeDelivery{m.RuntimeDelivery}}
	raw, _ := json.Marshal(cleanup.Lineage)
	cleanup.OwnershipDigest = stringDigest(raw)
	refused := func(label string) {
		t.Helper()
		ack, e := c.Cleanup(ctx, cleanup)
		if e == nil || ack.DeliveryID != uuid.Nil {
			t.Fatalf("%s falsely acknowledged", label)
		}
	}
	refused("missing receipt")
	ns, _ := os.Readlink("/proc/self/ns/net")
	boot, _ := resetBootID()
	receipt := runtimeResetReceipt{Version: 1, OwnerID: m.Manifest.NodeID, CleanupID: cleanup.ID, CleanupRevision: cleanup.DesiredRevision, CoveredDigest: resetCoveredDigest([]RuntimeJournalEntry{entry}), BootID: boot, Namespace: ns, Termination: "supervisor-confirmed-vm-stop", EvidenceDigest: stringDigest([]byte("synthetic disposable legacy reset proof"))}
	path := filepath.Join(dir, "reset-cleanup-"+cleanup.ID.String()+".json")
	write := func(r runtimeResetReceipt) {
		t.Helper()
		b, _ := json.Marshal(r)
		if e := os.WriteFile(path, b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	bad := receipt
	bad.BootID = uuid.NewString()
	write(bad)
	refused("foreign boot")
	write(receipt)
	os.Chmod(path, 0644)
	refused("public receipt")
	os.Chmod(path, 0600)
	moved := path + ".saved"
	os.Rename(path, moved)
	os.Symlink(moved, path)
	refused("symlink receipt")
	os.Remove(path)
	os.Rename(moved, path)
	if _, err = runKernelCommand(ctx, "/sbin/ip", "link", "add", "reset-collision", "alias", entry.Allocation.Tunnels[0].Alias, "type", "dummy"); err != nil {
		t.Fatal(err)
	}
	if _, err = runKernelCommand(ctx, "/sbin/ip", "link", "set", "dev", "reset-collision", "alias", entry.Allocation.Tunnels[0].Alias); err != nil {
		t.Fatal(err)
	}
	aliasInventory, _ := runKernelCommand(ctx, "/sbin/ip", "-j", "-d", "link", "show")
	if resetExtraObjectsAbsent(entry, aliasInventory, []byte(`[]`)) {
		t.Fatalf("alias inventory not recognized: %s", aliasInventory)
	}
	refused("renamed alias survivor")
	if _, err = runKernelCommand(ctx, "/sbin/ip", "link", "delete", "reset-collision"); err != nil {
		t.Fatal(err)
	}
	gate.refuse = true
	refused("failed conntrack drain")
	gate.refuse = false
	if err = c.Close(); err != nil {
		t.Fatal(err)
	}
	c, err = NewRuntimeController(config, nativeRuntimeLease{})
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	ack, err := c.Cleanup(ctx, cleanup)
	if err != nil || ack.Result != "cleaned" || !ack.GuardRetained {
		t.Fatal("verified reset cleanup", err)
	}
	entries, _ := c.journal.Entries()
	if len(entries) != 1 || entries[0].Allocation.Namespace != oldns || entries[0].ResetCleanup == nil || entries[0].Phase != RuntimeRetainedRefusal {
		t.Fatal("old ownership or reset audit lost")
	}
	if entries[0].Observed != entry.Observed || *entries[0].Recovery != *entry.Recovery {
		t.Fatal("recorded interface ownership or pending route duty changed")
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Cleanup(ctx, cleanup); err != nil {
		t.Fatal("idempotent retry", err)
	}
	if _, err = c.Apply(ctx, m); err == nil {
		t.Fatal("cleanup receipt authorized old Apply")
	}
	t.Log("native reset cleanup preserves old ownership, denies invalid proof/collisions/drain failure, and does not grant Apply")
}
