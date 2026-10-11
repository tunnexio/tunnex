//go:build linux

package ipsec

import (
	"bytes"
	"context"
	"github.com/google/uuid"
	"os"
	"os/exec"
	"testing"
	"time"
)

// Runs only in a new network=none disposable Linux namespace. Native daemon,
// keyless SA/kernel absence and NFT ownership/readback are real; no cloud lease
// or IPsec peer is manufactured by this fixture.
func TestNativeRetainedGuardHandoffAbsenceAndReadback(t *testing.T) {
	testNativeRetainedHandoff(t, false)
}
func TestNativeAzureBGPRecreationAbsenceAndReadback(t *testing.T) { testNativeRetainedHandoff(t, true) }
func testNativeRetainedHandoff(t *testing.T, azure bool) {
	if os.Getenv("TUNNEX_IPSEC_RETAINED_HANDOFF_LAB") != "1" {
		t.Skip("isolated retained handoff fixture only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	run := func(args ...string) []byte {
		t.Helper()
		out, err := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
		if err != nil {
			t.Fatalf("fixture operation %v: %v", args, err)
		}
		return out
	}
	if bytes.Contains(run("/usr/sbin/nft", "-j", "list", "tables"), []byte(`"table"`)) {
		t.Fatal("fixture must start with empty independent firewall")
	}
	daemon, err := StartDaemonProcess(ctx)
	if err != nil {
		t.Fatal("owned fixture daemon start", err)
	}
	defer daemon.Close()
	ns, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	old, successor, _ := retainedHandoffFixture(t)
	if azure {
		_, old = azureRecreationMaterial(t, nil, []string{"10.231.0.0/16"}, 8)
		old = retainedAzure(old)
		_, successor = azureRecreationMaterial(t, []RuntimeJournalEntry{old}, []string{"10.231.0.0/16", "10.235.77.0/24"}, 1)
	}
	old.Allocation.Namespace = ns
	successor.Allocation.Namespace = ns
	dir := journalDir(t)
	j, err := OpenRuntimeJournal(dir, old.Engines[0].Binding.GatewayID)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	reserved := old
	reserved.Phase = RuntimeReserved
	reserved.CleanupID = successor.CleanupID
	reserved.CleanupDesiredRevision = 0
	reserved.CoveredDeliveryRevision = 0
	if j.Save([]RuntimeJournalEntry{reserved}) != nil {
		t.Fatal("native journal reserve")
	}
	pending := old
	pending.Phase = RuntimeCleanupPending
	if j.Save([]RuntimeJournalEntry{pending}) != nil || j.Save([]RuntimeJournalEntry{old}) != nil {
		t.Fatal("native predecessor retained")
	}
	g, err := NewRuntimeGuard(j, "/usr/sbin/nft")
	if err != nil {
		t.Fatal(err)
	}
	c := &RuntimeController{journal: j, guard: g, replace: g.Replace, namespace: func() (string, error) { return ns, nil }, config: RuntimeControllerConfig{OrgID: old.Engines[0].Binding.OrgID, GatewayID: old.Engines[0].Binding.GatewayID, JournalDir: dir, IPPath: "/sbin/ip", NFTPath: "/usr/sbin/nft", Daemon: daemon.Client, DaemonAlive: daemon.Alive}}
	if err := c.Start(ctx); err != nil {
		t.Fatal("native predecessor startup denial", err)
	}
	qualification, err := ProbeRuntimePlatform(ctx, "/sbin/ip", "/usr/sbin/nft", daemon.Client, daemon.Alive)
	if err != nil || c.AttachQualification(qualification) != nil || c.RetainedGuardCapability() != 1 {
		t.Fatal("actual qualified successor capability refused", err)
	}
	if c.admitRetainedGuardHandoff(ctx, []RuntimeJournalEntry{old}, successor) != nil {
		t.Fatal("complete native absence refused")
	}
	if azure {
		// Synthetic old-boot metadata is a negative fixture, not a reboot proof.
		// Native absence and missing FRR metadata cannot discharge that history.
		oldBoot := old
		oldBoot.Restoration = &RuntimeRestoration{BootID: uuid.NewString()}
		if oldBoot.BGPProcess != nil || len(oldBoot.BGPProcessRetired) != 0 {
			t.Fatal("no-process boot fixture unexpectedly has FRR metadata")
		}
		if c.proveAzureBGPDutiesAbsent(ctx, oldBoot) == nil {
			t.Fatal("old boot without process metadata bypassed reset proof")
		}
		run("/sbin/ip", "link", "add", "tnx-peer-test", "type", "dummy")
		run("/sbin/ip", "link", "set", "dev", "tnx-peer-test", "up")
		run("/sbin/ip", "-4", "route", "add", old.Allocation.Tunnels[0].BGP.Peer.String()+"/32", "dev", "tnx-peer-test", "proto", "242", "metric", "50001")
		if c.admitRetainedGuardHandoff(ctx, []RuntimeJournalEntry{old}, successor) == nil {
			t.Fatal("renamed peer route survivor accepted")
		}
		run("/sbin/ip", "link", "delete", "tnx-peer-test")
	}

	// A renamed non-XFRM survivor carrying exact ownership alias must refuse.
	run("/sbin/ip", "link", "add", "tnx-hand-test", "type", "dummy")
	run("/sbin/ip", "link", "set", "tnx-hand-test", "alias", old.Allocation.Tunnels[0].Alias)
	if c.admitRetainedGuardHandoff(ctx, []RuntimeJournalEntry{old}, successor) == nil {
		t.Fatal("native renamed survivor authorized handoff")
	}
	if !bytes.Contains(run("/sbin/ip", "-j", "-d", "link", "show", "tnx-hand-test"), []byte(old.Allocation.Tunnels[0].Alias)) {
		t.Fatal("refusal removed foreign survivor")
	}
	run("/sbin/ip", "link", "delete", "tnx-hand-test")
	if c.admitRetainedGuardHandoff(ctx, []RuntimeJournalEntry{old}, successor) != nil {
		t.Fatal("absence after owned fixture cleanup refused")
	}
	if j.Save([]RuntimeJournalEntry{old, successor}) != nil {
		t.Fatal("native successor reserve")
	}
	manifest, err := c.refuse(ctx, []RuntimeJournalEntry{old, successor})
	if err != nil {
		t.Fatal("native exact successor combined denial", err)
	}
	if g.reader.Check(ctx, manifest) != nil {
		t.Fatal("native strict readback failed")
	}
	if bytes.Contains([]byte(manifest.NFT), []byte("counter accept")) {
		t.Fatal("native successor reservation manufactured permission")
	}
	j.Close()
	j, err = OpenRuntimeJournal(dir, old.Engines[0].Binding.GatewayID)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	g, err = NewRuntimeGuard(j, "/usr/sbin/nft")
	if err != nil {
		t.Fatal(err)
	}
	c.journal = j
	c.guard = g
	c.replace = g.Replace
	entries, err := j.Entries()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.refuse(ctx, entries); err != nil {
		t.Fatal("actual restart lost durable denial or empty predecessor sets", err)
	}
	t.Log("PASS actual owned charon/keyless kernel+XFRM absence, renamed alias survivor refusal, unchanged survivor, atomic successor denial with empty old lease sets, journal reopen/native strict readback; no peer/cloud lease or traffic claim")
}
