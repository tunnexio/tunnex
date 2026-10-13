//go:build linux

package ipsec

import (
	"context"
	"encoding/json"
	bgpengine "github.com/tunnexio/tunnex/apps/node/internal/bgp"
	"os"
	"os/exec"
	"reflect"
	"testing"
	"time"
)

// Real FRR, kernel, NFT, charon and durable journal; synthetic entry authority.
// No established peers, encrypted packet, fresh CP lease or normal API claim.
func TestHistoryTwentyRealFRRGenerationsNative(t *testing.T) {
	if os.Getenv("TUNNEX_HISTORY_NATIVE_LAB") != "1" {
		t.Skip("owned disposable native namespace")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	dir := os.Getenv("TUNNEX_HISTORY_JOURNAL_DIR")
	if dir == "" {
		dir = "/run/history-native"
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	daemon, err := StartDaemonProcess(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer daemon.Close()
	e := bgpEntryFixture(t)
	ns, _ := os.Readlink("/proc/self/ns/net")
	e.Allocation.Namespace = ns
	env, err := NewRuntimeEnvironmentInspector("/sbin/ip", "/usr/sbin/nft")
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewRuntimeController(RuntimeControllerConfig{OrgID: e.Engines[0].Binding.OrgID, GatewayID: e.Engines[0].Binding.GatewayID, JournalDir: dir, IPPath: "/sbin/ip", NFTPath: "/usr/sbin/nft", Daemon: daemon.Client, DaemonAlive: daemon.Alive, Environment: env}, qualificationNoLease{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err = c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	base, err := ProbeRuntimePlatform(ctx, "/sbin/ip", "/usr/sbin/nft", daemon.Client, daemon.Alive)
	if err != nil {
		t.Fatal("base", err)
	}
	if err = c.AttachQualification(base); err != nil {
		t.Fatal(err)
	}
	q, err := bgpengine.QualifyPreflight(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.AttachBGPQualification(q); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"link", "add", "histlan", "type", "veth", "peer", "name", "histpeer"}, {"addr", "add", "10.10.0.1/24", "dev", "histlan"}, {"link", "set", "histlan", "up"}, {"link", "set", "histpeer", "up"}} {
		if out, err := exec.CommandContext(ctx, "/sbin/ip", args...).CombinedOutput(); err != nil {
			t.Fatal(string(out), err)
		}
	}
	defer exec.Command("/sbin/ip", "link", "del", "histlan").Run()
	for _, phase := range []RuntimePhase{RuntimeReserved, RuntimeApplying, RuntimeApplied} {
		e.Phase = phase
		if err = c.journal.Save([]RuntimeJournalEntry{e}); err != nil {
			t.Fatal(err)
		}
	}
	e.Observed, err = c.kernel.Apply(ctx, e.Allocation, [2]Ownership{})
	if err != nil {
		t.Fatal("kernel", err)
	}
	defer c.kernel.Remove(ctx, e.Allocation, e.Observed)
	if err = c.journal.Save([]RuntimeJournalEntry{e}); err != nil {
		t.Fatal(err)
	}
	if _, err = c.refuse(ctx, []RuntimeJournalEntry{e}); err != nil {
		t.Fatal("denial", err)
	}
	cfg, cfgErr := runtimeBGPProcessConfig(e)
	if cfgErr != nil {
		t.Fatal("configuration", cfgErr)
	}
	if err := bgpengine.ProbePeerReachability(ctx, cfg.Peers); err != nil {
		t.Fatal("peer reachability", err)
	}
	if err := bgpengine.ProbeLocalReachability(ctx, cfg.LocalPrefixes); err != nil {
		t.Fatal("local reachability", err)
	}
	c.bgpCheckpointBeforeSave = func(identity bgpengine.ProcessIdentity) error {
		t.Logf("actual checkpoint %s children%d files%d", identity.Stage, len(identity.Children), len(identity.Files))
		return nil
	}
	rows := []map[string]any{}
	for n := uint64(1); n <= 20; n++ {
		if err = c.startBGPSession(ctx, e); err != nil {
			t.Fatalf("generation%d:%v", n, err)
		}
		entries, _ := c.journal.Entries()
		e = entries[0]
		p := c.bgpProcesses[e.DeliveryID]
		if p == nil || !p.Alive() || e.BGPProcess == nil || e.BGPProcess.Stage != "ready" || e.BGPProcess.Generation != n {
			t.Fatal("ready checkpoint")
		}
		status, err := p.Observe(ctx)
		if err != nil {
			t.Fatal("VTY", err)
		}
		for _, peer := range status.Peers {
			if peer.State == "established" {
				t.Fatal("unexpected authority")
			}
		}
		identity := *e.BGPProcess
		if err = c.finishKnownBGPSession(e); err != nil {
			t.Fatal("cleanup", err)
		}
		entries, _ = c.journal.Entries()
		e = entries[0]
		if e.BGPProcess.Stage != "cleaned" {
			t.Fatal("checkpoint")
		}
		names, err := os.ReadDir(identity.Directory)
		if err != nil || len(names) != 0 {
			t.Fatal("owned artifact absence", err)
		}
		if err = recoverRuntimeBGPProcess(identity); err != nil {
			t.Fatal("exact recovery", err)
		}
		if _, err = c.refuse(ctx, entries); err != nil {
			t.Fatal(err)
		}
		saved := e
		if err = c.journal.Close(); err != nil {
			t.Fatal(err)
		}
		c.journal, err = OpenRuntimeJournal(dir, e.Engines[0].Binding.GatewayID)
		if err != nil {
			t.Fatal(err)
		}
		c.guard, err = NewRuntimeGuard(c.journal, "/usr/sbin/nft")
		if err != nil {
			t.Fatal(err)
		}
		c.replace = c.guard.Replace
		entries, _ = c.journal.Entries()
		e = entries[0]
		if !reflect.DeepEqual(saved, e) {
			t.Fatal("durable lineage")
		}
		rows = append(rows, map[string]any{"generation": n, "identity": identity, "stage_after": "cleaned", "actual_empty_directory": true, "actual_children_absence_proved": true, "journal_version": c.journal.payload.Version, "compacted_count": historyCount(e.BGPProcessHistory)})
	}
	if c.journal.payload.Version != 8 || historyCount(e.BGPProcessHistory) != 3 || len(e.BGPProcessRetired) != 16 {
		t.Fatal("continuation absent")
	}
	proof := map[string]any{"scope": "actual20FRRstarts/checkpoints/cleanup/reload;syntheticentry,nopeers/noSAs", "namespace": ns, "base_capability": c.Capability(), "bgp_capability": c.BGPCapability(), "rows": rows, "last_generation": 20, "compacted_count": historyCount(e.BGPProcessHistory), "actual_charon_alive": daemon.Alive(), "passed": true}
	raw, _ := json.Marshal(proof)
	if err = os.WriteFile("/run/history-native-proof.json", raw, 0600); err != nil {
		t.Fatal(err)
	}
	t.Log("HISTORY_TWENTY_ACTUAL_FRR_GENERATIONS_PASS")
}
