//go:build linux

package ipsec

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

// This fixture consumes the actual host supervisor's stop proof and actual CLI
// receipt. Its fresh lease responder is explicitly synthetic component authority.
func TestHistoryTrustedNamespaceNative(t *testing.T) {
	if os.Getenv("TUNNEX_HISTORY_RESTORATION_LAB") != "1" {
		t.Skip("owned trusted supervisor native fixture")
	}
	dir := os.Getenv("TUNNEX_BGP_LAB_JOURNAL_DIR")
	if dir == "" {
		dir = "/state/ipsec"
	}
	org, gateway, err := ReadRuntimeJournalIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	daemon, err := StartDaemonProcess(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer daemon.Close()
	environment, err := NewRuntimeEnvironmentInspector("/sbin/ip", "/usr/sbin/nft")
	if err != nil {
		t.Fatal(err)
	}
	controller, err := NewRuntimeController(RuntimeControllerConfig{OrgID: org, GatewayID: gateway, JournalDir: dir, IPPath: "/sbin/ip", NFTPath: "/usr/sbin/nft", Daemon: daemon.Client, DaemonAlive: daemon.Alive, Environment: environment}, nativeRuntimeLease{})
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Close()
	entries, err := controller.journal.Entries()
	if err != nil || len(entries) != 1 {
		t.Fatal("one exact old duty required", err)
	}
	old := entries[0]
	ns, err := controller.namespace()
	if err != nil || ns == old.Allocation.Namespace {
		t.Fatal("actual new namespace required", err)
	}
	if err = controller.Start(ctx); err != nil {
		t.Fatal("retained denial startup", err)
	}
	candidate := old
	candidate.Allocation.Namespace = ns
	boot, err := resetBootID()
	if err != nil {
		t.Fatal(err)
	}
	policyHash := strings.Repeat("b", 64)
	if old.Engines[0].Binding.PolicyRevision > 0 {
		policyHash = ""
	}
	if err = controller.reserveRestoration(ctx, RuntimeMaterial{Policy: RuntimePolicy{Hash: policyHash}}, entries, 0, candidate, boot); err != nil {
		t.Fatal("trusted actual receipt restoration refused", err)
	}
	after, err := controller.journal.Entries()
	if err != nil {
		t.Fatal(err)
	}
	restored := after[0]
	oldEpoch := uint64(0)
	if old.Restoration != nil {
		oldEpoch = old.Restoration.Epoch
	}
	if restored.Allocation.Namespace != ns || restored.Allocation.Generation == old.Allocation.Generation || restored.BGPProcess != nil || restored.BGPRoutes != nil || restored.Restoration == nil || restored.Restoration.Epoch != oldEpoch+1 || len(restored.Restoration.Retired) > 16 || !reflect.DeepEqual(restored.Restoration.Retired[len(restored.Restoration.Retired)-1].Entry, flattenedRestorationEntry(old)) {
		t.Fatal("trusted restoration erased or adopted old duty")
	}
	if old.BGPProcess != nil {
		expected := old
		if compactBGPProcessHistory(&expected) != nil {
			t.Fatal("expected cleaned prefix refused")
		}
		if !reflect.DeepEqual(expected.BGPProcessHistory, restored.BGPProcessHistory) || len(restored.BGPProcessRetired) != len(expected.BGPProcessRetired)+1 || restored.BGPProcessRetired[len(restored.BGPProcessRetired)-1].Stage != "cleaned" {
			t.Fatal("exact old process cleanup history absent")
		}
		files, err := os.ReadDir(old.BGPProcess.Directory)
		if err != nil || len(files) != 0 {
			t.Fatal("old private residue not exactly cleaned", err)
		}
	}
	proof := struct {
		Old, Restored      RuntimeJournalEntry
		ActualNewNamespace string
		Authority          string
		Capability         int
	}{old, restored, ns, "synthetic fresh nonce lease; genuine external host stop evidence and CLI receipt", controller.BGPCapability()}
	raw, _ := json.Marshal(proof)
	if os.WriteFile("/run/history-native-restoration.json", raw, 0600) != nil {
		t.Fatal("receipt write")
	}
	t.Log("HISTORY_TRUSTED_NAMESPACE_RESTORATION_PASS")
}
