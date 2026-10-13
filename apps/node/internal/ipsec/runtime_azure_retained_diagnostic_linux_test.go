//go:build linux

package ipsec

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// Strict read-only observation after normal control-plane cleanup settlement.
func TestAzureOwnedRetainedAbsenceDiagnosticNative(t *testing.T) {
	if os.Getenv("TUNNEX_AZURE_OWNED_RETAINED_DIAGNOSTIC") != "1" {
		t.Skip("explicit owned retained diagnostic only")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root_required")
	}
	expected := os.Getenv("TUNNEX_AZURE_EXPECTED_NODE_SHA256")
	exe, e := os.ReadFile("/proc/1/exe")
	if e != nil || !validDigest(expected) || remediationSHA(exe) != expected {
		t.Fatal("node_executable_refused")
	}
	path := "/var/lib/tunnex-node/ipsec/journal.json"
	raw, st, e := remediationRead(path)
	if e != nil {
		t.Fatal("private_journal_refused")
	}
	var envelope runtimeJournalEnvelope
	if json.Unmarshal(raw, &envelope) != nil || !validJournalPayload(envelope.Payload) || journalChecksum(envelope.Payload) != envelope.Checksum {
		t.Fatal("strict_journal_refused")
	}
	ns, e := os.Readlink("/proc/self/ns/net")
	if e != nil || len(envelope.Payload.Entries) == 0 || len(envelope.Payload.Guards) != 1 {
		t.Fatal("scope_refused")
	}
	for _, entry := range envelope.Payload.Entries {
		if entry.Phase != RuntimeRetainedRefusal {
			t.Fatal("nonretained_duty_present")
		}
	}
	guard := envelope.Payload.Guards[0]
	if guard.Namespace != ns {
		t.Fatal("guard_namespace_refused")
	}
	ctx, stop := context.WithTimeout(context.Background(), 10*time.Second)
	defer stop()
	client, e := NewDaemonClient("/run/tunnex-ipsec/charon.vici")
	if e != nil {
		t.Fatal("daemon_client_refused")
	}
	daemon, e := client.Inspect(ctx)
	if e != nil {
		t.Fatal("daemon_inventory_refused")
	}
	kernel, e := NewKernelReader("/sbin/ip")
	if e != nil {
		t.Fatal("kernel_reader_refused")
	}
	inventory, e := kernel.Read(ctx)
	if e != nil || inventory.Namespace != ns {
		t.Fatal("kernel_inventory_refused")
	}
	xreader, e := NewXFRMReader("/sbin/ip")
	if e != nil {
		t.Fatal("xfrm_reader_refused")
	}
	xfrm, e := xreader.Read(ctx)
	if e != nil || xfrm.Namespace != ns {
		t.Fatal("xfrm_inventory_refused")
	}
	ownedLinks, ownedRoutes := 0, 0
	for _, link := range inventory.Links {
		for _, entry := range envelope.Payload.Entries {
			for _, tunnel := range entry.Allocation.Tunnels {
				if link.XFRMID != 0 && link.XFRMID == tunnel.XFRMID {
					ownedLinks++
				}
			}
		}
	}
	for _, route := range inventory.Routes {
		if route.Protocol == 242 {
			ownedRoutes++
		}
	}
	reader, e := NewGuardReader("/usr/sbin/nft")
	if e != nil {
		t.Fatal("guard_reader_refused")
	}
	manifest := GuardManifest{Namespace: ns, Revision: guard.Revision, Digest: guard.Digest, ExpectedJSON: guard.ExpectedJSON}
	full := reader.Check(ctx, manifest) == nil
	links, e := reader.interfaces()
	if e != nil {
		t.Fatal("guard_interfaces_refused")
	}
	observed, e := reader.run(ctx, "-j", "list", "table", "inet", "tunnex_ipsec")
	if e != nil {
		t.Fatal("guard_read_refused")
	}
	withdrawal := VerifyGuardWithdrawal([]byte(guard.ExpectedJSON), observed, links) == nil
	after, ast, e := remediationRead(path)
	stable := e == nil && ast.Dev == st.Dev && ast.Ino == st.Ino && bytes.Equal(raw, after)
	result := map[string]any{"all_entries_retained": true, "entries_count": len(envelope.Payload.Entries), "daemon_sas_count": len(daemon.SAs), "daemon_connections_count": len(daemon.Connections), "daemon_shared_keys_count": len(daemon.SharedKeys), "sad_count": len(xfrm.States), "spd_count": len(xfrm.Policies), "owned_links_count": ownedLinks, "protocol242_routes_count": ownedRoutes, "full_guard_verified": full, "withdrawal_guard_verified": withdrawal, "journal_unchanged": stable}
	safe, _ := json.Marshal(result)
	t.Log("AZURE_OWNED_RETAINED_ABSENCE_DIAGNOSTIC " + string(safe))
	if !stable || !full || !withdrawal || len(daemon.SAs) != 0 || len(daemon.Connections) != 0 || len(daemon.SharedKeys) != 0 || len(xfrm.States) != 0 || len(xfrm.Policies) != 0 || ownedLinks != 0 || ownedRoutes != 0 {
		t.Fatal("strict_retained_absence_refused")
	}
}
