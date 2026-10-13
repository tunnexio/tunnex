//go:build linux

package ipsec

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	bgpengine "github.com/tunnexio/tunnex/apps/node/internal/bgp"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"
)

// Separate read-only four-profile oracle; the original max-prefix contract stays unchanged.
func TestAzureOwnedProfileNativeProof(t *testing.T) {
	if os.Getenv("TUNNEX_AZURE_PROFILE_NATIVE_PROOF") != "1" {
		t.Skip("explicit owned native read-only proof only")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root_required")
	}
	bindingRaw, _, err := azureProofRead("/run/tunnex-qualification/azure-profile-binding.json", 32768)
	if err != nil {
		t.Fatal("binding_read_refused")
	}
	var binding azureProfileProofBinding
	decoder := json.NewDecoder(bytes.NewReader(bindingRaw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&binding) != nil || decoder.Decode(new(any)) != io.EOF {
		t.Fatal("binding_shape_refused")
	}
	ctx, stop := context.WithTimeout(t.Context(), 20*time.Second)
	defer stop()
	first, err := azureProofDaemonIdentity(ctx, binding.azureMaxProofBinding)
	if err != nil {
		t.Fatal("initial_process_binding_refused")
	}
	raw, st, err := azureProofRead(azureProofJournal, runtimeJournalLimit)
	if err != nil {
		t.Fatal("journal_read_refused")
	}
	payload, err := decodeRuntimeJournalSnapshot(raw)
	if err != nil {
		t.Fatal("whole_journal_checksum_refused")
	}
	historical := map[uuid.UUID]bool{}
	if binding.HistoricalBoot != nil {
		proofRaw, _, err := azureProofRead("/run/tunnex-qualification/historical-reboot-proof.json", 8192)
		if err != nil {
			t.Fatal("historical_proof_read_refused")
		}
		stoppedRaw, _, err := azureProofRead("/run/tunnex-qualification/historical-stopped-journal.json", runtimeJournalLimit)
		if err != nil {
			t.Fatal("historical_journal_read_refused")
		}
		historical, err = azureProofHistoricalEntries(payload, proofRaw, stoppedRaw, *binding.HistoricalBoot, first.Boot, first.Namespace, time.Now())
		if err != nil {
			t.Fatal("historical_boot_binding_refused")
		}
	}
	entry, err := azureProfileProofEntryHistory(payload, binding, first.Namespace, historical)
	if err != nil {
		t.Fatal("whole_journal_scope_refused")
	}
	kr, err := NewKernelReader("/sbin/ip")
	if err != nil {
		t.Fatal("kernel_reader_refused")
	}
	xr, err := NewXFRMReader("/sbin/ip")
	if err != nil {
		t.Fatal("xfrm_reader_refused")
	}
	gr, err := NewGuardReader("/usr/sbin/nft")
	if err != nil {
		t.Fatal("guard_reader_refused")
	}
	transport := viciTransport{dial: func(ctx context.Context) (net.Conn, error) {
		conn, e := azureProofBoundPeer(ctx, azureProofVICI, first.Charon.PID, first.Socket)
		return conn, e
	}}
	daemon := &DaemonClient{request: transport.call}
	guard := payload.Guards[0]
	manifest := GuardManifest{Namespace: guard.Namespace, Revision: guard.Revision, Digest: guard.Digest, ExpectedJSON: guard.ExpectedJSON}
	collect := func() (DaemonInventory, KernelInventory, XFRMInventory, bgpengine.Status, []bgpengine.LearnedRoute) {
		if err := azureProofProcesses(ctx, payload, entry, first, binding.Mode != "absence" && entry.BGP != nil, historical); err != nil {
			t.Logf("process_duties_reason=%s", azureProofProcessReason(err))
			t.Fatal("all_process_duties_refused")
		}
		if gr.Check(ctx, manifest) != nil {
			t.Fatal("whole_guard_refused")
		}
		d, e := daemon.Inspect(ctx)
		if e != nil {
			t.Fatal("managed_vici_refused")
		}
		k, e := kr.Read(ctx)
		if e != nil {
			t.Fatal("kernel_inventory_refused")
		}
		x, e := xr.Read(ctx)
		if e != nil {
			t.Fatal("xfrm_inventory_refused")
		}
		var status bgpengine.Status
		var routes []bgpengine.LearnedRoute
		if binding.Mode != "absence" {
			if entry.BGP != nil {
				status, routes, e = azureProofVTY(ctx, entry, nil)
				if e != nil {
					t.Fatal("independent_frr_read_refused")
				}
			}
			if azureProfileProofBaseline(entry, d, k, x, status, routes) != nil {
				t.Fatal("profile_native_binding_refused")
			}
		} else {
			if azureMaxProofAbsenceHistory(payload, d, k, x, historical) != nil {
				t.Fatal("all_retained_absence_refused")
			}
			links, e := gr.interfaces()
			if e != nil {
				t.Fatal("guard_interfaces_refused")
			}
			observed, e := gr.run(ctx, "-j", "list", "table", "inet", "tunnex_ipsec")
			if e != nil || VerifyGuardWithdrawal([]byte(guard.ExpectedJSON), observed, links) != nil {
				t.Fatal("whole_withdrawal_refused")
			}
		}
		return d, k, x, status, routes
	}
	exportMode := os.Getenv("TUNNEX_AZURE_LAN_EXPORT_PROOF") == "1"
	if exportMode && (binding.Mode != "baseline" || entry.Allocation.ProfileID != "azure-active-active-bgp-ipv4-v1") {
		t.Fatal("export_scope_refused")
	}
	d, k, x, status, routes := collect()
	var exports [2][]string
	if exportMode {
		exports, err = azureLANExports(ctx, entry)
		if err != nil {
			t.Fatal("first_export_read_refused")
		}
	}
	again, err := azureProofDaemonIdentity(ctx, binding.azureMaxProofBinding)
	if err != nil || again != first {
		t.Fatal("process_bracket_changed")
	}
	da, ka, xa, statusAfter, routesAfter := collect()
	if exportMode {
		second, e := azureLANExports(ctx, entry)
		if e != nil || !reflect.DeepEqual(exports, second) {
			t.Fatal("export_bracket_refused")
		}
	}
	last, err := azureProofDaemonIdentity(ctx, binding.azureMaxProofBinding)
	if err != nil || last != first {
		t.Fatal("process_bracket_changed")
	}
	if azureProofCanonical(d, k, x) != azureProofCanonical(da, ka, xa) {
		t.Fatal("native_identity_bracket_changed")
	}
	if !reflect.DeepEqual(status, statusAfter) || !reflect.DeepEqual(routes, routesAfter) {
		t.Fatal("bgp_bracket_changed")
	}
	trafficAdvanced, err := azureProofTrafficCounters(d, da)
	if err != nil {
		t.Fatal("traffic_counter_bracket_refused")
	}
	after, ast, err := azureProofRead(azureProofJournal, runtimeJournalLimit)
	if err != nil || !os.SameFile(st, ast) || !bytes.Equal(raw, after) || ctx.Err() != nil {
		t.Fatal("journal_bracket_changed")
	}
	projection := map[string]any{"version": 1, "kind": "owned_azure_profile_native_observation", "mode": binding.Mode, "profile_id": entry.Allocation.ProfileID, "org_id": binding.OrgID, "site_id": binding.SiteID, "gateway_id": binding.GatewayID, "connection_id": binding.ConnectionID, "desired_revision": binding.DesiredRevision, "configuration_revision": binding.ConfigurationRevision, "observed_at": time.Now().UTC(), "journal_sha256": remediationSHA(raw), "entry_count": len(payload.Entries), "historical_boot_entry_count": len(historical), "node_executable_sha256": last.Node.Hash, "namespace": last.Namespace, "namespace_device": last.Device, "namespace_inode": last.Inode, "active_tunnel_count": entry.Allocation.activeTunnelCount(), "ike_count": len(da.SAs), "sad_count": len(xa.States), "spd_count": len(xa.Policies), "bgp_route_count": len(routesAfter), "traffic_counters_monotonic_advanced": trafficAdvanced, "scope": "Fresh whole-journal/process/VICI/kernel/XFRM/guard two-pass readback; no API readiness or packet inference"}
	if binding.Mode == "absence" {
		// Counts come from the same independently collected second frame, never
		// from API intent or an inferred successful test result.
		for key, value := range azureProfileAbsenceProjection(payload, entry, binding.azureMaxProofBinding, time.Now().UTC(), remediationSHA(raw), da, ka, xa, statusAfter, routesAfter) {
			projection[key] = value
		}
	}
	if exportMode {
		projection["lan_export_two_frames"] = true
		projection["advertised_prefixes"] = exports
	}
	encoded, err := json.Marshal(projection)
	if err != nil {
		t.Fatal("typed_projection_refused")
	}
	fmt.Println("AZURE_PROFILE_NATIVE_PROOF " + string(encoded))
}

// Additional read only: every command is sent on the independently bound actual socket.
func azureLANExports(ctx context.Context, entry RuntimeJournalEntry) ([2][]string, error) {
	var result [2][]string
	cfg, err := runtimeBGPProcessConfig(entry)
	if err != nil || entry.BGPProcess == nil || cfg.LocalPrefixes == nil {
		return result, fmt.Errorf("export_config_refused")
	}
	expected := []string{}
	for _, prefix := range cfg.LocalPrefixes {
		expected = append(expected, prefix.String())
	}
	sort.Strings(expected)
	if !reflect.DeepEqual(expected, []string{"10.233.10.0/24"}) {
		return result, fmt.Errorf("export_local_scope_refused")
	}
	var socket bgpengine.FileIdentity
	for _, file := range entry.BGPProcess.Files {
		if file.Name == "bgpd.vty" {
			socket = file.File
		}
	}
	for index, peer := range cfg.Peers {
		child, cancel := context.WithTimeout(ctx, 2*time.Second)
		conn, e := azureProofBoundPeer(child, filepath.Join(entry.BGPProcess.Directory, "bgpd.vty"), entry.BGPProcess.Children[1].PID, socket)
		if e != nil {
			cancel()
			return result, fmt.Errorf("export_socket_refused")
		}
		deadline, _ := child.Deadline()
		e = conn.SetDeadline(deadline)
		var raw []byte
		if e == nil {
			raw, e = azureLANExportWire(conn, "show bgp ipv4 unicast neighbors "+peer.Remote.String()+" advertised-routes json", 1<<20)
		}
		conn.Close()
		cancel()
		if e != nil {
			return result, fmt.Errorf("export_wire_refused")
		}
		var document map[string]json.RawMessage
		if json.Unmarshal(raw, &document) != nil {
			return result, fmt.Errorf("export_json_refused")
		}
		var rows map[string]json.RawMessage
		if json.Unmarshal(document["advertisedRoutes"], &rows) != nil || rows == nil || len(rows) > 64 {
			return result, fmt.Errorf("export_shape_refused")
		}
		result[index] = []string{}
		for value := range rows {
			prefix, e := netip.ParsePrefix(value)
			if e != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() {
				return result, fmt.Errorf("export_prefix_refused")
			}
			result[index] = append(result[index], prefix.String())
		}
		sort.Strings(result[index])
		if !reflect.DeepEqual(result[index], expected) {
			return result, fmt.Errorf("export_exact_set_refused")
		}
	}
	return result, nil
}
