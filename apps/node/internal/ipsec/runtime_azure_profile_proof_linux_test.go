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
	"os"
	"reflect"
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
	d, k, x, status, routes := collect()
	again, err := azureProofDaemonIdentity(ctx, binding.azureMaxProofBinding)
	if err != nil || again != first {
		t.Fatal("process_bracket_changed")
	}
	da, ka, xa, statusAfter, routesAfter := collect()
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
	encoded, err := json.Marshal(projection)
	if err != nil {
		t.Fatal("typed_projection_refused")
	}
	fmt.Println("AZURE_PROFILE_NATIVE_PROOF " + string(encoded))
}
