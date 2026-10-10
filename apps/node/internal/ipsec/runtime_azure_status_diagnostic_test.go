package ipsec

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

type azureSlotDiagnostic struct {
	Slot          int            `json:"slot"`
	Status        string         `json:"status"`
	Category      string         `json:"category"`
	IKEMatches    int            `json:"ike_matches"`
	ChildStates   map[string]int `json:"child_states"`
	SADMatches    int            `json:"sad_matches"`
	SPDDirections map[string]int `json:"spd_directions"`
}

// Observation only: exact existing validators decide categories. Never creates
// a controller/lease/authority, changes native state, or emits raw bindings.
func azureNativeSlotDiagnostic(entry RuntimeJournalEntry, d DaemonInventory, k KernelInventory, x XFRMInventory) []azureSlotDiagnostic {
	output := []azureSlotDiagnostic{}
	for index, tunnel := range entry.Engines[:entry.Allocation.activeTunnelCount()] {
		item := azureSlotDiagnostic{Slot: index + 1, Status: runtimeTunnelStatus(tunnel, entry.Observed[index], d, k, x), Category: "native_observation", ChildStates: map[string]int{}, SPDDirections: map[string]int{}}
		for _, ike := range d.SAs {
			if ike.Name == engineName(tunnel) {
				item.IKEMatches++
			}
			for _, child := range ike.Children {
				if child.Name == engineName(tunnel) || child.ReqID == tunnel.ReqID || child.IfIDIn == tunnel.XFRMID || child.IfIDOut == tunnel.XFRMID {
					state := "other"
					switch child.State {
					case "INSTALLED", "DELETING", "DELETED":
						state = child.State
					}
					item.ChildStates[state]++
				}
			}
		}
		for _, state := range x.States {
			if state.IfID == tunnel.XFRMID || state.ReqID == tunnel.ReqID {
				item.SADMatches++
			}
		}
		for _, policy := range x.Policies {
			if policy.IfID == tunnel.XFRMID || policy.ReqID == tunnel.ReqID {
				direction := "other"
				switch policy.Direction {
				case "in", "out", "fwd":
					direction = policy.Direction
				}
				item.SPDDirections[direction]++
			}
		}
		_, child, retired, err := ownedRuntimeChildren(tunnel, d)
		if err != nil {
			item.Category = "owned_child_binding_refused"
		} else if _, _, err = ownedRuntimeSPIStates(tunnel, child, retired, x); err != nil {
			item.Category = "owned_spi_state_refused"
		} else if item.Status == "unknown" {
			item.Category = "remaining_native_binding_refused"
		}
		output = append(output, item)
	}
	return output
}

func TestAzureNativeSlotDiagnosticUsesExactValidators(t *testing.T) {
	entry, d, k, x := runtimeProofFixture()
	got := azureNativeSlotDiagnostic(entry, d, k, x)
	if got[0].Status != "up" || got[0].Category != "native_observation" {
		t.Fatal("valid fixture projection refused")
	}
	d.SAs[0].Children[0].State = "INSTALLED"
	d.SAs[0].Children = append(d.SAs[0].Children, d.SAs[0].Children[0])
	got = azureNativeSlotDiagnostic(entry, d, k, x)
	if got[0].Status != "unknown" || got[0].Category != "owned_child_binding_refused" || got[0].ChildStates["INSTALLED"] != 2 || got[1].Status != "up" {
		t.Fatal("duplicate installed child projection did not preserve exact refusal")
	}
	entry, d, k, x = runtimeProofFixture()
	x.States[0].SPI++
	got = azureNativeSlotDiagnostic(entry, d, k, x)
	if got[0].Category != "owned_spi_state_refused" {
		t.Fatal("SPI mismatch not classified")
	}
}

// Root compiles this test executable locally for the reviewed Linux image and
// executes ONLY this test inside that actual container after independent image
// verification. Default local/package runs skip all live reads.
func TestAzureOwnedNativeStatusDiagnostic(t *testing.T) {
	if os.Getenv("TUNNEX_AZURE_NATIVE_STATUS_DIAGNOSTIC") != "1" {
		t.Skip("explicit owned diagnostic only")
	}
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Fatal("requires actual owned Linux container root")
	}
	const journalPath = "/var/lib/tunnex-node/ipsec/journal.json"
	const viciPath = "/run/tunnex-ipsec/charon.vici"
	const ipPath = "/usr/sbin/ip"
	parent := filepath.Dir(journalPath)
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil || resolved != parent {
		t.Fatal("fixed journal parent refused")
	}
	info, err := os.Lstat(parent)
	if err != nil || !journalPrivate(info, true) {
		t.Fatal("fixed private journal parent refused")
	}
	file, err := journalOpenNoFollow(journalPath, false)
	if err != nil {
		t.Fatal("fixed journal read refused")
	}
	defer file.Close()
	info, err = file.Stat()
	if err != nil || !journalPrivate(info, false) || info.Size() > runtimeJournalLimit {
		t.Fatal("private bounded journal refused")
	}
	raw, err := io.ReadAll(io.LimitReader(file, runtimeJournalLimit+1))
	if err != nil || len(raw) > runtimeJournalLimit {
		t.Fatal("bounded journal read refused")
	}
	payload, err := decodeRuntimeJournalSnapshot(raw)
	if err != nil {
		t.Fatal("recorded journal validation refused")
	}
	entries := []RuntimeJournalEntry{}
	for _, entry := range payload.Entries {
		if entry.Phase != RuntimeRetainedRefusal {
			entries = append(entries, entry)
		}
	}
	if len(entries) != 1 || entries[0].ContractVersion != 3 || entries[0].Allocation.activeTunnelCount() != 2 || !IsAzureBGPProfile(entries[0].Allocation.ProfileID) {
		t.Fatal("expected one actual Azure AA BGP entry")
	}
	daemon, err := NewDaemonClient(viciPath)
	if err != nil {
		t.Fatal("fixed daemon endpoint refused")
	}
	kernel, err := NewKernelReader(ipPath)
	if err != nil {
		t.Fatal("fixed kernel reader refused")
	}
	xfrm, err := NewXFRMReader(ipPath)
	if err != nil {
		t.Fatal("fixed XFRM reader refused")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	d, err := daemon.Inspect(ctx)
	if err != nil {
		t.Fatal("actual owned VICI read refused")
	}
	k, err := kernel.Read(ctx)
	if err != nil {
		t.Fatal("actual kernel read refused")
	}
	x, err := xfrm.Read(ctx)
	if err != nil {
		t.Fatal("actual key-free XFRM read refused")
	}
	entry := entries[0]
	if k.Namespace != entry.Allocation.Namespace || x.Namespace != entry.Allocation.Namespace {
		t.Fatal("actual namespace differs from recorded obligation")
	}
	phase := "other"
	switch entry.Phase {
	case RuntimeApplied:
		phase = "applied"
	case RuntimeApplying:
		phase = "applying"
	}
	output := struct {
		ObservedAt string                `json:"observed_at"`
		Phase      string                `json:"journal_phase"`
		Slots      []azureSlotDiagnostic `json:"slots"`
		Scope      string                `json:"scope"`
	}{time.Now().UTC().Format(time.RFC3339Nano), phase, azureNativeSlotDiagnostic(entry, d, k, x), "Single native snapshot classification only; no authority or readiness inference"}
	encoded, err := json.Marshal(output)
	if err != nil {
		t.Fatal("safe projection encode refused")
	}
	fmt.Println(string(encoded))
}
