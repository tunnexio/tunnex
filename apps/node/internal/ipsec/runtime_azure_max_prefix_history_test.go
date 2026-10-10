package ipsec

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// External supervisor evidence only. These pins must come from independently
// verified original private bytes and the actual host machine identity.
type azureProofHistoricalPins struct {
	ProofSHA256               string `json:"proof_sha256"`
	StoppedJournalSHA256      string `json:"stopped_journal_sha256"`
	RootAttestedHostMachineID string `json:"root_attested_host_machine_id"`
}

func azureProofHistoricalEntries(current runtimeJournalPayload, proofRaw, stoppedRaw []byte, pins azureProofHistoricalPins, currentBoot, currentNS string, now time.Time) (map[uuid.UUID]bool, error) {
	fail := func() (map[uuid.UUID]bool, error) { return nil, fmt.Errorf("historical_boot_binding_refused") }
	if !validDigest(pins.ProofSHA256) || !validDigest(pins.StoppedJournalSHA256) || stringDigest(proofRaw) != pins.ProofSHA256 || stringDigest(stoppedRaw) != pins.StoppedJournalSHA256 || !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(pins.RootAttestedHostMachineID) {
		return fail()
	}
	var proof ResetRebootProof
	if !decodeResetInput(proofRaw, 8192, &proof) {
		return fail()
	}
	stopped, err := decodeRuntimeJournalSnapshot(stoppedRaw)
	if err != nil || !validJournalPayload(current) || stopped.OwnerID != current.OwnerID {
		return fail()
	}
	old, err := uuid.Parse(proof.OldBootID)
	if err != nil || old == uuid.Nil || old.String() != proof.OldBootID {
		return fail()
	}
	boot, err := uuid.Parse(currentBoot)
	if err != nil || boot == uuid.Nil || boot.String() != currentBoot || proof.OldBootID == currentBoot || proof.NewBootID != currentBoot || proof.Version != 1 || proof.Kind != "supervisor-confirmed-owned-vm-reboot" || proof.OwnerID != current.OwnerID || proof.MachineID != pins.RootAttestedHostMachineID || proof.StoppedJournalSHA256 != pins.StoppedJournalSHA256 || !validDigest(proof.CleanupSHA256) || proof.RequestedAt.IsZero() || !proof.CompletedAt.After(proof.RequestedAt) || proof.CompletedAt.After(now) {
		return fail()
	}
	archived := map[uuid.UUID]RuntimeJournalEntry{}
	for _, entry := range stopped.Entries {
		if _, ok := archived[entry.DeliveryID]; ok {
			return fail()
		}
		archived[entry.DeliveryID] = entry
	}
	matched := map[uuid.UUID]bool{}
	for _, entry := range current.Entries {
		if entry.Allocation.Namespace == currentNS {
			continue
		}
		prior, ok := archived[entry.DeliveryID]
		if !ok || matched[entry.DeliveryID] || entry.Phase != RuntimeRetainedRefusal || entry.AbsenceOnly || entry.ResetCleanup != nil || entry.Restoration == nil || entry.Restoration.BootID != proof.OldBootID || entry.Restoration.Epoch != 0 || entry.Restoration.Compacted != nil || len(entry.Restoration.Retired) != 0 || entry.BGPProcess == nil || entry.BGPProcess.Stage != "cleaned" || entry.BGPProcess.BootID != proof.OldBootID {
			return fail()
		}
		if prior.AbsenceOnly || prior.ResetCleanup != nil || prior.Restoration == nil || !reflect.DeepEqual(entry.Restoration, prior.Restoration) || entry.SiteID != prior.SiteID || entry.ContractVersion != prior.ContractVersion || entry.OwnershipDigest != prior.OwnershipDigest || !reflect.DeepEqual(entry.Allocation, prior.Allocation) || !reflect.DeepEqual(entry.Engines, prior.Engines) || !reflect.DeepEqual(entry.BGP, prior.BGP) || !reflect.DeepEqual(entry.Observed, prior.Observed) {
			return fail()
		}
		// Process lifecycle stage may progress to cleaned; the original exact
		// identity may not change. No old PID, directory or namespace is adopted.
		if prior.BGPProcess == nil {
			return fail()
		}
		process := *entry.BGPProcess
		process.Stage = prior.BGPProcess.Stage
		if !reflect.DeepEqual(process, *prior.BGPProcess) {
			return fail()
		}
		if len(entry.BGPProcessRetired) != 0 || entry.BGPProcessHistory != nil {
			return fail()
		}
		matched[entry.DeliveryID] = true
	}
	if len(matched) == 0 {
		return fail()
	}
	return matched, nil
}

func TestAzureMaxProofHistoricalRebootPinsAndImmutableBinding(t *testing.T) {
	p, active, binding, _, kernel, _, _, _ := azureMaxProofFixture(t)
	oldBoot, currentBoot := uuid.NewString(), uuid.NewString()
	entry := p.Entries[0]
	entry.Allocation.Namespace = "net:[991]"
	for i := range entry.Observed {
		entry.Observed[i].Namespace = entry.Allocation.Namespace
	}
	entry.Restoration = &RuntimeRestoration{BootID: oldBoot}
	process := *processStateFixture(t).BGPProcess
	process.Namespace = entry.Allocation.Namespace
	process.BootID = oldBoot
	process.Stage = "cleaned"
	process.Directory = filepath.Join("/var/lib/tunnex", "bgp-"+entry.DeliveryID.String()+"-g1")
	entry.BGPProcess = &process
	p.Entries[0] = entry
	if !validJournalPayload(p) {
		t.Fatal("invalid historical fixture")
	}
	encode := func(p runtimeJournalPayload) []byte {
		payload, _ := json.Marshal(p)
		raw, _ := json.Marshal(runtimeJournalEnvelope{Payload: p, Checksum: stringDigest(payload)})
		return raw
	}
	stopped := encode(p)
	now := time.Now()
	proof := ResetRebootProof{Version: 1, Kind: "supervisor-confirmed-owned-vm-reboot", OwnerID: p.OwnerID, MachineID: strings.Repeat("a", 32), OldBootID: oldBoot, NewBootID: currentBoot, StoppedJournalSHA256: stringDigest(stopped), CleanupSHA256: strings.Repeat("b", 64), RequestedAt: now.Add(-time.Hour), CompletedAt: now.Add(-50 * time.Minute)}
	raw, _ := json.Marshal(proof)
	pins := azureProofHistoricalPins{ProofSHA256: stringDigest(raw), StoppedJournalSHA256: stringDigest(stopped), RootAttestedHostMachineID: proof.MachineID}
	check := func(p runtimeJournalPayload, raw, stopped []byte, pins azureProofHistoricalPins, boot string) error {
		_, err := azureProofHistoricalEntries(p, raw, stopped, pins, boot, p.Guards[0].Namespace, now)
		return err
	}
	if check(p, raw, stopped, pins, currentBoot) != nil {
		t.Fatal("genuine hash-bound old boot refused")
	}
	matched, err := azureProofHistoricalEntries(p, raw, stopped, pins, currentBoot, kernel.Namespace, now)
	if err != nil || len(matched) != 1 || !matched[entry.DeliveryID] {
		t.Fatal("exact historical match missing")
	}
	if _, err := azureMaxProofEntry(p, binding, kernel.Namespace); err == nil {
		t.Fatal("unattested old namespace accepted")
	}
	selected, err := azureMaxProofEntryHistory(p, binding, kernel.Namespace, matched)
	if err != nil || selected.DeliveryID != active.DeliveryID {
		t.Fatal("historical evidence altered current selection")
	}
	absent := p
	absent.Entries = append([]RuntimeJournalEntry(nil), p.Entries...)
	last := &absent.Entries[len(absent.Entries)-1]
	last.Phase = RuntimeRetainedRefusal
	last.CleanupID = uuid.New()
	last.CleanupDesiredRevision = 41
	last.CoveredDeliveryRevision = 40
	last.BGPRoutes = &RuntimeBGPRoutes{Sequence: 2, Stage: "completed", Withdrawal: true, Owned: []RuntimeBGPRouteTuple{}, Target: []RuntimeBGPRouteTuple{}}
	if !validJournalPayload(absent) {
		t.Fatal("invalid absence fixture")
	}
	emptyKernel := KernelInventory{Namespace: kernel.Namespace}
	emptyXFRM := XFRMInventory{Namespace: kernel.Namespace}
	if azureMaxProofAbsence(absent, DaemonInventory{}, emptyKernel, emptyXFRM) == nil {
		t.Fatal("unattested historical absence accepted")
	}
	if azureMaxProofAbsenceHistory(absent, DaemonInventory{}, emptyKernel, emptyXFRM, matched) != nil {
		t.Fatal("historically discharged lifetime refused")
	}
	emptyKernel.Links = append(emptyKernel.Links, KernelLink{Name: entry.Allocation.Tunnels[0].Name})
	if azureMaxProofAbsenceHistory(absent, DaemonInventory{}, emptyKernel, emptyXFRM, matched) == nil {
		t.Fatal("historical evidence bypassed actual native absence")
	}
	for _, tc := range []string{"same_boot", "machine", "proof_hash", "journal_hash", "unmatched_delivery", "allocation", "observed", "restoration", "uncleaned", "process_identity", "future_completion"} {
		t.Run(tc, func(t *testing.T) {
			copyRaw, _ := json.Marshal(p)
			var changed runtimeJournalPayload
			json.Unmarshal(copyRaw, &changed)
			pr := proof
			pi := pins
			boot := currentBoot
			r := raw
			switch tc {
			case "same_boot":
				boot = oldBoot
			case "machine":
				pi.RootAttestedHostMachineID = strings.Repeat("c", 32)
			case "proof_hash":
				pi.ProofSHA256 = strings.Repeat("c", 64)
			case "journal_hash":
				pi.StoppedJournalSHA256 = strings.Repeat("c", 64)
			case "unmatched_delivery":
				changed.Entries[0].DeliveryID = uuid.New()
			case "allocation":
				changed.Entries[0].Allocation.Generation = uuid.New()
			case "observed":
				changed.Entries[0].Observed[0].InterfaceIndex++
			case "restoration":
				changed.Entries[0].Restoration.BootID = uuid.NewString()
			case "uncleaned":
				changed.Entries[0].BGPProcess.Stage = "reserved"
			case "process_identity":
				changed.Entries[0].BGPProcess.Supervisor.PID++
			case "future_completion":
				pr.CompletedAt = now.Add(time.Hour)
				r, _ = json.Marshal(pr)
				pi.ProofSHA256 = stringDigest(r)
			}
			if check(changed, r, stopped, pi, boot) == nil {
				t.Fatal("unbound historical evidence accepted")
			}
		})
	}
}
