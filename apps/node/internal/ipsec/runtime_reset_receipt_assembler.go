package ipsec

import (
	"bytes"
	"encoding/json"
	"io"
	"regexp"
	"time"

	"github.com/google/uuid"
)

// ResetRebootProof is a privileged external supervisor's attestation. The
// assembler cannot authenticate a bastion or perform the reboot: the operator
// must collect this evidence from the actual owned VM. Current boot identity
// and exact persisted old boot are independently checked, never inferred from
// container termination or namespace absence.
type ResetRebootProof struct {
	Version                             int
	Kind                                string
	OwnerID                             uuid.UUID
	MachineID, OldBootID, NewBootID     string
	StoppedJournalSHA256, CleanupSHA256 string
	RequestedAt, CompletedAt            time.Time
}

func decodeResetInput(raw []byte, limit int, value any) bool {
	if len(raw) == 0 || len(raw) > limit {
		return false
	}
	if _, ok := runtimeJSONObject(raw); !ok {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(value) != nil {
		return false
	}
	var extra any
	return d.Decode(&extra) == io.EOF
}

// AssembleResetCleanupReceipt writes no state and grants no permission. Its
// output is consumed by the existing exact receipt parser and subsequent
// independent two-pass kernel/daemon absence proof in Cleanup.
func AssembleResetCleanupReceipt(journalRaw, cleanupRaw, proofRaw []byte, boot, ns, machineID string, now time.Time) ([]byte, error) {
	fail := func() ([]byte, error) { return nil, ErrRuntimeController }
	payload, err := decodeRuntimeJournalSnapshot(journalRaw)
	if err != nil || !validKernelNamespace(ns) || !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(machineID) {
		return fail()
	}
	var cleanup RuntimeCleanup
	var proof ResetRebootProof
	if !decodeResetInput(cleanupRaw, 16<<20, &cleanup) || !decodeResetInput(proofRaw, 8192, &proof) {
		return fail()
	}
	old, err := uuid.Parse(proof.OldBootID)
	if err != nil || old == uuid.Nil || old.String() != proof.OldBootID {
		return fail()
	}
	current, err := uuid.Parse(boot)
	if err != nil || current == uuid.Nil || current.String() != boot || proof.OldBootID == boot {
		return fail()
	}
	if proof.Version != 1 || proof.Kind != "supervisor-confirmed-owned-vm-reboot" || proof.OwnerID != payload.OwnerID || proof.MachineID != machineID || proof.NewBootID != boot || proof.StoppedJournalSHA256 != stringDigest(journalRaw) || proof.CleanupSHA256 != stringDigest(cleanupRaw) || proof.RequestedAt.IsZero() || !proof.CompletedAt.After(proof.RequestedAt) || proof.CompletedAt.After(now) || now.Sub(proof.RequestedAt) > 15*time.Minute {
		return fail()
	}
	covered := []RuntimeJournalEntry{}
	lineage := map[uuid.UUID]RuntimeDelivery{}
	for _, d := range cleanup.Lineage {
		lineage[d.ID] = d
	}
	for _, e := range payload.Entries {
		if e.Allocation.ConnectionID != cleanup.Manifest.ConnectionID {
			continue
		}
		d, ok := lineage[e.DeliveryID]
		if !ok || d.OwnershipDigest != e.OwnershipDigest || d.DesiredRevision != e.Engines[0].Binding.DesiredRevision {
			return fail()
		}
		delete(lineage, e.DeliveryID)
		if e.Phase != RuntimeRetainedRefusal {
			if (e.ContractVersion != 2 && e.ContractVersion != 3 && e.ContractVersion != 4) || e.Phase != RuntimeCleanupPending || e.AbsenceOnly || e.ResetCleanup != nil || e.CleanupID != cleanup.ID || e.CleanupDesiredRevision != cleanup.DesiredRevision || e.CoveredDeliveryRevision != cleanup.CoversDeliveryRevision || e.Allocation.Namespace == ns || e.Restoration == nil || e.Restoration.BootID != proof.OldBootID {
				return fail()
			}
		}
		covered = append(covered, e)
	}
	if len(covered) == 0 || len(lineage) != 0 || !runtimeCleanupValid(cleanup, cleanup.Manifest.OrgID, payload.OwnerID) {
		return fail()
	}
	changed := false
	for _, e := range covered {
		if e.Phase != RuntimeRetainedRefusal {
			changed = true
		}
	}
	if !changed {
		return fail()
	}
	raw, err := json.Marshal(runtimeResetReceipt{Version: 1, OwnerID: payload.OwnerID, CleanupID: cleanup.ID, CleanupRevision: cleanup.DesiredRevision, CoveredDigest: resetCoveredDigest(covered), BootID: boot, Namespace: ns, Termination: "supervisor-confirmed-vm-stop", EvidenceDigest: stringDigest(proofRaw)})
	if err != nil {
		return fail()
	}
	if _, err = parseResetReceipt(raw, payload.OwnerID, cleanup, covered, boot, ns); err != nil {
		return fail()
	}
	return raw, nil
}
