package ipsec

import (
	"encoding/json"
	"github.com/google/uuid"
	"strings"
	"testing"
	"time"
)

// These lifecycle facts are synthetic unit fixtures, never live evidence.
func syntheticResetAssemblyProfile(t *testing.T, profile string) ([]byte, []byte, ResetRebootProof, time.Time, string, string) {
	t.Helper()
	m := runtimeMaterialFixture()
	if profile != "" {
		m = azureMaterialFixture(profile)
	}
	if profile == "" || profile == AzureActiveActiveStaticProfile {
		m.Manifest.RecoveryVersion = new(int)
		*m.Manifest.RecoveryVersion = 1
	}
	runtimeReseal(&m)
	e, _, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[42]")
	if err != nil {
		t.Fatal(err)
	}
	c := RuntimeCleanup{RuntimeDelivery: m.RuntimeDelivery, RetainGuard: true, Lineage: []RuntimeDelivery{m.RuntimeDelivery}}
	c.CoversDeliveryRevision = m.DesiredRevision
	c.ID = uuid.New()
	c.Kind = "cleanup"
	c.DesiredRevision++
	lineage, _ := json.Marshal(c.Lineage)
	c.OwnershipDigest = stringDigest(lineage)
	old, boot, ns := uuid.NewString(), uuid.NewString(), "net:[43]"
	e.Phase = RuntimeCleanupPending
	e.CleanupID = c.ID
	e.CleanupDesiredRevision = c.DesiredRevision
	e.CoveredDeliveryRevision = c.CoversDeliveryRevision
	e.Restoration = &RuntimeRestoration{BootID: old}
	payload := runtimeJournalPayload{Version: 10, OwnerID: m.Manifest.NodeID, Entries: []RuntimeJournalEntry{e}}
	j, _ := json.Marshal(runtimeJournalEnvelope{Payload: payload, Checksum: journalChecksum(payload)})
	raw, _ := json.Marshal(c)
	now := time.Now().UTC()
	p := ResetRebootProof{Version: 1, Kind: "supervisor-confirmed-owned-vm-reboot", OwnerID: m.Manifest.NodeID, MachineID: strings.Repeat("a", 32), OldBootID: old, NewBootID: boot, StoppedJournalSHA256: stringDigest(j), CleanupSHA256: stringDigest(raw), RequestedAt: now.Add(-time.Minute), CompletedAt: now.Add(-time.Second)}
	return j, raw, p, now, boot, ns
}
func syntheticResetAssembly(t *testing.T) ([]byte, []byte, ResetRebootProof, time.Time, string, string) {
	return syntheticResetAssemblyProfile(t, "")
}

func TestResetAssemblyAzureProfilesSynthetic(t *testing.T) {
	for _, profile := range []string{AzureActiveActiveBGPProfile, AzureActiveStandbyBGPProfile, AzureActiveActiveStaticProfile, AzureActiveStandbyStaticProfile} {
		t.Run(profile, func(t *testing.T) {
			j, c, p, now, boot, ns := syntheticResetAssemblyProfile(t, profile)
			proof, _ := json.Marshal(p)
			if _, err := AssembleResetCleanupReceipt(j, c, proof, boot, ns, p.MachineID, now); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestResetAssemblySyntheticExactBootChange(t *testing.T) {
	j, c, p, now, boot, ns := syntheticResetAssembly(t)
	proof, _ := json.Marshal(p)
	raw, err := AssembleResetCleanupReceipt(j, c, proof, boot, ns, p.MachineID, now)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := decodeRuntimeJournalSnapshot(j)
	if err != nil {
		t.Fatal(err)
	}
	var cleanup RuntimeCleanup
	json.Unmarshal(c, &cleanup)
	if _, err = parseResetReceipt(raw, p.OwnerID, cleanup, payload.Entries, boot, ns); err != nil {
		t.Fatal(err)
	}
}
func TestResetAssemblyRejectsUnprovedOrChangedInputs(t *testing.T) {
	for _, kind := range []string{"unchanged_boot", "wrong_old_boot", "stale", "future", "owner", "machine", "cleanup", "journal", "unknown", "namespace"} {
		t.Run(kind, func(t *testing.T) {
			j, c, p, now, boot, ns := syntheticResetAssembly(t)
			switch kind {
			case "unchanged_boot":
				boot = p.OldBootID
				p.NewBootID = boot
			case "wrong_old_boot":
				p.OldBootID = uuid.NewString()
			case "stale":
				p.RequestedAt = now.Add(-16 * time.Minute)
			case "future":
				p.CompletedAt = now.Add(time.Second)
			case "owner":
				p.OwnerID = uuid.New()
			case "machine":
				p.MachineID = strings.Repeat("b", 32)
			case "cleanup":
				var cleanup RuntimeCleanup
				json.Unmarshal(c, &cleanup)
				cleanup.ID = uuid.New()
				c, _ = json.Marshal(cleanup)
				p.CleanupSHA256 = stringDigest(c)
			case "journal":
				j = append(j, ' ')
			case "namespace":
				ns = "net:[42]"
			}
			proof, _ := json.Marshal(p)
			if kind == "unknown" {
				proof = append(proof[:len(proof)-1], []byte(`,"Unexpected":true}`)...)
			}
			if _, err := AssembleResetCleanupReceipt(j, c, proof, boot, ns, strings.Repeat("a", 32), now); err == nil {
				t.Fatal("unproved reset accepted")
			}
		})
	}
}
