package ipsec

import (
	"encoding/json"
	"github.com/google/uuid"
	"testing"
)

func TestAzureBGPResetCoverageBoundReceipt(t *testing.T) {
	_, target := azureRecreationMaterial(t, nil, []string{"10.231.0.0/16"}, 8)
	target = retainedAzure(target)
	oldBoot, boot := uuid.NewString(), uuid.NewString()
	target.Restoration = &RuntimeRestoration{BootID: oldBoot}
	sibling := target
	sibling.DeliveryID = uuid.New()
	sibling.CleanupID = uuid.New()
	ns := "net:[4026532992]"
	sibling.ResetCleanup = &RuntimeResetCleanup{BootID: boot, Namespace: ns, ReceiptDigest: stringDigest([]byte("receipt"))}
	entries := []RuntimeJournalEntry{target, sibling}
	covered, ok := retainedResetCoverage(target, sibling, entries, boot, ns)
	if !ok || len(covered) != 2 {
		t.Fatal("exact coverage refused")
	}
	cleanup := RuntimeCleanup{RuntimeDelivery: RuntimeDelivery{ID: sibling.CleanupID, DesiredRevision: sibling.CleanupDesiredRevision}, RetainGuard: true}
	receipt := runtimeResetReceipt{Version: 1, OwnerID: target.Engines[0].Binding.GatewayID, CleanupID: cleanup.ID, CleanupRevision: cleanup.DesiredRevision, CoveredDigest: resetCoveredDigest(covered), BootID: boot, Namespace: ns, Termination: "supervisor-confirmed-vm-stop", EvidenceDigest: stringDigest([]byte("external"))}
	raw, _ := json.Marshal(receipt)
	parsed, err := parseResetReceipt(raw, receipt.OwnerID, cleanup, covered, boot, ns)
	if err != nil || parsed.ReceiptDigest != stringDigest(raw) {
		t.Fatal("bound fixture receipt refused")
	}
	for _, test := range []struct {
		name   string
		change func(*RuntimeJournalEntry)
	}{
		{"other connection", func(e *RuntimeJournalEntry) { e.Allocation.ConnectionID = uuid.New() }},
		{"wrong boot", func(e *RuntimeJournalEntry) {
			e.ResetCleanup = &RuntimeResetCleanup{BootID: uuid.NewString(), Namespace: ns, ReceiptDigest: stringDigest(raw)}
		}},
		{"malformed recorded namespace", func(e *RuntimeJournalEntry) {
			e.ResetCleanup = &RuntimeResetCleanup{BootID: boot, Namespace: "malformed", ReceiptDigest: stringDigest(raw)}
		}},
		{"different old boot", func(e *RuntimeJournalEntry) { e.Restoration = &RuntimeRestoration{BootID: uuid.NewString()} }},
		{"partial coverage", func(e *RuntimeJournalEntry) { e.CoveredDeliveryRevision = 0 }},
		{"no accepted marker", func(e *RuntimeJournalEntry) { e.ResetCleanup = nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := sibling
			test.change(&changed)
			if _, ok := retainedResetCoverage(target, changed, entries, boot, ns); ok {
				t.Fatal("unbound coverage accepted")
			}
		})
	}
	changed := append([]RuntimeJournalEntry(nil), covered...)
	changed[0].OwnershipDigest = stringDigest([]byte("changed"))
	for _, set := range [][]RuntimeJournalEntry{covered[:1], changed} {
		if _, err := parseResetReceipt(raw, receipt.OwnerID, cleanup, set, boot, ns); err == nil {
			t.Fatal("changed full covered set accepted")
		}
	}
	persisted := *parsed
	if !retainedResetReceiptMatches(parsed, &persisted, boot, ns) {
		t.Fatal("original bound digest refused")
	}
	persisted.ReceiptDigest = stringDigest(append(raw, ' '))
	if retainedResetReceiptMatches(parsed, &persisted, boot, ns) {
		t.Fatal("changed persisted digest accepted")
	}
	if parsed.ReceiptDigest == stringDigest(append(raw, ' ')) {
		t.Fatal("changed raw receipt hash accepted")
	}
}

func TestAzureBGPPeerRouteCensusIncludesRenamedDevices(t *testing.T) {
	_, entry := azureRecreationMaterial(t, nil, []string{"10.231.0.0/16"}, 8)
	peer := entry.Allocation.Tunnels[0].BGP.Peer.String()
	for _, raw := range []string{`[{"dst":"` + peer + `","dev":"renamed"}]`, `[{"dst":"` + peer + `/32","dev":"foreign"}]`, `[{"dst":4}]`, `[] trailing`} {
		if azureBGPPeersAbsent(entry, []byte(raw)) {
			t.Fatal("peer or malformed route accepted")
		}
	}
	if !azureBGPPeersAbsent(entry, []byte(`[{"dst":"default","dev":"eth0"}]`)) {
		t.Fatal("unrelated route refused")
	}
}

func TestAzureBGPOriginalResetReceiptAfterNamespaceRecreation(t *testing.T) {
	_, target := azureRecreationMaterial(t, nil, []string{"10.231.0.0/16"}, 8)
	target = retainedAzure(target)
	target.Restoration = &RuntimeRestoration{BootID: uuid.NewString()}
	boot := uuid.NewString()
	originalNS, currentNS := "net:[4026532992]", "net:[4026533992]"
	sibling := target
	sibling.DeliveryID = uuid.New()
	sibling.CleanupID = uuid.New()
	sibling.ResetCleanup = &RuntimeResetCleanup{BootID: boot, Namespace: originalNS, ReceiptDigest: stringDigest([]byte("temporary"))}
	covered, ok := retainedResetCoverage(target, sibling, []RuntimeJournalEntry{target, sibling}, boot, currentNS)
	if !ok || len(covered) != 2 {
		t.Fatal("original VM-stop coverage refused after same-boot namespace recreation")
	}
	cleanup := RuntimeCleanup{RuntimeDelivery: RuntimeDelivery{ID: sibling.CleanupID, DesiredRevision: sibling.CleanupDesiredRevision}, RetainGuard: true}
	receipt := runtimeResetReceipt{Version: 1, OwnerID: target.Engines[0].Binding.GatewayID, CleanupID: cleanup.ID, CleanupRevision: cleanup.DesiredRevision, CoveredDigest: resetCoveredDigest(covered), BootID: boot, Namespace: originalNS, Termination: "supervisor-confirmed-vm-stop", EvidenceDigest: stringDigest([]byte("synthetic model VM-stop evidence"))}
	raw, _ := json.Marshal(receipt)
	parsed, err := parseResetReceipt(raw, receipt.OwnerID, cleanup, covered, boot, originalNS)
	if err != nil {
		t.Fatal(err)
	}
	persisted := *parsed
	if !retainedResetReceiptMatches(parsed, &persisted, boot, currentNS) {
		t.Fatal("immutable original namespace receipt refused")
	}
	for _, tc := range []struct {
		name   string
		mutate func(*RuntimeResetCleanup)
	}{{"wrong boot", func(v *RuntimeResetCleanup) { v.BootID = uuid.NewString() }}, {"wrong digest", func(v *RuntimeResetCleanup) { v.ReceiptDigest = stringDigest(append(raw, ' ')) }}, {"wrong recorded namespace", func(v *RuntimeResetCleanup) { v.Namespace = currentNS }}} {
		t.Run(tc.name, func(t *testing.T) {
			bad := persisted
			tc.mutate(&bad)
			if retainedResetReceiptMatches(parsed, &bad, boot, currentNS) {
				t.Fatal("foreign receipt accepted")
			}
		})
	}
	if retainedResetReceiptMatches(nil, &persisted, boot, currentNS) || retainedResetReceiptMatches(parsed, nil, boot, currentNS) {
		t.Fatal("missing receipt accepted")
	}
	for _, set := range [][]RuntimeJournalEntry{covered[:1], {}} {
		if _, err := parseResetReceipt(raw, receipt.OwnerID, cleanup, set, boot, originalNS); err == nil {
			t.Fatal("partial coverage accepted")
		}
	}
	if azureBGPPeersAbsent(target, []byte(`[{"dst":"`+target.Allocation.Tunnels[0].BGP.Peer.String()+`/32","dev":"foreign"}]`)) {
		t.Fatal("receipt discharged foreign current peer route")
	}
}
