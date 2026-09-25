package ipsec

import (
	"encoding/json"
	"github.com/google/uuid"
	"testing"
)

func TestResetReceiptExactCleanupBinding(t *testing.T) {
	e := journalFixture()
	cleanup := RuntimeCleanup{RuntimeDelivery: RuntimeDelivery{ID: uuid.New(), DesiredRevision: 9}, RetainGuard: true}
	boot := uuid.New().String()
	ns := "net:[9999]"
	owner := e.Engines[0].Binding.GatewayID
	receipt := runtimeResetReceipt{Version: 1, OwnerID: owner, CleanupID: cleanup.ID, CleanupRevision: 9, CoveredDigest: resetCoveredDigest([]RuntimeJournalEntry{e}), BootID: boot, Namespace: ns, Termination: "supervisor-confirmed-vm-stop", EvidenceDigest: stringDigest([]byte("verified external lifecycle evidence"))}
	raw, _ := json.Marshal(receipt)
	if _, err := parseResetReceipt(raw, owner, cleanup, []RuntimeJournalEntry{e}, boot, ns); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"owner", "cleanup", "revision", "covered", "boot", "namespace", "termination", "evidence"} {
		t.Run(kind, func(t *testing.T) {
			bad := receipt
			switch kind {
			case "owner":
				bad.OwnerID = uuid.New()
			case "cleanup":
				bad.CleanupID = uuid.New()
			case "revision":
				bad.CleanupRevision++
			case "covered":
				bad.CoveredDigest = stringDigest([]byte("other"))
			case "boot":
				bad.BootID = uuid.New().String()
			case "namespace":
				bad.Namespace = "net:[8888]"
			case "termination":
				bad.Termination = "assumed"
			case "evidence":
				bad.EvidenceDigest = ""
			}
			b, _ := json.Marshal(bad)
			if _, err := parseResetReceipt(b, owner, cleanup, []RuntimeJournalEntry{e}, boot, ns); err == nil {
				t.Fatal("mismatched proof accepted")
			}
		})
	}
	if _, err := parseResetReceipt(append(raw, raw...), owner, cleanup, []RuntimeJournalEntry{e}, boot, ns); err == nil {
		t.Fatal("trailing receipt accepted")
	}
	duplicate := append([]byte(`{"Version":1,`), raw[1:]...)
	if _, err := parseResetReceipt(duplicate, owner, cleanup, []RuntimeJournalEntry{e}, boot, ns); err == nil {
		t.Fatal("duplicate receipt field accepted")
	}
	var fields map[string]any
	json.Unmarshal(raw, &fields)
	fields["override"] = true
	b, _ := json.Marshal(fields)
	if _, err := parseResetReceipt(b, owner, cleanup, []RuntimeJournalEntry{e}, boot, ns); err == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestResetInventoryRefusesAliasesAndInsideAddresses(t *testing.T) {
	e := journalFixture()
	if !resetExtraObjectsAbsent(e, []byte(`[]`), []byte(`[]`)) {
		t.Fatal("empty inventory refused")
	}
	alias, _ := json.Marshal([]map[string]any{{"ifname": "renamed", "ifalias": e.Allocation.Tunnels[0].Alias}})
	if resetExtraObjectsAbsent(e, alias, []byte(`[]`)) {
		t.Fatal("renamed ownership alias accepted")
	}
	addr, _ := json.Marshal([]map[string]any{{"ifname": "foreign", "addr_info": []map[string]any{{"family": "inet", "local": e.Allocation.Tunnels[0].InsideAddress.Addr().String(), "prefixlen": 30}}}})
	if resetExtraObjectsAbsent(e, []byte(`[]`), addr) {
		t.Fatal("inside address survivor accepted")
	}
	if resetExtraObjectsAbsent(e, []byte(`garbage`), []byte(`[]`)) {
		t.Fatal("invalid inventory accepted")
	}
}
