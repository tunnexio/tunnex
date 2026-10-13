package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDeliveryReceiptBinding(t *testing.T) {
	id := "a77337ef-7eca-4484-a389-a9c9f344f68a"
	ns := "net:[4026532931]"
	raw := []byte(`{"Version":1,"DeliveryID":"a77337ef-7eca-4484-a389-a9c9f344f68a","Namespace":"net:[4026532931]"}`)
	if !receiptMatches(raw, id, ns) {
		t.Fatal("exact new genuine identity refused")
	}
	for _, bad := range []string{"", "../restore", "00000000-0000-0000-0000-000000000000", "A77337ef-7eca-4484-a389-a9c9f344f68a", "65171908-b2af-40fe-9203-a02d2281f4c3"} {
		if receiptMatches(raw, bad, ns) {
			t.Fatal("wrong delivery accepted", bad)
		}
	}
	if receiptMatches(raw, id, "net:[4026532592]") {
		t.Fatal("wrong namespace accepted")
	}
	if receiptMatches([]byte(`{"Version":0,"DeliveryID":"a77337ef-7eca-4484-a389-a9c9f344f68a","Namespace":"net:[4026532931]"}`), id, ns) {
		t.Fatal("wrong receipt version accepted")
	}
}

func TestAppliedDeliverySelection(t *testing.T) {
	id := "a77337ef-7eca-4484-a389-a9c9f344f68a"
	raw := []byte(`{"Payload":{"Entries":[{"DeliveryID":"old","Phase":"retained_refusal"},{"DeliveryID":"a77337ef-7eca-4484-a389-a9c9f344f68a","Phase":"applied"}]}}`)
	if !journalMatches(raw, id) {
		t.Fatal("one Applied with retainedhistory rejected")
	}
	for _, r := range []string{`{"Payload":{"Entries":[]}}`, `{"Payload":{"Entries":[{"DeliveryID":"a77337ef-7eca-4484-a389-a9c9f344f68a","Phase":"cleanup_pending"}]}}`, `{"Payload":{"Entries":[{"DeliveryID":"other","Phase":"applied"}]}}`} {
		if journalMatches([]byte(r), id) {
			t.Fatal("untrusted journal selected")
		}
	}
}

func TestCompleteMultiReceiptBarrier(t *testing.T) {
	owner := "11111111-1111-4111-8111-111111111111"
	ids := []string{"22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333"}
	entries := []map[string]string{}
	receipts := map[string][]byte{}
	set := receiptSet{OwnerID: owner, Namespace: "net:[42]", EvidenceDigest: strings.Repeat("a", 64), Receipts: map[string]string{}}
	for _, id := range ids {
		e := map[string]string{"DeliveryID": id, "Phase": "applied"}
		entries = append(entries, e)
		b, _ := json.Marshal(e)
		r, _ := json.Marshal(map[string]any{"Version": 1, "OwnerID": owner, "DeliveryID": id, "Namespace": set.Namespace, "EntryDigest": digest(b), "EvidenceDigest": set.EvidenceDigest, "Termination": "supervisor-confirmed-runtime-stop"})
		receipts[id] = r
		set.Receipts[id] = digest(r)
	}
	journal, _ := json.Marshal(map[string]any{"Payload": map[string]any{"OwnerID": owner, "Entries": entries}})
	set.JournalSHA = digest(journal)
	if !matchesReceiptSet(journal, set, receipts) {
		t.Fatal("complete pair refused")
	}

	for name, mutate := range map[string]func(map[string]any){
		"wrong owner":     func(r map[string]any) { r["OwnerID"] = ids[0] },
		"wrong namespace": func(r map[string]any) { r["Namespace"] = "net:[99]" },
		"stale entry":     func(r map[string]any) { r["EntryDigest"] = strings.Repeat("b", 64) },
		"wrong evidence":  func(r map[string]any) { r["EvidenceDigest"] = strings.Repeat("b", 64) },
		"wrong delivery":  func(r map[string]any) { r["DeliveryID"] = ids[1] },
	} {
		t.Run(name, func(t *testing.T) {
			saved := receipts[ids[0]]
			oldSHA := set.Receipts[ids[0]]
			var r map[string]any
			json.Unmarshal(saved, &r)
			mutate(r)
			bad, _ := json.Marshal(r)
			receipts[ids[0]] = bad
			set.Receipts[ids[0]] = digest(bad)
			if matchesReceiptSet(journal, set, receipts) {
				t.Fatal("invalid receipt accepted")
			}
			receipts[ids[0]] = saved
			set.Receipts[ids[0]] = oldSHA
		})
	}
	duplicateEntries := append(entries, entries[0])
	badJournal, _ := json.Marshal(map[string]any{"Payload": map[string]any{"OwnerID": owner, "Entries": duplicateEntries}})
	savedSHA := set.JournalSHA
	set.JournalSHA = digest(badJournal)
	if matchesReceiptSet(badJournal, set, receipts) {
		t.Fatal("duplicate obligation accepted")
	}
	set.JournalSHA = savedSHA
	delete(receipts, ids[1])
	if matchesReceiptSet(journal, set, receipts) {
		t.Fatal("partial set accepted")
	}
	receipts[ids[1]] = []byte("tampered")
	if matchesReceiptSet(journal, set, receipts) {
		t.Fatal("tampered accepted")
	}
}
