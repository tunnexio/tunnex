package ipsec

import (
	"encoding/json"
	"github.com/google/uuid"
	"strings"
	"testing"
)

func TestReadOnlyGuardSemanticClassifiesWithoutAuthorizing(t *testing.T) {
	set := `{"set":{"family":"inet","table":"tunnex_ipsec","name":"lease_test","type":"iface_index","flags":["timeout"],"timeout":60,"elem":[{"elem":{"val":10,"timeout":30}}]}}`
	expected := strings.Replace(guardExpectedFixture, `{"chain":`, set+`,{"chain":`, 1)
	p := runtimeJournalPayload{Version: 9, OwnerID: uuid.New(), Sequence: 3, Guards: []runtimeGuardTemplate{{Namespace: "net:[4026531992]", Revision: 1, Digest: strings.Repeat("a", 64), ExpectedJSON: expected}}}
	jr, _ := json.Marshal(runtimeJournalEnvelope{Payload: p, Checksum: journalChecksum(p)})
	for _, tc := range []struct {
		name, native     string
		normalize, match bool
		path             string
	}{
		{"exact", expected, true, true, ""},
		{"bounded expiry", strings.Replace(expected, `"val":10,"timeout":30`, `"val":10,"timeout":30,"expires":29`, 1), true, true, ""},
		{"expired member absent", strings.Replace(expected, `,"elem":[{"elem":{"val":10,"timeout":30}}]`, "", 1), true, true, ""},
		{"changed member timeout", strings.Replace(expected, `"val":10,"timeout":30`, `"val":10,"timeout":29`, 1), true, false, "/set/elem/0"},
		{"changed verdict", strings.Replace(expected, `"drop":null`, `"accept":null`, 1), true, false, "/expr/1"},
		{"expired member still visible", strings.Replace(expected, `"val":10,"timeout":30`, `"val":10,"timeout":30,"expires":0`, 1), false, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in, _ := json.Marshal(ReadOnlyGuardSemanticInput{Journal: jr, Native: json.RawMessage(tc.native), Namespace: "net:[4026531992]", Links: []GuardInterface{{Name: "tx-fixture", Index: 10}}, Phase: "outside_fault"})
			v, e := ReadOnlyGuardSemantic(in)
			if e != nil {
				t.Fatal(e)
			}
			if v["native_normalization_valid"] != tc.normalize || v["exact_prior_ownership_match_count"] != map[bool]int{true: 1, false: 0}[tc.match] {
				t.Fatalf("wrong classification: %v", v)
			}
			rows := v["candidates"].([]map[string]any)
			if tc.path != "" && !strings.Contains(rows[0]["first_semantic_difference_path"].(string), tc.path) {
				t.Fatalf("missing exact semantic path: %v", rows)
			}
			if v["no_packet_permission_or_health_receipt"] != true || v["historical_failure_reproduced"] != false {
				t.Fatal("classification promoted to authority")
			}
			if !tc.normalize {
				s := v["raw_set_shape_observations"].([]map[string]any)
				if len(s) != 1 || s[0]["zero_expiry_count"] != 1 {
					t.Fatal("zero expiry unclassified")
				}
			}
		})
	}
	bad := p
	bad.Sequence++
	br, _ := json.Marshal(runtimeJournalEnvelope{Payload: bad, Checksum: journalChecksum(p)})
	in, _ := json.Marshal(ReadOnlyGuardSemanticInput{Journal: br, Native: json.RawMessage(expected), Namespace: "net:[4026531992]", Phase: "outside_fault"})
	if _, e := ReadOnlyGuardSemantic(in); e == nil {
		t.Fatal("corrupt journal accepted")
	}
}

func TestReadOnlyGuardSemanticAzureSchema10(t *testing.T) {
	for _, profile := range []string{AzureActiveActiveBGPProfile, AzureActiveActiveStaticProfile, AzureActiveStandbyBGPProfile, AzureActiveStandbyStaticProfile} {
		t.Run(profile, func(t *testing.T) {
			m := azureMaterialFixture(profile)
			e, _, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]")
			if err != nil || (profile == AzureActiveStandbyStaticProfile && e.ContractVersion != 4) {
				t.Fatal("Azure contract fixture refused", err)
			}
			p := runtimeJournalPayload{Version: 10, OwnerID: m.Manifest.NodeID, Sequence: 3, Entries: []RuntimeJournalEntry{e}, Guards: []runtimeGuardTemplate{{Namespace: "net:[4026531992]", Revision: 1, Digest: strings.Repeat("a", 64), ExpectedJSON: guardExpectedFixture}}}
			classify := func(p runtimeJournalPayload, checksum, ns, native string) (map[string]any, error) {
				raw, _ := json.Marshal(runtimeJournalEnvelope{Payload: p, Checksum: checksum})
				in, _ := json.Marshal(ReadOnlyGuardSemanticInput{Journal: raw, Native: json.RawMessage(native), Namespace: ns, Links: []GuardInterface{{Name: "tx-fixture", Index: 10}}, Phase: "outside_fault"})
				return ReadOnlyGuardSemantic(in)
			}
			result, err := classify(p, journalChecksum(p), "net:[4026531992]", guardExpectedFixture)
			if err != nil || result["whole_journal_valid"] != true || result["exact_prior_ownership_match_count"] != 1 {
				t.Fatal("valid Azure journal refused", err, result)
			}
			if _, err := classify(p, strings.Repeat("0", 64), "net:[4026531992]", guardExpectedFixture); err == nil {
				t.Fatal("corrupt checksum accepted")
			}
			legacy := p
			legacy.Version = 9
			if _, err := classify(legacy, journalChecksum(legacy), "net:[4026531992]", guardExpectedFixture); e.ContractVersion == 4 && err == nil {
				t.Fatal("Azure accepted in old schema")
			}
			mismatch := p
			mismatch.Entries = append([]RuntimeJournalEntry(nil), p.Entries...)
			mismatch.Entries[0].Engines[0].ProfileID = GCPClassicStaticProfile
			if _, err := classify(mismatch, journalChecksum(mismatch), "net:[4026531992]", guardExpectedFixture); err == nil {
				t.Fatal("mismatched profile accepted")
			}
			result, err = classify(p, journalChecksum(p), "net:[4026531993]", guardExpectedFixture)
			if err != nil || result["exact_prior_ownership_match_count"] != 0 {
				t.Fatal("foreign namespace matched", err)
			}
			result, err = classify(p, journalChecksum(p), "net:[4026531992]", strings.Replace(guardExpectedFixture, `"drop":null`, `"accept":null`, 1))
			if err != nil || result["exact_prior_ownership_match_count"] != 0 {
				t.Fatal("changed verdict matched", err)
			}
			encoded, _ := json.Marshal(result)
			if strings.Contains(string(encoded), m.Manifest.Tunnels[0].OutsideAddress) || strings.Contains(string(encoded), "tunnex_ipsec") {
				t.Fatal("raw table/address leaked")
			}
		})
	}
}
