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
		{"expired member still visible", strings.Replace(expected, `"val":10,"timeout":30`, `"val":10,"timeout":30,"expires":0`, 1), false, true, ""},
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

func TestReadOnlyGuardSemanticMemberCountsSchema10(t *testing.T) {
	set := `{"set":{"family":"inet","table":"tunnex_ipsec","name":"lease_test","type":"iface_index","flags":["timeout"],"timeout":60,"elem":[{"elem":{"val":10,"timeout":30}}]}}`
	expected := strings.Replace(guardExpectedFixture, `{"chain":`, set+`,{"chain":`, 1)
	material := azureMaterialFixture(AzureActiveActiveBGPProfile)
	entry, _, err := runtimeMaterialEntry(material, material.Manifest.OrgID, material.Manifest.NodeID, "net:[4026531992]")
	if err != nil {
		t.Fatal(err)
	}
	payload := runtimeJournalPayload{Version: 10, OwnerID: material.Manifest.NodeID, Sequence: 3, Entries: []RuntimeJournalEntry{entry}, Guards: []runtimeGuardTemplate{{Namespace: "net:[4026531992]", Revision: 1, Digest: strings.Repeat("a", 64), ExpectedJSON: expected}}}
	journal, _ := json.Marshal(runtimeJournalEnvelope{Payload: payload, Checksum: journalChecksum(payload)})
	for _, tc := range []struct {
		name, native                                                                     string
		observed, missing, extra, positive, zero, invalid, missingExpiry, missingTimeout int
		match                                                                            bool
	}{
		{"complete", expected, 1, 0, 0, 0, 0, 0, 1, 0, true},
		{"positive", strings.Replace(expected, `"timeout":30}`, `"timeout":30,"expires":29}`, 1), 1, 0, 0, 1, 0, 0, 0, 0, true},
		{"disappeared", strings.Replace(expected, `,"elem":[{"elem":{"val":10,"timeout":30}}]`, "", 1), 0, 1, 0, 0, 0, 0, 0, 0, true},
		{"foreign member", strings.Replace(expected, `"val":10`, `"val":11`, 1), 1, 1, 1, 0, 0, 0, 1, 0, false},
		{"zero", strings.Replace(expected, `"timeout":30}`, `"timeout":30,"expires":0}`, 1), 1, 0, 0, 0, 1, 0, 0, 0, true},
		{"invalid expiry", strings.Replace(expected, `"timeout":30}`, `"timeout":30,"expires":-1}`, 1), 1, 0, 0, 0, 0, 1, 0, 0, false},
		{"missing timeout", strings.Replace(expected, `"timeout":30}`, `"expires":29}`, 1), 1, 0, 0, 1, 0, 0, 0, 1, false},
		{"foreign structure", strings.Replace(expected, `"drop":null`, `"accept":null`, 1), 1, 0, 0, 0, 0, 0, 1, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in, _ := json.Marshal(ReadOnlyGuardSemanticInput{Journal: journal, Native: json.RawMessage(tc.native), Namespace: "net:[4026531992]", Links: []GuardInterface{{Name: "tx-fixture", Index: 10}}, Phase: "recovery"})
			result, err := ReadOnlyGuardSemantic(in)
			if err != nil {
				t.Fatal(err)
			}
			candidate := result["candidates"].([]map[string]any)[0]
			if candidate["set_member_count_projection_valid"] != true || candidate["withdrawal_matches"] != tc.match {
				t.Fatal("wrong diagnostic/validator result", candidate)
			}
			rows := candidate["set_member_counts"].([]map[string]any)
			if len(rows) != 1 {
				t.Fatal(rows)
			}
			row := rows[0]
			want := map[string]int{"expected_member_count": 1, "observed_member_count": tc.observed, "missing_member_count": tc.missing, "extra_member_count": tc.extra, "observed_positive_expiry_count": tc.positive, "observed_zero_expiry_count": tc.zero, "observed_invalid_expiry_count": tc.invalid, "observed_missing_expiry_count": tc.missingExpiry, "observed_missing_element_timeout_count": tc.missingTimeout}
			for key, v := range want {
				if row[key] != v {
					t.Fatalf("%s got%v want%d", key, row[key], v)
				}
			}
			if row["name_sha256"] != diagHash([]byte("lease_test")) || row["member_comparison_valid"] != true {
				t.Fatal(row)
			}
			raw, _ := json.Marshal(row)
			if strings.Contains(string(raw), "lease_test") || strings.Contains(string(raw), "tunnex_ipsec") || strings.Contains(string(raw), "tx-fixture") || strings.Contains(string(raw), `"val"`) {
				t.Fatal("member/name payload leaked")
			}
			if result["no_packet_permission_or_health_receipt"] != true || result["historical_failure_reproduced"] != false {
				t.Fatal("diagnostic promoted")
			}
		})
	}
}

func TestReadOnlyGuardSemanticMemberCountsMalformedAndBounded(t *testing.T) {
	set := `{"nftables":[{"set":{"name":"private-name","type":"iface_index","elem":[{"elem":{"val":10}}]}}]}`
	rows, ok := diagSetMemberCounts([]byte(set), []byte(strings.Replace(set, `"val":10`, `"val":"tx-fixture"`, 1)), map[string]int{"tx-fixture": 10})
	if !ok || len(rows) != 1 || rows[0]["missing_member_count"] != 0 || rows[0]["extra_member_count"] != 0 {
		t.Fatal("canonical interface comparison refused", rows)
	}
	malformed := strings.Replace(set, `{"elem":{"val":10}}`, `{"elem":{"val":10}},{"elem":{"val":10}}`, 1)
	rows, ok = diagSetMemberCounts([]byte(set), []byte(malformed), nil)
	if !ok || rows[0]["member_comparison_valid"] != false || rows[0]["missing_member_count"] != nil || rows[0]["extra_member_count"] != nil {
		t.Fatal("duplicate member implied comparison", rows)
	}
	if _, ok := diagSetMemberCounts([]byte(set), append([]byte(set), []byte(`{}`)...), nil); ok {
		t.Fatal("trailing data accepted")
	}
	if _, ok := diagSetMemberCounts([]byte(set), []byte(strings.Repeat("x", kernelDumpLimit+1)), nil); ok {
		t.Fatal("unbounded diagnostic accepted")
	}
}
