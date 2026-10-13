package ipsec

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"sort"
)

// This harness constructs no controller, journal, reader or authority. All
// ownership/normalization predicates below are the current source validators.
type ReadOnlyGuardSemanticInput struct {
	Journal   json.RawMessage  `json:"journal"`
	Native    json.RawMessage  `json:"native"`
	Namespace string           `json:"namespace"`
	Links     []GuardInterface `json:"links"`
	Phase     string           `json:"phase"`
}

func diagHash(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
func diagValueHash(v any) string { b, _ := json.Marshal(v); return diagHash(b) }
func diagFirstDifference(a, b any, path string) string {
	if reflect.DeepEqual(a, b) {
		return ""
	}
	if x, ok := a.(map[string]any); ok {
		if y, ok := b.(map[string]any); ok {
			keys := map[string]bool{}
			for k := range x {
				keys[k] = true
			}
			for k := range y {
				keys[k] = true
			}
			order := make([]string, 0, len(keys))
			for k := range keys {
				order = append(order, k)
			}
			sort.Strings(order)
			for _, k := range order {
				av, ap := x[k]
				bv, bp := y[k]
				if ap != bp {
					return path + "/" + k + "/presence"
				}
				if d := diagFirstDifference(av, bv, path+"/"+k); d != "" {
					return d
				}
			}
		}
	}
	if x, ok := a.([]any); ok {
		if y, ok := b.([]any); ok {
			if len(x) != len(y) {
				return path + "/length"
			}
			for i := range x {
				if d := diagFirstDifference(x[i], y[i], fmt.Sprintf("%s/%d", path, i)); d != "" {
					return d
				}
			}
		}
	}
	return path
}

// diffWithdrawal uses exactly the permitted observed-member subset relation.
// It only reports a mismatch path; VerifyGuardWithdrawal remains authoritative.
func diagWithdrawalPath(want, got []any) string {
	if len(want) != len(got) {
		return "/objects/length"
	}
	for i, w := range want {
		wf := w.(map[string]any)
		gf := got[i].(map[string]any)
		path := fmt.Sprintf("/objects/%d", i)
		ws, isSet := wf["set"].(map[string]any)
		if !isSet {
			if d := diagFirstDifference(wf, gf, path); d != "" {
				return d
			}
			continue
		}
		gs, ok := gf["set"].(map[string]any)
		if !ok {
			return path + "/set/presence"
		}
		allowed := map[string]any{}
		if elems, ok := ws["elem"].([]any); ok {
			for _, v := range elems {
				e := v.(map[string]any)["elem"].(map[string]any)
				allowed[guardSetMemberKey(e["val"])] = v
			}
		}
		if elems, ok := gs["elem"].([]any); ok {
			for n, v := range elems {
				e := v.(map[string]any)["elem"].(map[string]any)
				if !reflect.DeepEqual(allowed[guardSetMemberKey(e["val"])], v) {
					return fmt.Sprintf("%s/set/elem/%d", path, n)
				}
			}
		}
		delete(ws, "elem")
		delete(gs, "elem")
		if d := diagFirstDifference(ws, gs, path+"/set"); d != "" {
			return d
		}
	}
	return ""
}

// Raw set summaries expose name hashes and shape/count predicates, never expressions,
// addresses, member values or the journal contents. They do not permit packets.
func diagNativeSetShapes(raw []byte) []map[string]any {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var env map[string]any
	if d.Decode(&env) != nil {
		return nil
	}
	items, _ := env["nftables"].([]any)
	out := []map[string]any{}
	for _, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			continue
		}
		set, ok := object["set"].(map[string]any)
		if !ok {
			continue
		}
		name, ok := set["name"].(string)
		if !ok || len(name) > 128 {
			continue
		}
		elems, _ := set["elem"].([]any)
		zero, missing, invalid := 0, 0, 0
		for _, item := range elems {
			w, ok := item.(map[string]any)
			if !ok {
				invalid++
				continue
			}
			e, ok := w["elem"].(map[string]any)
			if !ok {
				invalid++
				continue
			}
			if _, ok := e["timeout"]; !ok {
				missing++
			}
			if n, ok := e["expires"].(json.Number); ok && n.String() == "0" {
				zero++
			}
			if x, present := e["expires"]; present {
				if _, ok := guardPositiveSeconds(x); !ok {
					invalid++
				}
			}
		}
		if zero > 0 || missing > 0 || invalid > 0 {
			out = append(out, map[string]any{"name_sha256": diagHash([]byte(name)), "element_count": len(elems), "zero_expiry_count": zero, "missing_element_timeout_count": missing, "nonpositive_or_invalid_expiry_count": invalid})
		}
	}
	return out
}

// These bounded counts describe raw shape only. Parsed member values never leave
// this diagnostic; production normalization/withdrawal remains authoritative.
type diagSetShape struct {
	members                                                                                         map[string]bool
	count, invalidMembers, positiveExpiry, zeroExpiry, invalidExpiry, missingExpiry, missingTimeout int
}

func diagSets(raw []byte, links map[string]int) (map[string]diagSetShape, bool) {
	if len(raw) > kernelDumpLimit {
		return nil, false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var env map[string]any
	if d.Decode(&env) != nil {
		return nil, false
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, false
	}
	objects, ok := env["nftables"].([]any)
	if !ok || len(objects) > kernelEntryLimit {
		return nil, false
	}
	out := map[string]diagSetShape{}
	for _, object := range objects {
		wrapper, ok := object.(map[string]any)
		if !ok {
			return nil, false
		}
		rawSet, present := wrapper["set"]
		if !present {
			continue
		}
		set, ok := rawSet.(map[string]any)
		if !ok {
			return nil, false
		}
		name, ok := set["name"].(string)
		if !ok || name == "" || len(name) > 128 {
			return nil, false
		}
		if _, duplicate := out[name]; duplicate {
			return nil, false
		}
		shape := diagSetShape{members: map[string]bool{}}
		values := []any{}
		if elems, present := set["elem"]; present {
			var valid bool
			values, valid = elems.([]any)
			if !valid || len(values) > kernelEntryLimit {
				return nil, false
			}
		}
		shape.count = len(values)
		for _, value := range values {
			w, ok := value.(map[string]any)
			if !ok || len(w) != 1 {
				shape.invalidMembers++
				shape.invalidExpiry++
				continue
			}
			e, ok := w["elem"].(map[string]any)
			if !ok {
				shape.invalidMembers++
				shape.invalidExpiry++
				continue
			}
			member := e["val"]
			if set["type"] == "iface_index" {
				var translated bool
				member, translated = translateGuardIndex(member, links)
				if !translated {
					member = nil
				}
			}
			n, valid := member.(json.Number)
			if !valid || !guardCounterNumber(n) || n.String() == "0" || shape.members[n.String()] {
				shape.invalidMembers++
			} else {
				shape.members[n.String()] = true
			}
			if _, present := e["timeout"]; !present {
				shape.missingTimeout++
			}
			expiry, present := e["expires"]
			if !present {
				shape.missingExpiry++
			} else if number, valid := expiry.(json.Number); valid && number.String() == "0" {
				shape.zeroExpiry++
			} else if _, positive := guardPositiveSeconds(expiry); positive {
				shape.positiveExpiry++
			} else {
				shape.invalidExpiry++
			}
		}
		out[name] = shape
	}
	return out, true
}
func diagSetMemberCounts(expected, observed []byte, links map[string]int) ([]map[string]any, bool) {
	want, wok := diagSets(expected, nil)
	got, gok := diagSets(observed, links)
	if !wok || !gok {
		return []map[string]any{}, false
	}
	names := map[string]bool{}
	for name := range want {
		names[name] = true
	}
	for name := range got {
		names[name] = true
	}
	if len(names) > kernelEntryLimit {
		return []map[string]any{}, false
	}
	order := make([]string, 0, len(names))
	for name := range names {
		order = append(order, name)
	}
	sort.Strings(order)
	rows := make([]map[string]any, 0, len(order))
	for _, name := range order {
		w, wp := want[name]
		g, gp := got[name]
		valid := w.invalidMembers == 0 && g.invalidMembers == 0
		var missing, extra any
		if valid {
			m, x := 0, 0
			for value := range w.members {
				if !g.members[value] {
					m++
				}
			}
			for value := range g.members {
				if !w.members[value] {
					x++
				}
			}
			missing, extra = m, x
		}
		rows = append(rows, map[string]any{"name_sha256": diagHash([]byte(name)), "expected_set_present": wp, "observed_set_present": gp, "expected_member_count": w.count, "observed_member_count": g.count, "member_comparison_valid": valid, "missing_member_count": missing, "extra_member_count": extra, "expected_invalid_member_count": w.invalidMembers, "observed_invalid_member_count": g.invalidMembers, "observed_positive_expiry_count": g.positiveExpiry, "observed_zero_expiry_count": g.zeroExpiry, "observed_invalid_expiry_count": g.invalidExpiry, "observed_missing_expiry_count": g.missingExpiry, "observed_missing_element_timeout_count": g.missingTimeout})
	}
	return rows, true
}

func ReadOnlyGuardSemantic(raw []byte) (map[string]any, error) {
	if len(raw) > runtimeJournalLimit+2*kernelDumpLimit {
		return nil, fmt.Errorf("bounded input refused")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	var in ReadOnlyGuardSemanticInput
	if d.Decode(&in) != nil {
		return nil, fmt.Errorf("input refused")
	}
	if _, e := d.Token(); e != io.EOF {
		return nil, fmt.Errorf("input trailing data refused")
	}
	if len(in.Journal) > runtimeJournalLimit || len(in.Native) > kernelDumpLimit || in.Namespace == "" || len(in.Links) > kernelEntryLimit || in.Phase != "outside_fault" && in.Phase != "fault" && in.Phase != "recovery" {
		return nil, fmt.Errorf("scope refused")
	}
	payload, err := decodeRuntimeJournalSnapshot(in.Journal)
	if err != nil {
		return nil, fmt.Errorf("whole journal validation refused")
	}
	mapping := map[string]int{}
	indices := map[int]bool{}
	for _, l := range in.Links {
		if l.Name == "" || l.Index <= 0 || mapping[l.Name] != 0 || indices[l.Index] {
			return nil, fmt.Errorf("interface mapping refused")
		}
		mapping[l.Name] = l.Index
		indices[l.Index] = true
	}
	got, nativeOK := normalizedGuardObjectsWithInterfaces(in.Native, mapping)
	rows := []map[string]any{}
	matches := 0
	for _, g := range payload.Guards {
		want, expectedOK := normalizedGuardObjects([]byte(g.ExpectedJSON))
		match := g.Namespace == in.Namespace && VerifyGuardWithdrawal([]byte(g.ExpectedJSON), in.Native, in.Links) == nil
		if match {
			matches++
		}
		memberCounts, memberCountsValid := diagSetMemberCounts([]byte(g.ExpectedJSON), in.Native, mapping)
		row := map[string]any{"namespace_matches": g.Namespace == in.Namespace, "revision": g.Revision, "digest": g.Digest, "expected_normalization_valid": expectedOK, "withdrawal_matches": match, "set_member_count_projection_valid": memberCountsValid, "set_member_counts": memberCounts}
		if expectedOK && nativeOK && !match && g.Namespace == in.Namespace {
			freshGot, _ := normalizedGuardObjectsWithInterfaces(in.Native, mapping)
			row["expected_normalized_sha256"] = diagValueHash(want)
			row["observed_normalized_sha256"] = diagValueHash(freshGot)
			row["first_semantic_difference_path"] = diagWithdrawalPath(want, freshGot)
		}
		rows = append(rows, row)
	}
	_ = got
	return map[string]any{"read_only": true, "phase": in.Phase, "whole_journal_valid": true, "no_controller_reader_or_authority_constructed": true, "journal_raw_sha256": diagHash(in.Journal), "native_raw_sha256": diagHash(in.Native), "journal_sequence": payload.Sequence, "candidate_count": len(rows), "exact_prior_ownership_match_count": matches, "native_normalization_valid": nativeOK, "raw_set_shape_observations": diagNativeSetShapes(in.Native), "candidates": rows, "historical_failure_reproduced": false, "no_packet_permission_or_health_receipt": true}, nil
}
