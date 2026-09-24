package ipsec

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"sort"
	"strconv"
	"unicode/utf8"
)

var ErrGuardReadback = errors.New("IPsec guard readback does not match")

// VerifyGuardReadback compares full rendered intent with observed nft objects.
// expected must come from RenderGuard, not an API or an owner-marker echo.
// Equality alone is not a receipt or authority to activate a connection.
func VerifyGuardReadback(expected, observed []byte) error {
	want, ok := normalizedGuardObjects(expected)
	if !ok {
		return ErrGuardReadback
	}
	got, ok := normalizedGuardObjects(observed)
	if !ok || !reflect.DeepEqual(want, got) {
		return ErrGuardReadback
	}
	return nil
}
func normalizedGuardObjects(raw []byte) ([]any, bool) {
	return normalizedGuardObjectsWithInterfaces(raw, nil)
}
func normalizedGuardObjectsWithInterfaces(raw []byte, interfaces map[string]int) ([]any, bool) {
	if len(raw) > kernelDumpLimit || !utf8.Valid(raw) {
		return nil, false
	}
	scanner := json.NewDecoder(bytes.NewReader(raw))
	scanner.UseNumber()
	if !kernelJSONValue(scanner, 0) {
		return nil, false
	}
	if _, err := scanner.Token(); err != io.EOF {
		return nil, false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var envelope map[string]any
	if decoder.Decode(&envelope) != nil || len(envelope) != 1 {
		return nil, false
	}
	items, ok := envelope["nftables"].([]any)
	if !ok || len(items) == 0 || len(items) > kernelEntryLimit {
		return nil, false
	}
	result := make([]any, 0, len(items))
	var ruleObjects, setObjects, ownerObjects []any
	tables, chains, rules := 0, 0, 0
	metadata := false
	for _, item := range items {
		object, ok := item.(map[string]any)
		if !ok || len(object) != 1 {
			return nil, false
		}
		if meta, present := object["metainfo"]; present {
			if metadata {
				return nil, false
			}
			metadata = true
			fields, ok := meta.(map[string]any)
			if !ok {
				return nil, false
			}
			for key := range fields {
				if key != "version" && key != "release_name" && key != "json_schema_version" {
					return nil, false
				}
			}
			continue
		}
		kind := ""
		var fields map[string]any
		for name, value := range object {
			kind = name
			fields, ok = value.(map[string]any)
		}
		if !ok {
			return nil, false
		}
		switch kind {
		case "table":
			tables++
			if fields["name"] != "tunnex_ipsec" {
				return nil, false
			}
		case "set":
			if !translateGuardSet(fields, interfaces) || !normalizeGuardSet(fields) {
				return nil, false
			}
		case "chain":
			chains++
		case "rule":
			rules++
		default:
			return nil, false
		}
		if fields["family"] != "inet" {
			return nil, false
		}
		if kind != "table" && fields["table"] != "tunnex_ipsec" {
			return nil, false
		}
		if handle, present := fields["handle"]; present {
			if !guardCounterNumber(handle) {
				return nil, false
			}
			delete(fields, "handle")
		}
		if kind == "rule" {
			exprs, ok := fields["expr"].([]any)
			if !ok || len(exprs) == 0 {
				return nil, false
			}
			for _, rawExpr := range exprs {
				expr, ok := rawExpr.(map[string]any)
				if !ok || len(expr) != 1 {
					return nil, false
				}
				if !translateGuardMatch(expr, interfaces) {
					return nil, false
				}
				if counter, present := expr["counter"]; present {
					if counter != nil {
						counts, ok := counter.(map[string]any)
						if !ok || len(counts) != 2 {
							return nil, false
						}
						for _, name := range []string{"packets", "bytes"} {
							if !guardCounterNumber(counts[name]) {
								return nil, false
							}
						}
					}
					expr["counter"] = nil
				}
			}
		}
		if kind == "chain" && fields["name"] == "owner" {
			ownerObjects = append(ownerObjects, object)
		} else if kind == "set" {
			setObjects = append(setObjects, object)
		} else if kind == "rule" {
			ruleObjects = append(ruleObjects, object)
		} else {
			result = append(result, object)
		}
	}
	// nft groups definitions before rules; retain definition and rule order.
	// The unhooked owner marker is recreated on refresh and moves in listing.
	// Named set declaration order reflects kernel creation history, not packet
	// evaluation. Keep complete descriptors/members, reject duplicate names, and
	// canonicalize only declarations. Per-chain rule order is never sorted.
	setNames := map[string]bool{}
	for _, object := range setObjects {
		fields := object.(map[string]any)["set"].(map[string]any)
		name, ok := fields["name"].(string)
		if !ok || name == "" || setNames[name] {
			return nil, false
		}
		setNames[name] = true
	}
	sort.Slice(setObjects, func(i, j int) bool {
		return setObjects[i].(map[string]any)["set"].(map[string]any)["name"].(string) < setObjects[j].(map[string]any)["set"].(map[string]any)["name"].(string)
	})
	result = append(result, ownerObjects...)
	result = append(result, setObjects...)
	result = append(result, ruleObjects...)
	return result, tables == 1 && chains > 0 && rules > 0
}
func guardCounterNumber(value any) bool {
	n, ok := value.(json.Number)
	if !ok {
		return false
	}
	_, valid := kernelNumber(json.RawMessage(n.String()), 64)
	return valid
}

// Expiry is observed remaining life, never renewal authority. Callers must also
// enforce their monotonic lease deadline before and after application/readback.
func normalizeGuardSet(fields map[string]any) bool {
	if (!reflect.DeepEqual(fields["type"], "iface_index") && !reflect.DeepEqual(fields["type"], map[string]any{"typeof": map[string]any{"ipsec": map[string]any{"dir": "out", "key": "reqid", "spnum": json.Number("0")}}})) || !reflect.DeepEqual(fields["flags"], []any{"timeout"}) {
		return false
	}
	duration, ok := guardPositiveSeconds(fields["timeout"])
	if !ok {
		return false
	}
	raw, present := fields["elem"]
	if !present {
		return true
	}
	elements, ok := raw.([]any)
	if !ok || len(elements) > 2 {
		return false
	}
	seen := map[string]bool{}
	for _, rawElement := range elements {
		wrapper, ok := rawElement.(map[string]any)
		if !ok || len(wrapper) != 1 {
			return false
		}
		element, ok := wrapper["elem"].(map[string]any)
		if !ok {
			return false
		}
		value, ok := element["val"].(json.Number)
		if !ok || !guardCounterNumber(value) || value.String() == "0" || seen[value.String()] {
			return false
		}
		seen[value.String()] = true
		timeout, ok := guardPositiveSeconds(element["timeout"])
		if !ok || timeout > duration {
			return false
		}
		if remaining, present := element["expires"]; present {
			expiry, ok := guardPositiveSeconds(remaining)
			if !ok || expiry > timeout {
				return false
			}
			delete(element, "expires")
		}
		if len(element) != 2 {
			return false
		}
	}
	return true
}
func guardPositiveSeconds(value any) (uint64, bool) {
	n, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	seconds, ok := kernelNumber(json.RawMessage(n.String()), 64)
	return seconds, ok && seconds > 0 && seconds <= 60
}

// GuardInterface must be independently read in the same network namespace.
// nft JSON may resolve iface_index values to names even with --numeric.
// Callers recheck namespace and link identity after readback; this is not a receipt.
type GuardInterface struct {
	Name  string
	Index int
}

func VerifyGuardReadbackWithInterfaces(expected, observed []byte, links []GuardInterface) error {
	mapping := map[string]int{}
	indices := map[int]bool{}
	if len(links) > kernelEntryLimit {
		return ErrGuardReadback
	}
	for _, link := range links {
		if link.Name == "" || link.Index <= 0 || int64(link.Index) > 2147483647 || mapping[link.Name] != 0 || indices[link.Index] {
			return ErrGuardReadback
		}
		mapping[link.Name] = link.Index
		indices[link.Index] = true
	}
	want, ok := normalizedGuardObjects(expected)
	if !ok {
		return ErrGuardReadback
	}
	got, ok := normalizedGuardObjectsWithInterfaces(observed, mapping)
	if !ok || !reflect.DeepEqual(want, got) {
		return ErrGuardReadback
	}
	return nil
}
func translateGuardIndex(value any, links map[string]int) (any, bool) {
	name, isName := value.(string)
	if !isName {
		return value, true
	}
	index, ok := links[name]
	if !ok {
		return nil, false
	}
	return json.Number(strconv.Itoa(index)), true
}
func translateGuardMatch(expr map[string]any, links map[string]int) bool {
	match, ok := expr["match"].(map[string]any)
	if !ok {
		return true
	}
	left, ok := match["left"].(map[string]any)
	if !ok {
		return true
	}
	meta, ok := left["meta"].(map[string]any)
	if !ok || (meta["key"] != "iif" && meta["key"] != "oif") {
		return true
	}
	// Named set references remain exact semantic values.
	if name, ok := match["right"].(string); ok && len(name) > 0 && name[0] == '@' {
		return true
	}
	if set, ok := match["right"].(map[string]any); ok {
		values, ok := set["set"].([]any)
		if !ok {
			return true
		}
		for i, value := range values {
			converted, ok := translateGuardIndex(value, links)
			if !ok {
				return false
			}
			values[i] = converted
		}
		return true
	}
	converted, ok := translateGuardIndex(match["right"], links)
	if !ok {
		return false
	}
	match["right"] = converted
	return true
}
func translateGuardSet(fields map[string]any, links map[string]int) bool {
	if fields["type"] != "iface_index" {
		return true
	}
	elements, _ := fields["elem"].([]any)
	for _, raw := range elements {
		wrapper, ok := raw.(map[string]any)
		if !ok {
			return false
		}
		element, ok := wrapper["elem"].(map[string]any)
		if !ok {
			return false
		}
		converted, ok := translateGuardIndex(element["val"], links)
		if !ok {
			return false
		}
		element["val"] = converted
	}
	return true
}
