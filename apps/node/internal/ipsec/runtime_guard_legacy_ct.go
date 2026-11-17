package ipsec

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

// This compatibility proof authorizes only replacement by permanent refusal.
// It never changes a saved template or the ordinary positive/withdrawal readers.
// nft 1.1.6 compiled the old related-ICMP untyped original daddr /16 and /24
// into a shifted scalar host. Other lengths are deliberately not inferred.
func verifyLegacyCTGuardRefusal(candidate runtimeGuardTemplate, intent GuardIntent, refusal GuardManifest, observed []byte, links []GuardInterface) error {
	canonical, ok := canonicalGuard(intent)
	if !ok || candidate.Namespace != intent.Namespace {
		return ErrGuardReadback
	}
	for _, connection := range canonical.Connections {
		if !connection.PrefixOnly {
			return ErrGuardReadback
		}
	}
	want, ok := normalizedGuardObjects([]byte(candidate.ExpectedJSON))
	if !ok {
		return ErrGuardReadback
	}
	denial, ok := normalizedGuardObjects([]byte(refusal.ExpectedJSON))
	if !ok || !legacyCTRefusalsPreserved(want, denial) {
		return ErrGuardReadback
	}
	owner := fmt.Sprintf("tunnex-ipsec:%s:%d:%s", intent.OwnerID, candidate.Revision, candidate.Digest)
	owners, changed := 0, 0
	for _, raw := range want {
		object := raw.(map[string]any)
		if chain, ok := object["chain"].(map[string]any); ok && chain["name"] == "owner" {
			if chain["comment"] != owner {
				return ErrGuardReadback
			}
			owners++
		}
		rule, ok := object["rule"].(map[string]any)
		if !ok {
			continue
		}
		exprs, _ := rule["expr"].([]any)
		for _, expr := range exprs {
			right, match := legacyCTMatch(expr, "==", guardOriginalCT("daddr", ""))
			prefix, valid := legacyCTPrefix(right)
			if !match || !valid || (prefix.Bits() != 16 && prefix.Bits() != 24) {
				continue
			}
			if !legacyCTRelatedRule(rule) {
				return ErrGuardReadback
			}
			// Native proof covers /16 and /24 independently, including a
			// second /24 network. Do not apply this to /25, /31 or hosts.
			address := prefix.Addr().As4()
			binary.BigEndian.PutUint32(address[:], binary.BigEndian.Uint32(address[:])>>uint(32-prefix.Bits()))
			expr.(map[string]any)["match"].(map[string]any)["right"] = netip.AddrFrom4(address).String()
			changed++
		}
	}
	if owners != 1 || changed == 0 {
		return ErrGuardReadback
	}
	_, err := verifyGuardWithdrawalObjectsSnapshot(want, observed, links)
	return err
}

// Preserve every existing drop independent of a possibly vanished interface:
// protected prefixes, NAT tuple refusals and BGP peer denials. Merely having no
// accepts is insufficient if the replacement omits a former protected prefix.
func legacyCTRefusalsPreserved(prior, next []any) bool {
	denials := map[string]bool{}
	for _, raw := range next {
		if set, ok := raw.(map[string]any)["set"].(map[string]any); ok {
			if members, _ := set["elem"].([]any); len(members) != 0 {
				return false
			}
		}
		if rule, ok := raw.(map[string]any)["rule"].(map[string]any); ok {
			exprs, _ := rule["expr"].([]any)
			if len(exprs) == 0 || !reflect.DeepEqual(exprs[len(exprs)-1], map[string]any{"drop": nil}) {
				return false
			}
			encoded, _ := json.Marshal(rule)
			denials[string(encoded)] = true
		}
	}
	count := 0
	for _, raw := range prior {
		rule, ok := raw.(map[string]any)["rule"].(map[string]any)
		if !ok {
			continue
		}
		exprs, _ := rule["expr"].([]any)
		if len(exprs) == 0 || !reflect.DeepEqual(exprs[len(exprs)-1], map[string]any{"drop": nil}) {
			continue
		}
		interfaceBound := false
		for _, rawExpr := range exprs {
			expr, _ := rawExpr.(map[string]any)
			match, _ := expr["match"].(map[string]any)
			left, _ := match["left"].(map[string]any)
			_, meta := left["meta"]
			interfaceBound = interfaceBound || meta
		}
		if interfaceBound {
			continue
		}
		encoded, _ := json.Marshal(rule)
		if !denials[string(encoded)] {
			return false
		}
		count++
	}
	return count > 0
}

// Reconstruct the complete old related-ICMP recipe, including exact source,
// router, original parent tuple, ports and reply set. No generic CT rewriting.
func legacyCTRelatedRule(rule map[string]any) bool {
	exprs, ok := rule["expr"].([]any)
	if !ok || len(rule) != 4 || rule["family"] != "inet" || rule["table"] != "tunnex_ipsec" {
		return false
	}
	offset := 1
	if rule["chain"] == "forward_guard" {
		offset = 2
	} else if rule["chain"] != "input_guard" {
		return false
	}
	if len(exprs) != offset+13 {
		return false
	}
	iif, ok := legacyCTIndex(exprs[0], "iif")
	if !ok {
		return false
	}
	oif := 0
	if offset == 2 {
		oif, ok = legacyCTIndex(exprs[1], "oif")
		if !ok {
			return false
		}
	}
	routerValue, routerMatch := legacyCTMatch(exprs[offset], "==", guardPayload("ip", "saddr"))
	router, routerOK := legacyCTPrefix(routerValue)
	sourceValue, sourceMatch := legacyCTMatch(exprs[offset+1], "==", guardPayload("ip", "daddr"))
	source, sourceOK := legacyCTPrefix(sourceValue)
	destinationValue, destinationMatch := legacyCTMatch(exprs[offset+8], "==", guardOriginalCT("daddr", ""))
	destination, destinationOK := legacyCTPrefix(destinationValue)
	if !routerMatch || !routerOK || !sourceMatch || !sourceOK || source.Bits() != 32 || !destinationMatch || !destinationOK || (destination.Bits() != 16 && destination.Bits() != 24) {
		return false
	}
	port, ok := legacyCTMatch(exprs[offset+9], "==", guardOriginalCT("proto-dst", ""))
	if !ok {
		return false
	}
	low, high, ok := legacyCTPorts(port)
	if !ok {
		return false
	}
	lease, ok := legacyCTMatch(exprs[offset+10], "==", guardMeta("iif"))
	name, stringOK := lease.(string)
	if !ok || !stringOK || !strings.HasPrefix(name, "@reply_lease_") {
		return false
	}
	id, err := uuid.Parse(strings.TrimPrefix(name, "@reply_lease_"))
	if err != nil || id == uuid.Nil || name != "@"+guardReplyLeaseName(id) {
		return false
	}
	rebuilt := guardRemoteFragmentNeeded(GuardConnection{ID: id}, GuardGrant{Source: source, Destination: destination, Protocol: GuardTCP, PortLow: low, PortHigh: high}, iif, oif, router).expr
	encoded, err := json.Marshal(rebuilt)
	if err != nil {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var expected []any
	if decoder.Decode(&expected) != nil {
		return false
	}
	for _, raw := range expected {
		expr := raw.(map[string]any)
		if _, counter := expr["counter"]; counter {
			expr["counter"] = nil
		}
		if !translateGuardMatch(expr, nil, false) {
			return false
		}
	}
	expected[offset+8].(map[string]any)["match"].(map[string]any)["left"] = guardOriginalCT("daddr", "")
	return reflect.DeepEqual(exprs, expected)
}

func legacyCTMatch(value any, op string, left any) (any, bool) {
	expr, ok := value.(map[string]any)
	if !ok || len(expr) != 1 {
		return nil, false
	}
	match, ok := expr["match"].(map[string]any)
	if !ok || len(match) != 3 || match["op"] != op || !reflect.DeepEqual(match["left"], left) {
		return nil, false
	}
	return match["right"], true
}

func legacyCTIndex(value any, key string) (int, bool) {
	right, ok := legacyCTMatch(value, "==", guardMeta(key))
	number, numberOK := right.(json.Number)
	index, err := strconv.ParseInt(string(number), 10, 32)
	return int(index), ok && numberOK && err == nil && index > 0
}

func legacyCTPrefix(value any) (netip.Prefix, bool) {
	if text, ok := value.(string); ok {
		address, err := netip.ParseAddr(text)
		return netip.PrefixFrom(address, 32), err == nil && address.Is4() && address.String() == text
	}
	object, ok := value.(map[string]any)
	prefix, prefixOK := object["prefix"].(map[string]any)
	text, textOK := prefix["addr"].(string)
	bits, bitsOK := prefix["len"].(json.Number)
	length, err := strconv.Atoi(string(bits))
	address, addrErr := netip.ParseAddr(text)
	p := netip.PrefixFrom(address, length)
	return p, ok && len(object) == 1 && prefixOK && len(prefix) == 2 && textOK && bitsOK && err == nil && addrErr == nil && address.Is4() && address.String() == text && length > 0 && length <= 32 && p == p.Masked()
}

func legacyCTPorts(value any) (uint16, uint16, bool) {
	parse := func(v any) (uint16, bool) {
		n, ok := v.(json.Number)
		p, err := strconv.ParseUint(string(n), 10, 16)
		return uint16(p), ok && err == nil && p > 0
	}
	if low, ok := parse(value); ok {
		return low, low, true
	}
	object, ok := value.(map[string]any)
	values, valuesOK := object["range"].([]any)
	if !ok || len(object) != 1 || !valuesOK || len(values) != 2 {
		return 0, 0, false
	}
	low, lowOK := parse(values[0])
	high, highOK := parse(values[1])
	return low, high, lowOK && highOK && low < high
}
