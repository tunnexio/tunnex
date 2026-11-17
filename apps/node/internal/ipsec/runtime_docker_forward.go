package ipsec

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

const runtimeDockerForwardComment = "tunnex-ipsec-fwd:"

// These are structural forwarding exceptions, not authority. Every tuple is
// copied from a fully rendered forward grant, whose earlier inet guard retains
// its protocol, port, interface, SA and native expiring-set checks. A refused or
// expired guard therefore still drops traffic even if Docker's exception remains.
// Appending to FORWARD, after Docker's jumps, preserves DOCKER-USER denies.
type runtimeDockerForwardPlan struct {
	owner   uuid.UUID
	rules   []map[string]any
	remove  []uint64
	foreign string
}

// runtimeDockerForwardRule is shared with the independent host census. The
// marker alone proves nothing: both interfaces and both IPv4 prefixes are
// mandatory, and no other statement or verdict is admitted.
func runtimeDockerForwardRule(raw map[string]json.RawMessage) bool {
	encoded, err := json.Marshal(raw)
	if err != nil {
		return false
	}
	o, ok := runtimeDockerForwardObject(encoded)
	if !ok || o["family"] != "ip" || o["table"] != "filter" || o["chain"] != "FORWARD" {
		return false
	}
	for key := range o {
		if key != "family" && key != "table" && key != "chain" && key != "expr" && key != "comment" && key != "handle" {
			return false
		}
	}
	if h, exists := o["handle"]; exists && !guardCounterNumber(h) {
		return false
	}
	comment, _ := o["comment"].(string)
	id, err := uuid.Parse(strings.TrimPrefix(comment, runtimeDockerForwardComment))
	if err != nil || id == uuid.Nil || comment != runtimeDockerForwardComment+id.String() {
		return false
	}
	exprs, ok := o["expr"].([]any)
	if !ok || len(exprs) != 6 {
		return false
	}
	for i, key := range []string{"iif", "oif", "saddr", "daddr"} {
		expr, ok := exprs[i].(map[string]any)
		if !ok || len(expr) != 1 {
			return false
		}
		match, ok := expr["match"].(map[string]any)
		if !ok || len(match) != 3 || match["op"] != "==" {
			return false
		}
		left := guardPayload("ip", key)
		if i < 2 {
			left = guardMeta(key)
			if !runtimeDockerForwardInterface(match["right"]) {
				return false
			}
		} else if !runtimeDockerForwardPrefix(match["right"]) {
			return false
		}
		if !reflect.DeepEqual(match["left"], left) {
			return false
		}
	}
	counter, ok := exprs[4].(map[string]any)
	if !ok || len(counter) != 1 {
		return false
	}
	value, exists := counter["counter"]
	if !exists {
		return false
	}
	if value != nil {
		counts, ok := value.(map[string]any)
		if !ok || len(counts) != 2 || !guardCounterNumber(counts["packets"]) || !guardCounterNumber(counts["bytes"]) {
			return false
		}
	}
	return reflect.DeepEqual(exprs[5], map[string]any{"accept": nil})
}

func runtimeDockerForwardInterface(value any) bool {
	if n, ok := value.(json.Number); ok {
		v, err := strconv.ParseUint(n.String(), 10, 31)
		return err == nil && v > 0
	}
	name, ok := value.(string)
	if !ok || name == "" || len(name) > 15 {
		return false
	}
	for _, ch := range name {
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '_' || ch == '-' || ch == '.' || ch == ':') {
			return false
		}
	}
	return name != "." && name != ".."
}

func runtimeDockerForwardPrefix(value any) bool {
	if text, ok := value.(string); ok {
		addr, err := netip.ParseAddr(text)
		return err == nil && addr.Is4() && addr.String() == text
	}
	object, ok := value.(map[string]any)
	if !ok || len(object) != 1 {
		return false
	}
	p, ok := object["prefix"].(map[string]any)
	if !ok || len(p) != 2 {
		return false
	}
	text, _ := p["addr"].(string)
	bits, ok := p["len"].(json.Number)
	length, err := strconv.Atoi(string(bits))
	addr, addrErr := netip.ParseAddr(text)
	return ok && err == nil && addrErr == nil && addr.Is4() && length > 0 && length <= 32 && addr.String() == text && netip.PrefixFrom(addr, length).Masked().Addr() == addr
}

func runtimeDockerForwardObject(raw []byte) (map[string]any, bool) {
	var o map[string]any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if d.Decode(&o) != nil || o == nil {
		return nil, false
	}
	return o, true
}

// Structural tuples are extracted from the trusted guard renderer, never a
// live firewall or persisted lease. Host-origin and refusal rules produce none.
func runtimeDockerForwardRules(expected string, owner uuid.UUID) ([]map[string]any, error) {
	rows, ok := runtimeCensusRows([]byte(expected))
	if !ok || owner == uuid.Nil {
		return nil, ErrGuardRead
	}
	unique := map[string]map[string]any{}
	for _, row := range rows {
		raw, exists := row["rule"]
		if !exists {
			continue
		}
		o, ok := runtimeDockerForwardObject(raw)
		if !ok {
			return nil, ErrGuardRead
		}
		if o["chain"] != "forward_guard" {
			continue
		}
		exprs, ok := o["expr"].([]any)
		if !ok || len(exprs) == 0 {
			return nil, ErrGuardRead
		}
		if !reflect.DeepEqual(exprs[len(exprs)-1], map[string]any{"accept": nil}) {
			continue
		}
		if len(exprs) < 6 {
			return nil, ErrGuardRead
		}
		rule := map[string]any{"family": "ip", "table": "filter", "chain": "FORWARD", "comment": runtimeDockerForwardComment + owner.String(), "expr": append(append([]any{}, exprs[:4]...), map[string]any{"counter": nil}, map[string]any{"accept": nil})}
		encoded, _ := json.Marshal(rule)
		var rawRule map[string]json.RawMessage
		if json.Unmarshal(encoded, &rawRule) != nil || !runtimeDockerForwardRule(rawRule) {
			return nil, ErrGuardRead
		}
		key, _, err := runtimeDockerForwardKey(rule, nil, false)
		if err != nil {
			return nil, err
		}
		unique[key] = rule
	}
	keys := make([]string, 0, len(unique))
	for key := range unique {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]map[string]any, 0, len(keys))
	for _, key := range keys {
		out = append(out, unique[key])
	}
	return out, nil
}

func runtimeDockerForwardKey(rule map[string]any, links map[string]int, withdrawal bool) (string, uint64, error) {
	encoded, err := json.Marshal(rule)
	if err != nil {
		return "", 0, ErrGuardRead
	}
	copy, ok := runtimeDockerForwardObject(encoded)
	if !ok {
		return "", 0, ErrGuardRead
	}
	var handle uint64
	if value, exists := copy["handle"]; exists {
		n, ok := value.(json.Number)
		if !ok {
			return "", 0, ErrGuardRead
		}
		handle, err = strconv.ParseUint(n.String(), 10, 64)
		if err != nil || handle == 0 {
			return "", 0, ErrGuardRead
		}
		delete(copy, "handle")
	}
	exprs, ok := copy["expr"].([]any)
	if !ok {
		return "", 0, ErrGuardRead
	}
	for _, value := range exprs {
		expr, ok := value.(map[string]any)
		if !ok || !translateGuardMatch(expr, links, withdrawal) {
			return "", 0, ErrGuardRead
		}
		if _, exists := expr["counter"]; exists {
			expr["counter"] = nil
		}
	}
	encoded, err = json.Marshal(copy)
	if err != nil {
		return "", 0, ErrGuardRead
	}
	return string(encoded), handle, nil
}

func (a *RuntimeGuard) prepareDockerForward(ctx context.Context, manifest GuardManifest, prior *runtimeGuardTemplate, links []GuardInterface, intent GuardIntent) (*runtimeDockerForwardPlan, error) {
	if a.dockerNFT == "" { // existing injected non-native owners retain their seam
		return nil, nil
	}
	raw, err := a.reader.run(ctx, "-j", "list", "ruleset")
	if err != nil {
		return nil, ErrGuardRead
	}
	rows, ok := runtimeCensusRows(raw)
	if !ok {
		return nil, ErrGuardRead
	}
	present := false
	for _, row := range rows {
		if table, ok := kernelObject(row["table"]); ok {
			family, _ := kernelString(table, "family")
			name, _ := kernelString(table, "name")
			present = present || family == "ip" && name == "filter"
		}
	}
	if !present {
		return nil, nil
	}
	// The qualified census independently verifies Docker's complete native and
	// iptables views. A name-only or partly recognized foreign table is refused.
	protected := append([]netip.Prefix(nil), intent.RefusalPrefixes...)
	for _, connection := range intent.Connections {
		protected = append(protected, connection.Local...)
		protected = append(protected, connection.Remote...)
	}
	plan, err := runtimeDockerForwardPlanForSnapshot(manifest, prior, rows, links)
	if err != nil {
		return nil, err
	}
	if len(plan.rules) == 0 && runtimeDockerPermanentRefusal(intent, manifest, prior) {
		view, ok := runtimeDockerWithdrawalViewForSnapshot(rows, manifest.OwnerID, plan.remove, links)
		if ok && view.count > 0 {
			if !a.qualifyDockerWithdrawal(ctx, manifest.Namespace, view, plan, links, protected) {
				return nil, ErrGuardRead
			}
			return plan, nil
		}
	}
	if !runtimeQualifiedHookCensus(ctx, a.dockerNFT, raw, protected) {
		return nil, ErrGuardRead
	}
	return plan, nil
}

func runtimeDockerForwardPlanForSnapshot(manifest GuardManifest, prior *runtimeGuardTemplate, rows []map[string]json.RawMessage, links []GuardInterface) (*runtimeDockerForwardPlan, error) {
	rules, err := runtimeDockerForwardRules(manifest.ExpectedJSON, manifest.OwnerID)
	if err != nil {
		return nil, err
	}
	allowed := map[string]bool{}
	if prior != nil {
		previous, e := runtimeDockerForwardRules(prior.ExpectedJSON, manifest.OwnerID)
		if e != nil {
			return nil, e
		}
		for _, rule := range previous {
			key, _, e := runtimeDockerForwardKey(rule, nil, false)
			if e != nil {
				return nil, e
			}
			allowed[key] = true
		}
	}
	plan := &runtimeDockerForwardPlan{owner: manifest.OwnerID, rules: rules}
	current, foreign, err := runtimeDockerForwardSnapshot(rows, manifest.OwnerID, links, true)
	if err != nil {
		return nil, err
	}
	for key, handles := range current {
		if !allowed[key] {
			return nil, ErrGuardRead
		}
		plan.remove = append(plan.remove, handles...)
	}
	sort.Slice(plan.remove, func(i, j int) bool { return plan.remove[i] < plan.remove[j] })
	plan.foreign = foreign
	return plan, nil
}

func runtimeDockerForwardSnapshot(rows []map[string]json.RawMessage, owner uuid.UUID, links []GuardInterface, withdrawal bool) (map[string][]uint64, string, error) {
	mapping := map[string]int{}
	for _, link := range links {
		mapping[link.Name] = link.Index
	}
	current := map[string][]uint64{}
	foreign := []any{}
	ownedTail := false
	for _, row := range rows {
		for kind, raw := range row {
			o, ok := runtimeDockerForwardObject(raw)
			if !ok || o["family"] != "ip" || kind == "table" && o["name"] != "filter" || kind != "table" && o["table"] != "filter" {
				continue
			}
			comment, _ := o["comment"].(string)
			if kind == "rule" && strings.HasPrefix(comment, runtimeDockerForwardComment) {
				fields, ok := kernelObject(raw)
				if !ok || !runtimeDockerForwardRule(fields) || comment != runtimeDockerForwardComment+owner.String() {
					return nil, "", ErrGuardRead
				}
				key, handle, err := runtimeDockerForwardKey(o, mapping, withdrawal)
				if err != nil || handle == 0 {
					return nil, "", ErrGuardRead
				}
				current[key] = append(current[key], handle)
				ownedTail = true
				continue
			}
			if kind == "rule" && o["chain"] == "FORWARD" && ownedTail {
				// Structural accepts must never run before a foreign policy rule.
				return nil, "", ErrGuardRead
			}
			if exprs, ok := o["expr"].([]any); ok {
				for _, expr := range exprs {
					if object, ok := expr.(map[string]any); ok {
						if _, exists := object["counter"]; exists {
							object["counter"] = nil
						}
					}
				}
			}
			foreign = append(foreign, map[string]any{kind: o})
		}
	}
	encoded, err := json.Marshal(foreign)
	if err != nil {
		return nil, "", ErrGuardRead
	}
	return current, string(encoded), nil
}

func (p *runtimeDockerForwardPlan) transaction(guard string) (string, error) {
	var doc struct {
		NFTables []any `json:"nftables"`
	}
	if json.Unmarshal([]byte(guard), &doc) != nil || doc.NFTables == nil {
		return "", ErrGuardRead
	}
	for _, handle := range p.remove {
		doc.NFTables = append(doc.NFTables, map[string]any{"delete": map[string]any{"rule": map[string]any{"family": "ip", "table": "filter", "chain": "FORWARD", "handle": handle}}})
	}
	for _, rule := range p.rules {
		doc.NFTables = append(doc.NFTables, map[string]any{"add": map[string]any{"rule": rule}})
	}
	encoded, err := json.Marshal(doc)
	if err != nil || len(encoded) > kernelDumpLimit {
		return "", ErrGuardRead
	}
	return string(encoded), nil
}

func (a *RuntimeGuard) checkDockerForward(ctx context.Context, plan *runtimeDockerForwardPlan, links []GuardInterface) error {
	raw, err := a.reader.run(ctx, "-j", "list", "table", "ip", "filter")
	if err != nil {
		return ErrGuardRead
	}
	rows, ok := runtimeCensusRows(raw)
	if !ok {
		return ErrGuardRead
	}
	current, foreign, err := runtimeDockerForwardSnapshot(rows, plan.owner, links, false)
	if err != nil || foreign != plan.foreign || len(current) != len(plan.rules) {
		return ErrGuardRead
	}
	for _, rule := range plan.rules {
		key, _, err := runtimeDockerForwardKey(rule, nil, false)
		if err != nil || len(current[key]) != 1 {
			return ErrGuardRead
		}
	}
	return nil
}
