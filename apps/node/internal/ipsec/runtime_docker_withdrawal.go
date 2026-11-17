package ipsec

import (
	"context"
	"encoding/json"
	"net/netip"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

// nft retains a deleted interface's numeric index, but iptables-nft-save omits
// that predicate. Such a listing can NEVER qualify a permitting replacement.
// Only an independently journal-proven removal plan may project those exact
// rows out of both views while qualifying every remaining foreign object.
type runtimeDockerWithdrawalView struct {
	rows    []map[string]json.RawMessage
	owned   []any // complete native order, handles and predicates; counters excluded
	lines   []string
	orphans []bool
	count   int
}

func runtimeDockerPermanentRefusal(intent GuardIntent, manifest GuardManifest, prior *runtimeGuardTemplate) bool {
	canonical, ok := canonicalGuard(intent)
	if !ok || prior == nil || prior.Namespace != canonical.Namespace || manifest.OwnerID != canonical.OwnerID || manifest.Namespace != canonical.Namespace || manifest.Revision != canonical.Revision {
		return false
	}
	for _, connection := range canonical.Connections {
		if !connection.PrefixOnly {
			return false
		}
	}
	previous, previousOK := normalizedGuardObjects([]byte(prior.ExpectedJSON))
	next, nextOK := normalizedGuardObjects([]byte(manifest.ExpectedJSON))
	return previousOK && nextOK && legacyCTRefusalsPreserved(previous, next)
}

func runtimeDockerWithdrawalViewForSnapshot(rows []map[string]json.RawMessage, owner uuid.UUID, handles []uint64, links []GuardInterface) (*runtimeDockerWithdrawalView, bool) {
	mapping, indices := map[string]int{}, map[int]bool{}
	for _, link := range links {
		if link.Name == "" || link.Index <= 0 || mapping[link.Name] != 0 || indices[link.Index] {
			return nil, false
		}
		mapping[link.Name], indices[link.Index] = link.Index, true
	}
	// This also rejects any foreign rule after an owned FORWARD tail.
	if _, _, err := runtimeDockerForwardSnapshot(rows, owner, links, true); err != nil {
		return nil, false
	}
	view := &runtimeDockerWithdrawalView{}
	observedHandles := []uint64{}
	for _, row := range rows {
		raw, isRule := row["rule"]
		rule, ok := runtimeDockerForwardObject(raw)
		if !isRule || !ok || rule["family"] != "ip" || rule["table"] != "filter" || rule["chain"] != "FORWARD" || rule["comment"] != runtimeDockerForwardComment+owner.String() {
			view.rows = append(view.rows, row)
			continue
		}
		_, handle, err := runtimeDockerForwardKey(rule, mapping, true)
		clean, cleanOK := runtimeDockerHostClean(raw, false)
		line, lineOK := runtimeDockerHostForwardSave(clean)
		if err != nil || handle == 0 || !cleanOK || !lineOK {
			return nil, false
		}
		orphan := false
		exprs := rule["expr"].([]any)
		for i, flag := range []string{" -i ", " -o "} {
			match := exprs[i].(map[string]any)["match"].(map[string]any)
			name, ok := match["right"].(string)
			if !ok {
				return nil, false
			}
			if mapping[name] != 0 { // a real interface can have a numeric name
				continue
			}
			index, err := strconv.ParseInt(name, 10, 32)
			if err != nil || index <= 0 || strconv.FormatInt(index, 10) != name || indices[int(index)] {
				return nil, false
			}
			// Independently reproduced native behavior: only the missing
			// interface option disappears; every other token remains exact.
			line = strings.Replace(line, flag+name, "", 1)
			orphan = true
		}
		observedHandles = append(observedHandles, handle)
		view.owned = append(view.owned, clean)
		view.lines = append(view.lines, line)
		view.orphans = append(view.orphans, orphan)
		if orphan {
			view.count++
		} else {
			view.rows = append(view.rows, row)
		}
	}
	sort.Slice(observedHandles, func(i, j int) bool { return observedHandles[i] < observedHandles[j] })
	wantHandles := append([]uint64(nil), handles...)
	sort.Slice(wantHandles, func(i, j int) bool { return wantHandles[i] < wantHandles[j] })
	if !reflect.DeepEqual(observedHandles, wantHandles) {
		return nil, false
	}
	return view, true
}

func (v *runtimeDockerWithdrawalView) listing(raw []byte) ([]byte, bool) {
	// Validate the complete bounded listing before projecting exact lines.
	if _, ok := runtimeDockerHostSaveTable(raw, "filter"); !ok {
		return nil, false
	}
	lines := strings.Split(string(raw), "\n")
	positions := []int{}
	for i, line := range lines {
		if strings.HasPrefix(strings.Join(strings.Fields(line), " "), "-A FORWARD ") {
			positions = append(positions, i)
		}
	}
	if len(positions) < len(v.lines) {
		return nil, false
	}
	tail := positions[len(positions)-len(v.lines):]
	for i, position := range tail {
		if strings.Join(strings.Fields(lines[position]), " ") != v.lines[i] {
			return nil, false
		}
	}
	for i, position := range tail {
		if v.orphans[i] {
			lines[position] = ""
		}
	}
	return []byte(strings.Join(lines, "\n")), true
}

func runtimeQualifiedDockerWithdrawalCensusWithCommands(ctx context.Context, nftPath string, view *runtimeDockerWithdrawalView, owner uuid.UUID, handles []uint64, links []GuardInterface, protected []netip.Prefix, run func(context.Context, string, ...string) ([]byte, error)) bool {
	if view == nil || view.count == 0 {
		return false
	}
	fenced := false
	qualified := runtimeQualifiedDockerHostCensus(ctx, nftPath, view.rows, protected, func(c context.Context, path string, args ...string) ([]byte, error) {
		raw, err := run(c, path, args...)
		if err != nil {
			return nil, err
		}
		if filepath.Base(path) == "iptables-nft-save" && reflect.DeepEqual(args, []string{"-t", "filter"}) {
			projected, ok := view.listing(raw)
			if !ok {
				return nil, ErrGuardRead
			}
			return projected, nil
		}
		if path == nftPath && reflect.DeepEqual(args, []string{"-j", "list", "ruleset"}) {
			rows, ok := runtimeCensusRows(raw)
			if !ok {
				return nil, ErrGuardRead
			}
			after, ok := runtimeDockerWithdrawalViewForSnapshot(rows, owner, handles, links)
			if !ok || !reflect.DeepEqual(view.owned, after.owned) || !reflect.DeepEqual(view.lines, after.lines) || !reflect.DeepEqual(view.orphans, after.orphans) {
				return nil, ErrGuardRead
			}
			fenced = true
			return json.Marshal(map[string]any{"nftables": after.rows})
		}
		return raw, nil
	})
	return qualified && fenced
}

func (a *RuntimeGuard) qualifyDockerWithdrawal(ctx context.Context, namespace string, view *runtimeDockerWithdrawalView, plan *runtimeDockerForwardPlan, links []GuardInterface, protected []netip.Prefix) bool {
	current := func() bool {
		ns, err := a.reader.namespace()
		if err != nil || ns != namespace {
			return false
		}
		observed, err := a.reader.interfaces()
		if err != nil {
			return false
		}
		expected := append([]GuardInterface(nil), links...)
		sort.Slice(observed, func(i, j int) bool { return observed[i].Index < observed[j].Index })
		sort.Slice(expected, func(i, j int) bool { return expected[i].Index < expected[j].Index })
		return reflect.DeepEqual(observed, expected) && ctx.Err() == nil
	}
	return current() && runtimeQualifiedDockerWithdrawalCensusWithCommands(ctx, a.dockerNFT, view, plan.owner, plan.remove, links, protected, runKernelCommand) && current()
}
