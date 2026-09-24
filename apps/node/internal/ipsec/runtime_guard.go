package ipsec

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os/exec"
	"reflect"
	"sort"
	"sync"
	"time"
)

// VerifyGuardWithdrawal proves only that the prior rendered objects still have
// their exact known structure and no widened set members. Expired members may
// disappear. It is NEVER a permit receipt, lease renewal or cleanup receipt.
func VerifyGuardWithdrawal(expected, observed []byte, links []GuardInterface) error {
	mapping := map[string]int{}
	indices := map[int]bool{}
	for _, l := range links {
		if l.Name == "" || l.Index <= 0 || mapping[l.Name] != 0 || indices[l.Index] {
			return ErrGuardReadback
		}
		mapping[l.Name] = l.Index
		indices[l.Index] = true
	}
	want, ok := normalizedGuardObjects(expected)
	if !ok {
		return ErrGuardReadback
	}
	got, ok := normalizedGuardObjectsWithInterfaces(observed, mapping)
	if !ok || len(want) != len(got) {
		return ErrGuardReadback
	}
	for i, w := range want {
		wf := w.(map[string]any)
		gf := got[i].(map[string]any)
		ws, isSet := wf["set"].(map[string]any)
		if !isSet {
			if !reflect.DeepEqual(wf, gf) {
				return ErrGuardReadback
			}
			continue
		}
		gs, ok := gf["set"].(map[string]any)
		if !ok {
			return ErrGuardReadback
		}
		allowed := map[string]any{}
		if elems, ok := ws["elem"].([]any); ok {
			for _, v := range elems {
				e := v.(map[string]any)["elem"].(map[string]any)
				allowed[e["val"].(json.Number).String()] = v
			}
		}
		if elems, ok := gs["elem"].([]any); ok {
			for _, v := range elems {
				e := v.(map[string]any)["elem"].(map[string]any)
				if !reflect.DeepEqual(allowed[e["val"].(json.Number).String()], v) {
					return ErrGuardReadback
				}
			}
		}
		delete(ws, "elem")
		delete(gs, "elem")
		if !reflect.DeepEqual(ws, gs) {
			return ErrGuardReadback
		}
	}
	return nil
}

// RuntimeGuard owns only the journal-bound inet table. The journal stores prior
// semantic templates for withdrawal, never authority to reinstall their permits.
type RuntimeGuard struct {
	mu      sync.Mutex
	journal *RuntimeJournal
	reader  *GuardReader
	apply   func(context.Context, []byte) error
}

func NewRuntimeGuard(j *RuntimeJournal, nftPath string) (*RuntimeGuard, error) {
	if j == nil {
		return nil, ErrGuardRead
	}
	r, e := NewGuardReader(nftPath)
	if e != nil {
		return nil, e
	}
	return &RuntimeGuard{journal: j, reader: r, apply: func(ctx context.Context, data []byte) error {
		cmd := exec.CommandContext(ctx, nftPath, "-j", "-f", "-")
		cmd.Stdin = bytes.NewReader(data)
		cmd.Stderr = io.Discard
		var out kernelOutput
		cmd.Stdout = &out
		cmd.WaitDelay = 250 * time.Millisecond
		if cmd.Run() != nil || ctx.Err() != nil {
			return ErrGuardRead
		}
		return nil
	}}, nil
}
func guardTablePresent(raw []byte) (bool, error) {
	if len(raw) > kernelDumpLimit {
		return false, ErrGuardRead
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if !kernelJSONValue(d, 0) {
		return false, ErrGuardRead
	}
	if _, e := d.Token(); e != io.EOF {
		return false, ErrGuardRead
	}
	var env struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&env) != nil || env.NFTables == nil || len(env.NFTables) > kernelEntryLimit {
		return false, ErrGuardRead
	}
	found := false
	for _, obj := range env.NFTables {
		if len(obj) != 1 {
			return false, ErrGuardRead
		}
		if _, ok := obj["metainfo"]; ok {
			continue
		}
		table, ok := obj["table"]
		if !ok {
			return false, ErrGuardRead
		}
		var t struct{ Family, Name string }
		if json.Unmarshal(table, &t) != nil || t.Family == "" || t.Name == "" {
			return false, ErrGuardRead
		}
		if t.Family == "inet" && t.Name == "tunnex_ipsec" {
			if found {
				return false, ErrGuardRead
			}
			found = true
		}
	}
	return found, nil
}

// Replace serializes, verifies exact previous ownership (including expired
// member subsets), fsyncs potential replacement BEFORE mutation, then requires
// the unchanged strict complete readback before committing the new template.
func (a *RuntimeGuard) Replace(ctx context.Context, intent GuardIntent) (GuardManifest, error) {
	fail := func() (GuardManifest, error) { return GuardManifest{}, ErrGuardRead }
	if a == nil || a.journal == nil || a.reader == nil || a.apply == nil {
		return fail()
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, kernelReadTimeout)
	defer cancel()
	m, e := RenderGuard(intent)
	if e != nil {
		return fail()
	}
	before, e := a.reader.namespace()
	if e != nil || before != m.Namespace {
		return fail()
	}
	links, e := a.reader.interfaces()
	if e != nil {
		return fail()
	}
	tables, e := a.reader.run(ctx, "-j", "list", "tables")
	if e != nil {
		return fail()
	}
	present, e := guardTablePresent(tables)
	if e != nil {
		return fail()
	}
	templates, _, e := a.journal.guardTemplates()
	if e != nil {
		return fail()
	}
	var matched *runtimeGuardTemplate
	if present {
		actual, e := a.reader.run(ctx, "-j", "list", "table", "inet", "tunnex_ipsec")
		if e != nil {
			return fail()
		}
		for _, candidate := range templates {
			if candidate.Namespace == before && VerifyGuardWithdrawal([]byte(candidate.ExpectedJSON), actual, links) == nil {
				copy := candidate
				matched = &copy
				break
			}
		}
		if matched == nil {
			return fail()
		}
	}
	afterLinks, e := a.reader.interfaces()
	if e != nil {
		return fail()
	}
	after, e := a.reader.namespace()
	if e != nil || after != before || ctx.Err() != nil {
		return fail()
	}
	sort.Slice(links, func(i, j int) bool { return links[i].Index < links[j].Index })
	sort.Slice(afterLinks, func(i, j int) bool { return afterLinks[i].Index < afterLinks[j].Index })
	if !reflect.DeepEqual(links, afterLinks) {
		return fail()
	}
	// Resolve an interrupted atomic replacement to the independently observed
	// candidate before reserving a successor. No packet permit is inferred here.
	if e = a.journal.resolveGuardOwnership(matched); e != nil {
		return fail()
	}
	if e = a.journal.prepareGuard(m); e != nil {
		return fail()
	}
	if e = a.apply(ctx, []byte(m.NFTJSON)); e != nil || ctx.Err() != nil {
		return fail()
	}
	if e = a.reader.Check(ctx, m); e != nil || ctx.Err() != nil {
		return fail()
	}
	if e = a.journal.finishGuard(m); e != nil {
		return fail()
	}
	return m, nil
}
