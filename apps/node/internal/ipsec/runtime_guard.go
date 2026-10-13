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

	"github.com/google/uuid"
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
	got, ok := normalizedGuardWithdrawalObjectsWithInterfaces(observed, mapping)
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
	diagnostic func(RuntimeDiagnostic)
	mu         sync.Mutex
	journal    *RuntimeJournal
	reader     *GuardReader
	apply      func(context.Context, []byte) error
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
func (a *RuntimeGuard) Replace(ctx context.Context, intent GuardIntent) (manifestResult GuardManifest, resultErr error) {
	fail := func() (GuardManifest, error) { return GuardManifest{}, ErrGuardRead }
	if a == nil || a.journal == nil || a.reader == nil || a.apply == nil {
		return fail()
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, kernelReadTimeout)
	defer cancel()
	stage := "guard_render"
	started := time.Now()
	defer func() {
		emitRuntimeDiagnostic(a.diagnostic, ctx, "guard_replace", stage, uuid.Nil, started, resultErr != nil)
	}()
	m, e := RenderGuard(intent)
	if e != nil {
		return fail()
	}
	stage = "guard_namespace"
	before, e := a.reader.namespace()
	if e != nil || before != m.Namespace {
		return fail()
	}
	stage = "guard_interfaces"
	links, e := a.reader.interfaces()
	if e != nil {
		return fail()
	}
	stage = "guard_table_read"
	tables, e := a.reader.run(ctx, "-j", "list", "tables")
	if e != nil {
		return fail()
	}
	present, e := guardTablePresent(tables)
	if e != nil {
		return fail()
	}
	stage = "journal_inventory"
	templates, _, e := a.journal.guardTemplates()
	if e != nil {
		return fail()
	}
	var matched *runtimeGuardTemplate
	stage = "guard_prior_ownership"
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
	stage = "guard_source_bracket"
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
	stage = "guard_resolve_journal"
	if e = a.journal.resolveGuardOwnership(matched); e != nil {
		return fail()
	}
	stage = "guard_prepare_journal"
	if e = a.journal.prepareGuard(m); e != nil {
		return fail()
	}
	stage = "guard_atomic_replace"
	if e = a.apply(ctx, []byte(m.NFTJSON)); e != nil || ctx.Err() != nil {
		return fail()
	}
	stage = "guard_complete_readback"
	if e = a.reader.Check(ctx, m); e != nil || ctx.Err() != nil {
		return fail()
	}
	stage = "guard_finish_journal"
	if e = a.journal.finishGuard(m); e != nil {
		return fail()
	}
	return m, nil
}

// withdrawConnection only removes the exact owner's three permit sets. The
// current trusted template remains valid for withdrawal; no member is added or
// renewed and other owners retain their original native deadlines.
func (a *RuntimeGuard) withdrawConnection(ctx context.Context, namespace string, id uuid.UUID) error {
	if a == nil || a.journal == nil || a.reader == nil || a.apply == nil || id == uuid.Nil {
		return ErrGuardRead
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, kernelReadTimeout)
	defer cancel()
	templates, _, err := a.journal.guardTemplates()
	if err != nil || len(templates) != 1 || templates[0].Namespace != namespace {
		return ErrGuardRead
	}
	template := templates[0]
	manifest := GuardManifest{Namespace: namespace, ExpectedJSON: template.ExpectedJSON}
	names := map[string]bool{guardLeaseName(id): true, guardReplyLeaseName(id): true, guardSALeaseName(id): true}
	verify := func(expected, observed []byte, links []GuardInterface, empty bool) error {
		if VerifyGuardWithdrawal(expected, observed, links) != nil {
			return ErrGuardReadback
		}
		mapping := map[string]int{}
		for _, link := range links {
			mapping[link.Name] = link.Index
		}
		objects, ok := normalizedGuardWithdrawalObjectsWithInterfaces(observed, mapping)
		if !ok {
			return ErrGuardReadback
		}
		found := 0
		for _, object := range objects {
			if set, ok := object.(map[string]any)["set"].(map[string]any); ok && names[set["name"].(string)] {
				found++
				if members, ok := set["elem"].([]any); empty && ok && len(members) != 0 {
					return ErrGuardReadback
				}
			}
		}
		if found != 3 {
			return ErrGuardReadback
		}
		return nil
	}
	if a.reader.check(ctx, manifest, func(e, o []byte, links []GuardInterface) error { return verify(e, o, links, false) }) != nil {
		return ErrGuardRead
	}
	current, _, err := a.journal.guardTemplates()
	if err != nil || !reflect.DeepEqual(current, templates) || ctx.Err() != nil {
		return ErrGuardRead
	}
	transaction := []any{}
	for _, name := range []string{guardLeaseName(id), guardReplyLeaseName(id), guardSALeaseName(id)} {
		transaction = append(transaction, map[string]any{"flush": map[string]any{"set": map[string]any{"family": "inet", "table": "tunnex_ipsec", "name": name}}})
	}
	raw, err := json.Marshal(map[string]any{"nftables": transaction})
	if err != nil || a.apply(ctx, raw) != nil || ctx.Err() != nil {
		return ErrGuardRead
	}
	if a.reader.check(ctx, manifest, func(e, o []byte, links []GuardInterface) error { return verify(e, o, links, true) }) != nil {
		return ErrGuardRead
	}
	current, _, err = a.journal.guardTemplates()
	if err != nil || !reflect.DeepEqual(current, templates) || ctx.Err() != nil {
		return ErrGuardRead
	}
	return nil
}
