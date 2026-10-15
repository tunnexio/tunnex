package ipsec

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os/exec"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// VerifyGuardWithdrawal proves only that the prior rendered objects still have
// their exact known structure and no widened set members. Expired members may
// disappear. It is NEVER a permit receipt, lease renewal or cleanup receipt.
func VerifyGuardWithdrawal(expected, observed []byte, links []GuardInterface) error {
	_, err := verifyGuardWithdrawalSnapshot(expected, observed, links)
	return err
}

// The returned intent belongs only to this readback; retain positive members.
func verifyGuardWithdrawalSnapshot(expected, observed []byte, links []GuardInterface) ([]any, error) {
	want, ok := normalizedGuardObjects(expected)
	if !ok {
		return nil, ErrGuardReadback
	}
	return verifyGuardWithdrawalObjectsSnapshot(want, observed, links)
}

// want is locally normalized from the exact expected bytes for this read only.
func verifyGuardWithdrawalObjectsSnapshot(want []any, observed []byte, links []GuardInterface) ([]any, error) {
	return verifyGuardWithdrawalObjectsSnapshotClass(want, observed, links, nil)
}

func verifyGuardWithdrawalObjectsSnapshotClass(want []any, observed []byte, links []GuardInterface, classify func(string)) ([]any, error) {
	return verifyGuardOwnershipObjectsSnapshotClass(want, observed, links, classify, true)
}

// Positive per-connection proof may tolerate another connection's expired
// members, but must not inherit withdrawal-only orphaned-interface parsing.
func verifyGuardOwnershipObjectsSnapshotClass(want []any, observed []byte, links []GuardInterface, classify func(string), allowOrphanedIndex bool) ([]any, error) {
	mark := func(value string) {
		if classify != nil {
			classify(value)
		}
	}
	mark("interface_mapping")
	mapping := map[string]int{}
	indices := map[int]bool{}
	for _, l := range links {
		if l.Name == "" || l.Index <= 0 || mapping[l.Name] != 0 || indices[l.Index] {
			return nil, ErrGuardReadback
		}
		mapping[l.Name] = l.Index
		indices[l.Index] = true
	}
	got, ok := normalizedGuardObservedObjectsWithOrphans(observed, mapping, true, allowOrphanedIndex)
	if !ok {
		mark("observed_invalid")
		return nil, ErrGuardReadback
	}
	if len(want) != len(got) {
		mark("object_count")
		return nil, ErrGuardReadback
	}
	for i, w := range want {
		wf := w.(map[string]any)
		gf := got[i].(map[string]any)
		ws, isSet := wf["set"].(map[string]any)
		if !isSet {
			if !reflect.DeepEqual(wf, gf) {
				if classify != nil {
					mark(guardNonsetMismatchClass(wf, gf))
				}
				return nil, ErrGuardReadback
			}
			continue
		}
		gs, ok := gf["set"].(map[string]any)
		if !ok {
			mark("set_metadata_mismatch")
			return nil, ErrGuardReadback
		}
		allowed := map[string]any{}
		if elems, ok := ws["elem"].([]any); ok {
			for _, v := range elems {
				e := v.(map[string]any)["elem"].(map[string]any)
				allowed[guardSetMemberKey(e["val"])] = v
			}
		}
		if elems, ok := gs["elem"].([]any); ok {
			for _, v := range elems {
				e := v.(map[string]any)["elem"].(map[string]any)
				if !reflect.DeepEqual(allowed[guardSetMemberKey(e["val"])], v) {
					mark("set_member_mismatch")
					return nil, ErrGuardReadback
				}
			}
		}
		// Compare metadata without erasing the original expected positive members.
		wantMetadata, gotMetadata := map[string]any{}, map[string]any{}
		for k, v := range ws {
			if k != "elem" {
				wantMetadata[k] = v
			}
		}
		for k, v := range gs {
			if k != "elem" {
				gotMetadata[k] = v
			}
		}
		if !reflect.DeepEqual(wantMetadata, gotMetadata) {
			mark("set_metadata_mismatch")
			return nil, ErrGuardReadback
		}
	}
	return want, nil
}

// Classifies already-compared normalized objects only; never supplies authority.
func guardNonsetMismatchClass(want, got map[string]any) string {
	for _, kind := range []string{"table", "chain", "rule"} {
		w, ok := want[kind].(map[string]any)
		if !ok {
			continue
		}
		g, ok := got[kind].(map[string]any)
		if !ok {
			return "nonset_kind_mismatch"
		}
		if kind != "chain" || w["name"] != "owner" || g["name"] != "owner" {
			return kind + "_mismatch"
		}
		wm, gm := map[string]any{}, map[string]any{}
		for k, v := range w {
			if k != "comment" {
				wm[k] = v
			}
		}
		for k, v := range g {
			if k != "comment" {
				gm[k] = v
			}
		}
		if !reflect.DeepEqual(wm, gm) {
			return "owner_structure_mismatch"
		}
		wc, wok := w["comment"].(string)
		gc, gok := g["comment"].(string)
		wp, gp := strings.Split(wc, ":"), strings.Split(gc, ":")
		if !wok || !gok || len(wp) != 4 || len(gp) != 4 || wp[0] != "tunnex-ipsec" || gp[0] != wp[0] || wp[1] != gp[1] {
			return "owner_comment_mismatch"
		}
		wr, we := strconv.ParseInt(wp[2], 10, 64)
		gr, ge := strconv.ParseInt(gp[2], 10, 64)
		if we != nil || ge != nil || wr <= 0 || gr <= 0 || !validDigest(wp[3]) || !validDigest(gp[3]) {
			return "owner_comment_mismatch"
		}
		if wp[2] != gp[2] && wp[3] != gp[3] {
			return "owner_revision_digest_mismatch"
		}
		if wp[2] != gp[2] {
			return "owner_revision_mismatch"
		}
		if wp[3] != gp[3] {
			return "owner_digest_mismatch"
		}
		return "owner_comment_mismatch"
	}
	return "nonset_mismatch"
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
	if matched != nil {
		m.NFTJSON, e = replaceOwnedFQDNSets(m.NFTJSON, matched.ExpectedJSON)
		if e != nil {
			return fail()
		}
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
