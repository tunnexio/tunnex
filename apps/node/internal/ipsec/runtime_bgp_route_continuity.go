package ipsec

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"reflect"
	"time"
)

// A selected-path switch is not a permission change when the complete remote
// prefix set is unchanged. Callers still prove both exact encrypted paths.
func sameBGPRoutePrefixes(before, after []RuntimeBGPRouteTuple) bool {
	if len(before) == 0 || len(before) != len(after) {
		return false
	}
	for i := range before {
		if before[i].Prefix != after[i].Prefix {
			return false
		}
	}
	return true
}

func (c *RuntimeController) canPreserveBGPRouteSwitch(a runtimeActive, target []RuntimeBGPRouteTuple, health [2]string) bool {
	e := a.Entry
	if e.ContractVersion != 3 || e.Allocation.ProfileID != "" || !e.Allocation.BGP || !validBGPRoutes(e) || e.BGPRoutes == nil || e.BGPRoutes.Stage != "completed" || !sameBGPRoutePrefixes(e.BGPRoutes.Owned, target) || health != [2]string{"up", "up"} {
		return false
	}
	marked := false
	for _, g := range a.Grants {
		if g.FQDNManaged {
			if g.FQDN.Version != 2 {
				return false
			}
			marked = true
		}
	}
	// This window is only an extra scheduling bound. Authority and actual native
	// membership are independently proved below; the window can never grant access.
	w, ok := c.fqdnNativeWindows[e.Allocation.ConnectionID]
	return marked && ok && reflect.DeepEqual(w.owner, a) && w.deadline-c.recoveryNow() > 5*time.Second
}

// Prove the existing native guard already permits both exact tunnel interfaces
// and reqids, and every retained FQDN member has enough actual finite runway.
// It does not render, replace, or renew any native permission.
func (c *RuntimeController) proveBGPRouteSwitchGuard(ctx context.Context, a runtimeActive, reserve uint64) error {
	templates, _, err := c.journal.guardTemplates()
	if err != nil || len(templates) != 1 || templates[0].Namespace != a.Entry.Allocation.Namespace || c.guard == nil || c.guard.reader == nil {
		return ErrRuntimeController
	}
	template := templates[0]
	objects, ok := normalizedGuardObjects([]byte(template.ExpectedJSON))
	if !ok {
		return ErrRuntimeController
	}
	id := a.Entry.Allocation.ConnectionID
	required := map[string][]string{
		guardLeaseName(id):      {fmt.Sprint(a.Entry.Observed[0].InterfaceIndex), fmt.Sprint(a.Entry.Observed[1].InterfaceIndex)},
		guardReplyLeaseName(id): {fmt.Sprint(a.Entry.Observed[0].InterfaceIndex), fmt.Sprint(a.Entry.Observed[1].InterfaceIndex)},
		guardSALeaseName(id):    {fmt.Sprint(a.Entry.Engines[0].ReqID), fmt.Sprint(a.Entry.Engines[1].ReqID)},
	}
	for _, g := range a.Grants {
		if g.FQDNManaged {
			required[guardFQDNSetName(g)] = []string{g.Destination.Addr().String()}
		}
	}
	seen := map[string]bool{}
	for _, o := range objects {
		s, ok := o.(map[string]any)["set"].(map[string]any)
		if !ok {
			continue
		}
		name, _ := s["name"].(string)
		values, needed := required[name]
		if !needed {
			continue
		}
		elements, ok := s["elem"].([]any)
		if !ok || len(elements) != len(values) {
			return ErrRuntimeController
		}
		for _, value := range values {
			found := false
			for _, raw := range elements {
				wrapper, ok := raw.(map[string]any)
				if !ok {
					return ErrRuntimeController
				}
				elem, ok := wrapper["elem"].(map[string]any)
				if !ok {
					return ErrRuntimeController
				}
				found = found || fmt.Sprint(elem["val"]) == value
			}
			if !found {
				return ErrRuntimeController
			}
		}
		seen[name] = true
	}
	if len(seen) != len(required) {
		return ErrRuntimeController
	}
	return c.guard.reader.check(ctx, GuardManifest{Namespace: template.Namespace, ExpectedJSON: template.ExpectedJSON}, func(expected, observed []byte, links []GuardInterface) error {
		if VerifyGuardReadbackWithInterfaces(expected, observed, links) != nil {
			return ErrGuardRead
		}
		var envelope struct {
			Objects []map[string]json.RawMessage `json:"nftables"`
		}
		if json.Unmarshal(observed, &envelope) != nil {
			return ErrGuardRead
		}
		found := map[string]bool{}
		for _, o := range envelope.Objects {
			var s struct {
				Name     string `json:"name"`
				Elements []struct {
					Element map[string]any `json:"elem"`
				} `json:"elem"`
			}
			dec := json.NewDecoder(bytes.NewReader(o["set"]))
			dec.UseNumber()
			if dec.Decode(&s) != nil {
				continue
			}
			if _, needed := required[s.Name]; !needed {
				continue
			}
			if len(s.Elements) == 0 {
				return ErrGuardRead
			}
			for _, v := range s.Elements {
				seconds, ok := guardPositiveSeconds(v.Element["expires"])
				if !ok || seconds <= reserve {
					return ErrGuardRead
				}
			}
			found[s.Name] = true
		}
		if len(found) != len(required) {
			return ErrGuardRead
		}
		return nil
	})
}

func (c *RuntimeController) preserveBGPRouteSwitch(ctx context.Context, entries []RuntimeJournalEntry, original runtimeActive, target []RuntimeBGPRouteTuple) ([]RuntimeJournalEntry, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	original = cloneMaintenanceActive(original)
	id := original.Entry.Allocation.ConnectionID
	process := c.bgpProcesses[original.Entry.DeliveryID]
	templates, _, templateErr := c.journal.guardTemplates()
	var captured runtimeGuardTemplate
	if templateErr == nil && len(templates) == 1 && templates[0].Namespace == original.Entry.Allocation.Namespace {
		captured = templates[0]
	}
	fail := func() ([]RuntimeJournalEntry, error) {
		c.withdrawDNSOwnerView(id)
		delete(c.active, id)
		// Validate also uses this reconciler and does not have maintenance's failure
		// wrapper. Refusal must finish even if the route transaction's deadline ended.
		denialCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if _, err := c.refuse(denialCtx, entries); err != nil && captured.Namespace != "" {
			if c.guard.withdrawConnectionCaptured(denialCtx, captured, id) == nil {
				// The journal retains its original pending/possibly-completed duties.
				// Stopping this known process is separate from claiming durable cleanup.
				if process != nil && process.Close() == nil {
					delete(c.bgpProcesses, original.Entry.DeliveryID)
				}
			}
		}
		return nil, ErrRuntimeController
	}
	current := func() error {
		a, ok := c.active[id]
		if ctx.Err() != nil || !ok || !reflect.DeepEqual(a, original) || !c.qualification.current() || c.config.DaemonAlive == nil || !c.config.DaemonAlive() || process == nil || c.bgpProcesses[original.Entry.DeliveryID] != process || !process.Alive() || !c.fqdnGrantsCurrent(original.Grants) {
			return ErrRuntimeController
		}
		if _, err := original.Authority.RemainingForApply(original.Identity, 5*time.Second); err != nil {
			return err
		}
		for _, g := range original.Grants {
			if g.FQDNManaged {
				if !g.FQDN.ExpiresAt.After(time.Now()) {
					return ErrRuntimeController
				}
				if _, err := original.Authority.RemainingFQDNForApply(original.Identity, guardFQDNGrantDigest(g), 5*time.Second); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if captured.Namespace == "" || current() != nil || c.proveCurrent(ctx, original.Entry, original.Environment) != nil || c.proveDesktopGrants(ctx, original.Grants) != nil || c.proveBGPRouteSwitchGuard(ctx, original, 5) != nil || current() != nil {
		return fail()
	}
	if reconcileBGPRoutesPermitMode(ctx, c.journal, c.kernel, original.Entry.DeliveryID.String(), target, current, true) != nil || current() != nil {
		return fail()
	}
	latest, err := c.journal.Entries()
	if err != nil {
		return fail()
	}
	next := original
	found := false
	for _, e := range latest {
		if e.DeliveryID == original.Entry.DeliveryID {
			expected := copyDNSEntry(original.Entry)
			expected.BGPRoutes = e.BGPRoutes
			if !reflect.DeepEqual(e, expected) || e.BGPRoutes == nil || e.BGPRoutes.Stage != "completed" || !reflect.DeepEqual(e.BGPRoutes.Owned, target) {
				return fail()
			}
			next.Entry = e
			found = true
		}
	}
	// Re-read the selected RIB and transport state after the route operation.
	// A second change is not adopted or retried inside this continuity window.
	status, statusErr := process.Observe(ctx)
	if statusErr != nil {
		return fail()
	}
	routes, routeErr := process.ObserveRoutes(ctx, status)
	if routeErr != nil {
		return fail()
	}
	health := c.observeRecovery(ctx, next.Entry)
	selected := []RuntimeBGPRouteTuple{}
	for _, r := range routes {
		if r.Slot >= 1 && r.Slot <= 2 {
			selected = append(selected, RuntimeBGPRouteTuple{Prefix: r.Prefix, Slot: uint8(r.Slot), InterfaceIndex: next.Entry.Observed[r.Slot-1].InterfaceIndex, Table: 254, Protocol: 242, Metric: 50000 + uint32(r.Slot)})
		}
	}
	if statusErr != nil || routeErr != nil || health != [2]string{"up", "up"} || !reflect.DeepEqual(selected, target) {
		return fail()
	}
	if !found || c.proveCurrent(ctx, next.Entry, next.Environment) != nil || c.proveDesktopGrants(ctx, next.Grants) != nil || c.proveBGPRouteSwitchGuard(ctx, next, 0) != nil || current() != nil {
		return fail()
	}
	c.active[id] = next
	if window, ok := c.fqdnNativeWindows[id]; ok && reflect.DeepEqual(window.owner, original) {
		window.owner = next
		c.fqdnNativeWindows[id] = window
	}
	return latest, nil
}

// A route-only maintenance continuation retains no observed native state. It
// proves that the bounded reconciler changed only this owner's exact route
// checkpoint, while the complete native guard and all original authorities
// stayed untouched. The normal fresh lease and final installer remain required.
func (c *RuntimeController) bgpRouteSwitchMaintenanceCurrent(id uuid.UUID, before map[uuid.UUID]runtimeActive, entries []RuntimeJournalEntry, templates []runtimeGuardTemplate) ([]RuntimeJournalEntry, bool) {
	old, known := before[id]
	after, present := c.active[id]
	if !known || !present || len(before) != len(c.active) || old.Entry.BGPRoutes == nil || after.Entry.BGPRoutes == nil || after.Entry.BGPRoutes.Stage != "completed" || reflect.DeepEqual(old.Entry.BGPRoutes, after.Entry.BGPRoutes) || !sameBGPRoutePrefixes(old.Entry.BGPRoutes.Owned, after.Entry.BGPRoutes.Owned) {
		return nil, false
	}
	expected := cloneMaintenanceActive(old)
	expected.Entry.BGPRoutes = after.Entry.BGPRoutes
	if !reflect.DeepEqual(expected, after) {
		return nil, false
	}
	for ownerID, original := range before {
		if ownerID != id && !reflect.DeepEqual(original, c.active[ownerID]) {
			return nil, false
		}
	}
	currentTemplates, _, err := c.journal.guardTemplates()
	if err != nil || len(templates) != 1 || !reflect.DeepEqual(templates, currentTemplates) {
		return nil, false
	}
	latest, err := c.journal.Entries()
	if err != nil || len(latest) != len(entries) {
		return nil, false
	}
	found := false
	for i, e := range entries {
		if e.DeliveryID == old.Entry.DeliveryID {
			if found || !reflect.DeepEqual(e, old.Entry) {
				return nil, false
			}
			found = true
			e = copyDNSEntry(e)
			e.BGPRoutes = after.Entry.BGPRoutes
		}
		if !reflect.DeepEqual(e, latest[i]) {
			return nil, false
		}
	}
	return latest, found
}
