package ipsec

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func recoveryDiagnosticEvents(events []RuntimeDiagnostic, operation string) []RuntimeDiagnostic {
	var out []RuntimeDiagnostic
	for _, event := range events {
		if event.Operation == operation {
			out = append(out, event)
		}
	}
	return out
}

func TestRecoveryDiagnosticApplyHoldKeepsDenialAndHistory(t *testing.T) {
	r := newRecoveryTestRig(t)
	var events []RuntimeDiagnostic
	r.c.config.Diagnostic = func(event RuntimeDiagnostic) { events = append(events, event) }
	before, _ := r.c.journal.Entries()
	if r.apply() == nil {
		t.Fatal("initial down evidence must remain refused")
	}
	selected := recoveryDiagnosticEvents(events, "recovery_apply")
	if len(selected) != 1 || !selected[0].Refused || selected[0].Stage != "recovery_hold" || selected[0].ContextState != "active" || selected[0].ConnectionID != r.m.Manifest.ConnectionID {
		t.Fatalf("opaque hold diagnostic: %+v", selected)
	}
	after, _ := r.c.journal.Entries()
	if !reflect.DeepEqual(before, after) || r.switches != 0 || len(r.c.active) != 0 || r.c.recoveryHistory[r.m.Manifest.ConnectionID] == nil {
		t.Fatal("diagnostic changed hold/denial/history")
	}
}

func TestRecoveryDiagnosticRefreshSuccessPreservesExactNativeAuthority(t *testing.T) {
	r := newRecoveryTestRig(t)
	r.status = [2]string{"up", "up"}
	if err := r.apply(); err != nil {
		t.Fatal(err)
	}
	refreshDeniedFixture(t, r)
	before, _ := r.c.journal.Entries()
	active := r.c.active[r.m.Manifest.ConnectionID]
	writes := len(r.events)
	switches := r.switches
	r.c.client = &refreshLeaseFixture{}
	r.status = [2]string{"down", "up"}
	r.now = 5 * time.Second
	var events []RuntimeDiagnostic
	r.c.config.Diagnostic = func(event RuntimeDiagnostic) { events = append(events, event) }
	if err := r.c.RefreshIPsecRecovery(context.Background()); err != nil {
		t.Fatal(err)
	}
	selected := recoveryDiagnosticEvents(events, "recovery_refresh")
	if len(selected) != 1 || selected[0].Refused || selected[0].Stage != "recovery_advice" || selected[0].ContextState != "active" {
		t.Fatalf("completed refresh mislabeled: %+v", selected)
	}
	after, _ := r.c.journal.Entries()
	current := r.c.active[r.m.Manifest.ConnectionID]
	if !reflect.DeepEqual(before, after) || current.Authority != active.Authority || current.Identity != active.Identity || len(r.events) != writes || r.switches != switches {
		t.Fatal("passive refresh changed permissions,route,authority or journal")
	}
}

func TestRecoveryDiagnosticRefreshForeignGuardRefusalKeepsOriginalWithdrawal(t *testing.T) {
	r := newRecoveryTestRig(t)
	r.status = [2]string{"up", "up"}
	if err := r.apply(); err != nil {
		t.Fatal(err)
	}
	raw := refreshDeniedFixture(t, r)
	*raw = []byte(`{"nftables":[{"table":{"family":"inet","name":"tunnex_ipsec"}}]}`)
	r.now = 5 * time.Second
	r.status = [2]string{"down", "up"}
	r.c.client = &refreshLeaseFixture{}
	before, _ := r.c.journal.Entries()
	writes := len(r.events)
	switches := r.switches
	var events []RuntimeDiagnostic
	r.c.config.Diagnostic = func(event RuntimeDiagnostic) { events = append(events, event) }
	if r.c.RefreshIPsecRecovery(context.Background()) == nil || r.c.recoveryHistory[r.m.Manifest.ConnectionID] != nil {
		t.Fatal("existing refusal/history invalidation changed")
	}
	denial := recoveryDiagnosticEvents(events, "recovery_guard_denial")
	refresh := recoveryDiagnosticEvents(events, "recovery_refresh")
	if len(denial) != 1 || denial[0].Stage != "guard_prior_ownership" || !denial[0].Refused || denial[0].ContextState != "active" || len(refresh) != 1 || refresh[0].Stage != "guard_denial_read" || !refresh[0].Refused {
		t.Fatalf("foreign guard cause remains opaque: denial=%+v refresh=%+v", denial, refresh)
	}
	after, _ := r.c.journal.Entries()
	if !reflect.DeepEqual(before, after) || len(r.events) != writes || r.switches != switches {
		t.Fatal("diagnostic performed authority writes")
	}
}

func TestRecoveryDiagnosticNativeChildDeadlineKeepsParentActive(t *testing.T) {
	r := newRecoveryTestRig(t)
	r.status = [2]string{"up", "up"}
	if err := r.apply(); err != nil {
		t.Fatal(err)
	}
	refreshDeniedFixture(t, r)
	entries, _ := r.c.journal.Entries()
	before, _ := r.c.journal.Entries()
	writes := len(r.events)
	r.c.guard.reader.run = func(ctx context.Context, _ ...string) ([]byte, error) { <-ctx.Done(); return nil, ctx.Err() }
	var events []RuntimeDiagnostic
	r.c.config.Diagnostic = func(event RuntimeDiagnostic) { events = append(events, event) }
	parent := context.Background()
	_, err := r.c.recoveryGuardDenials(parent, entries)
	if !errors.Is(err, ErrGuardReadback) || parent.Err() != nil {
		t.Fatal("child cancellation changed parent or refusal")
	}
	denial := recoveryDiagnosticEvents(events, "recovery_guard_denial")
	if len(denial) != 1 || denial[0].Stage != "guard_table_read" || denial[0].ContextState != "deadline" || !denial[0].Refused || denial[0].ElapsedMillis < 4900 || denial[0].ConnectionID != r.m.Manifest.ConnectionID {
		t.Fatalf("real bounded child timeout mislabeled: %+v", denial)
	}
	after, _ := r.c.journal.Entries()
	if !reflect.DeepEqual(before, after) || len(r.events) != writes {
		t.Fatal("diagnostic wrote runtime")
	}
}

func TestRecoveryDiagnosticUnknownNativeDoesNotExposeErrorBody(t *testing.T) {
	r := newRecoveryTestRig(t)
	r.status = [2]string{"unknown", "up"}
	var events []RuntimeDiagnostic
	r.c.config.Diagnostic = func(event RuntimeDiagnostic) { events = append(events, event) }
	if r.apply() == nil {
		t.Fatal("unknown transport must refuse")
	}
	observed := recoveryDiagnosticEvents(events, "recovery_observe")
	if len(observed) != 1 || observed[0].Stage != "native_status" || !observed[0].Refused {
		t.Fatalf("unknown native observation opaque: %+v", observed)
	}
	for _, event := range events {
		if !validRuntimeDiagnostic(event.Operation, event.Stage) || strings.Contains(event.Stage, "password") || event.ElapsedMillis < 0 {
			t.Fatal("unsafe diagnostic shape")
		}
	}
	beforeInvalid := len(events)
	r.c.emitRuntimeDiagnostic(context.Background(), "recovery_apply", "PSK=private", r.m.Manifest.ConnectionID, time.Now(), true)
	if len(events) != beforeInvalid {
		t.Fatal("invalid label escaped allowlist")
	}
}
