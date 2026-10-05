package sandboxes

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func organizationTestBinding() BoundedRuntimeBinding {
	b := persistentTestBinding()
	b.Admission = "organization"
	b.CreatorID, b.TerminalDeviceID = uuid.Nil, uuid.Nil
	return b
}

func TestOrganizationBindingRequiresExplicitBoundedAdmission(t *testing.T) {
	b := organizationTestBinding()
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if !b.Allows(b.OrgID, uuid.New(), time.Now()) {
			t.Fatal("authorized org identity excluded by deployment creator pin")
		}
	}
	if b.Allows(uuid.New(), uuid.New(), time.Now()) || b.Allows(b.OrgID, uuid.Nil, time.Now()) {
		t.Fatal("foreign or absent identity admitted")
	}
	for _, change := range []func(*BoundedRuntimeBinding){
		func(b *BoundedRuntimeBinding) { b.Admission = "*" },
		func(b *BoundedRuntimeBinding) { b.Mode = "trial" },
		func(b *BoundedRuntimeBinding) { b.CreatorID = uuid.New() },
		func(b *BoundedRuntimeBinding) { b.TerminalDeviceID = uuid.New() },
		func(b *BoundedRuntimeBinding) { b.OrgID = uuid.Nil },
		func(b *BoundedRuntimeBinding) { b.GatewayID = uuid.Nil },
		func(b *BoundedRuntimeBinding) { b.DevReservation = &DevHistoricalReservation{} },
	} {
		copy := b
		change(&copy)
		if copy.Validate() == nil {
			t.Fatal("mixed, wildcard or unscoped deployment accepted")
		}
	}
	device := uuid.New()
	if selected, err := b.terminalDevice(&device); err != nil || selected != device {
		t.Fatal("explicit terminal selection lost", err)
	}
	zero := uuid.Nil
	for _, selection := range []*uuid.UUID{nil, &zero} {
		if _, err := b.terminalDevice(selection); !errors.Is(err, ErrInvalid) {
			t.Fatal("missing terminal selection accepted", err)
		}
	}
	for _, quotas := range [][2]int32{{0, 0}, {1, 1}, {3, 8}} {
		user, total := b.quotas(quotas[0], quotas[1])
		if user > quotas[0] || total > quotas[1] || user > 1 || total > 1 {
			t.Fatal("runtime raised an org quota", quotas, user, total)
		}
	}
}

func TestLegacyBindingSerializationAndTerminalPinsRemainExact(t *testing.T) {
	b := persistentTestBinding()
	// Match the pre-admission struct's field order and names exactly. Empty new
	// fields must not change durable worker pins or require legacy migration.
	legacy := struct {
		RemoteTerminal                          *RemoteTerminalBinding
		Mode                                    string
		Profiles                                []QualifiedRuntimeProfile
		DevReservation                          *DevHistoricalReservation
		OrgID, CreatorID, GatewayID, TemplateID uuid.UUID
		TerminalDeviceID                        uuid.UUID
		ImageDigest                             string
		MemoryMiB, CPUs, PIDs                   int
		MaxTTLSeconds                           int32
		ExpiresAt                               time.Time
	}{b.RemoteTerminal, b.Mode, b.Profiles, b.DevReservation, b.OrgID, b.CreatorID, b.GatewayID, b.TemplateID, b.TerminalDeviceID, b.ImageDigest, b.MemoryMiB, b.CPUs, b.PIDs, b.MaxTTLSeconds, b.ExpiresAt}
	want, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	got, err := json.Marshal(b)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("legacy serialized binding changed", err)
	}
	var restored BoundedRuntimeBinding
	if json.Unmarshal(want, &restored) != nil || !bindingEqual(b, restored) || restored.Validate() != nil {
		t.Fatal("legacy worker pin no longer restores")
	}
	if b.Allows(b.OrgID, uuid.New(), time.Now()) {
		t.Fatal("legacy creator pin widened")
	}
	if device, err := b.terminalDevice(nil); err != nil || device != b.TerminalDeviceID {
		t.Fatal("legacy terminal fallback changed", err)
	}
	other := uuid.New()
	if _, err := b.terminalDevice(&other); !errors.Is(err, ErrForbidden) {
		t.Fatal("legacy terminal pin replaced", err)
	}
}

func TestOrganizationWorkerRetainsIdentityAcrossRestartAndSequentialOwners(t *testing.T) {
	b := organizationTestBinding()
	server, client, _ := persistentRPCFixture(t, b)
	ctx := context.Background()
	a := testAuthorization(b, 0)
	a.CreatorID, a.TerminalDeviceID = uuid.New(), uuid.New()
	if err := client.AuthorizeRuntime(ctx, a); err != nil {
		t.Fatal(err)
	}
	server.active, server.sandboxID = nil, uuid.Nil
	if retired, err := server.CheckRetirement(); err != nil || retired || server.active == nil || !sameWorkload(*server.active, a) {
		t.Fatal("restart lost original creator/device", retired, err)
	}
	for _, change := range []func(*RuntimeAuthorization){
		func(a *RuntimeAuthorization) { a.CreatorID = uuid.New() },
		func(a *RuntimeAuthorization) { a.TerminalDeviceID = uuid.New() },
		func(a *RuntimeAuthorization) { a.OrgID = uuid.New() },
		func(a *RuntimeAuthorization) { a.GatewayID = uuid.New() },
		func(a *RuntimeAuthorization) { a.ExpiresAt = a.ExpiresAt.Add(time.Second) },
		func(a *RuntimeAuthorization) { a.CreatorID = uuid.Nil },
		func(a *RuntimeAuthorization) { a.TerminalDeviceID = uuid.Nil },
	} {
		changed := a
		changed.Generation++
		change(&changed)
		if err := client.AuthorizeRuntime(ctx, changed); err == nil {
			t.Fatal("immutable workload identity changed")
		}
	}
	next := testAuthorization(b, 1)
	next.CreatorID, next.TerminalDeviceID = uuid.New(), uuid.New()
	if err := client.AuthorizeRuntime(ctx, next); err == nil {
		t.Fatal("another owner bypassed retained worker slot")
	}
	changedBinding := b
	changedBinding.Admission = ""
	changedBinding.CreatorID, changedBinding.TerminalDeviceID = a.CreatorID, a.TerminalDeviceID
	server.Binding = changedBinding
	if _, err := server.CheckRetirement(); err == nil {
		t.Fatal("active deployment admission changed without draining")
	}
	server.Binding = b
	a.Generation, a.Desired = 2, "deleted"
	if err := client.AuthorizeRuntime(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := client.Delete(ctx, a.SandboxID); err != nil {
		t.Fatal(err)
	}
	if err := client.RetireRuntime(ctx, a.SandboxID); err != nil {
		t.Fatal(err)
	}
	if err := client.AuthorizeRuntime(ctx, next); err != nil {
		t.Fatal("retirement did not release capacity to next owner", err)
	}
	if _, err := server.dispatch(ctx, workerRequest{Version: workerRPCVersion, Operation: "start", ID: a.SandboxID, Generation: 1}); err == nil {
		t.Fatal("stale original owner started next owner's workload")
	}
}
