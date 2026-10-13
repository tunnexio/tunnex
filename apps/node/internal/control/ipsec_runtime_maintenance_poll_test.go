package control

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/node/internal/ipsec"
)

// Retaining the passed batch slice checks that the poll-owned material is cleared
// on return, including rejection and fallback. Transport fixture copies are separate.
type maintenancePollFake struct {
	runtimePollFake
	items                     []ipsec.RuntimePending
	materials                 map[uuid.UUID]ipsec.RuntimeMaterial
	passedMaterials           []ipsec.RuntimeMaterial
	applyCount, maintainCount int
	events                    []string
	change                    func([]ipsec.RuntimeMaintenanceResult) ([]ipsec.RuntimeMaintenanceResult, error)
	afterAck                  func()
}

func newMaintenancePollFake(t *testing.T) *maintenancePollFake {
	t.Helper()
	f := &maintenancePollFake{materials: map[uuid.UUID]ipsec.RuntimeMaterial{}}
	for range 2 {
		item := ipsec.RuntimePending{ConnectionID: uuid.New(), DesiredRevision: 2, Kind: "apply"}
		f.item = item
		m, _ := f.runtimePollFake.IPsecMaterial(context.Background(), item.ConnectionID, 2)
		m.OwnershipDigest = "synthetic-owned-delivery"
		m.Secrets = [2]ipsec.RuntimeSecret{{PSK: "synthetic-private-test-value"}}
		f.items = append(f.items, item)
		f.materials[item.ConnectionID] = m
	}
	return f
}
func (f *maintenancePollFake) IPsecPending(context.Context, *uuid.UUID, int) (ipsec.RuntimePendingPage, error) {
	return ipsec.RuntimePendingPage{Items: f.items}, nil
}
func (f *maintenancePollFake) IPsecMaterial(_ context.Context, id uuid.UUID, _ int64) (ipsec.RuntimeMaterial, error) {
	f.events = append(f.events, "material")
	return f.materials[id], nil
}
func (f *maintenancePollFake) IPsecCleanup(_ context.Context, id uuid.UUID, revision int64) (ipsec.RuntimeCleanup, error) {
	return ipsec.RuntimeCleanup{RuntimeDelivery: ipsec.RuntimeDelivery{ID: uuid.New(), Kind: "cleanup", DesiredRevision: revision, Manifest: ipsec.RuntimeManifest{ConnectionID: id, DesiredRevision: revision - 1}}}, nil
}
func (f *maintenancePollFake) Cleanup(_ context.Context, m ipsec.RuntimeCleanup) (ipsec.RuntimeAcknowledgement, error) {
	f.events = append(f.events, "cleanup")
	return ipsec.RuntimeAcknowledgement{DeliveryID: m.ID, Kind: "cleanup", DesiredRevision: m.DesiredRevision, Result: "cleaned"}, nil
}
func (f *maintenancePollFake) Apply(ctx context.Context, m ipsec.RuntimeMaterial) (ipsec.RuntimeAcknowledgement, error) {
	f.applyCount++
	f.events = append(f.events, "apply")
	return f.runtimePollFake.Apply(ctx, m)
}
func (f *maintenancePollFake) IPsecReportStatus(ctx context.Context, id uuid.UUID, r ipsec.RuntimeStatusReport) error {
	f.events = append(f.events, "report")
	return f.runtimePollFake.IPsecReportStatus(ctx, id, r)
}
func (f *maintenancePollFake) IPsecAcknowledge(ctx context.Context, id uuid.UUID, a ipsec.RuntimeAcknowledgement) error {
	f.events = append(f.events, "ack")
	err := f.runtimePollFake.IPsecAcknowledge(ctx, id, a)
	if f.afterAck != nil {
		f.afterAck()
	}
	return err
}
func (f *maintenancePollFake) MaintainIPsecRuntime(ctx context.Context, materials []ipsec.RuntimeMaterial) ([]ipsec.RuntimeMaintenanceResult, error) {
	f.passedMaterials = materials
	f.maintainCount++
	f.events = append(f.events, "maintain")
	var results []ipsec.RuntimeMaintenanceResult
	for _, m := range materials {
		r, _ := f.runtimePollFake.ObserveIPsecStatus(ctx, m.RuntimeDelivery)
		results = append(results, ipsec.RuntimeMaintenanceResult{Acknowledgement: ipsec.RuntimeAcknowledgement{DeliveryID: m.ID, Kind: "apply", Result: "applied", DesiredRevision: m.DesiredRevision, OwnershipDigest: m.OwnershipDigest}, Report: r})
	}
	if f.change != nil {
		return f.change(results)
	}
	return results, nil
}
func assertMaintenanceSecretsCleared(t *testing.T, f *maintenancePollFake) {
	t.Helper()
	if len(f.passedMaterials) == 0 {
		t.Fatal("maintenance material boundary was not exercised")
	}
	for _, m := range f.passedMaterials {
		for _, s := range m.Secrets {
			if s.PSK != "" {
				t.Fatal("fetched private material survived polling")
			}
		}
	}
}

func TestIPsecMaintenancePollPreservesObservationAndRepairsAcknowledgement(t *testing.T) {
	f := newMaintenancePollFake(t)
	f.reportFailure = true
	validated, err := PollIPsecRuntimeValidated(context.Background(), f, f)
	if err == nil || validated || f.acks != 2 || len(f.reports) != 2 || f.applyCount != 0 || f.maintainCount != 1 {
		t.Fatal("completed maintenance did not preserve telemetry/ACK semantics")
	}
	for _, r := range f.reports {
		if r.Tunnels[0].Status != "unknown" || r.Tunnels[1].Status != "down" {
			t.Fatal("maintenance invented transport health")
		}
	}
	assertMaintenanceSecretsCleared(t, f)
}

func TestIPsecMaintenancePollFallbackAndCleanupPriority(t *testing.T) {
	f := newMaintenancePollFake(t)
	f.items = append(f.items, ipsec.RuntimePending{ConnectionID: uuid.New(), DesiredRevision: 3, Kind: "cleanup"})
	f.change = func(r []ipsec.RuntimeMaintenanceResult) ([]ipsec.RuntimeMaintenanceResult, error) { return r[:1], nil }
	validated, err := PollIPsecRuntimeValidated(context.Background(), f, f)
	if err != nil || !validated || f.acks != 3 || f.applyCount != 1 || len(f.reports) != 2 || f.maintainCount != 1 || len(f.events) == 0 || f.events[0] != "cleanup" {
		t.Fatal("cleanup priority or omitted-delivery normal Apply lost", err)
	}
	assertMaintenanceSecretsCleared(t, f)
}

func TestIPsecMaintenancePollRejectsWholeMalformedResultBeforePublication(t *testing.T) {
	cases := map[string]func([]ipsec.RuntimeMaintenanceResult) ([]ipsec.RuntimeMaintenanceResult, error){
		"duplicate": func(r []ipsec.RuntimeMaintenanceResult) ([]ipsec.RuntimeMaintenanceResult, error) {
			r[1] = r[0]
			return r, nil
		},
		"unknown delivery": func(r []ipsec.RuntimeMaintenanceResult) ([]ipsec.RuntimeMaintenanceResult, error) {
			r[1].Acknowledgement.DeliveryID = uuid.New()
			return r, nil
		},
		"revision": func(r []ipsec.RuntimeMaintenanceResult) ([]ipsec.RuntimeMaintenanceResult, error) {
			r[1].Acknowledgement.DesiredRevision++
			return r, nil
		},
		"digest": func(r []ipsec.RuntimeMaintenanceResult) ([]ipsec.RuntimeMaintenanceResult, error) {
			r[1].Acknowledgement.OwnershipDigest = "foreign"
			return r, nil
		},
		"report identity": func(r []ipsec.RuntimeMaintenanceResult) ([]ipsec.RuntimeMaintenanceResult, error) {
			r[1].Report.DeliveryID = uuid.New()
			return r, nil
		},
		"partial failure": func(r []ipsec.RuntimeMaintenanceResult) ([]ipsec.RuntimeMaintenanceResult, error) {
			return r[:1], errors.New("refused")
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			f := newMaintenancePollFake(t)
			f.change = change
			validated, err := PollIPsecRuntimeValidated(context.Background(), f, f)
			if err == nil || validated || f.acks != 0 || len(f.reports) != 0 || f.applyCount != 0 {
				t.Fatal("malformed batch published partial success")
			}
			assertMaintenanceSecretsCleared(t, f)
		})
	}
}

func TestIPsecMaintenancePollCancellationAndEmptyPassRequireValidation(t *testing.T) {
	f := newMaintenancePollFake(t)
	ctx, cancel := context.WithCancel(context.Background())
	f.change = func(r []ipsec.RuntimeMaintenanceResult) ([]ipsec.RuntimeMaintenanceResult, error) {
		cancel()
		return r, nil
	}
	validated, err := PollIPsecRuntimeValidated(ctx, f, f)
	if err == nil || validated || f.acks != 0 || len(f.reports) != 0 {
		t.Fatal("cancelled maintenance accepted")
	}
	assertMaintenanceSecretsCleared(t, f)
	f = newMaintenancePollFake(t)
	f.items = nil
	validated, err = PollIPsecRuntimeValidated(context.Background(), f, f)
	if err != nil || validated || f.maintainCount != 0 {
		t.Fatal("empty poll bypassed independent validation")
	}
}

func TestIPsecMaintenancePollPublishesBeforeFallbackChangesRuntime(t *testing.T) {
	f := newMaintenancePollFake(t)
	// The first item needs Apply; the later item's maintained result must be sent first.
	f.change = func(r []ipsec.RuntimeMaintenanceResult) ([]ipsec.RuntimeMaintenanceResult, error) { return r[1:], nil }
	validated, err := PollIPsecRuntimeValidated(context.Background(), f, f)
	if err != nil || !validated || f.acks != 2 || f.applyCount != 1 {
		t.Fatal("mixed renewal failed", err)
	}
	firstReport, firstAck, firstApply := -1, -1, -1
	for i, event := range f.events {
		if event == "report" && firstReport < 0 {
			firstReport = i
		}
		if event == "ack" && firstAck < 0 {
			firstAck = i
		}
		if event == "apply" && firstApply < 0 {
			firstApply = i
		}
	}
	if firstReport < 0 || firstAck <= firstReport || firstApply <= firstAck {
		t.Fatal("cached maintenance published after fallback changed runtime")
	}
	assertMaintenanceSecretsCleared(t, f)
}

func TestIPsecMaintenancePollLastRPCCancellationRequiresValidation(t *testing.T) {
	f := newMaintenancePollFake(t)
	ctx, cancel := context.WithCancel(context.Background())
	f.afterAck = func() {
		if f.acks == 2 {
			cancel()
		}
	}
	validated, err := PollIPsecRuntimeValidated(ctx, f, f)
	if err == nil || validated || f.acks != 2 {
		t.Fatal("last RPC cancellation bypassed validation")
	}
	assertMaintenanceSecretsCleared(t, f)
}
