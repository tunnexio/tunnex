package control

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/node/internal/ipsec"
	"testing"
)

type runtimePollFake struct {
	item          ipsec.RuntimePending
	acks          int
	failure       bool
	reports       []ipsec.RuntimeStatusReport
	reportFailure bool
}

func (f *runtimePollFake) IPsecPending(context.Context, *uuid.UUID, int) (ipsec.RuntimePendingPage, error) {
	return ipsec.RuntimePendingPage{Items: []ipsec.RuntimePending{f.item}}, nil
}
func (f *runtimePollFake) IPsecMaterial(context.Context, uuid.UUID, int64) (ipsec.RuntimeMaterial, error) {
	return ipsec.RuntimeMaterial{RuntimeDelivery: ipsec.RuntimeDelivery{ID: uuid.New(), Kind: "apply", DesiredRevision: f.item.DesiredRevision, Manifest: ipsec.RuntimeManifest{ConnectionID: f.item.ConnectionID, DesiredRevision: f.item.DesiredRevision}}}, nil
}
func (f *runtimePollFake) IPsecCleanup(context.Context, uuid.UUID, int64) (ipsec.RuntimeCleanup, error) {
	return ipsec.RuntimeCleanup{}, errors.New("refused")
}
func (f *runtimePollFake) IPsecAcknowledge(context.Context, uuid.UUID, ipsec.RuntimeAcknowledgement) error {
	f.acks++
	return nil
}
func (f *runtimePollFake) Apply(_ context.Context, m ipsec.RuntimeMaterial) (ipsec.RuntimeAcknowledgement, error) {
	if f.failure {
		return ipsec.RuntimeAcknowledgement{}, errors.New("refused")
	}
	return ipsec.RuntimeAcknowledgement{DeliveryID: m.ID, DesiredRevision: m.DesiredRevision, Kind: "apply", Result: "applied"}, nil
}
func (f *runtimePollFake) Cleanup(context.Context, ipsec.RuntimeCleanup) (ipsec.RuntimeAcknowledgement, error) {
	return ipsec.RuntimeAcknowledgement{}, errors.New("refused")
}
func TestIPsecRuntimePollAcknowledgesOnlyCompletedApply(t *testing.T) {
	f := &runtimePollFake{item: ipsec.RuntimePending{ConnectionID: uuid.New(), DesiredRevision: 2, Kind: "apply"}, failure: true}
	if PollIPsecRuntime(context.Background(), f, f) == nil || f.acks != 0 {
		t.Fatal("failed apply acknowledged")
	}
	f.failure = false
	if e := PollIPsecRuntime(context.Background(), f, f); e != nil || f.acks != 1 {
		t.Fatal("completed apply not acknowledged", e)
	}
	f.item.Kind = "unknown"
	if PollIPsecRuntime(context.Background(), f, f) == nil || f.acks != 1 {
		t.Fatal("unknown intent accepted")
	}
}

func (f *runtimePollFake) ObserveIPsecStatus(_ context.Context, d ipsec.RuntimeDelivery) (ipsec.RuntimeStatusReport, error) {
	return ipsec.RuntimeStatusReport{DeliveryID: d.ID, DesiredRevision: d.DesiredRevision, ConfigurationRevision: 1, Tunnels: [2]ipsec.RuntimeTunnelStatus{{ID: uuid.New(), Slot: 1, Status: "unknown", Selected: true}, {ID: uuid.New(), Slot: 2, Status: "down"}}}, nil
}
func (f *runtimePollFake) IPsecReportStatus(_ context.Context, _ uuid.UUID, r ipsec.RuntimeStatusReport) error {
	f.reports = append(f.reports, r)
	if f.reportFailure {
		return errors.New("synthetic private failure")
	}
	return nil
}
func TestIPsecRuntimeStatusReportedEvenWhenApplyFails(t *testing.T) {
	f := &runtimePollFake{item: ipsec.RuntimePending{ConnectionID: uuid.New(), DesiredRevision: 2, Kind: "apply"}, failure: true}
	if PollIPsecRuntime(context.Background(), f, f) == nil || len(f.reports) != 1 || f.acks != 0 {
		t.Fatal("failed apply omitted independent status")
	}
	if f.reports[0].Tunnels[0].Status != "unknown" || f.reports[0].Tunnels[1].Status != "down" {
		t.Fatal("observed statuses replaced by apply result")
	}
	f.failure = false
	f.reportFailure = true
	if PollIPsecRuntime(context.Background(), f, f) == nil || f.acks != 1 {
		t.Fatal("telemetry failure withheld completed apply acknowledgement")
	}
}
