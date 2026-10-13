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
	bgp           bool
}

func (f *runtimePollFake) IPsecPending(context.Context, *uuid.UUID, int) (ipsec.RuntimePendingPage, error) {
	return ipsec.RuntimePendingPage{Items: []ipsec.RuntimePending{f.item}}, nil
}
func (f *runtimePollFake) IPsecMaterial(context.Context, uuid.UUID, int64) (ipsec.RuntimeMaterial, error) {
	m := ipsec.RuntimeManifest{ConnectionID: f.item.ConnectionID, DesiredRevision: f.item.DesiredRevision, ConfigurationRevision: 1, ProfileID: "aws-static-ipv4-v1"}
	for i := range m.Tunnels {
		m.Tunnels[i] = ipsec.RuntimeTunnel{ID: uuid.New(), Slot: i + 1, Selected: !f.bgp && i == 0}
	}
	if f.bgp {
		version := 1
		m.ProfileID = "aws-bgp-ipv4-v1"
		m.BGPVersion = &version
		m.BGP = &ipsec.BGPConfig{MaximumPrefixes: 64}
		m.RemotePrefixes = []string{"10.20.0.0/24"}
	}
	return ipsec.RuntimeMaterial{RuntimeDelivery: ipsec.RuntimeDelivery{ID: uuid.New(), Kind: "apply", DesiredRevision: f.item.DesiredRevision, Manifest: m}}, nil
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
	return ipsec.RuntimeStatusReport{DeliveryID: d.ID, DesiredRevision: d.DesiredRevision, ConfigurationRevision: 1, Tunnels: [2]ipsec.RuntimeTunnelStatus{{ID: d.Manifest.Tunnels[0].ID, Slot: 1, Status: "unknown", Selected: d.Manifest.Tunnels[0].Selected}, {ID: d.Manifest.Tunnels[1].ID, Slot: 2, Status: "down", Selected: d.Manifest.Tunnels[1].Selected}}}, nil
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

func TestIPsecBGPStatusWithoutObservationPreservesDeliveryContext(t *testing.T) {
	f := &runtimePollFake{item: ipsec.RuntimePending{ConnectionID: uuid.New(), DesiredRevision: 2, Kind: "apply"}, bgp: true}
	if err := PollIPsecRuntime(context.Background(), f, f); err != nil || len(f.reports) != 1 {
		t.Fatal("honest no-observation BGP status refused", err)
	}
	if f.reports[0].BGP != nil || f.reports[0].Tunnels[0].Selected || f.reports[0].Tunnels[1].Selected {
		t.Fatal("invented BGP measurement or static fallback")
	}
	material, _ := f.IPsecMaterial(context.Background(), f.item.ConnectionID, 2)
	report, _ := f.ObserveIPsecStatus(context.Background(), material.RuntimeDelivery)
	report.Tunnels[0].Selected = true
	if runtimeStatusMatchesDelivery(material.RuntimeDelivery, report) {
		t.Fatal("BGP delivery accepted static status")
	}
	report.Tunnels[0].Selected = false
	material.Manifest.ProfileID = "aws-static-ipv4-v1"
	material.Manifest.BGP = nil
	material.Manifest.BGPVersion = nil
	if runtimeStatusMatchesDelivery(material.RuntimeDelivery, report) {
		t.Fatal("static delivery accepted unselected BGP wire")
	}
}
