//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/control"
	"github.com/tunnexio/tunnex/apps/node/internal/egress"
)

// fakeInventoryControlPlane records every report. refuseV2 makes it answer like a control plane from
// before version 2: the same refusal it gives any report it will not store.
type fakeInventoryControlPlane struct {
	refuseV2 bool
	fail     error
	reports  []control.K8sServiceInventoryReport
}

func (f *fakeInventoryControlPlane) ReportK8sServiceInventory(_ context.Context, report control.K8sServiceInventoryReport) error {
	if err := control.ValidateK8sServiceInventoryReport(report); err != nil {
		return err
	}
	f.reports = append(f.reports, report)
	if f.fail != nil {
		return f.fail
	}
	if f.refuseV2 && report.Version != control.K8sServiceInventoryVersion {
		return fmt.Errorf("%w: status 400", control.ErrK8sServiceInventoryRefused)
	}
	return nil
}

func newTestInventorySender(client *fakeInventoryControlPlane) *k8sServiceInventorySender {
	var sequence uint64
	return &k8sServiceInventorySender{client: client, now: func() time.Time { return time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC) },
		nextSequence: func() (uint64, error) { sequence++; return sequence, nil }}
}

func testInventoryItems() []egress.ServiceInventoryItem {
	many := map[string]string{}
	for i := 0; i < 40; i++ {
		many[fmt.Sprintf("k%03d", i)] = "v"
	}
	return []egress.ServiceInventoryItem{
		{Namespace: "shop", Service: "web", UID: "uid-web", Ports: []egress.ServiceInventoryPort{{Protocol: "tcp", Port: 80}}, Labels: map[string]string{"app": "web"}},
		{Namespace: "shop", Service: "wide", UID: "uid-wide", Ports: []egress.ServiceInventoryPort{{Protocol: "tcp", Port: 81}}, Labels: many},
	}
}

func TestInventorySenderSendsLabelsAsVersion2(t *testing.T) {
	cp := &fakeInventoryControlPlane{}
	sender := newTestInventorySender(cp)
	version, err := sender.send(context.Background(), testInventoryItems())
	if err != nil || version != control.K8sServiceInventoryVersionLabels || len(cp.reports) != 1 {
		t.Fatalf("version=%d err=%v reports=%d", version, err, len(cp.reports))
	}
	report := cp.reports[0]
	if report.Version != 2 || report.Services[0].Labels["app"] != "web" || report.Services[0].LabelsTruncated {
		t.Fatalf("report=%+v", report)
	}
	// 40 labels do not fit: the first 32 in key order are sent and the Service says it is incomplete.
	wide := report.Services[1]
	if !wide.LabelsTruncated || len(wide.Labels) != control.MaxK8sServiceInventoryLabels || wide.Labels["k031"] != "v" {
		t.Fatalf("wide labels=%d truncated=%v", len(wide.Labels), wide.LabelsTruncated)
	}
	if _, late := wide.Labels["k032"]; late {
		t.Fatal("labels beyond the bound were sent")
	}
}

func TestInventorySenderFallsBackToVersion1ForAnOldControlPlane(t *testing.T) {
	cp := &fakeInventoryControlPlane{refuseV2: true}
	sender := newTestInventorySender(cp)
	version, err := sender.send(context.Background(), testInventoryItems())
	if err != nil || version != control.K8sServiceInventoryVersion {
		t.Fatalf("the Service list must still be reported: version=%d err=%v", version, err)
	}
	if len(cp.reports) != 2 || cp.reports[0].Version != 2 || cp.reports[1].Version != 1 || cp.reports[1].Sequence <= cp.reports[0].Sequence {
		t.Fatalf("want version 2 then version 1 under a later sequence: %+v", cp.reports)
	}
	for _, service := range cp.reports[1].Services {
		if len(service.Labels) != 0 || service.LabelsTruncated {
			t.Fatalf("a version 1 report carried labels: %+v", service)
		}
	}
	// Version 1 only for the next 20 reports: one request each, not two.
	for i := 0; i < k8sServiceInventoryV1Reports; i++ {
		if version, err := sender.send(context.Background(), testInventoryItems()); err != nil || version != 1 {
			t.Fatalf("report %d: version=%d err=%v", i, version, err)
		}
	}
	if len(cp.reports) != 2+k8sServiceInventoryV1Reports {
		t.Fatalf("requests=%d, want one per report while on version 1", len(cp.reports))
	}
	// Then version 2 is tried again; an upgraded control plane takes it and the gateway stays on it.
	cp.refuseV2 = false
	for i := 0; i < 2; i++ {
		if version, err := sender.send(context.Background(), testInventoryItems()); err != nil || version != 2 {
			t.Fatalf("after the control plane was upgraded: version=%d err=%v", version, err)
		}
	}
	if len(cp.reports) != 4+k8sServiceInventoryV1Reports {
		t.Fatalf("requests=%d", len(cp.reports))
	}
}

func TestInventorySenderDoesNotFallBackOnOtherFailures(t *testing.T) {
	cp := &fakeInventoryControlPlane{fail: errors.New("Kubernetes Service inventory status 503")}
	sender := newTestInventorySender(cp)
	if _, err := sender.send(context.Background(), testInventoryItems()); err == nil {
		t.Fatal("a failed report must be returned")
	}
	if len(cp.reports) != 1 || sender.v1Left != 0 {
		t.Fatalf("a 503 must not cause a version 1 retry: requests=%d v1Left=%d", len(cp.reports), sender.v1Left)
	}
	// A refusal that version 1 gets too (a standby gateway) is returned, and the next report is one request.
	cp.fail = fmt.Errorf("%w: status 400", control.ErrK8sServiceInventoryRefused)
	if _, err := sender.send(context.Background(), testInventoryItems()); !errors.Is(err, control.ErrK8sServiceInventoryRefused) {
		t.Fatalf("err=%v", err)
	}
	if len(cp.reports) != 3 {
		t.Fatalf("requests=%d, want the version 2 attempt and one version 1 attempt", len(cp.reports))
	}
	if _, err := sender.send(context.Background(), testInventoryItems()); err == nil || len(cp.reports) != 4 {
		t.Fatalf("while on version 1 a refused report is one request: err=%v requests=%d", err, len(cp.reports))
	}
}
