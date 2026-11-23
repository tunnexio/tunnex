//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/control"
	"github.com/tunnexio/tunnex/apps/node/internal/egress"
)

type serviceInventoryReporter interface {
	ReportK8sServiceInventory(context.Context, control.K8sServiceInventoryReport) error
}

const (
	minK8sServiceInventoryInterval = 10 * time.Second
	maxK8sServiceInventoryInterval = 60 * time.Second
	// After the control plane refuses a version 2 report, this many reports go out as version 1 before
	// version 2 is tried again (10 minutes at the default interval).
	k8sServiceInventoryV1Reports = 20
)

// buildK8sServiceInventoryReport turns the watcher's snapshot into a report of the given version.
// Version 2 carries each Service's labels, bounded; version 1 carries none.
func buildK8sServiceInventoryReport(version int, sequence uint64, observedAt time.Time, items []egress.ServiceInventoryItem) control.K8sServiceInventoryReport {
	services := make([]control.K8sServiceInventoryService, len(items))
	for i, item := range items {
		ports := make([]control.K8sServiceInventoryPort, len(item.Ports))
		for j, port := range item.Ports {
			ports[j] = control.K8sServiceInventoryPort{Name: port.Name, Protocol: port.Protocol, Port: port.Port}
		}
		services[i] = control.K8sServiceInventoryService{Namespace: item.Namespace, Service: item.Service, UID: item.UID, Ports: ports}
		if version == control.K8sServiceInventoryVersionLabels {
			services[i].Labels, services[i].LabelsTruncated = control.BoundK8sServiceInventoryLabels(item.Labels)
		}
	}
	report := control.K8sServiceInventoryReport{Version: version, Sequence: sequence, ObservedAt: observedAt, Services: services}
	report.Digest = control.K8sServiceInventoryReportDigest(report)
	return report
}

// k8sServiceInventorySender sends each snapshot as version 2 and falls back to version 1 when the
// control plane refuses it, so a gateway upgraded before its control plane keeps reporting.
type k8sServiceInventorySender struct {
	client       serviceInventoryReporter
	nextSequence func() (uint64, error)
	now          func() time.Time
	// v1Left > 0: the control plane refused version 2 recently; send version 1 this many more times.
	v1Left int
}

// send reports one snapshot and returns the version the control plane accepted.
func (s *k8sServiceInventorySender) send(ctx context.Context, items []egress.ServiceInventoryItem) (int, error) {
	version := control.K8sServiceInventoryVersionLabels
	if s.v1Left > 0 {
		version = control.K8sServiceInventoryVersion
		s.v1Left--
	}
	sequence, err := s.nextSequence()
	if err != nil {
		return 0, fmt.Errorf("sequence: %w", err)
	}
	err = s.client.ReportK8sServiceInventory(ctx, buildK8sServiceInventoryReport(version, sequence, s.now().UTC(), items))
	if err == nil || version == control.K8sServiceInventoryVersion || !errors.Is(err, control.ErrK8sServiceInventoryRefused) {
		return version, err
	}
	// Refused as version 2. The control plane does not say why, so try the same Services as version 1
	// now, under a new sequence, and stay on version 1 for a while whatever the answer.
	s.v1Left = k8sServiceInventoryV1Reports
	sequence, err = s.nextSequence()
	if err != nil {
		return 0, fmt.Errorf("sequence: %w", err)
	}
	return control.K8sServiceInventoryVersion, s.client.ReportK8sServiceInventory(ctx, buildK8sServiceInventoryReport(control.K8sServiceInventoryVersion, sequence, s.now().UTC(), items))
}

func reportK8sServiceInventoryLoop(ctx context.Context, client serviceInventoryReporter, watcher *egress.K8sWatcher, sequencePath string, interval time.Duration, logger *slog.Logger) {
	if client == nil || watcher == nil {
		return
	}
	if interval < minK8sServiceInventoryInterval || interval > maxK8sServiceInventoryInterval {
		interval = 30 * time.Second
	}
	sender := &k8sServiceInventorySender{client: client, now: time.Now, nextSequence: func() (uint64, error) { return nextK8sServiceUIDSequence(sequencePath) }}
	run := func() {
		items, ok := watcher.ServiceInventory()
		if !ok {
			if logger != nil {
				logger.Warn("k8s_service_inventory_unavailable")
			}
			return
		}
		version, err := sender.send(ctx, items)
		if err != nil {
			if logger != nil {
				logger.Warn("k8s_service_inventory_report_failed", slog.String("error", err.Error()))
			}
			return
		}
		if logger != nil {
			logger.Info("k8s_service_inventory_reported", slog.Int("services", len(items)), slog.Int("version", version))
		}
	}
	run()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}
