//go:build linux

package main

import (
	"context"
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
)

func reportK8sServiceInventoryLoop(ctx context.Context, client serviceInventoryReporter, watcher *egress.K8sWatcher, sequencePath string, interval time.Duration, logger *slog.Logger) {
	if client == nil || watcher == nil {
		return
	}
	if interval < minK8sServiceInventoryInterval || interval > maxK8sServiceInventoryInterval {
		interval = 30 * time.Second
	}
	run := func() {
		items, ok := watcher.ServiceInventory()
		if !ok {
			if logger != nil {
				logger.Warn("k8s_service_inventory_unavailable")
			}
			return
		}
		services := make([]control.K8sServiceInventoryService, len(items))
		for i, item := range items {
			ports := make([]control.K8sServiceInventoryPort, len(item.Ports))
			for j, port := range item.Ports {
				ports[j] = control.K8sServiceInventoryPort{Name: port.Name, Protocol: port.Protocol, Port: port.Port}
			}
			services[i] = control.K8sServiceInventoryService{Namespace: item.Namespace, Service: item.Service, UID: item.UID, Ports: ports}
		}
		sequence, err := nextK8sServiceUIDSequence(sequencePath)
		if err != nil {
			if logger != nil {
				logger.Warn("k8s_service_inventory_sequence_failed", slog.String("error", err.Error()))
			}
			return
		}
		report := control.K8sServiceInventoryReport{Version: control.K8sServiceInventoryVersion, Sequence: sequence, ObservedAt: time.Now().UTC(), Services: services}
		report.Digest = control.K8sServiceInventoryDigest(report.Sequence, report.ObservedAt, report.Services)
		if err := client.ReportK8sServiceInventory(ctx, report); err != nil {
			if logger != nil {
				logger.Warn("k8s_service_inventory_report_failed", slog.String("error", err.Error()))
			}
			return
		}
		if logger != nil {
			logger.Info("k8s_service_inventory_reported", slog.Int("services", len(services)))
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
