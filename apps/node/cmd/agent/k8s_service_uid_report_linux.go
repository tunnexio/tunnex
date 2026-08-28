//go:build linux

package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/control"
	"github.com/tunnexio/tunnex/apps/node/internal/egress"
	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
)

var k8sServiceObservationSequenceMu sync.Mutex

type serviceUIDObservationLookup func(namespace, service string) ([]control.K8sServiceUIDObservation, bool)

type appliedVIPMapSource interface {
	AppliedVIPMap() []nodepolicy.VIPMapping
}

type serviceUIDObservationReporter interface {
	ReportK8sServiceUIDObservations(context.Context, control.K8sServiceUIDObservationReport) error
}

// reportK8sServiceUIDObservationsLoop reports only exact Service identities in
// the last successfully applied, server-owned VIP map. The watcher remains the
// sole UID authority; policy only limits which identities can leave the node.
func reportK8sServiceUIDObservationsLoop(ctx context.Context, client serviceUIDObservationReporter, watcher *egress.K8sWatcher, manager appliedVIPMapSource, sequencePath string, interval time.Duration, logger *slog.Logger) {
	if watcher == nil {
		return
	}
	if interval <= 0 {
		interval = 10 * time.Second
	}
	if logger != nil {
		logger.Info("k8s_service_uid_report_loop_started", slog.Duration("interval", interval))
	}
	last := map[string]string{}
	unavailable := map[string]bool{}
	lookup := func(namespace, service string) ([]control.K8sServiceUIDObservation, bool) {
		observed, ok := watcher.ServiceUIDObservations(namespace, service)
		entries := make([]control.K8sServiceUIDObservation, len(observed))
		for i, item := range observed {
			entries[i] = control.K8sServiceUIDObservation{Namespace: item.Namespace, Service: item.Service, UID: item.UID, State: item.State}
		}
		return entries, ok
	}
	run := func() {
		reportK8sServiceUIDObservationsOnce(ctx, client, lookup, manager, sequencePath, last, unavailable, logger)
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

func reportK8sServiceUIDObservationsOnce(ctx context.Context, client serviceUIDObservationReporter, lookup serviceUIDObservationLookup, manager appliedVIPMapSource, sequencePath string, last map[string]string, unavailable map[string]bool, logger *slog.Logger) {
	if client == nil || lookup == nil || manager == nil {
		return
	}
	keys := map[string][2]string{}
	for _, mapping := range manager.AppliedVIPMap() {
		if mapping.Namespace == "" || mapping.Service == "" {
			continue
		}
		key := mapping.Namespace + "\x00" + mapping.Service
		keys[key] = [2]string{mapping.Namespace, mapping.Service}
	}
	ordered := make([]string, 0, len(keys))
	for key := range keys {
		ordered = append(ordered, key)
	}
	sort.Strings(ordered)
	for _, key := range ordered {
		identity := keys[key]
		entries, ok := lookup(identity[0], identity[1])
		if !ok {
			if !unavailable[key] && logger != nil {
				logger.Warn("k8s_service_uid_observation_unavailable", slog.String("namespace", identity[0]), slog.String("service", identity[1]))
			}
			unavailable[key] = true
			continue
		}
		delete(unavailable, key)
		entries = append([]control.K8sServiceUIDObservation(nil), entries...)
		sort.Slice(entries, func(i, j int) bool {
			if entries[i].UID != entries[j].UID {
				return entries[i].UID < entries[j].UID
			}
			return entries[i].State < entries[j].State
		})
		signatureParts := make([]string, 0, len(entries))
		for _, entry := range entries {
			signatureParts = append(signatureParts, entry.Namespace+"\x00"+entry.Service+"\x00"+entry.UID+"\x00"+entry.State)
		}
		signature := strings.Join(signatureParts, "\x01")
		if last[key] == signature {
			continue
		}
		sequence, err := nextK8sServiceUIDSequence(sequencePath)
		if err != nil {
			if logger != nil {
				logger.Warn("k8s_service_uid_sequence_failed", slog.String("error", err.Error()))
			}
			continue
		}
		report := control.K8sServiceUIDObservationReport{Version: control.K8sServiceUIDObservationVersion, Sequence: sequence, Observations: entries}
		report.Digest = control.K8sServiceUIDObservationDigest(report.Sequence, report.Observations)
		if err := client.ReportK8sServiceUIDObservations(ctx, report); err != nil {
			if logger != nil {
				logger.Warn("k8s_service_uid_report_failed", slog.String("namespace", identity[0]), slog.String("service", identity[1]), slog.String("error", err.Error()))
			}
			continue
		}
		last[key] = signature
		if logger != nil {
			logger.Info("k8s_service_uid_reported", slog.String("namespace", identity[0]), slog.String("service", identity[1]), slog.Int("observations", len(entries)))
		}
	}
}

// nextK8sServiceUIDSequence persists before send. Crashing between persistence
// and the request creates a harmless gap, never a replay. A wall-clock seed
// advances pre-file deployments beyond an existing server watermark.
func nextK8sServiceUIDSequence(path string) (uint64, error) {
	k8sServiceObservationSequenceMu.Lock()
	defer k8sServiceObservationSequenceMu.Unlock()
	var current uint64
	raw, err := os.ReadFile(path)
	if err == nil {
		current, err = strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("parse sequence: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return 0, err
	}
	seed := uint64(time.Now().UnixNano())
	if current < seed {
		current = seed
	} else {
		current++
	}
	if current == 0 {
		return 0, fmt.Errorf("sequence exhausted")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return 0, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strconv.FormatUint(current, 10)+"\n"), 0o600); err != nil {
		return 0, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return 0, err
	}
	return current, nil
}
