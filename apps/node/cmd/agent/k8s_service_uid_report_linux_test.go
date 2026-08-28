//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/tunnexio/tunnex/apps/node/internal/control"
	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
)

type fakeUIDReporter struct {
	reports []control.K8sServiceUIDObservationReport
	fail    bool
}

func (f *fakeUIDReporter) ReportK8sServiceUIDObservations(_ context.Context, report control.K8sServiceUIDObservationReport) error {
	f.reports = append(f.reports, report)
	if f.fail {
		return errors.New("send failed")
	}
	return nil
}

type fakeAppliedVIPMap struct{ mappings []nodepolicy.VIPMapping }

func (f *fakeAppliedVIPMap) AppliedVIPMap() []nodepolicy.VIPMapping {
	return append([]nodepolicy.VIPMapping(nil), f.mappings...)
}

func TestUIDReportUsesOnlyAppliedServerMapAndReportsRecreateOnce(t *testing.T) {
	reporter := &fakeUIDReporter{}
	manager := &fakeAppliedVIPMap{mappings: []nodepolicy.VIPMapping{
		{Namespace: "prod", Service: "api"},
		{Namespace: "prod", Service: "api"}, // duplicate exposure still reports one identity
	}}
	observed := map[string][]control.K8sServiceUIDObservation{
		"prod/api":   {{Namespace: "prod", Service: "api", UID: "uid-a", State: "live"}},
		"prod/other": {{Namespace: "prod", Service: "other", UID: "uid-x", State: "live"}},
	}
	lookup := func(namespace, service string) ([]control.K8sServiceUIDObservation, bool) {
		entries, ok := observed[namespace+"/"+service]
		return append([]control.K8sServiceUIDObservation(nil), entries...), ok
	}
	last, unavailable := map[string]string{}, map[string]bool{}
	sequencePath := filepath.Join(t.TempDir(), "uid-sequence")
	reportK8sServiceUIDObservationsOnce(t.Context(), reporter, lookup, manager, sequencePath, last, unavailable, nil)
	if len(reporter.reports) != 1 || len(reporter.reports[0].Observations) != 1 || reporter.reports[0].Observations[0].UID != "uid-a" {
		t.Fatalf("initial scoped reports = %+v", reporter.reports)
	}
	firstSequence := reporter.reports[0].Sequence
	reportK8sServiceUIDObservationsOnce(t.Context(), reporter, lookup, manager, sequencePath, last, unavailable, nil)
	if len(reporter.reports) != 1 {
		t.Fatalf("unchanged observation was resent: %+v", reporter.reports)
	}

	observed["prod/api"] = []control.K8sServiceUIDObservation{
		{Namespace: "prod", Service: "api", UID: "uid-a", State: "deleted"},
		{Namespace: "prod", Service: "api", UID: "uid-b", State: "live"},
	}
	reportK8sServiceUIDObservationsOnce(t.Context(), reporter, lookup, manager, sequencePath, last, unavailable, nil)
	if len(reporter.reports) != 2 || len(reporter.reports[1].Observations) != 2 || reporter.reports[1].Sequence <= firstSequence {
		t.Fatalf("delete/recreate report = %+v", reporter.reports)
	}
	for _, report := range reporter.reports {
		for _, entry := range report.Observations {
			if entry.Service == "other" {
				t.Fatal("watcher inventory outside the applied VIP map was reported")
			}
		}
	}
}

func TestUIDReportFailureRetriesWithNewPersistedSequence(t *testing.T) {
	reporter := &fakeUIDReporter{fail: true}
	manager := &fakeAppliedVIPMap{mappings: []nodepolicy.VIPMapping{{Namespace: "prod", Service: "api"}}}
	lookup := func(_, _ string) ([]control.K8sServiceUIDObservation, bool) {
		return []control.K8sServiceUIDObservation{{Namespace: "prod", Service: "api", UID: "uid-a", State: "live"}}, true
	}
	last, unavailable := map[string]string{}, map[string]bool{}
	sequencePath := filepath.Join(t.TempDir(), "uid-sequence")
	reportK8sServiceUIDObservationsOnce(t.Context(), reporter, lookup, manager, sequencePath, last, unavailable, nil)
	reporter.fail = false
	reportK8sServiceUIDObservationsOnce(t.Context(), reporter, lookup, manager, sequencePath, last, unavailable, nil)
	if len(reporter.reports) != 2 || reporter.reports[1].Sequence <= reporter.reports[0].Sequence {
		t.Fatalf("retry sequences = %+v", reporter.reports)
	}
	raw, err := os.ReadFile(sequencePath)
	if err != nil {
		t.Fatal(err)
	}
	persisted, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil || persisted != reporter.reports[1].Sequence {
		t.Fatalf("persisted sequence=%q parsed=%d err=%v", raw, persisted, err)
	}
}

func TestNextUIDSequenceRejectsCorruptState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "uid-sequence")
	if err := os.WriteFile(path, []byte("not-a-sequence\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := nextK8sServiceUIDSequence(path); err == nil || !strings.Contains(err.Error(), "parse sequence") {
		t.Fatalf("corrupt persistent sequence was accepted: %v", err)
	}
}

func TestSharedUIDAndInventorySequenceAllocationIsConcurrentSafe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "uid-sequence")
	const workers = 16
	values := make(chan uint64, workers)
	errors := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			value, err := nextK8sServiceUIDSequence(path)
			if err != nil {
				errors <- err
				return
			}
			values <- value
		}()
	}
	wg.Wait()
	close(values)
	close(errors)
	for err := range errors {
		t.Fatal(err)
	}
	seen := map[uint64]bool{}
	for value := range values {
		if seen[value] {
			t.Fatalf("duplicate sequence %d", value)
		}
		seen[value] = true
	}
	if len(seen) != workers {
		t.Fatalf("sequences=%d", len(seen))
	}
}
