//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBGPQualificationRetryRecoversTransientRefusalAndStopsAfterAttach(t *testing.T) {
	var retry bgpQualificationRetry
	now := time.Unix(100, 0)
	if !retry.due(now) {
		t.Fatal("first independent observation missing")
	}
	for _, delay := range []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second, 30 * time.Second, 30 * time.Second} {
		retry.completed(now, false)
		if retry.qualified || retry.backoff != delay || retry.due(now.Add(delay-time.Nanosecond)) || !retry.due(now.Add(delay)) {
			t.Fatal("refusal promoted support or retry escaped bounded backoff")
		}
		now = now.Add(delay)
	}
	retry.completed(now, true)
	if retry.due(now) || retry.due(now.Add(24*time.Hour)) {
		t.Fatal("attached native qualification retried")
	}
}

func TestBGPQualificationRetryRetainsObserverCleanupObligations(t *testing.T) {
	parent := t.TempDir()
	if err := bgpPreflightResidueClear(parent); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "bgp-preflight-old")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	original := []byte("retained cleanup identity")
	if err := os.WriteFile(filepath.Join(path, "supervisor.lock"), original, 0600); err != nil {
		t.Fatal(err)
	}
	if bgpPreflightResidueClear(parent) == nil {
		t.Fatal("retained obligation admitted observer retry")
	}
	actual, err := os.ReadFile(filepath.Join(path, "supervisor.lock"))
	if err != nil || string(actual) != string(original) {
		t.Fatal("retained cleanup modified")
	}
}
