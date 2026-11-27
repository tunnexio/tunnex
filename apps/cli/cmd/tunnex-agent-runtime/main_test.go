package main

import (
	"os"
	"path/filepath"
	"testing"
)

// AI-UX-1: a host without resolvconf (Ubuntu 24.04 without systemd-resolved) still starts. The runtime
// leaves the DNS line out of the tunnel configuration there and says so on its report.
func TestManagedAgentRuntimeStartsWithoutAResolver(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"wg"} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir)
	if err := preflight(); err != nil {
		t.Fatalf("a host without resolvconf must still start: %v", err)
	}
}

func TestManagedAgentRuntimeMissingWireGuardRefusesBeforeStateWork(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "resolvconf")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	if err := preflight(); err == nil {
		t.Fatal("missing wg must refuse startup")
	}
}

func TestManagedAgentRuntimePreflightAcceptsDocumentedResolver(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"wg", "resolvconf"} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir)
	if err := preflight(); err != nil {
		t.Fatalf("documented resolver should pass preflight: %v", err)
	}
}
