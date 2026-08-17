package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestManagedAgentRuntimeMissingResolverRefusesBeforeStateWork(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"wg"} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir)
	if err := preflight(); err == nil {
		t.Fatal("missing resolver must refuse startup")
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
