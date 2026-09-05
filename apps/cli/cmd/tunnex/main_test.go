package main

import (
	"bytes"
	"testing"
)

func TestBuildVersionLineIsOnlyBuildVersion(t *testing.T) {
	previous := version
	t.Cleanup(func() { version = previous })

	version = "v0.9.1"
	var out bytes.Buffer
	if err := writeVersion(&out); err != nil {
		t.Fatalf("writeVersion: %v", err)
	}
	if got := out.String(); got != "v0.9.1\n" {
		t.Fatalf("version output = %q, want only exact injected version and newline", got)
	}

	version = "  "
	if got := buildVersionLine(); got != "unknown" {
		t.Fatalf("empty build version = %q, want truthful unknown", got)
	}
}
