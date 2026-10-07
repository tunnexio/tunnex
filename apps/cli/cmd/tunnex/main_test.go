package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestOrdinaryHelpOmitsShelvedSandbox(t *testing.T) {
	var out bytes.Buffer
	writeUsage(&out)
	help := out.String()
	if strings.Contains(help, "sandbox") {
		t.Fatalf("ordinary help exposes shelved sandbox: %s", help)
	}
	for _, command := range []string{"editor", "login", "logout", "device create", "up | down", "k8s", "ai models", "workload run", "beam publish|resume|policy|audience|list|get|pause|stop|extend", "version"} {
		if !strings.Contains(help, "tunnex "+command) {
			t.Errorf("ordinary help lost %q", command)
		}
	}
}

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
