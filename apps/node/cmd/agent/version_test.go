package main

import "testing"

func TestVersionUsesBuildStampByDefaultAndExplicitOverrideWhenPresent(t *testing.T) {
	original := buildVersion
	t.Cleanup(func() { buildVersion = original })
	buildVersion = "v0.42.0"
	t.Setenv("TUNNEX_AGENT_VERSION", "")

	if got := version(); got != "v0.42.0" {
		t.Fatalf("unstamped environment version=%q, want build stamp", got)
	}
	t.Setenv("TUNNEX_AGENT_VERSION", "operator-override")
	if got := version(); got != "operator-override" {
		t.Fatalf("explicit override version=%q", got)
	}
	t.Setenv("TUNNEX_AGENT_VERSION", "")
	if got := version(); got != "v0.42.0" {
		t.Fatalf("empty override replaced build provenance: %q", got)
	}
}

func TestVersionFallsBackToHonestDevWhenBuildStampIsEmpty(t *testing.T) {
	original := buildVersion
	t.Cleanup(func() { buildVersion = original })
	buildVersion = ""
	t.Setenv("TUNNEX_AGENT_VERSION", "")
	if got := version(); got != "dev" {
		t.Fatalf("empty build stamp version=%q, want dev", got)
	}
}
