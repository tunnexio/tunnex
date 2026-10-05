package config

import "testing"

func TestSandboxModuleCapabilityCompatibility(t *testing.T) {
	for _, tc := range []struct {
		c       Config
		want    string
		invalid bool
	}{
		{Config{}, "disabled", false}, {Config{SandboxRuntimeConfigFile: "/etc/tunnex/sandbox-runtime.json"}, "enabled", false},
		{Config{SandboxFixtureOrgID: "legacy-fixture"}, "enabled", false}, {Config{SandboxModule: "on"}, "enabled", false},
		{Config{SandboxModule: "off"}, "disabled", false}, {Config{SandboxModule: "off", SandboxRuntimeConfigFile: "configured"}, "disabled", true},
		{Config{SandboxModule: "draining", SandboxRuntimeConfigFile: "configured"}, "draining", false},
		{Config{SandboxModule: "draining"}, "draining", true}, {Config{SandboxModule: "typo"}, "disabled", true},
	} {
		if got := tc.c.SandboxModuleState(); got != tc.want {
			t.Fatalf("state %v: %s", tc.c, got)
		}
		if (tc.c.ValidateSandboxModule() != nil) != tc.invalid {
			t.Fatalf("validation %v", tc.c)
		}
	}
	t.Setenv("TUNNEX_SANDBOX_MODULE", "draining")
	if Load().SandboxModule != "draining" {
		t.Fatal("environment not loaded")
	}
}
