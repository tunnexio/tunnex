package main

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/config"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxes"
	"testing"
)

func TestSandboxModuleOffNeverConstructsRuntime(t *testing.T) {
	for _, c := range []config.Config{{}, {SandboxModule: "off"}} {
		checks := 0
		m, err := initializeSandboxModule(c, func() error { checks++; return nil }, func() (sandboxModule, error) { t.Fatal("off constructed runtime"); return sandboxModule{}, nil })
		deps := m.deps()
		if err != nil || checks != 1 || m.store != nil || m.run != nil || m.close != nil || m.wake != nil || m.available() || deps.Sandboxes != nil || deps.SandboxRunnerEnrollment != nil || deps.SandboxRunnerQualification != nil {
			t.Fatal("off not inert", m, err)
		}
	}
	if _, err := initializeSandboxModule(config.Config{}, func() error { return sandboxes.ErrModuleRetirementPending }, func() (sandboxModule, error) {
		t.Fatal("pending retirement constructed runtime")
		return sandboxModule{}, nil
	}); !errors.Is(err, sandboxes.ErrModuleRetirementPending) {
		t.Fatal(err)
	}
}
func TestSandboxModuleLegacyAndDrainingKeepCleanup(t *testing.T) {
	for _, mode := range []string{"", "draining"} {
		configured := 0
		runs := 0
		c := config.Config{SandboxModule: mode, SandboxRuntimeConfigFile: "/etc/tunnex/sandbox-runtime.json"}
		enrollment := &sandboxes.RunnerEnrollmentService{}
		qualification := &sandboxes.RunnerQualificationService{}
		m, err := initializeSandboxModule(c, func() error { t.Fatal("configured deployment checked off ledger"); return nil }, func() (sandboxModule, error) {
			configured++
			return sandboxModule{store: sandboxes.NewStore(nil), enrollment: enrollment, qualification: qualification, available: func() bool { return true }, run: func(context.Context, func(uuid.UUID, error)) error { runs++; return nil }}, nil
		})
		if err != nil || configured != 1 || m.run == nil || m.deps().Sandboxes == nil {
			t.Fatal("cleanup detached", err)
		}
		if m.available() != (mode == "") {
			t.Fatal("creation gate lost", mode)
		}
		deps := m.deps()
		if deps.SandboxRunnerEnrollment != enrollment || deps.SandboxRunnerQualification != qualification {
			t.Fatal("runner retirement/review authority detached", mode)
		}
		if err = m.run(context.Background(), nil); err != nil || runs != 1 {
			t.Fatal("cleanup stopped", err)
		}
	}
}
