package main

import (
	"github.com/tunnexio/tunnex/apps/api/internal/config"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxproduct"
)

// TODO(sandbox-reentry): docs/S-sandbox-shelved-main-reentry.md. Do not load
// private runtime configuration, construct workers or consult retirement state
// while product development is paused. Shared server initialization stays active.
func initializeSandboxProduct(c config.Config, retired func() error, configure func() (sandboxModule, error)) (sandboxModule, error) {
	if sandboxproduct.Shelved {
		return sandboxModule{state: "disabled", available: func() bool { return false }}, nil
	}
	return initializeSandboxModule(c, retired, configure)
}

func validateSandboxProductConfiguration(c config.Config) error {
	if sandboxproduct.Shelved {
		return nil
	}
	if err := c.ValidateSandboxFixture(); err != nil {
		return err
	}
	if err := c.ValidateSandboxRuntime(); err != nil {
		return err
	}
	return c.ValidateSandboxModule()
}
