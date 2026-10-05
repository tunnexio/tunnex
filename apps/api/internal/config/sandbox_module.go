package config

import "errors"

// SandboxModuleState preserves previously configured installations while new,
// unconfigured deployments carry no sandbox runtime services.
func (c Config) SandboxModuleState() string {
	switch c.SandboxModule {
	case "on":
		return "enabled"
	case "draining":
		return "draining"
	case "off":
		return "disabled"
	default:
		if c.SandboxRuntimeConfigFile != "" || c.SandboxFixtureOrgID != "" {
			return "enabled"
		}
		return "disabled"
	}
}
func (c Config) ValidateSandboxModule() error {
	switch c.SandboxModule {
	case "", "on":
		return nil
	case "off":
		if c.SandboxRuntimeConfigFile != "" || c.SandboxFixtureOrgID != "" {
			return errors.New("sandbox off requires drained resources and removed runtime configuration; use draining first")
		}
	case "draining":
		if c.SandboxRuntimeConfigFile == "" && c.SandboxFixtureOrgID == "" {
			return errors.New("sandbox draining requires the existing cleanup runtime configuration")
		}
	default:
		return errors.New("TUNNEX_SANDBOX_MODULE must be on, off, or draining")
	}
	return nil
}
