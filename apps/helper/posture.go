package helper

import (
	"strings"
	"time"
)

// postureCmdTimeout bounds the external posture reads (fdesetup / powershell).
// The tunnel verbs have no exec timeout convention (they drive long-lived state);
// posture reads are pure queries and must never wedge the root helper's dispatch,
// so they introduce one.
const postureCmdTimeout = 10 * time.Second

// parseFileVaultStatus maps `fdesetup status` output to the tri-state fact.
// nil = unrecognized output → the fact is INDETERMINATE (reported absent, never
// guessed). fdesetup prints English constants ("FileVault is On." / "FileVault
// is Off." — possibly followed by detail lines), not localized text.
func parseFileVaultStatus(out string) *bool {
	switch {
	case strings.Contains(out, "FileVault is On"):
		v := true
		return &v
	case strings.Contains(out, "FileVault is Off"):
		v := false
		return &v
	default:
		return nil
	}
}

// parseProtectionStatus maps a Win32_EncryptableVolume ProtectionStatus value
// (numeric, locale-safe — never parse manage-bde's localized prose) to the
// tri-state fact: 1 = protected, 0 = unprotected, 2/garbage = indeterminate.
func parseProtectionStatus(out string) *bool {
	switch strings.TrimSpace(out) {
	case "1":
		v := true
		return &v
	case "0":
		v := false
		return &v
	default:
		return nil
	}
}
