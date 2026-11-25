package bootstrap

import "bytes"

// SetupErrorPrefix starts the single structured line the target helper (or its launcher) prints when it refuses
// setup for a reason it can name (SA-UX-3). Only the code after it is ever used; the rest of the output is discarded.
const SetupErrorPrefix = "TUNNEX SSH SETUP ERROR "

// setupErrorLineLimit bounds the structured line; every allow-listed code is far shorter.
const setupErrorLineLimit = 80

// SetupErrorCodes is the fixed allow-list shared by the gateway (parsing) and the control plane (re-check and
// message). helper.py and authorize.py may print only these; a Go test keeps the three in sync.
var SetupErrorCodes = map[string]bool{
	"setup_not_root":              true,
	"setup_unsupported_os":        true,
	"setup_unsupported_distro":    true,
	"setup_no_systemd":            true,
	"setup_missing_systemctl":     true,
	"setup_missing_ssh_keygen":    true,
	"setup_missing_ip":            true,
	"setup_no_openssh":            true,
	"setup_selinux_enforcing":     true,
	"setup_unsafe_path":           true,
	"setup_existing_setup":        true,
	"setup_foreign_setup":         true,
	"setup_identity_differs":      true,
	"setup_ca_mismatch":           true,
	"setup_principal_conflict":    true,
	"setup_ip_mismatch":           true,
	"setup_port_invalid":          true,
	"setup_port_in_use":           true,
	"setup_no_eligible_accounts":  true,
	"setup_too_many_accounts":     true,
	"setup_service_failed":        true,
	"setup_authorization_expired": true,
	"setup_installer_mismatch":    true,
}

// ParseSetupError returns the allow-listed code from the last line that is exactly SetupErrorPrefix followed by a
// known code, or "". Free text, unknown codes, trailing content and oversize lines are never returned.
func ParseSetupError(output []byte) string {
	code := ""
	for _, line := range bytes.Split(output, []byte("\n")) {
		line = bytes.TrimSuffix(line, []byte("\r"))
		if len(line) > setupErrorLineLimit || !bytes.HasPrefix(line, []byte(SetupErrorPrefix)) {
			continue
		}
		if candidate := string(line[len(SetupErrorPrefix):]); SetupErrorCodes[candidate] {
			code = candidate
		}
	}
	return code
}
