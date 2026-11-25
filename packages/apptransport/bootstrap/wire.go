package bootstrap

import "time"

// Job contains public provisioning material only. The gateway keeps its private key in memory.
type Job struct {
	ID          string    `json:"id"`
	State       string    `json:"state"`
	IP          string    `json:"ip"`
	Port        int       `json:"port"`
	Account     string    `json:"account"`
	Fingerprint string    `json:"fingerprint"`
	Script      string    `json:"script"`
	ExpiresAt   time.Time `json:"expires_at"`
	// HostKeyAttestation tells the gateway that the control plane verifies the management host key from an
	// attestation produced by the one-time authorization command (SA-UX-2). Fingerprint may then be empty. Older
	// gateways ignore the field and keep requiring Fingerprint.
	HostKeyAttestation bool `json:"host_key_attestation,omitempty"`
	// SetupErrorCodes tells the gateway that the control plane accepts Report.SetupError (SA-UX-3). Older gateways
	// ignore the field; a newer gateway sends SetupError only when it is set, because older control planes decode
	// reports strictly.
	SetupErrorCodes bool `json:"setup_error_codes,omitempty"`
}
type Report struct {
	PublicKey string  `json:"public_key,omitempty"`
	Result    string  `json:"result,omitempty"`
	Setup     *Result `json:"setup,omitempty"`
	// Sent only when the job advertised HostKeyAttestation (the control plane decodes reports strictly).
	HostKeyAttestation bool   `json:"host_key_attestation,omitempty"`
	HostKey            string `json:"host_key,omitempty"`
	Attestation        string `json:"attestation,omitempty"`
	// SetupError is an allow-listed SetupErrorCodes code, sent only with Result "setup_failed" and only when the job
	// advertised SetupErrorCodes. Never free text from the target.
	SetupError string `json:"setup_error,omitempty"`
}
type Result struct {
	Version         int      `json:"version"`
	OrgID           string   `json:"org_id"`
	ServerID        string   `json:"server_id"`
	HostFingerprint string   `json:"host_fingerprint"`
	SSHPort         int      `json:"ssh_port"`
	Accounts        []string `json:"accounts"`
}

// AttestationPrefix starts the single line the target's launcher prints before running the installer.
const AttestationPrefix = "TUNNEX HOST KEY ATTESTATION "
