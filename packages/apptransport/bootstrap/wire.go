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
}
type Report struct {
	PublicKey string  `json:"public_key,omitempty"`
	Result    string  `json:"result,omitempty"`
	Setup     *Result `json:"setup,omitempty"`
}
type Result struct {
	Version         int      `json:"version"`
	OrgID           string   `json:"org_id"`
	ServerID        string   `json:"server_id"`
	HostFingerprint string   `json:"host_fingerprint"`
	SSHPort         int      `json:"ssh_port"`
	Accounts        []string `json:"accounts"`
}
