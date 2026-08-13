// Package cli implements the tunnex CLI: login (loopback + device-code
// fallback), logout, device creation (the one-time config capture), and the
// wg-quick up/down wrapper.
package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Credential is the locally-stored CLI credential (0600). The token is the
// only secret; everything else is display metadata.
type Credential struct {
	Server      string    `json:"server"`
	Token       string    `json:"token"`
	Fingerprint string    `json:"fingerprint"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// StateDir resolves the CLI state directory (~/.config/tunnex, XDG-aware).
func StateDir() (string, error) {
	if v := os.Getenv("TUNNEX_STATE_DIR"); v != "" {
		return v, nil
	}
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "tunnex"), nil
}

func credentialPath() (string, error) {
	dir, err := StateDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "credential.json"), nil
}

// ConfigPath is where the WireGuard device config lives (0600).
func ConfigPath() (string, error) {
	dir, err := StateDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "device.conf"), nil
}

// WriteFileAtomic0600 writes data to path with 0600 permissions via a same-dir
// temp file + rename: the file is never observable partially written or with
// looser permissions (the browser's ~/Downloads drop is the anti-pattern).
func WriteFileAtomic0600(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) //nolint:errcheck // no-op after successful rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// SaveCredential persists the credential (atomic, 0600).
func SaveCredential(c Credential) error {
	p, err := credentialPath()
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return WriteFileAtomic0600(p, b)
}

// LoadCredential reads the stored credential; ErrNotLoggedIn if absent.
var ErrNotLoggedIn = errors.New("not logged in — run 'tunnex login'")

func LoadCredential() (Credential, error) {
	p, err := credentialPath()
	if err != nil {
		return Credential{}, err
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return Credential{}, ErrNotLoggedIn
	}
	if err != nil {
		return Credential{}, err
	}
	var c Credential
	if err := json.Unmarshal(b, &c); err != nil {
		return Credential{}, fmt.Errorf("corrupt credential file %s: %w", p, err)
	}
	return c, nil
}

// DeleteCredential removes the local credential (idempotent).
func DeleteCredential() error {
	p, err := credentialPath()
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
