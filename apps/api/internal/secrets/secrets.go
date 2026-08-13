// Package secrets implements first-boot bootstrap of the platform's roots of
// trust: the master encryption key, the session-signing secret, and the
// WireGuard server keypair.
//
// Security contract (S0.3):
//   - Each secret is generated once, on first boot, and persisted with 0600
//     permissions on a dedicated volume owned by the API's runtime uid.
//   - Bootstrap is idempotent: an existing, readable secret is loaded as-is.
//   - It NEVER silently regenerates. If a secret file exists but is unreadable
//     or malformed, bootstrap fails loudly. Regenerating the master key would
//     render every value previously sealed under it permanently undecryptable —
//     the one failure mode this package must make impossible.
package secrets

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
)

const (
	masterKeyFile     = "master.key"
	sessionSecretFile = "session.key"

	secretPerm = 0o600
	dirPerm    = 0o700
)

// Secrets holds the decoded roots of trust loaded at startup.
//
// Note: there is intentionally NO WireGuard server key here. In the S3.2
// architecture the tunnex-node agent GENERATES its own WG keypair locally (the
// private key never leaves the node); the control plane stores only pubkeys. The
// S0.3-era bootstrapped WG server key was vestigial and has been removed.
type Secrets struct {
	MasterKey     []byte // 32 bytes — AES-256 key for the Sealer
	SessionSecret []byte // 32 bytes — cookie/session signing
	// GeneratedAny is true if any secret was created on this boot (first boot).
	GeneratedAny bool
}

// ExternalSource is an operator-provided root of trust that PRE-EMPTS the volume
// file (S10.1 externalization — an ephemeral K8s pod can't rely on a volume-
// persisted key). File (a mounted secret path) is the PREFERRED shape — it is the
// same on-disk form the volume already uses; Value (inline base64 via env) is the
// documented FALLBACK: env leaks through process listings, crash dumps, and
// `kubectl describe` on the pod spec, so a mounted file is safer.
//
// If EITHER field is set the source is AUTHORITATIVE: a read or parse failure is
// FATAL, never a fall-through to the volume. Falling back would load or generate a
// DIFFERENT key, orphaning every value previously sealed under the real one — the
// one failure mode this package must make impossible.
type ExternalSource struct {
	File  string
	Value string
}

func (e ExternalSource) set() bool { return e.File != "" || e.Value != "" }

// ExternalSecrets carries the operator-provided master and session sources. An
// empty value for a secret means "use the volume file" (the self-hosted default).
type ExternalSecrets struct {
	Master  ExternalSource
	Session ExternalSource
}

// LoadOrInit loads existing secrets from dir, generating any that are absent
// (the self-hosted default: no external sources). It fails loudly (never
// regenerates) on unreadable or malformed files.
func LoadOrInit(dir string) (*Secrets, error) {
	return LoadOrInitExt(dir, ExternalSecrets{})
}

// LoadOrInitExt resolves each root of trust from its external source (if set,
// authoritative + never written) or the volume file (load-or-init). It touches
// the volume ONLY for secrets whose external source is unset — so a fully-
// external deployment can mount a read-only secrets dir or none at all.
func LoadOrInitExt(dir string, ext ExternalSecrets) (*Secrets, error) {
	if !ext.Master.set() || !ext.Session.set() {
		if err := os.MkdirAll(dir, dirPerm); err != nil {
			return nil, fmt.Errorf("create secrets dir %q: %w", dir, err)
		}
	}

	s := &Secrets{}

	master, genMaster, err := resolveKey("master", ext.Master, filepath.Join(dir, masterKeyFile), crypto.KeySize)
	if err != nil {
		return nil, err
	}
	s.MasterKey = master

	session, genSession, err := resolveKey("session", ext.Session, filepath.Join(dir, sessionSecretFile), 32)
	if err != nil {
		return nil, err
	}
	s.SessionSecret = session

	s.GeneratedAny = genMaster || genSession
	return s, nil
}

// resolveKey uses the external source when set (authoritative, never writes) and
// otherwise loads-or-inits the volume file. generated is true only on a volume
// init — an externally-provided key is never "generated" here.
func resolveKey(name string, ext ExternalSource, volPath string, n int) (key []byte, generated bool, err error) {
	if ext.set() {
		k, e := loadExternalKey(name, ext, n)
		return k, false, e
	}
	return loadOrCreateKey(volPath, n)
}

// loadExternalKey reads an authoritative operator-provided key. File is preferred;
// a set-but-broken source is FATAL (no fall-through to the volume, which would
// orphan sealed data).
func loadExternalKey(name string, ext ExternalSource, n int) ([]byte, error) {
	if ext.File != "" {
		data, err := os.ReadFile(ext.File)
		if err != nil {
			return nil, fmt.Errorf(
				"external %s key file %q is set but unreadable; refusing to fall back to a volume key "+
					"(a different key would orphan all data sealed under the real one): %w",
				name, ext.File, err,
			)
		}
		return decodeExternalKey(name, "file "+ext.File, data, n)
	}
	return decodeExternalKey(name, "env value", []byte(ext.Value), n)
}

// decodeExternalKey validates an external key is well-formed base64 of exactly n
// bytes, failing loudly (never silently truncating or padding).
func decodeExternalKey(name, origin string, data []byte, n int) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("external %s key (%s): malformed base64: %w", name, origin, err)
	}
	if len(decoded) != n {
		return nil, fmt.Errorf("external %s key (%s): expected %d bytes, got %d", name, origin, n, len(decoded))
	}
	return decoded, nil
}

// loadOrCreateKey returns a decoded n-byte random key, generating it if missing.
func loadOrCreateKey(path string, n int) (key []byte, generated bool, err error) {
	data, readErr := os.ReadFile(path)
	if readErr == nil {
		decoded, decErr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
		if decErr != nil {
			return nil, false, refuseRegen(path, fmt.Errorf("malformed base64: %w", decErr))
		}
		if len(decoded) != n {
			return nil, false, refuseRegen(path, fmt.Errorf("expected %d bytes, got %d", n, len(decoded)))
		}
		return decoded, false, nil
	}
	if !errors.Is(readErr, os.ErrNotExist) {
		// Exists but unreadable (e.g. permissions), or an I/O error.
		return nil, false, refuseRegen(path, readErr)
	}

	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return nil, false, fmt.Errorf("generate key %q: %w", path, err)
	}
	if err := writeSecret(path, base64.StdEncoding.EncodeToString(buf)); err != nil {
		return nil, false, err
	}
	return buf, true, nil
}

// refuseRegen wraps an error to make the "never regenerate" contract explicit
// in logs and to operators.
func refuseRegen(path string, cause error) error {
	return fmt.Errorf(
		"secret %q exists but could not be used; refusing to regenerate "+
			"(a new key would orphan all data encrypted under the old one): %w",
		path, cause,
	)
}

// writeSecret writes a secret with 0600 permissions. The file inherits the
// running process's uid; the compose volume is pre-owned by that uid so the
// files land as 0600 owned by uid 10001 (see api.Dockerfile / docker-compose).
func writeSecret(path, contents string) error {
	if err := os.WriteFile(path, []byte(contents+"\n"), secretPerm); err != nil {
		return fmt.Errorf("write secret %q: %w", path, err)
	}
	// Re-assert perms in case a umask widened them.
	if err := os.Chmod(path, secretPerm); err != nil {
		return fmt.Errorf("chmod secret %q: %w", path, err)
	}
	return nil
}

// Fingerprint returns a short, non-reversible identifier for a secret, safe to
// log. Used to prove across restarts that a key was reused, not regenerated.
func Fingerprint(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:6])
}
