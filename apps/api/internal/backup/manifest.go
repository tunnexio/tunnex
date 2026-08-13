// Package backup implements the control plane's backup manifest and its restore-time verification (S11 D2).
//
// WHAT A BACKUP IS: a Postgres dump PLUS this manifest. Nothing else — and that is a conclusion from the
// schema, not a scoping decision. Gateway and device WireGuard private keys are NOT control-plane state
// ("the private key never leaves the node… the control plane stores pubkeys only", 0009_node_wg; "there is
// deliberately NO private_key column", 0010_devices), so a CP backup CANNOT carry them. The roadmap's
// "DB + master key + node-agent state (WG private keys on each gateway)" was misfiled: a backup must not
// promise a recovery it is structurally unable to perform.
//
// WHAT THE MASTER KEY GUARDS. These are sealed under it, and a wrong key makes every one unreadable:
//   - the AGENT CA private key — agents PIN this CA, so losing it ORPHANS THE FLEET: no certificate can ever
//     again be issued that an enrolled agent will trust;
//   - the OpenVPN CA private key and every issued client profile key;
//   - MFA/TOTP secrets (every enrolled user loses their second factor);
//   - SSO and IdP-sync client secrets.
//
// THE KEY IS NOT IN THE BACKUP — DELIBERATELY. A backup that carries its own key is equivalent to no
// encryption at rest for anyone who obtains the file, and backups are the most-copied, least-guarded artifact
// in any deployment (offsite storage, object buckets, a laptop). The whole purpose of sealing is that
// possessing the database is NOT ENOUGH. The manifest therefore stores a KEYED FINGERPRINT of the master key
// — HMAC-derived, never the key itself, and never reversible to it.
//
// DO NOT "HELPFULLY" ADD THE KEY HERE LATER. If a future change puts key material in the manifest, every
// backup ever taken becomes a full compromise of the sealed material it protects. The fingerprint exists so
// a restore can VERIFY the operator has the right key, not so the artifact can supply it.
package backup

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// ManifestVersion is the manifest schema version. It is checked on restore so a future format change fails
// loudly rather than being half-understood by an older binary.
const ManifestVersion = 1

// keyProbe is the fixed plaintext whose KEYED fingerprint identifies a master key. Fixed on purpose: the
// same key always yields the same fingerprint, so a restore can compare, while the fingerprint reveals
// nothing about the key (it is an HMAC under a subkey derived from that key, not a hash of it).
const keyProbe = "tunnex-master-key-identity"

// Fingerprinter is the crypto.Sealer capability this package needs. Narrow by intent: the manifest must be
// able to IDENTIFY a key and must never be able to seal or open with it.
type Fingerprinter interface {
	Fingerprint(plaintext []byte) string
}

// Manifest travels beside the database dump. It carries no secret material.
type Manifest struct {
	Version int       `json:"version"`
	TakenAt time.Time `json:"taken_at"`
	// MasterKeyFingerprint is a KEYED fingerprint (HMAC under a subkey derived from the master key), NEVER
	// the key and never a bare hash of it. It answers exactly one question at restore time: "is the key this
	// control plane has the key this backup's sealed data was written under?"
	MasterKeyFingerprint string `json:"master_key_fingerprint"`
	// SchemaVersion is the migration version the dump was taken at, so a restore into an older binary is
	// caught rather than discovered through confusing failures.
	SchemaVersion int64 `json:"schema_version"`
	// Note is free text for the operator (which environment, why taken).
	Note string `json:"note,omitempty"`
}

// KeyFingerprint returns the identity fingerprint for the master key behind s.
func KeyFingerprint(s Fingerprinter) string { return s.Fingerprint([]byte(keyProbe)) }

// NewManifest builds the manifest for a dump taken now.
func NewManifest(s Fingerprinter, schemaVersion int64, note string) Manifest {
	return Manifest{
		Version:              ManifestVersion,
		TakenAt:              time.Now().UTC(),
		MasterKeyFingerprint: KeyFingerprint(s),
		SchemaVersion:        schemaVersion,
		Note:                 note,
	}
}

func (m Manifest) Write(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(m)
}

func Read(r io.Reader) (Manifest, error) {
	var m Manifest
	if err := json.NewDecoder(r).Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("read manifest: %w", err)
	}
	return m, nil
}

// ErrKeyMismatch is the refusal that matters: this control plane's master key is NOT the one the backup's
// sealed data was written under.
var ErrKeyMismatch = errors.New("master key mismatch")

// Verify checks a manifest against the master key this control plane actually holds. It is called BEFORE a
// restore writes anything.
//
// THE LAW APPLIED AT THE RESTORE SEAM (S10.1: set-but-broken is fatal, never regenerate). The catastrophic
// outcome is not a failed restore — it is a restore that SUCCEEDS with the wrong key. That produces a control
// plane which looks healthy, serves requests, and cannot read its own agent CA: every enrolled gateway is
// orphaned, and the operator discovers it later, from the fleet, with the backup already restored over the
// evidence. So the check runs FIRST and refuses LOUDLY, naming both fingerprints, and no partial state is
// written. A restore that half-applies and then fails is worse than one that refuses.
func Verify(m Manifest, s Fingerprinter) error {
	if m.Version != ManifestVersion {
		return fmt.Errorf("manifest version %d is not supported by this binary (expected %d) — "+
			"restore with a matching Tunnex version", m.Version, ManifestVersion)
	}
	if m.MasterKeyFingerprint == "" {
		return errors.New("manifest carries no master-key fingerprint: it cannot be verified, and restoring " +
			"blind risks a control plane that cannot read its own agent CA — refusing")
	}
	have := KeyFingerprint(s)
	if have != m.MasterKeyFingerprint {
		return fmt.Errorf("%w: this control plane's master key (fingerprint %s) is NOT the key this backup "+
			"was sealed under (fingerprint %s).\n\n"+
			"Restoring anyway would produce a control plane that starts, serves, and CANNOT READ ITS OWN "+
			"AGENT CA — every enrolled gateway would be orphaned and would have to re-enroll.\n"+
			"Restore the master key that belongs to this backup, then retry. The key is never contained in "+
			"the backup; it is the separate artifact you were asked to custody.",
			ErrKeyMismatch, have, m.MasterKeyFingerprint)
	}
	return nil
}
