package serveraccess

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/tunnexio/tunnex/packages/apptransport/bootstrap"
)

// Host-key attestation (SA-UX-2 item 2). The one-time authorization command carries a per-job key K over the
// administrator's trusted channel; root on the real server reads its ed25519 host keys and the forced command
// prints HMAC(K, job, keys). The gateway reports the host key it actually saw plus that line; only a party holding
// K can bind a host key to this job. K never leaves the control plane except inside the authorization command.

const attestationContext = "tunnex-enroll-host-keys-v1\n"

var errAttestation = errors.New("host key attestation failed")

func newAttestationKey() (string, error) {
	k := make([]byte, 32)
	if _, e := rand.Read(k); e != nil {
		return "", e
	}
	return base64.StdEncoding.EncodeToString(k), nil
}

type attestationLine struct {
	V        int      `json:"v"`
	Job      string   `json:"job"`
	HostKeys []string `json:"host_keys"`
	MAC      string   `json:"mac"`
}

func attestationMAC(key []byte, job string, hostKeys []string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(attestationContext + job + "\n" + strings.Join(hostKeys, "\n")))
	return m.Sum(nil)
}

// verifyHostKeyAttestation accepts seen only if the attestation was produced with key for job and lists seen.
func verifyHostKeyAttestation(encodedKey, job, seen, raw string) error {
	key, e := base64.StdEncoding.DecodeString(encodedKey)
	if e != nil || len(key) != 32 || !validFingerprint(seen) || len(raw) > 4096 {
		return errAttestation
	}
	raw = strings.TrimPrefix(strings.TrimSpace(raw), bootstrap.AttestationPrefix)
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	var line attestationLine
	if decoder.Decode(&line) != nil || line.V != 1 || line.Job != job || len(line.HostKeys) < 1 || len(line.HostKeys) > 8 {
		return errAttestation
	}
	if !slices.IsSorted(line.HostKeys) {
		return errAttestation
	}
	for _, fp := range line.HostKeys {
		if !validFingerprint(fp) {
			return errAttestation
		}
	}
	mac, e := hex.DecodeString(line.MAC)
	if e != nil || !hmac.Equal(mac, attestationMAC(key, job, line.HostKeys)) {
		return errAttestation
	}
	if !slices.Contains(line.HostKeys, seen) {
		return errAttestation
	}
	return nil
}
