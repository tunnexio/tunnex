package nodes

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
)

// RekeyIdentifier is HOW a re-key caller names itself, and re-key answers to exactly TWO kinds (S13.1 D10).
//
// WHY TWO, WRITTEN HERE SO NOBODY LATER "SIMPLIFIES" IT BACK TO ONE:
//
// The serial alone cannot survive a LOST RESPONSE. Re-key commits the new serial and the new public key, then
// answers; if that answer never arrives, the control plane holds a serial the agent never received. The agent
// retries with the serial from its stored certificate — which no row carries any more — and is refused forever. One
// dropped packet, and the only recovery is an operator minting a join token: a NEW node, site binding gone, devices
// needing re-issue.
//
// The key fingerprint survives it, because it names material the control plane RECORDED (0057) and the agent still
// holds. The agent persists its pending key BEFORE submitting, so after a lost response it can prove possession of
// the key the control plane now has on file and ask again — converging on the same identity instead of losing it.
//
// THE ALTERNATIVE THAT WAS REJECTED: a grace window on the previous serial. It reintroduces a TIME BOUND of exactly
// the kind D3 spent this epic removing — recovery working for an hour and then not, for reasons invisible from
// outside. The fingerprint adds a lookup key rather than a new secret, and a public-key fingerprint is at least as
// unguessable as a serial, which was D9's whole criterion for choosing the serial over the node name.
//
// THE COST, STATED RATHER THAN DISCOVERED: an unauthenticated endpoint now answers to two lookup keys, so the
// uniform-refusal discipline must hold across BOTH — an unknown serial, an unknown fingerprint, a malformed
// fingerprint, both identifiers at once, neither, and an AMBIGUOUS fingerprint must all be indistinguishable to the
// caller. TestBothIdentifiersRefuseIndistinguishably is the guard.
type RekeyIdentifier struct {
	Kind  string // "cert_serial" | "key_fingerprint" — persisted with the challenge so the two cannot be mixed
	Value string
}

const (
	IdentifierCertSerial     = "cert_serial"
	IdentifierKeyFingerprint = "key_fingerprint"
)

// keyFingerprintHexLen is the length of a SHA-256 digest in lowercase hex. Exact — see ParseRekeyIdentifier.
const keyFingerprintHexLen = 64

// maxSerialLen bounds the serial a caller may name. The body cap already bounds the request; this bounds what
// reaches a database parameter.
const maxSerialLen = 100

// isPrintableASCII refuses control bytes — NUL above all, which Postgres rejects in a text value and which
// therefore turned an attacker-controlled field into a 500.
func isPrintableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// ParseRekeyIdentifier turns the wire's two optional fields into ONE identifier, or refuses.
//
// EXACTLY ONE, and the refusal for "both" is the same as the refusal for "neither" and for "malformed". A caller who
// could tell those apart could learn which identifier kinds a control plane supports and what shape they take, and
// while neither is a secret, an endpoint that answers questions is an endpoint that gets asked.
//
// The fingerprint must be EXACTLY 64 lowercase hex characters — never a prefix, never a case-insensitive or trimmed
// match. A prefix match would let a caller narrow the fleet's key space one request at a time, which is the
// enumeration property D9 chose the serial over the node name to avoid. Normalising case here would be a small
// kindness with the same effect as accepting two spellings of an identity, so it does not.
func ParseRekeyIdentifier(certSerial, keyFingerprint string) (RekeyIdentifier, bool) {
	switch {
	case certSerial != "" && keyFingerprint != "":
		return RekeyIdentifier{}, false
	case certSerial != "":
		// THE VALUE IS VALIDATED, not just its presence (review pass 1 #12). A NUL byte — which the schema
		// explicitly permits, since it carries no pattern — reached a Postgres text bind and came back as a raw
		// encoding error: a 500, distinguishable at a glance from the 403 every other refusal returns. Exact
		// sibling of the identifier_kind defect already fixed in rekey.go, one field over: the parser checked the
		// KIND and never the VALUE, and the serial branch inspected nothing at all.
		//
		// Serials are hex as this CA issues them; the check is deliberately a shade wider (printable, bounded) so
		// it refuses what breaks a bind without asserting a format the issuer might legitimately change.
		if len(certSerial) > maxSerialLen || !isPrintableASCII(certSerial) {
			return RekeyIdentifier{}, false
		}
		return RekeyIdentifier{Kind: IdentifierCertSerial, Value: certSerial}, true
	case keyFingerprint != "":
		if len(keyFingerprint) != keyFingerprintHexLen || !isLowerHex(keyFingerprint) {
			return RekeyIdentifier{}, false
		}
		return RekeyIdentifier{Kind: IdentifierKeyFingerprint, Value: keyFingerprint}, true
	default:
		return RekeyIdentifier{}, false
	}
}

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// KeyFingerprint is THE definition of the identifier: SHA-256 over the SPKI DER, lowercase hex.
//
// THREE IMPLEMENTATIONS EXIST AND ALL THREE ARE PINNED TO ONE GOLDEN VECTOR. This one (for logs and for the audit
// prefix), the DATABASE's generated column (which is what the lookup actually matches on — migration 0061), and the
// AGENT's, in a separate Go module that cannot import this one. Two of them are load-bearing and none of them can
// import the others, so `testKeyFingerprintGolden` is asserted in the CP unit tests, in an integration test against
// the generated column, and in the agent's own tests. That is how three implementations of one digest agree on
// purpose rather than by luck.
//
// Over the DER, not over the base64 text the column stores: a digest of an encoding changes when the encoding
// changes, and a key's identity must not depend on how it was written down.
func KeyFingerprint(spkiDER []byte) string {
	sum := sha256.Sum256(spkiDER)
	return hex.EncodeToString(sum[:])
}

// KeyFingerprintFromStored computes the identifier from cert_public_key as stored (base64 SPKI DER). Returns "" when
// the value is absent or not decodable — an unrecorded key matches nothing, which is the coverage limitation D1(a)
// keeps the join token for, not a failure to handle.
func KeyFingerprintFromStored(spkiB64 string) string {
	if spkiB64 == "" {
		return ""
	}
	der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(spkiB64))
	if err != nil {
		return ""
	}
	return KeyFingerprint(der)
}
