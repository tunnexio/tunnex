package nodes

import (
	"encoding/base64"
	"strings"
	"testing"
)

// The SAME golden vector the agent pins (apps/node/internal/control/fingerprint_test.go) and the SAME one the
// integration test asserts against the database's GENERATED column. Three implementations, two Go modules that
// cannot import each other plus one SQL expression — so they agree on purpose rather than by luck.
const (
	goldenSPKIB64     = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxdvgFUdNnFAg1ksdPieol2FK5vt7iQ6oI9AtqA2wZW7tet/f7tRS2xSz4vpUCHJGb12x3auzeVf3/7q/QL9/XgrWh5MBp1wVRuKQG/I86Rr6fp4070xmBhXk2NjmT8CH+honySylp2nJ3LAFFtHPwoV/zyRqpB9BS0iuooFS3Pr+HbEtEX91I5i7Z0ymzwjdnbMVd5YHCf2JjODV1uGpRlf8HoG9kA4UOR3Eki4B69nl3kA2uz+8g4Ka20icXAwaNjMEq8R6oeDW1wmu+ZXPS9YnVYSvEntwDzPz9Kkal372q9Ojt03W27E2X6ouXTlT1KblEXvv73bV6C7VuvCB6QIDAQAB"
	goldenFingerprint = "1e98cb7cd8f91d59b2f90727f5543f9c9e5413332b160c93534c283ea3bdba94"
)

func TestKeyFingerprintMatchesTheGoldenVector(t *testing.T) {
	der, err := base64.StdEncoding.DecodeString(goldenSPKIB64)
	if err != nil {
		t.Fatal(err)
	}
	if got := KeyFingerprint(der); got != goldenFingerprint {
		t.Fatalf("the fingerprint construction changed.\n got %s\nwant %s\n\nThe AGENT computes this identifier "+
			"independently and the DATABASE matches on a generated column computing it a third time. A change made "+
			"in one place and not the others makes re-key-by-fingerprint match nothing, and that failure is "+
			"indistinguishable from 'this gateway cannot be recovered'.", got, goldenFingerprint)
	}
	if got := KeyFingerprintFromStored(goldenSPKIB64); got != goldenFingerprint {
		t.Fatalf("the stored (base64) form must yield the same digest as the DER form; got %s", got)
	}
}

// TestAuditFingerprintIsAPrefixOfTheIdentifier — the redefinition (D10) asserted rather than assumed.
//
// `old_key_fingerprint` in an audit row used to digest the base64 TEXT; it now digests the SPKI DER, so an operator
// can match an audit row against the identifier an agent sent. If these two ever diverge again, the audit trail
// starts naming keys in a vocabulary nothing else speaks.
func TestAuditFingerprintIsAPrefixOfTheIdentifier(t *testing.T) {
	short := keyFingerprint(goldenSPKIB64)
	if !strings.HasPrefix(goldenFingerprint, short) {
		t.Fatalf("the audit fingerprint %q must be a prefix of the identifier %q", short, goldenFingerprint)
	}
	if len(short) != 12 {
		t.Fatalf("audit fingerprint must stay 12 hex for at-a-glance comparison; got %d", len(short))
	}
	if keyFingerprint("") != "none" {
		t.Fatal("an unrecorded key must render as 'none', never as an empty string that reads like a real value")
	}
	if keyFingerprint("!!!not base64!!!") != "none" {
		t.Fatal("an undecodable stored key must render as 'none' rather than a digest of garbage")
	}
}

// TestParseRekeyIdentifierAcceptsEXACTLYOne — the wire contract, and every refusal is the SAME refusal.
//
// A caller who could tell "both identifiers" from "malformed fingerprint" from "unknown node" would learn the shape
// of the identifier space one request at a time. That is the property D9 chose the serial over the node name for, and
// D10 has to preserve it across a second identifier rather than spend it.
func TestParseRekeyIdentifierAcceptsEXACTLYOne(t *testing.T) {
	if _, ok := ParseRekeyIdentifier("abc123", ""); !ok {
		t.Fatal("a serial alone must be accepted")
	}
	if id, ok := ParseRekeyIdentifier("", goldenFingerprint); !ok || id.Kind != IdentifierKeyFingerprint {
		t.Fatal("a well-formed fingerprint alone must be accepted, as the fingerprint kind")
	}
	if _, ok := ParseRekeyIdentifier("abc123", goldenFingerprint); ok {
		t.Fatal("BOTH identifiers must be refused: two claims about who is asking is not one identity, and picking " +
			"one would let a caller probe with a valid identifier while smuggling a guess in the other")
	}
	if _, ok := ParseRekeyIdentifier("", ""); ok {
		t.Fatal("neither identifier must be refused")
	}
}

// TestFingerprintLookupIsEXACTMatchOnly — the ruled condition, red'd.
//
// Never a prefix, never a fuzzy or normalised match. A prefix match would let a caller narrow the fleet's key space
// one request at a time — and unlike a wrong guess, a PARTIAL match that succeeded would tell them they were close.
func TestFingerprintLookupIsEXACTMatchOnly(t *testing.T) {
	for _, bad := range []struct{ value, why string }{
		{goldenFingerprint[:32], "a 32-char PREFIX of a real fingerprint must be refused — a prefix match is an " +
			"enumeration primitive, and one that reports 'warmer'"},
		{goldenFingerprint + "00", "a longer-than-64 value must be refused rather than truncated to a match"},
		{strings.ToUpper(goldenFingerprint), "UPPERCASE must be refused rather than normalised: accepting two " +
			"spellings of an identity is how one identity becomes two"},
		{" " + goldenFingerprint, "a leading space must be refused rather than trimmed"},
		{goldenFingerprint[:63] + "g", "a non-hex character must be refused"},
		{strings.Repeat("0", 64), "a well-formed fingerprint nobody holds is accepted HERE and refused at the " +
			"lookup — shape validity must not be observable separately from existence"},
	} {
		_, ok := ParseRekeyIdentifier("", bad.value)
		if bad.value == strings.Repeat("0", 64) {
			if !ok {
				t.Errorf("a well-formed unknown fingerprint must parse (and be refused later): %s", bad.why)
			}
			continue
		}
		if ok {
			t.Errorf("ParseRekeyIdentifier accepted %q: %s", bad.value, bad.why)
		}
	}
}

// TestSerialVALUEIsValidatedNotJustPresent — review pass 1 #12.
//
// A NUL byte in cert_serial reached a Postgres text bind and returned a RAW encoding error: a 500, visibly
// different from the 403 every other refusal returns, on an unauthenticated route. Exact sibling of the
// identifier_kind defect already fixed one file over — the parser validated the KIND and never the VALUE, and the
// serial branch inspected nothing at all. The schema permits it, deliberately, because adding a pattern would
// create a 400-vs-403 split of its own.
func TestSerialVALUEIsValidatedNotJustPresent(t *testing.T) {
	for _, bad := range []struct{ value, why string }{
		{"abc\x00def", "a NUL byte is what Postgres rejects in a text value, turning an attacker-controlled field " +
			"into a 500 that is distinguishable at a glance from the uniform refusal"},
		{"abc\ndef", "a newline is a control byte and has no business in a certificate serial"},
		{strings.Repeat("a", maxSerialLen+1), "an unbounded serial reaches a database parameter"},
		{"abc\x7fdef", "DEL is a control byte"},
	} {
		if _, ok := ParseRekeyIdentifier(bad.value, ""); ok {
			t.Errorf("ParseRekeyIdentifier accepted %q: %s", bad.value, bad.why)
		}
	}
	// A real serial still parses — the check must not be so narrow that it refuses what this CA issues.
	if _, ok := ParseRekeyIdentifier("bb79126b0ae42e44d477931c28256b31", ""); !ok {
		t.Fatal("a hex serial as this CA issues them must be accepted")
	}
}
