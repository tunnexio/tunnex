package licence

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// ⭐ THE CROSS-REPO GOLDEN VECTOR.
//
// The signer is TypeScript in `tunnex-web`; this verifier is Go. They must agree BYTE FOR BYTE on the wire
// format and they cannot import each other.
//
// ⛔ THIS LITERAL IS HAND-MAINTAINED AND SO IS ITS TWIN (tunnex-web/src/lib/golden.test.ts). It is never
// generated, never shared through a package, and never fetched. Derive one from the other and the two files
// agree BY CONSTRUCTION — which is exactly the failure the twin canonical-hash goldens exist to prevent:
// "a check must be able to DISAGREE with the thing it checks; derivation removes that ability while looking
// like rigour" (docs/laws.md).
//
// ⚠ A FORMAT CHANGE MUST BREAK BOTH FILES, OR THE GUARD IS DECORATIVE. The pain of updating two literals by
// hand IS the mechanism. Anyone who finds that duplication annoying and factors it out has removed the only
// thing it was doing.
//
// The vector is deliberately awkward: a NULL gateway ceiling (unlimited), a UNICODE domain, and an expiry
// far in the future — because the disagreements that survive between two languages are encoding ones, not
// happy-path ones.
// ⚠ REGENERATED IN S12.1 when `tier` entered the wire format, and TRANSCRIBED BY HAND from the tunnex-web
// twin — never derived from it, never shared through a package. If only one side had been updated the
// other would be red right now, which is the entire reason two literals exist.
// goldenKeys is the golden vector's OWN key set.
//
// ⛔ THE GOLDEN KID IS NO LONGER IN TrustedKeys, AND THAT IS THE POINT. Its private half is a published
// test seed, so trusting it in production meant anyone could mint themselves a Scale licence. The vector
// still proves what it always proved — that this repo's Go verifier and tunnex-web's TS signer agree
// byte-for-byte — because the guard is about the FORMAT, not about which keys ship.
//
// ⚠ It verifies through the same `Verify` production uses; only the key set differs.
func goldenKeys() map[string]ed25519.PublicKey {
	b, err := base64.RawURLEncoding.DecodeString(GoldenPublicKey)
	if err != nil || len(b) != ed25519.PublicKeySize {
		panic("golden public key is malformed")
	}
	return map[string]ed25519.PublicKey{GoldenKid: ed25519.PublicKey(b)}
}

const goldenWire = "tnxl_eyJ2IjoxLCJraWQiOiJrLWdvbGRlbi0xIiwiaWQiOiIxMTExMTExMS0yMjIyLTMzMzMtNDQ0NC01NTU1NTU1NTU1NTUiLCJkb20iOiJtw7xuY2hlbi1nbWJoLmV4YW1wbGUiLCJ0aWVyIjoic2NhbGUiLCJiYW5kIjoic2NhbGUiLCJndyI6bnVsbCwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjQxMDI0NDQ4MDB9.lvAsH4hNbeLb-GU9RvYZbvI0IoH_HMWc6Mx2Felw39rmFtZN-Su_dM8P3ShS0K-tYWJ8TFILAuH2dVz5ki1lAw"

func TestGoldenVectorVerifiesAndYieldsExactClaims(t *testing.T) {
	// ⚠ Verified through TrustedKeys — the SAME path production uses. A test-only key map here would let
	// the shipped set drift from the one the vector proves.
	res, err := Verify(goldenKeys(), goldenWire)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.OK {
		t.Fatalf("⛔ THE GOLDEN VECTOR DOES NOT VERIFY (%s).\n\nEither this Go verifier or the TypeScript "+
			"signer has changed the wire format. Both literals must be updated together, BY HAND — and if "+
			"only one side changed, THAT IS THE BUG this vector exists to catch.", res.Reason)
	}

	c := res.Claims
	if c.Version != 1 {
		t.Errorf("v = %d, want 1", c.Version)
	}
	if c.Kid != "k-golden-1" {
		t.Errorf("kid = %q, want k-golden-1", c.Kid)
	}
	if c.ID != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("id = %q", c.ID)
	}
	// ⚠ UNICODE: the signer emits UTF-8 inside JSON; a verifier that mangled the encoding would still
	// verify the signature (it is over bytes) and then hand back a corrupted domain.
	if c.Domain != "münchen-gmbh.example" {
		t.Errorf("dom = %q, want münchen-gmbh.example", c.Domain)
	}
	if c.Tier != "scale" {
		t.Errorf("tier = %q, want scale", c.Tier)
	}
	if c.Band != "scale" {
		t.Errorf("band = %q, want scale", c.Band)
	}
	// ⛔ NULL IS UNLIMITED, and it must arrive as nil rather than 0. A verifier that decoded null as zero
	// would report the most permissive band as the most restrictive one.
	if c.Gateways != nil {
		t.Errorf("gw = %v, want nil (unlimited)", *c.Gateways)
	}
	if c.IssuedAt != 1700000000 {
		t.Errorf("iat = %d", c.IssuedAt)
	}
	if c.ExpiresAt != 4102444800 {
		t.Errorf("exp = %d", c.ExpiresAt)
	}
}

// ⛔ THE VECTOR MUST BE ABLE TO FAIL. A golden that only ever passes is indistinguishable from one that
// checks nothing, so this mutates the wire and asserts each mutation is caught.
func TestGoldenVectorRejectsTampering(t *testing.T) {
	body := goldenWire[len(Prefix):strings.IndexByte(goldenWire, '.')]

	for _, tc := range []struct {
		name string
		wire string
		want Reason
	}{
		// ⚠ The replacement must DIFFER from what is there. An earlier version of this table appended "Aw"
		// — which is exactly how the vector already ends — so the "mutation" mutated nothing and the case
		// passed by not being a case. A mutation you did not verify applied is not a mutation.
		{"a flipped signature byte", goldenWire[:len(goldenWire)-2] + "Bw", ReasonBadSignature},
		{"truncated in transit", goldenWire[:len(goldenWire)-20], ReasonBadSignature},
		{"no prefix", strings.TrimPrefix(goldenWire, Prefix), ReasonMalformed},
		{"no signature segment", Prefix + body, ReasonMalformed},
		{"empty", "", ReasonMalformed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := Verify(goldenKeys(), tc.wire)
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if res.OK {
				t.Fatal("⛔ a tampered key VERIFIED — the signature is not covering what it must")
			}
			if res.Reason != tc.want {
				t.Errorf("reason = %q, want %q", res.Reason, tc.want)
			}
		})
	}
}

// ⛔ AN UNKNOWN kid IS A REFUSAL, NEVER A FALLBACK TO "the only key we have".
//
// This is the mutation that turns a key SET back into a single key while every other test stays green: a
// verifier that falls back accepts a key signed by a RETIRED — possibly compromised — kid, and dropping a
// kid from the set then stops nothing.
func TestUnknownKidIsRefusedNeverFallenBackFrom(t *testing.T) {
	// The golden key under a DIFFERENT kid: the signature is valid, the kid is not trusted.
	keys := map[string]ed25519.PublicKey{"some-other-kid": goldenKeys()[GoldenKid]}

	res, err := Verify(keys, goldenWire)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.OK {
		t.Fatal("⛔ A KEY SIGNED UNDER AN UNTRUSTED kid WAS ACCEPTED. The set has silently become a single " +
			"key, and retiring a kid now stops nothing.")
	}
	if res.Reason != ReasonUnknownKid {
		t.Errorf("reason = %q, want %q", res.Reason, ReasonUnknownKid)
	}
}

func TestExpiryIsReportedNotEnforced(t *testing.T) {
	res, _ := Verify(goldenKeys(), goldenWire)
	// ⚠ The claims are readable regardless of the clock — expiry is a fact ABOUT A CLOCK, not about the
	// signature, and S12.2 gates nothing on it.
	if !res.OK {
		t.Fatal("a valid key must verify irrespective of expiry")
	}
	if res.Claims.Expired(time.Unix(1700000001, 0)) {
		t.Error("not expired at iat+1")
	}
	if !res.Claims.Expired(time.Unix(4102444801, 0)) {
		t.Error("expired one second after exp")
	}
}

func TestEmptyKeySetIsABuildErrorNotAKeyProblem(t *testing.T) {
	_, err := Verify(nil, goldenWire)
	if err == nil {
		t.Fatal("an empty trusted set must be a loud build error — a deployment that cannot verify " +
			"anything must not look like a deployment holding a bad key")
	}
}
