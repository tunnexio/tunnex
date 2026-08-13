package licence

import (
	"crypto/ed25519"
	"encoding/base64"
)

// TrustedKeys is the SET of public keys this build accepts, keyed by kid.
//
// ⛔ COMPILED IN — not a file, not an env var, not configuration. BAKED AT BUILD TIME MEANS A ROTATION IS
// A RELEASE, and saying it any other way implies an operator could fix a signing-key compromise. They
// cannot: rotation is add-a-kid → ship → customers upgrade → issue under the new kid → later remove the
// old kid → ship again.
//
// ⭐ A SET RATHER THAN ONE KEY (D4, ruled) is what makes that sequence expressible at all. It does NOT
// make rotation cheap — keys minted under the old kid run to their own expiry, the installed base still
// upgrades twice, and a compromise remains undetectable because deployments never call home.
//
// ⚠ THE GOLDEN KEY IS PRESENT DELIBERATELY. It signs the cross-repo golden vector and nothing else; its
// private half is a published test seed. It is harmless — no real key is ever minted under it, and its
// presence is what lets the vector be verified by the SAME code path production uses, rather than by a
// test-only shim that could drift from it.
var TrustedKeys = mustKeys(map[string]string{
	// kid       base64url of the raw 32-byte Ed25519 public key (a JWK "x" value)
	ProductionKid: "UyvvFIJJzBr1PLYyRFr4Z_h2grIwv_jetjdI8KQQq4c",
})

// ProductionKid is the kid the live issuer signs with.
//
// ⛔ MEASURED, NOT ASSUMED: `issued_keys.kid` in the live D1 reads `k2026` for the one real key ever minted.
// The public half above is the `x` of the Worker's `SIGNING_PUBLIC_JWK`, supplied by the founder — the
// secret itself is write-only and appears in neither repo, which is why this could not be derived here.
//
// ⭐ A PUBLIC KEY IN A PUBLIC REPO IS NOT A LEAK. It is the point: D4 ruled a baked-in SET precisely so a
// verifier needs no network and no configuration. Publishing it changes nothing an attacker could do —
// verification keys are for checking signatures, never for making them.
const ProductionKid = "k2026"

// ⛔ `k-golden-1` WAS IN THIS SET AND HAS BEEN REMOVED. IT WAS A LIVE VULNERABILITY.
//
// The golden vector's signing key is a PUBLISHED TEST SEED — `tunnex-web/src/lib/golden.test.ts` carries
// its private `d` in plain text, deliberately, so two repos can assert one frozen vector without sharing
// code. That is correct for a test fixture and catastrophic for a trusted signer.
//
// > ## ⛔ **WHILE THIS KID WAS TRUSTED, ANYONE WITH THE PUBLIC REPO COULD MINT THEMSELVES A SCALE LICENCE —
// > ## UNLIMITED GATEWAYS, ANY EXPIRY — AND EVERY SHIPPED BUILD WOULD HAVE ACCEPTED IT.**
//
// ⚠ IT WAS NOT A THEORETICAL HOLE. It was exercised: a Growth key was minted with that seed in one command,
// installed on a running deployment, and flipped `/meta` to `enterprise`. The comment beside it read
// "It is harmless — no real key is ever minted under it", which was a statement of INTENT that nothing
// enforced, and one command falsified.
//
// ⭐ AND THE GOLDEN VECTOR STILL VERIFIES, which is what makes the removal free: `golden_test.go` supplies
// its own single-entry key set, exactly as `TestUnknownKidIsRefused` already did. The cross-repo guard is
// unchanged; what is gone is production TRUST in a key whose private half is on the internet.
const GoldenKid = "k-golden-1"

// GoldenPublicKey is the golden vector's verifying key, kept for TESTS ONLY and deliberately NOT in
// TrustedKeys. ⚠ Referencing it from a non-test file would silently re-trust the published seed.
const GoldenPublicKey = "2XAC4iGhtpJ-P3VxrW-6_OU9XHF-T2DXvDGlw6JTv_s"

func mustKeys(raw map[string]string) map[string]ed25519.PublicKey {
	out := make(map[string]ed25519.PublicKey, len(raw))
	for kid, b64 := range raw {
		b, err := base64.RawURLEncoding.DecodeString(b64)
		if err != nil || len(b) != ed25519.PublicKeySize {
			// A malformed literal is a BUILD defect, and failing at init is the only honest moment:
			// discovering it when a customer pastes a key means the deployment shipped unable to verify.
			panic("licence: malformed trusted key for kid " + kid)
		}
		out[kid] = ed25519.PublicKey(b)
	}
	return out
}
