package licence

import "testing"

// ⛔ THE CROSS-REPO BAND GUARD. Its ABSENCE is how `gw: 20` reached a customer's inbox on a trial key.
//
// Two sources hold one set of numbers: `BANDS` in `tunnex-web/src/lib/licence.ts` (what the issuer MINTS)
// and `gatewayCeiling` here (what the product ENFORCES). Two repos, two languages, and until now nothing
// compared them — so the Go side could be corrected to `trial: 2` while the Worker kept minting 20, with
// both test suites green. That is exactly what happened.
//
// ⚠ THE GOLDEN VECTOR DOES NOT COVER THIS AND CANNOT. It proves the two sides agree on the wire FORMAT —
// field names, encoding, byte-for-byte output. It is a single *scale* key, so it never exercises the trial
// band, and it would be equally green with every number wrong.
//
// > ## ⛔ **A FORMAT GUARD IS NOT A VALUE GUARD. AGREEING ON WHERE THE NUMBER GOES SAYS NOTHING ABOUT THE
// > ## NUMBER.**
//
// ⭐ HAND-MAINTAINED IN BOTH REPOS, exactly like the golden vector, and for the same reason: the twin must
// be able to DISAGREE. Derive either side from the other — a shared package, a generated file, a fetch —
// and they agree by construction while looking like rigour (docs/laws.md).
//
// ⚠ THE PAIN OF EDITING TWO FILES BY HAND IS THE MECHANISM. A band change must break both, or the guard is
// decorative.
//
//	tunnex-web/src/lib/bands.test.ts  ← the twin. Change one, change both.
func TestBandsAgreeWithTheIssuer(t *testing.T) {
	// ⛔ TRANSCRIBED BY HAND from tunnex-web/src/lib/licence.ts `BANDS`. NEVER generated, never fetched.
	issuerMints := map[Tier]*int{
		TierTrial:   ptr(2),
		TierStarter: ptr(5),
		TierGrowth:  ptr(20),
		TierScale:   nil, // unlimited — `null` in the issuer, and never a sentinel
	}

	for tier, want := range issuerMints {
		got, known := GatewayCeilingFor(tier)
		if !known {
			t.Errorf("⛔ the issuer mints band %q and this build does not know it — every key sold under "+
				"that band reads as Community", tier)
			continue
		}
		switch {
		case want == nil && got != nil:
			t.Errorf("⛔ BAND %q: the issuer mints UNLIMITED, this build enforces %d. A customer who paid "+
				"for unlimited gateways is capped.", tier, *got)
		case want != nil && got == nil:
			t.Errorf("⛔ BAND %q: the issuer mints %d, this build enforces UNLIMITED. Every deployment on "+
				"that band is uncapped and nobody decided that.", tier, *want)
		case want != nil && got != nil && *want != *got:
			t.Errorf("⛔ BAND %q DISAGREES: the issuer mints gw=%d, this build enforces %d.\n\n"+
				"A key already in a customer's hands attests the issuer's number — `gw` is resolved at "+
				"mint and cannot be recalled. Whichever side is wrong, one of them is lying to a paying "+
				"customer.\n\nFix BOTH files, by hand: tunnex-web/src/lib/licence.ts BANDS and "+
				"apps/api/internal/licence/entitlements.go gatewayCeiling.", tier, *want, *got)
		}
	}

	// ⛔ SET EQUALITY THE OTHER WAY. A band this build knows and the issuer cannot mint is a tier the
	// pricing page may sell and nobody can be issued a key for — which is a live gap today for Starter,
	// Growth and Scale (the admin surface is trial-only).
	for tier := range gatewayCeiling {
		if tier == TierCommunity {
			continue // Community holds no key at all, so it is never a band
		}
		if _, ok := issuerMints[tier]; !ok {
			t.Errorf("⚠ this build knows band %q and the issuer's BANDS does not mint it", tier)
		}
	}
}
