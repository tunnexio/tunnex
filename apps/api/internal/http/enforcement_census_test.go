package http

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/tunnexio/tunnex/apps/api/internal/licence"
)

// ⛔ THE SECOND CENSUS, AND IT ASKS THE QUESTION THE FIRST ONE CANNOT.
//
// `entitlement_census_test.go` asks: does every capability have a TIER RULING — has someone decided who
// pays for it. That is a question about the MAP.
//
// This one asks: does every paid capability have somewhere that REFUSES. That is a question about the
// CODE, and the two are completely independent. A feature can be perfectly dispositioned as Enterprise, in
// a map that is beautifully maintained, and be free to every deployment on earth because no line anywhere
// consults it. That is exactly the state this repo was in for six slices — `TestPaidCapabilitiesAreNotYetEnforced`
// existed to say so out loud — and nothing structural would ever have ended it.
//
// > ## ⛔ **A TIER MAP IS A STATEMENT OF INTENT. UNTIL SOMETHING READS IT, IT IS A PRICE LIST WITH NO TILL.**
//
// ⚠ AND THE SUBJECT IS THE CAPABILITY, NOT THE SHAPE. It would be far easier to assert "sso_handlers.go
// contains a licence check" — and that would pass forever after someone deleted the capability, renamed the
// file, or moved the gate somewhere that never runs. The subject here is each Feature in the map, and the
// question asked of it is "name the mechanism that refuses you".

// enforcement is the HAND-WRITTEN claim that a capability is gated, and by what.
//
// ⛔ HAND-WRITTEN IS THE MECHANISM, exactly as in the tier census. Deriving "what enforces X" from the code
// would make the census ask the code to describe itself — it would pass for every possible codebase,
// including one that enforces nothing (docs/laws.md: a check must be able to DISAGREE with the thing it
// checks, and derivation removes that ability while looking like rigour).
type enforcement struct {
	// symbol is the identifier a reader can grep for to find the refusal.
	symbol string
	// why names the seam in words, so a stale entry reads as stale rather than as fine.
	why string
	// pending, when non-empty, is a NAMED slice that will close this gap. ⚠ A gap with a name is a
	// schedule; a gap without one is a giveaway. TestNoEnforcementGapSurvivesTheStory asserts this is
	// empty by the end.
	pending string
}

var ENFORCEMENT = map[string]enforcement{
	"multi_gateway": {
		symbol: "GatewayCeilingFor",
		why:    "nodes.checkGatewayCeiling refuses an enrolment past the band, at creation only",
	},
	"multi_org": {
		symbol: "OrgCeilingFor",
		why:    "tenancy.checkOrgCeiling refuses creating an org past the band, at creation only",
	},
	"sso": {
		symbol: "FeatSSO",
		why: "apiServer.requireSSOAdmin refuses configuring SSO or claiming a domain. ⚠ The LOGIN " +
			"path is deliberately not gated — see the comment there; a licence must never lock a human out",
	},
	"idp_sync": {
		symbol: "FeatIdpSync",
		why: "the directory-sync reconciler refuses the ADDITIVE half. ⛔ Its subtractive half is " +
			"never gated: a licence may stop granting access, it must never stop removing it",
	},
}

// enforcementSites finds every non-test line in the API that mentions a symbol, EXCLUDING the licence
// package itself — a definition is not an enforcement, and counting it would let a feature enforce itself
// into existence.
func enforcementSites(t *testing.T, symbol string) []string {
	t.Helper()
	var hits []string
	scanned := 0
	root := "../.." // apps/api
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return err
		}
		if strings.Contains(p, "/internal/licence/") || strings.Contains(p, "/internal/api/") {
			return nil // the definition, and generated code
		}
		// ⛔ AND THE LICENCE STATUS HANDLER IS EXCLUDED, WHICH IS THE SUBTLEST LINE IN THIS FILE.
		//
		// license_handlers.go reads every ceiling and every feature — to DISPLAY them. It matched all four
		// symbols, so the census went green while genuinely believing it had found enforcement, and
		// deleting the real gate in nodes or tenancy would not have moved it. A screen that TELLS you the
		// limit is not a limit; counting it made the census unable to disagree with anything, which is the
		// exact failure mode its hand-written map exists to avoid.
		if strings.HasSuffix(p, "license_handlers.go") {
			return nil
		}
		scanned++
		b, e := os.ReadFile(p)
		if e != nil {
			return nil
		}
		for i, line := range strings.Split(string(b), "\n") {
			if strings.Contains(line, symbol) && !strings.HasPrefix(strings.TrimSpace(line), "//") {
				hits = append(hits, fmt.Sprintf("%s:%d", strings.TrimPrefix(p, "../../"), i+1))
			}
		}
		return nil
	})
	// ⛔ THE VACUITY FLOOR. Its twin in entitlement_census_test.go is the only reason a subject that moved
	// out from under a guard surfaced as a failure rather than as a clean bill of health over zero files —
	// which happened to a DIFFERENT guard in this same story, on the same day, for the same cause.
	if err != nil || scanned == 0 {
		t.Fatalf("⛔ the census scanned NOTHING (err=%v, files=%d) — it would report every capability "+
			"unenforced, or every capability fine, depending only on which way the assertion points", err, scanned)
	}
	return hits
}

// ⛔ SET EQUALITY WITH THE TIER MAP, BOTH DIRECTIONS — so a new Feature cannot be added without someone
// naming what refuses it, and a removed one cannot leave a stale claim of enforcement behind.
func TestEveryPaidCapabilityNamesItsEnforcement(t *testing.T) {
	var missing, stale []string
	for _, f := range licence.AllFeatures() {
		if _, ok := ENFORCEMENT[string(f)]; !ok {
			missing = append(missing, "  "+string(f))
		}
	}
	for name := range ENFORCEMENT {
		found := false
		for _, f := range licence.AllFeatures() {
			if string(f) == name {
				found = true
			}
		}
		if !found {
			stale = append(stale, "  "+name)
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)
	if len(missing) > 0 {
		t.Errorf("⛔ PAID CAPABILITY WITH NO NAMED ENFORCEMENT — it is in the tier map, so it is meant to "+
			"be paid for, and nobody has said what refuses it:\n%s", strings.Join(missing, "\n"))
	}
	if len(stale) > 0 {
		t.Errorf("⚠ ENFORCEMENT CLAIMED FOR A CAPABILITY THAT NO LONGER EXISTS:\n%s", strings.Join(stale, "\n"))
	}
}

// ⭐ THE ONE THAT WOULD HAVE CAUGHT THE GIVEAWAY. Every claimed enforcement must exist in the source, and
// the census prints WHERE — so a reader can check the claim rather than trust it.
func TestEveryNamedEnforcementActuallyExists(t *testing.T) {
	for _, f := range licence.AllFeatures() {
		e, ok := ENFORCEMENT[string(f)]
		if !ok {
			continue // reported by the set-equality test
		}
		sites := enforcementSites(t, e.symbol)
		if len(sites) == 0 {
			if e.pending != "" {
				t.Logf("⚠ %s is NOT ENFORCED YET — scheduled: %s. It is free to every deployment until "+
					"then. DO NOT RELEASE.", f, e.pending)
				continue
			}
			t.Errorf("⛔ %q IS GIVEN AWAY. Its enforcement is claimed to be %q (%s) and that symbol appears "+
				"NOWHERE in non-test source. Every deployment has this capability for free.",
				f, e.symbol, e.why)
			continue
		}
		t.Logf("%-14s enforced at %s", f, strings.Join(sites, ", "))
	}
}

// ⛔ PROVE THE CENSUS REJECTS. A census nobody has watched fail is a census nobody knows the polarity of —
// and this one is a handful of string operations away from reporting "all clear" unconditionally.
//
// ⚠ THE PLANT IS A CAPABILITY, NOT A FILE. It names a symbol that genuinely does not exist anywhere, which
// is exactly the state a real giveaway is in: someone adds `FeatAuditExport` to the map, ships it, and no
// line ever reads it.
func TestTheCensusRejectsAnUnenforcedCapability(t *testing.T) {
	planted := enforcement{symbol: "FeatNothingReadsThisConstantAnywhere", why: "a deliberately unenforced capability"}
	if sites := enforcementSites(t, planted.symbol); len(sites) != 0 {
		t.Fatalf("⛔ THE CENSUS FOUND ENFORCEMENT FOR A CAPABILITY THAT DOES NOT EXIST — it reports "+
			"whatever it is asked, so its passes mean nothing: %v", sites)
	}
	// And the positive control, so an always-empty scanner cannot pass the line above.
	if sites := enforcementSites(t, "GatewayCeilingFor"); len(sites) == 0 {
		t.Fatal("⛔ THE CENSUS FOUND NOTHING FOR A SYMBOL THAT DEMONSTRABLY EXISTS — it would report every " +
			"capability as unenforced, and the 'reject' above proves only that it is broken")
	}
}

// ⛔ THE TRIPWIRE THAT REPLACES TestPaidCapabilitiesAreNotYetEnforced — which was deleted only because
// THIS exists, never because the gap closed on its own.
//
// That test said, in prose, "SSO and IdP sync are free right now; do not release". Prose does not fail a
// build. This does, the moment the last scheduled gap is meant to be closed.
func TestNoEnforcementGapSurvivesTheStory(t *testing.T) {
	var open []string
	for name, e := range ENFORCEMENT {
		if e.pending != "" {
			open = append(open, fmt.Sprintf("  %-14s free until: %s", name, e.pending))
		}
	}
	sort.Strings(open)
	if len(open) > 0 {
		t.Errorf("⛔ PAID CAPABILITIES ARE STILL FREE TO EVERY DEPLOYMENT:\n%s\n\nThis is survivable only "+
			"while unreleased. Close them, or the licensing model is a document rather than a product.",
			strings.Join(open, "\n"))
	}
}
