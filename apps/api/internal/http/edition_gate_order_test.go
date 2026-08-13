package http

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// ⛔ THE PERMISSION GATE MUST PRECEDE THE EDITION GATE IN EVERY DOUBLE-GATED HANDLER.
//
// THE ONE-LINE REASON: **the edition answer leaks what a caller is not entitled to ask about.**
//
// `403 edition_required` names a capability and invites a purchase. Returned to a caller whose ROLE forbids the
// capability regardless of edition, it is a purchase prompt shown on the strength of the wrong gate — the
// S14.5 HALT running forward. `403 forbidden` is the honest answer, and it is also the one that discloses
// nothing about what the deployment does or does not have.
//
// WHY THIS TEST IS A SOURCE SCAN AND NOT A CALL-LEVEL TEST — stated because it is the unusual choice:
//
//   THERE IS NO SHARED SEAM. The pair
//       if _, err := authorize(ctx, req.OrgId, rbac.PermX); err != nil { return nil, err }
//       if s.port == nil { return nil, xEditionRequired() }
//   is HAND-WRITTEN in 41 handlers. No helper composes the two, so no single call site can be tested to cover
//   them all, and one test per handler is 41 tests that a 42nd handler would silently not have. A static
//   assertion over the source is the only form that covers a handler nobody has written yet.
//
// WHAT PROMPTED IT: the S14.11 web view-model had this order BACKWARDS, twice in one file, and a mutation that
// swapped the two lines SURVIVED — the ordering was untested on both sides of the wire. The server was already
// correct at all 41 sites; this test is what keeps it that way. See docs/laws.md → A MUTATION SURVIVOR IS NOT
// AUTOMATICALLY A MISSING TEST.
//
// PROVEN TO FIRE: swapping the two lines in ListGroups makes this test red, naming that handler.

// preSessionEditionGates are the handlers that legitimately have an edition gate and NO permission gate,
// enumerated by name with the reason, so "no permission gate" can never be a silent pass.
//
// SSO login begins BEFORE a session exists, so there is no principal to authorize and nothing to check first.
// The edition answer there discloses a DEPLOYMENT fact ("this deployment has no SSO") rather than a per-caller
// entitlement — and the caller must be told, or the login button leads nowhere.
var preSessionEditionGates = map[string]string{
	"StartSsoLogin": "pre-session: no principal exists yet; the caller must learn the login method is absent",
	"SsoCallback":   "pre-session: the IdP round-trip lands here before a session is minted",
}

var (
	reHandler = regexp.MustCompile(`^func \(s apiServer\) (\w+)\(`)
	reAuth    = regexp.MustCompile(`\b(authorize|requireVerifiedSessionUser|requireVerifiedUser)\(ctx`)
	reEdnDecl = regexp.MustCompile(`^func (\w*[Ee]ditionRequired\w*)\(`)
)

func TestEditionGateNeverPrecedesPermissionGate(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}

	// The edition-gate helper names are HARVESTED FROM THE SOURCE, not hardcoded. A hardcoded list silently
	// stops covering a helper someone adds — the failure mode where a census keeps reporting "0 leaks" about a
	// shrinking share of the code.
	helpers := map[string]bool{}
	var bodies []struct {
		file, fn string
		lines    []string
		at       int
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(string(b), "\n")
		fn, start := "", 0
		for i, l := range lines {
			if m := reEdnDecl.FindStringSubmatch(l); m != nil {
				helpers[m[1]] = true
			}
			if m := reHandler.FindStringSubmatch(l); m != nil {
				if fn != "" {
					bodies = append(bodies, struct {
						file, fn string
						lines    []string
						at       int
					}{f, fn, lines[start:i], start})
				}
				fn, start = m[1], i
			}
		}
		if fn != "" {
			bodies = append(bodies, struct {
				file, fn string
				lines    []string
				at       int
			}{f, fn, lines[start:], start})
		}
	}
	if len(helpers) == 0 {
		t.Fatal("harvested ZERO edition-gate helpers — the scan is broken, and a broken scan reports no leaks")
	}

	gated, permFirst := 0, 0
	for _, h := range bodies {
		authAt, ednAt := -1, -1
		for j, l := range h.lines {
			if authAt < 0 && reAuth.MatchString(l) {
				authAt = j
			}
			if ednAt < 0 {
				for name := range helpers {
					if strings.Contains(l, name+"()") {
						ednAt = j
						break
					}
				}
			}
		}
		if ednAt < 0 {
			continue // not edition-gated
		}
		gated++
		if authAt < 0 {
			if _, ok := preSessionEditionGates[h.fn]; !ok {
				t.Errorf("%s: %s has an EDITION gate and NO permission gate, and is not in preSessionEditionGates.\n"+
					"  Either add a permission gate, or enumerate it with the reason it has no principal.",
					h.file, h.fn)
			}
			continue
		}
		if authAt > ednAt {
			t.Errorf("%s: %s checks the EDITION at line %d BEFORE the permission at line %d.\n"+
				"  A caller whose role forbids this capability would be told to buy it. Swap them.",
				h.file, h.fn, h.at+ednAt+1, h.at+authAt+1)
			continue
		}
		permFirst++
	}

	// ⛔ THE FLOOR. Without it this test passes vacuously the day the glob, the regex, or the receiver name
	// stops matching — reporting "no leaks" about zero handlers. The number is a floor, not an equality, so
	// ADDING a gated handler does not fail the build; losing 20% of them does.
	//
	// docs/laws.md → COULD THIS CHECK HAVE FAILED? Measured at authorship: 43 gated, 41 permission-first,
	// 2 pre-session.
	if gated < 40 {
		t.Fatalf("scanned only %d edition-gated handlers (expected ~43) — the SCAN regressed, not the code", gated)
	}
	t.Logf("edition-gated handlers: %d — permission-first: %d, pre-session: %d",
		gated, permFirst, gated-permFirst)
}
