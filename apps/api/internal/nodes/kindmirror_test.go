package nodes

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// notRenderedInUI names kinds that legitimately have no explicit case in the web renderer, with the reason.
// Anything else absent from healthview.ts falls through to a GENERIC degraded badge, which loses the one thing
// a kind exists to carry: its remedy.
var notRenderedInUI = map[string]string{
	"healthy": "not a degradation — the renderer's default branch covers the non-degraded case",
}

// TestEveryHealthKindReachesItsMirrorSurfaces — CENSUS-THE-MIRROR-SURFACE, at the health-kind seam.
//
// WHY THIS EXISTS. `AllKinds()` already guarantees a kind reaches the METRICS. It guarantees nothing about the
// two surfaces an operator actually looks at. The S11 walk censused them by hand and found
// `k8s_endpoints_unavailable` (shipped in S10.3) present in the Go enum, the transition table and the metrics —
// and absent from BOTH the OpenAPI enum and healthview.ts. Consequences, none of which any existing test could
// see:
//
//   - the spec that is the single source of truth omitted a value the server emits, so every generated client
//     type (Go, TS, CLI) was missing it;
//   - the web UI fell through to `default`, showing a generic degraded badge instead of the named remedy — the
//     kind existed and was invisible.
//
// That is the who-reads-this probe at the UI tier: a producer shipped without its consumer, and the failure mode
// is silence rather than breakage, so it survived a release.
//
// The guard reads the actual files rather than a duplicated list, because a duplicated list is one more thing to
// forget. Deriving from AllKinds() means a 15th kind is caught the moment it is added.
func TestEveryHealthKindReachesItsMirrorSurfaces(t *testing.T) {
	repo := filepath.Join("..", "..", "..", "..")

	spec, err := os.ReadFile(filepath.Join(repo, "openapi", "openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	// The enum line, not the whole document: a kind mentioned only in prose is documented, not declared, and a
	// client generated from the spec would still reject it.
	enumLine := ""
	for _, line := range strings.Split(string(spec), "\n") {
		if strings.Contains(line, "enum: [healthy, apply_failing") {
			enumLine = line
			break
		}
	}
	if enumLine == "" {
		t.Fatal("could not locate the policy_degraded_kind enum in openapi.yaml — the guard would vouch for nothing")
	}

	view, err := os.ReadFile(filepath.Join(repo, "apps", "web", "src", "lib", "healthview.ts"))
	if err != nil {
		t.Fatal(err)
	}

	var missingSpec, missingUI []string
	for _, k := range AllKinds() {
		kind := string(k)
		// Quoted-and-bounded so a substring cannot vouch for a longer name (`site_link_down` must not satisfy
		// a check for a hypothetical `site_link_down_hard`).
		if !strings.Contains(enumLine, kind+",") && !strings.Contains(enumLine, kind+"]") {
			missingSpec = append(missingSpec, kind)
		}
		// ⛔ TWO FORMS, BECAUSE THE RENDERER CHANGED SHAPE AND THIS CENSUS WENT SILENTLY RED (S14.8).
		//
		// `policyHealthBadge` was a `switch` with `case "<kind>":` arms; S14.8 replaced it with a
		// `Record<NonHealthyPolicyDegradedKind, HealthBadge>` keyed `<kind>: { label, tone }`, so that the TS
		// COMPILER refuses a new kind with no badge. That is a STRONGER guard than this one — and it defeated
		// this one, because the literal `case "` disappeared and all thirteen kinds read as unrendered.
		//
		// ⛔ BOTH GUARDS STAY, BECAUSE THEY CATCH DIFFERENT FAILURES:
		//   THE RECORD  catches a kind that IS in openapi.yaml but has no badge — at TS compile time.
		//   THIS CENSUS catches a kind that is in the GO ENUM and never reached the spec at all, so the
		//               generated TS union does not contain it and the compiler has nothing to complain about.
		//
		// The second is exactly how `k8s_endpoints_unavailable` shipped invisible: Go enum + metrics, absent
		// from the spec, rendering as a generic "degraded". A compiler cannot see across that gap; only a
		// cross-surface census can.
		rendered := strings.Contains(string(view), `case "`+kind+`":`) || // switch form (pre-S14.8)
			strings.Contains(string(view), "\n  "+kind+": {") // Record form (S14.8 on)
		if _, ok := notRenderedInUI[kind]; !ok && !rendered {
			missingUI = append(missingUI, kind)
		}
	}

	sort.Strings(missingSpec)
	sort.Strings(missingUI)
	if len(missingSpec) != 0 {
		t.Errorf("health kind(s) the server can emit are MISSING from the openapi.yaml policy_degraded_kind "+
			"enum: %v\n\nThe spec is the single source of truth: every generated client type (Go, TS, CLI) is "+
			"built from it, so a kind absent here is a value clients cannot represent. Add it to the enum and "+
			"run `make generate`.", missingSpec)
	}
	if len(missingUI) != 0 {
		t.Errorf("health kind(s) have NO case in apps/web/src/lib/healthview.ts: %v\n\nThey fall through to the "+
			"generic degraded badge, so the kind's REMEDY — the only reason to distinguish kinds at all — is "+
			"invisible in the product. Add a case with its label and tone, or add it to `notRenderedInUI` with "+
			"the reason it needs none.", missingUI)
	}
}
