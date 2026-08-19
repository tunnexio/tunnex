package cmd_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// notShipped names each cmd/ package that is DELIBERATELY absent from the runtime image, with the reason. A
// package here is a stated decision; a package in neither this map nor the image is the defect this guard
// exists to catch.
var notShipped = map[string]string{
	"migrate":         "shipped in its own image (deploy/docker/migrate.Dockerfile) so a migration job is a separate, restartable unit",
	"rbac-policy-gen": "build-time codegen (make generate); runs in the toolchain container, never in production",
	"releasesign":     "CI-only signing tool; private release keys must never be present in the production API image",
	"seed":            "development fixture — seeding a production database is not a supported operation",
	"seed-enterprise": "development fixture, same reason as seed",
	"seed-fixtures":   "development fixture (S14.5) — a populated demo network for reviewing the redesigned screens; seeding a production database is not a supported operation",
	// ⛔ MUST NOT SHIP, and not merely because it is a dev convenience. This tool writes a sealed SSO config
	// while SKIPPING `requireSSOAdmin` — the entitlement gate the real endpoint enforces. That is acceptable
	// on a laptop, where the gate is the only thing standing between an operator and walking the login flow
	// on an unlicensed stack; in the production image it would be a gate-bypassing credential writer sitting
	// next to the master key it seals with.
	"dev-sso-config": "development tool (F-SSO) — writes a sealed per-org SSO config while bypassing the SSO entitlement gate; shipping a gate-bypassing credential writer into the runtime image is the opposite of the reason the gate exists",
	"walk-bootstrap": "box-walk rig setup; a test harness, not an operator tool",
}

// TestEveryOperatorToolShipsInTheImage — the packaging tier of artifact-exists-≠-artifact-works.
//
// WHY THIS EXISTS. The EPIC 11 walk found `backupctl` and `preflight` absent from the api image (WF-S11-1):
// both were written, both were unit-tested, both were named by command in docs/backup-restore.md and
// docs/upgrade.md — and neither was in api.Dockerfile, which built ./cmd/server alone. Every layer said the
// tools existed. The runbook told an operator to run commands that were not there.
//
// A unit test cannot catch that, because the unit passed. The seam is between the code and the image, so the
// guard has to read the Dockerfile. It is a census rather than a build assertion for the reason every census in
// this repo is one: a NEW cmd/ package is silently uncovered by an allowlist, and loudly uncovered by an
// enumeration that fails on anything it does not recognize.
func TestEveryOperatorToolShipsInTheImage(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "deploy", "docker", "api.Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	dockerfile := string(raw)

	// Read the build stage's own words rather than guessing binary names from package names: the output name
	// need not match the package (./cmd/server builds `tunnex-api`), so the pairing has to come from the
	// -o flag. Anything else is a heuristic that either misses a real gap or fails on a working image.
	buildRe := regexp.MustCompile(`-o\s+/out/(\S+)\s+\./cmd/(\S+)`)
	builtAs := map[string]string{} // package -> output binary name
	for _, m := range buildRe.FindAllStringSubmatch(dockerfile, -1) {
		builtAs[m[2]] = m[1]
	}

	var missing []string
	checked := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pkg := e.Name()
		checked++
		if _, ok := notShipped[pkg]; ok {
			continue
		}
		// Both halves matter: built in the build stage AND copied into the runtime stage. A binary compiled
		// into /out and never COPY'd is exactly as absent as one never compiled.
		bin, built := builtAs[pkg]
		copied := built && strings.Contains(dockerfile, "/out/"+bin+" /usr/local/bin/")
		if !built {
			missing = append(missing, pkg+" (not built)")
		} else if !copied {
			missing = append(missing, pkg+" (built as "+bin+", never COPY'd into the runtime stage)")
		}
	}

	if checked == 0 {
		t.Fatal("no cmd/ packages were examined — the guard would vouch for nothing")
	}
	if len(missing) != 0 {
		sort.Strings(missing)
		t.Fatalf("cmd/ package(s) are in neither the api image nor the notShipped census: %v\n\n"+
			"Either build+COPY them in deploy/docker/api.Dockerfile, or add each to `notShipped` with the "+
			"reason it is deliberately absent. An operator tool the runbook names but the image lacks is a "+
			"documented procedure that cannot be followed (S11 walk WF-S11-1).", missing)
	}
	t.Logf("census: %d cmd/ packages, %d deliberately not shipped, 0 unaccounted", checked, len(notShipped))
}
