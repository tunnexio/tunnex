package cmd_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// ⛔ EVERY `//go:embed` TARGET MUST BE GO-RELEVANT TO CI'S DIFF CLASSIFIER.
//
// THE SEAM THIS GUARDS, stated plainly because it is why the hole was invisible:
//
//	THE CLASSIFIER REASONS ABOUT FILE EXTENSIONS. THE COMPILER REASONS ABOUT COMPILE INPUTS.
//	`//go:embed` IS WHERE THOSE DISAGREE — it makes a file of ANY extension a build input to a Go package.
//
// S14.11 found `apps/api/cmd/seed-fixtures/fixtures.sql` matching NONE of the classifier's patterns, so a
// fixtures-only diff set `go=false` and skipped `build-editions` — the step that fails when an embed target
// is renamed or deleted, because a missing embed target is a COMPILE ERROR. In a classifier whose own header
// reads "fails closed — anything uncertain runs everything." Prose said one thing, behaviour did another, and
// nothing compared the two (docs/CUT-REGISTER.md → the prose-versus-behaviour class).
//
// ⛔ WHY A TEST AND NOT JUST A WIDER REGEX: a suffix list is a GUESS ABOUT THE FUTURE. Adding `\.sql$` closes
// today's hole and says nothing about tomorrow's `//go:embed banner.txt` or `//go:embed templates/*.tmpl`.
// This re-derives the embed set FROM SOURCE on every run, so the next embed either matches the pattern or
// breaks the build with an instruction.
//
// It lives in apps/api/cmd/ alongside `shipcensus_test.go`, which likewise reads outside the module (the api
// Dockerfile). `make test-editions` mounts the REPO ROOT precisely so these cross-surface guards can run.

var (
	reEmbed = regexp.MustCompile(`(?m)^\s*//go:embed\s+(.+)$`)
	// The classifier's own regex, transcribed. Kept as a literal on purpose: if someone edits ci.yml and not
	// this line, `TestClassifierPatternMatchesTheWorkflow` below fails and names the drift.
	classifierPattern = `(\.go$|go\.(mod|sum)$|\.sql$|Dockerfile|Makefile|\.github/|openapi/|apps/api/db/|apps/api/internal/mail/)`
)

// ⛔ THE ONE EXEMPTION, AND WHY IT IS NARROWER THAN IT LOOKS.
//
// S14.15 MEASURED that this file's own rule had made the classifier useless in practice: because CI diffs
// BASE...HEAD, ONE edit to `fixtures.sql` early in a branch pinned `go=true` for EVERY later push. Across 18
// runs on two PRs, 17 were go=true and 16 of those were triggered by `fixtures.sql` ALONE — including 10
// commits that were docs-only. A guard that is always on is not a guard; it is a constant.
//
// The exemption is safe for exactly one reason, and it is a CENSUS claim, not an opinion: `fixtures.sql` is a
// compile input ONLY to `cmd/seed-fixtures`, which `shipcensus_test.go` declares DELIBERATELY NOT SHIPPED.
// Its CONTENT therefore cannot break any shipped build.
//
//	BUT ITS ABSENCE STILL CAN — `//go:embed` fails to COMPILE when its target is missing, which is the
//	original S14.11 finding and it has NOT been repealed.
//
// So the exemption is conditional on CI tracking DELETIONS separately, and the test below REFUSES THE
// EXEMPTION unless that mechanism is present in the workflow. An exemption that trusted a comment would be
// the prose-versus-behaviour class this file was written to catch.
var embedExemptContentOnly = map[string]string{
	"apps/api/cmd/seed-fixtures/fixtures.sql": "cmd/seed-fixtures is declared not-shipped in shipcensus_test.go; only its DELETION can break a build, and CI tracks deletions with --diff-filter=D",
}

// deletionGuard is the literal CI must contain for the exemption above to hold.
const deletionGuard = `--diff-filter=D`

// repoRoot is three levels up from apps/api/cmd — the same hop shipcensus_test.go makes.
const repoRoot = "../../.."

func TestGoEmbedTargetsAreGoRelevantToCI(t *testing.T) {
	pat := regexp.MustCompile(classifierPattern)

	type embed struct{ dir, spec, path string }
	var found []embed

	err := filepath.Walk(repoRoot, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // unreadable paths are not this guard's business
		}
		if info.IsDir() {
			switch info.Name() {
			case "node_modules", ".git", "vendor", "dist", "build":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		for _, m := range reEmbed.FindAllStringSubmatch(string(b), -1) {
			for _, spec := range strings.Fields(strings.TrimSpace(m[1])) {
				// `all:` / `//go:embed` prefixes are directives, not path text.
				spec = strings.TrimPrefix(spec, "all:")
				dir := filepath.Dir(p)
				// The path AS CI WOULD SEE IT: repo-relative, forward slashes, no leading "./".
				rel, rerr := filepath.Rel(repoRoot, filepath.Join(dir, spec))
				if rerr != nil {
					continue
				}
				found = append(found, embed{dir: dir, spec: spec, path: filepath.ToSlash(rel)})
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// ⛔ THE VACUITY FLOOR. Without it this passes the day the walk, the suffix filter, or the regex stops
	// matching — reporting "every embed is covered" about zero embeds. Measured at authorship: 2.
	if len(found) < 2 {
		t.Fatalf("found only %d //go:embed targets (expected >= 2) — the SCAN regressed, not the code", len(found))
	}

	for _, e := range found {
		if why, exempt := embedExemptContentOnly[e.path]; exempt {
			// ⛔ THE EXEMPTION IS NOT SELF-CERTIFYING. It holds only while CI still forces the Go legs on a
			// DELETION, so verify that mechanism EXISTS rather than trusting the map entry.
			// Checked PER WORKFLOW, and only where the exclusion actually exists: a workflow that does
			// NOT exclude this path is already conservative and needs no deletion guard. Requiring it
			// everywhere would force an edit to a file that was never unsafe — a guard should demand the
			// mechanism where the risk is, not everywhere the name appears.
			for _, wf := range []string{"ci.yml", "security.yml"} {
				b, err := os.ReadFile(filepath.Join(repoRoot, ".github", "workflows", wf))
				if err != nil {
					t.Fatal(err)
				}
				body := string(b)
				if !strings.Contains(body, "grep -vxF '"+e.path+"'") {
					t.Logf("not exempt in %s (still Go-relevant there) — no deletion guard needed", wf)
					continue
				}
				if !strings.Contains(body, deletionGuard) {
					t.Errorf("%s is EXCLUDED from the Go-relevance patterns in %s (%s) — but that file no\n"+
						"  longer contains %q.\n"+
						"  The exclusion covers CONTENT edits ONLY. A missing embed target is a COMPILE ERROR,\n"+
						"  so a DELETION must still force the Go legs. Either restore the deletion guard or\n"+
						"  remove the exclusion.", e.path, wf, why, deletionGuard)
				}
			}
			t.Logf("exempt (content-only): %-38s — %s", e.path, why)
			continue
		}
		if !pat.MatchString(e.path) {
			t.Errorf("//go:embed target is INVISIBLE to CI's diff classifier: %s\n"+
				"  (embedded by a Go package in %s, so it is a COMPILE INPUT — a diff touching only this\n"+
				"   file would set go=false and SKIP build-editions, which is the step a missing embed\n"+
				"   target would fail.)\n"+
				"  FIX: widen the Go-relevance regex in .github/workflows/ci.yml AND the transcription in\n"+
				"  this file, so both move together.", e.path, e.dir)
			continue
		}
		t.Logf("covered: %-52s (embedded by %s)", e.path, e.dir)
	}
}

// TestClassifierPatternMatchesTheWorkflow keeps the transcription above honest. Without it the two can drift
// and this guard would cheerfully validate embeds against a pattern CI no longer uses — a guard checking a
// copy of the thing instead of the thing.
func TestClassifierPatternMatchesTheWorkflow(t *testing.T) {
	// ⛔ THERE ARE TWO CLASSIFIERS, AND CHECKING ONE IS HOW THIS GUARD MISSED A REAL SKIP.
	//
	// S14.12: `.sql$` was added to ci.yml and NOT to security.yml. This test passed — it only read ci.yml —
	// while security.yml's scope job emitted go=false on a diff containing `fixtures.sql`, SILENTLY SKIPPING
	// govulncheck (5 modules), gofmt+vet parity, and Trivy. A skipped security job reports as `skipped`,
	// which is indistinguishable from "not applicable" at a glance.
	//
	//   A GUARD THAT VALIDATES ONE COPY OF A DUPLICATED RULE CERTIFIES THE COPY, NOT THE RULE.
	//
	// Both files are now required to carry the identical pattern.
	for _, wf := range []string{"ci.yml", "security.yml"} {
		b, err := os.ReadFile(filepath.Join(repoRoot, ".github", "workflows", wf))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), classifierPattern) {
			t.Errorf("the classifier regex in %s does not match the copy in this file.\n"+
				"  expected: %s\n"+
				"  BOTH workflows classify the diff, and they must agree — otherwise one set of jobs\n"+
				"  skips on a diff the other set runs, and a skipped job looks like a passing one.",
				wf, classifierPattern)
		}
	}
}
