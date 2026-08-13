package authctx_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// THE CENSUS, RE-RUN — S15.2 / D24, and it is a MERGE GATE rather than a review note.
//
// ⛔ THE S15.0 CENSUS DOES NOT COVER THIS. It found `MachineID` had exactly one construction site, which is
// why a constructor was licensed there instead of a per-handler guard. Adding an agent principal leaves that
// sentence literally true — an agent carries `NodeID` — and **retires the guarantee it stood for**, because
// the guarantee was never about `MachineID`. It was: *a non-human principal cannot be built without passing
// through the one place that enforces ownership.* A second kind has its own doorway, and the old census says
// nothing about it.
//
// > **A CENSUS IS A STATEMENT ABOUT A MOMENT AND IT IS NOT SELF-RENEWING.** Code added after it is not
// > covered by it. So the replacement for the old guarantee is not a claim — it is this file, which fails if
// > a second construction site ever appears.
//
// ⚠ CENSUSED BY THE **INPUT**, NOT BY THE FUNCTION. That distinction is the whole lesson of
// `policyHealthBadge`: seven sites, four wrong, and **two of them never called the function at all**. A
// census that greps for calls to `NewAgentPrincipal` would miss exactly the sites that matter — the ones
// that build a `Principal` literal by hand.

// principalLiteral matches a composite literal of authctx.Principal / Principal, which is the doorway a
// constructor is supposed to be the only user of.
var principalLiteral = regexp.MustCompile(`(?:authctx\.)?Principal\{`)

// nodeIDAssign matches an assignment into the agent identity field.
//
// ⛔ SCOPED TO THE PRINCIPAL BLOCK, NEVER TO THE FIELD NAME ALONE — AND THE FIRST VERSION OF THIS CENSUS GOT
// THAT WRONG. Matching `NodeID:` anywhere hit access-log events (`accesslog/ingest.go`, `store.go`) and
// device params (`devices/service.go`, `restore.go`), none of which build a principal. The gate would have
// shipped permanently red.
//
// ⚠ AND A PERMANENTLY-RED GATE IS WORSE THAN NO GATE: it gets suppressed, and the suppression outlives the
// reason. The census's input must be the PRINCIPAL, not a field name the codebase happens to share.
var nodeIDAssign = regexp.MustCompile(`\bNodeID:\s`)

func TestAgentPrincipalHasExactlyOneConstructionSite(t *testing.T) {
	root := filepath.Join("..", "..")
	type hit struct{ file, line string }
	var literals, nodeIDs []hit

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			// Generated code and vendored trees are not construction sites anyone reasons about.
			if name := info.Name(); name == "sqlc" || name == "node_modules" || name == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		lines := strings.Split(string(b), "\n")
		// depth > 0 means we are INSIDE a Principal composite literal; only there does NodeID mean the
		// agent identity field rather than some other struct's column.
		depth := 0
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
				continue
			}
			loc := rel + ":" + itoa(i+1)
			if depth == 0 && principalLiteral.MatchString(line) {
				literals = append(literals, hit{loc, trimmed})
				depth = 1
				// A single-line literal opens and closes here; fall through to the brace count below.
			}
			if depth > 0 {
				if nodeIDAssign.MatchString(line) {
					nodeIDs = append(nodeIDs, hit{loc, trimmed})
				}
				depth += strings.Count(line, "{") - strings.Count(line, "}")
				if depth < 0 {
					depth = 0
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	// ⛔ A CENSUS THAT FINDS NOTHING IS A CENSUS THAT DID NOT RUN. The vacuity floor: if the walk stopped
	// matching (a moved package, a changed field name, a broken regex), this test would otherwise pass by
	// finding zero sites and would keep passing forever.
	if len(literals) == 0 {
		t.Fatal("VACUOUS: the census found no Principal literals at all — the walk or the pattern is broken, " +
			"not the codebase. A census that cannot find the known sites proves nothing about unknown ones.")
	}

	// The agent identity field must be written in exactly ONE place: the constructor.
	const constructorFile = "internal/authctx/authctx.go"
	var offenders []hit
	for _, h := range nodeIDs {
		if !strings.HasPrefix(h.file, constructorFile) {
			offenders = append(offenders, h)
		}
	}
	if len(offenders) > 0 {
		var b strings.Builder
		b.WriteString("A SECOND AGENT-PRINCIPAL CONSTRUCTION SITE APPEARED, and the census is the gate that " +
			"catches it (S15.2/D24).\n\nNodeID is assigned outside " + constructorFile + ":\n")
		for _, h := range offenders {
			b.WriteString("  " + h.file + "\t" + h.line + "\n")
		}
		b.WriteString("\nEither route it through NewAgentPrincipal, or — if a second doorway is genuinely " +
			"right — RE-ARGUE 'necessary AND sufficient' for BOTH and update this gate deliberately. " +
			"What is not acceptable is a second site added quietly, inheriting a guarantee it was never inside.")
		t.Fatal(b.String())
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
