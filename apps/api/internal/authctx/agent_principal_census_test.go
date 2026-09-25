package authctx_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
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

// Parse actual composite-literal types and their direct fields. Field names in
// runtime DTOs, comments, strings and nested unrelated literals are not identity
// construction. Import aliases must not bypass the canonical constructor gate.
type constructionHit struct{ file, line, function string }

func principalConstructionSites(path string, source []byte) (literals, nodeIDs []constructionHit, err error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, source, 0)
	if err != nil {
		return nil, nil, err
	}
	aliases := map[string]bool{"authctx": true}
	for _, imp := range file.Imports {
		value, e := strconv.Unquote(imp.Path.Value)
		if e == nil && value == "github.com/tunnexio/tunnex/apps/api/internal/authctx" {
			name := "authctx"
			if imp.Name != nil {
				name = imp.Name.Name
			}
			aliases[name] = true
		}
	}
	isPrincipal := func(expr ast.Expr) bool {
		switch typ := expr.(type) {
		case *ast.Ident:
			return typ.Name == "Principal"
		case *ast.SelectorExpr:
			pkg, ok := typ.X.(*ast.Ident)
			return ok && aliases[pkg.Name] && typ.Sel.Name == "Principal"
		}
		return false
	}
	lines := strings.Split(string(source), "\n")
	for _, decl := range file.Decls {
		fn := ""
		if f, ok := decl.(*ast.FuncDecl); ok {
			fn = f.Name.Name
		}
		ast.Inspect(decl, func(node ast.Node) bool {
			literal, ok := node.(*ast.CompositeLit)
			if !ok || !isPrincipal(literal.Type) {
				return true
			}
			line := fset.Position(literal.Pos()).Line
			hit := constructionHit{file: path + ":" + strconv.Itoa(line), line: strings.TrimSpace(lines[line-1]), function: fn}
			literals = append(literals, hit)
			for _, element := range literal.Elts {
				field, ok := element.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				name, ok := field.Key.(*ast.Ident)
				if ok && name.Name == "NodeID" {
					nodeIDs = append(nodeIDs, hit)
				}
			}
			return true
		})
	}
	return literals, nodeIDs, nil
}

func TestAgentPrincipalHasExactlyOneConstructionSite(t *testing.T) {
	root := filepath.Join("..", "..")
	var literals, nodeIDs []constructionHit

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
		found, assigned, parseErr := principalConstructionSites(rel, b)
		if parseErr != nil {
			return parseErr
		}
		literals = append(literals, found...)
		nodeIDs = append(nodeIDs, assigned...)
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
	var offenders []constructionHit
	for _, h := range nodeIDs {
		if !strings.HasPrefix(h.file, constructorFile+":") || h.function != "NewAgentPrincipal" {
			offenders = append(offenders, h)
		}
	}
	if len(nodeIDs) != 1 {
		t.Errorf("expected exactly one canonical NodeID constructor, found %d", len(nodeIDs))
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
