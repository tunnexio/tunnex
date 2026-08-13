package nodes

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

// TestEveryHealthKindIsEnumerated — S11 D3.1's substance.
//
// The metrics layer ranges over AllKinds() (derived from transitionTable) rather than a hand-written list,
// so a health kind can never be a series that silently never appears. This census makes that guarantee real:
// it PARSES the PolicyDegradedKind const block and asserts every declared kind is enumerated.
//
// Why a source census and not a runtime check: Go cannot reflect over untyped constants, so a 14th kind added
// to the const block and forgotten everywhere else is invisible at runtime — the exact producer-without-
// consumer trap this guards. The advisor named 6 kinds from memory and the assistant's own first regex found
// 12 of 13 (k8s_endpoints_unavailable was missed): if humans and greps both under-count this enum, a
// hand-maintained metric list drifts the first time kind #14 lands.
func TestEveryHealthKindIsEnumerated(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "policyhealth.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Collect every `KindX PolicyDegradedKind = "..."` declared in the source.
	declared := map[string]string{} // const name -> string value
	ast.Inspect(f, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok || vs.Type == nil {
			return true
		}
		id, ok := vs.Type.(*ast.Ident)
		if !ok || id.Name != "PolicyDegradedKind" {
			return true
		}
		for i, name := range vs.Names {
			if i >= len(vs.Values) {
				continue
			}
			lit, ok := vs.Values[i].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				continue
			}
			v, err := strconv.Unquote(lit.Value)
			if err != nil {
				continue
			}
			declared[name.Name] = v
		}
		return true
	})
	if len(declared) == 0 {
		t.Fatal("parsed no PolicyDegradedKind constants — the census cannot vouch for anything")
	}

	enumerated := map[PolicyDegradedKind]bool{}
	for _, k := range AllKinds() {
		enumerated[k] = true
	}

	var missing []string
	for name, value := range declared {
		if !enumerated[PolicyDegradedKind(value)] {
			missing = append(missing, name+" (\""+value+"\")")
		}
	}
	if len(missing) != 0 {
		t.Fatalf("health kind(s) declared but NOT enumerated by AllKinds(), so they would never appear as a "+
			"metric series — add them to transitionTable:\n  %s", strings.Join(missing, "\n  "))
	}

	// The inverse: AllKinds must not invent a kind the enum doesn't declare.
	values := map[string]bool{}
	for _, v := range declared {
		values[v] = true
	}
	for _, k := range AllKinds() {
		if !values[string(k)] {
			t.Fatalf("AllKinds() yields %q, which is not a declared PolicyDegradedKind constant", k)
		}
	}

	t.Logf("census: %d health kinds declared, all enumerated", len(declared))
}
