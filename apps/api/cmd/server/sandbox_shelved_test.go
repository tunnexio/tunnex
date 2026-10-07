package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"testing"

	"github.com/tunnexio/tunnex/apps/api/internal/config"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxproduct"
)

func TestSandboxShelvedStartupIgnoresDedicatedConfiguration(t *testing.T) {
	for _, mode := range []string{"", "on", "off", "draining", "stale-value"} {
		c := config.Config{SandboxModule: mode, SandboxFixtureOrgID: "invalid-old-fixture", SandboxRuntimeConfigFile: "/missing/private/runtime.json"}
		if err := validateSandboxProductConfiguration(c); err != nil {
			t.Fatalf("shelved configuration %q blocked ordinary startup: %v", mode, err)
		}
		m, err := initializeSandboxProduct(c, func() error {
			t.Fatal("shelved startup consulted retirement state")
			return nil
		}, func() (sandboxModule, error) {
			t.Fatal("shelved startup loaded dedicated configuration or constructed a runtime")
			return sandboxModule{}, nil
		})
		d := m.deps()
		if err != nil || m.state != "disabled" || m.available() || m.store != nil || m.run != nil || m.close != nil || m.wake != nil || d.Sandboxes != nil || d.SandboxRunnerEnrollment != nil || d.SandboxRunnerQualification != nil {
			t.Fatalf("shelved startup retained runtime wiring: %#v, %v", m, err)
		}
	}
	// The wrapper must not weaken ordinary API TLS validation.
	if (config.Config{APITLSCertificateFile: "/missing/certificate"}).ValidateAPITLS() == nil {
		t.Fatal("ordinary TLS validation unexpectedly accepted partial configuration")
	}
}

// A cross-platform entry-point census covers Linux-only binaries without running
// fixtures or private configuration. Native execution remains a separate check.
func TestSandboxShelvedExecutableGuardsBeforeDedicatedInput(t *testing.T) {
	if !sandboxproduct.Shelved {
		t.Fatal("sandbox product gate is active")
	}
	for _, path := range []string{
		"../tunnex-sandbox-fixture-setup/main.go", "../tunnex-sandbox-runner-enroll/main.go",
		"../tunnex-sandbox-runtime/main_linux.go", "../tunnex-sandbox-ssh-probe/main.go", "../tunnex-sandbox-worker/main_linux.go",
	} {
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Clean(path), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name.Name != "main" {
				continue
			}
			first, ok := fn.Body.List[0].(*ast.IfStmt)
			if !ok {
				t.Fatalf("%s reads dedicated input before its shelving guard", path)
			}
			guard, ok := first.Cond.(*ast.SelectorExpr)
			if !ok || guard.Sel.Name != "Shelved" {
				t.Fatalf("%s lacks the static shelving guard", path)
			}
			pkg, ok := guard.X.(*ast.Ident)
			if !ok || pkg.Name != "sandboxproduct" {
				t.Fatalf("%s uses a different activation boundary", path)
			}
			ast.Inspect(first.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				selector, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || selector.Sel.Name != "Exit" || len(call.Args) != 1 {
					return true
				}
				owner, ok := selector.X.(*ast.Ident)
				status, literal := call.Args[0].(*ast.BasicLit)
				found = ok && owner.Name == "os" && literal && status.Value == "1"
				return true
			})
		}
		if !found {
			t.Fatalf("%s does not refuse before dedicated input", path)
		}
	}
}
