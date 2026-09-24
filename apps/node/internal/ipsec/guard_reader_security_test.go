package ipsec

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestGuardReaderSecurityRefusesInterruptedIdentity(t *testing.T) {
	for _, kind := range []string{"cancel during command", "rename after command", "duplicate indices", "duplicate names", "oversized interfaces", "namespace error", "interfaces error"} {
		t.Run(kind, func(t *testing.T) {
			r, m := guardReaderFixture()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch kind {
			case "cancel during command":
				r.run = func(context.Context, ...string) ([]byte, error) { cancel(); return []byte(guardExpectedFixture), nil }
			case "rename after command":
				n := 0
				r.interfaces = func() ([]GuardInterface, error) {
					n++
					name := "tnxi-a"
					if n > 1 {
						name = "reused"
					}
					return []GuardInterface{{Name: name, Index: 10}}, nil
				}
			case "duplicate indices":
				r.interfaces = func() ([]GuardInterface, error) {
					return []GuardInterface{{Name: "a", Index: 10}, {Name: "b", Index: 10}}, nil
				}
			case "duplicate names":
				r.interfaces = func() ([]GuardInterface, error) {
					return []GuardInterface{{Name: "a", Index: 10}, {Name: "a", Index: 11}}, nil
				}
			case "oversized interfaces":
				r.interfaces = func() ([]GuardInterface, error) { return make([]GuardInterface, kernelEntryLimit+1), nil }
			case "namespace error":
				r.namespace = func() (string, error) { return m.Namespace, errors.New("private diagnostic") }
			case "interfaces error":
				r.interfaces = func() ([]GuardInterface, error) { return nil, errors.New("private diagnostic") }
			}
			if err := r.Check(ctx, m); err != ErrGuardRead {
				t.Fatalf("unsafe observation not statically refused: %v", err)
			}
		})
	}
}

func TestGuardReaderSecurityCanceledBeforeAnyCommand(t *testing.T) {
	r, m := guardReaderFixture()
	called := false
	r.run = func(context.Context, ...string) ([]byte, error) { called = true; return nil, nil }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.Check(ctx, m); err != ErrGuardRead || called {
		t.Fatal("canceled request reached command")
	}
}

func TestGuardReaderSecurityReqIDSetCannotUseInterfaceAlias(t *testing.T) {
	m, err := RenderGuard(encryptedGuardFixture())
	if err != nil {
		t.Fatal(err)
	}
	// A reqid is numeric SA identity, never an interface name—even if a supplied
	// link mapping would numerically resolve that name to the same value.
	observed := strings.Replace(m.ExpectedJSON, `"val":41`, `"val":"alias-for-reqid"`, 1)
	if observed == m.ExpectedJSON {
		t.Fatal("fixture failed to replace reqid")
	}
	if VerifyGuardReadbackWithInterfaces([]byte(m.ExpectedJSON), []byte(observed), []GuardInterface{{Name: "alias-for-reqid", Index: 41}}) == nil {
		t.Fatal("SA identity accepted interface alias")
	}
}
