package ipsec

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func guardReaderFixture() (*GuardReader, GuardManifest) {
	manifest := GuardManifest{Namespace: "net:[123]", ExpectedJSON: guardExpectedFixture}
	return &GuardReader{namespace: func() (string, error) { return manifest.Namespace, nil }, interfaces: func() ([]GuardInterface, error) { return []GuardInterface{{Name: "tnxi-a", Index: 10}}, nil }, run: func(ctx context.Context, args ...string) ([]byte, error) { return []byte(guardExpectedFixture), nil }}, manifest
}
func TestGuardReaderExactReadOnlyCommand(t *testing.T) {
	r, m := guardReaderFixture()
	r.run = func(ctx context.Context, args ...string) ([]byte, error) {
		if !reflect.DeepEqual(args, []string{"-j", "list", "table", "inet", "tunnex_ipsec"}) {
			t.Fatal(args)
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("unbounded command")
		}
		return []byte(guardExpectedFixture), nil
	}
	if r.Check(context.Background(), m) != nil {
		t.Fatal("exact readback rejected")
	}
	if _, err := NewGuardReader("nft"); err == nil {
		t.Fatal("PATH lookup accepted")
	}
}
func TestGuardReaderIdentityAndFailureRefusal(t *testing.T) {
	for _, kind := range []string{"namespace", "links", "error", "oversize", "canceled", "semantic"} {
		t.Run(kind, func(t *testing.T) {
			r, m := guardReaderFixture()
			ctx := context.Background()
			switch kind {
			case "namespace":
				n := 0
				r.namespace = func() (string, error) {
					n++
					if n == 1 {
						return m.Namespace, nil
					}
					return "net:[456]", nil
				}
			case "links":
				n := 0
				r.interfaces = func() ([]GuardInterface, error) { n++; return []GuardInterface{{Name: "tnxi-a", Index: 10 + n}}, nil }
			case "error":
				r.run = func(context.Context, ...string) ([]byte, error) {
					return []byte("sensitive marker"), errors.New("sensitive marker")
				}
			case "oversize":
				r.run = func(context.Context, ...string) ([]byte, error) { return make([]byte, kernelOutputLimit+1), nil }
			case "canceled":
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			case "semantic":
				r.run = func(context.Context, ...string) ([]byte, error) { return []byte(`{"nftables":[]}`), nil }
			}
			if err := r.Check(ctx, m); err != ErrGuardRead {
				t.Fatalf("failure not statically refused: %v", err)
			}
		})
	}
}
