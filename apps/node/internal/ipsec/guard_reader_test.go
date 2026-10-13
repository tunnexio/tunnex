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

func TestGuardReaderReleasesReadContextAfterObservation(t *testing.T) {
	for _, kind := range []string{"success", "read_error", "parent_cancel"} {
		t.Run(kind, func(t *testing.T) {
			r, m := guardReaderFixture()
			parent, cancelParent := context.WithCancel(context.Background())
			defer cancelParent()
			var readCtx context.Context
			r.run = func(ctx context.Context, _ ...string) ([]byte, error) {
				readCtx = ctx
				switch kind {
				case "read_error":
					return nil, errors.New("fixture read refusal")
				case "parent_cancel":
					cancelParent()
				}
				return []byte(guardExpectedFixture), nil
			}
			observed := 0
			err := r.checkObserved(parent, m, VerifyGuardReadbackWithInterfaces, func(timing guardReadTiming) {
				observed++
				want := "none"
				if kind == "read_error" {
					want = "structural_or_read"
				} else if kind == "parent_cancel" {
					want = "context_canceled"
				}
				if timing.FailureClass != want {
					t.Fatalf("classification before cleanup: %s != %s", timing.FailureClass, want)
				}
				if kind != "parent_cancel" && readCtx.Err() != nil {
					t.Fatal("read context canceled before diagnostic observation")
				}
			})
			if (err == nil) != (kind == "success") || observed != 1 || readCtx == nil || readCtx.Err() != context.Canceled {
				t.Fatal("read context or observation lifecycle changed", err, observed)
			}
			if kind != "parent_cancel" && parent.Err() != nil {
				t.Fatal("read cleanup canceled its caller")
			}
		})
	}
}
