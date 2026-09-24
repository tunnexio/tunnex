package ipsec

import (
	"context"
	"reflect"
	"testing"
)

func TestXFRMReaderAlwaysNoKeys(t *testing.T) {
	var calls [][]string
	r := &XFRMReader{namespace: func() (string, error) { return "net:[42]", nil }, run: func(_ context.Context, args ...string) ([]byte, error) {
		calls = append(calls, args)
		if len(calls) == 1 {
			return []byte(xfrmStateFixture), nil
		}
		return []byte(xfrmPolicyFixture), nil
	}}
	got, err := r.Read(context.Background())
	if err != nil || len(got.States) != 1 {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(calls, [][]string{{"xfrm", "state", "list", "nokeys"}, {"xfrm", "policy", "list", "nosock"}}) {
		t.Fatal("unsafe command shape")
	}
	calls = nil
	n := 0
	r.namespace = func() (string, error) {
		n++
		if n == 1 {
			return "net:[42]", nil
		}
		return "net:[43]", nil
	}
	if _, err = r.Read(context.Background()); err != ErrXFRMRead {
		t.Fatal("namespace change accepted")
	}
}

func TestXFRMReaderRefusals(t *testing.T) {
	if _, err := NewXFRMReader("ip"); err != ErrXFRMRead {
		t.Fatal("relative binary accepted")
	}
	for _, mode := range []string{"command", "oversize", "malformed", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			r := &XFRMReader{namespace: func() (string, error) { return "net:[42]", nil }, run: func(context.Context, ...string) ([]byte, error) {
				calls++
				switch mode {
				case "command":
					return nil, ErrXFRMInventoryInvalid
				case "oversize":
					return make([]byte, kernelOutputLimit+1), nil
				default:
					return []byte("untrusted diagnostic"), nil
				}
			}}
			if mode == "cancelled" {
				cancel()
			}
			got, err := r.Read(ctx)
			if err != ErrXFRMRead || got.Namespace != "" {
				t.Fatal("unsafe observation accepted")
			}
			if mode == "cancelled" && calls != 0 {
				t.Fatal("cancelled command ran")
			}
		})
	}
}
