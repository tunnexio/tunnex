package ipsec

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestRuntimeRestartMissingLinksRequiresFreshLease(t *testing.T) {
	r := newRecoveryTestRig(t)
	r.c.recoveryPrepared = nil
	r.lease.deny = true
	mutations := 0
	r.c.kernel = &KernelApplier{namespace: r.c.namespace, run: func(_ context.Context, args ...string) ([]byte, error) {
		q := strings.Join(args, " ")
		if q == "xfrm state list nokeys" || q == "xfrm policy list nosock" {
			return nil, nil
		}
		if strings.HasPrefix(q, "-j ") {
			return []byte(`[]`), nil
		}
		mutations++
		return nil, errors.New("unexpected mutation")
	}}
	if r.apply() == nil {
		t.Fatal("recreated without CP lease")
	}
	if mutations != 0 || len(r.c.active) != 0 {
		t.Fatal("denied restart mutated kernel or granted traffic")
	}
	if len(r.events) == 0 || r.events[0] != "deny" {
		t.Fatal("restart did not first withdraw traffic")
	}
}
