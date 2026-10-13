package main

import (
	"strings"
	"testing"
)

const policy = "src 10.70.0.0/24 dst 10.80.0.0/24\n dir out priority 375423 ptype main\n tmpl src 34.131.136.132 dst 34.153.32.207\n proto esp reqid 2716755764 mode tunnel\n if_id 0xa1ee6734\n"

func TestProductionPolicyProjection(t *testing.T) {
	p, e := parse([]byte(policy))
	if e != nil || len(p) != 1 || p[0].IfID != 2716755764 || p[0].Templates[0].ReqID != 2716755764 {
		t.Fatal("projection refused", e)
	}
	for _, raw := range []string{policy + policy, strings.Replace(policy, "mode tunnel", "mode transport", 1), policy + " mark 0x1/0xffffffff\n", `[{"reqid":1}]`} {
		if _, e := parse([]byte(raw)); e == nil {
			t.Fatal("unknown policy admitted")
		}
	}
	p, e = parse(nil)
	if e != nil || len(p) != 0 {
		t.Fatal("empty nosock inventory refused")
	}
}
