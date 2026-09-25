package ipsec

import (
	"strings"
	"testing"
)

func TestGuardReadbackHostPrefixCanonicalization(t *testing.T) {
	for _, field := range []string{"saddr", "daddr"} {
		t.Run(field, func(t *testing.T) {
			host := `{"prefix":{"addr":"10.203.10.10","len":32}}`
			match := `{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"` + field + `"}},"right":` + host + `}},`
			expected := strings.Replace(guardExpectedFixture, `{"counter":null}`, match+`{"counter":null}`, 1)
			observed := strings.Replace(expected, host, `"10.203.10.10"`, 1)
			observed = strings.Replace(observed, `{"counter":null}`, `{"counter":{"packets":5,"bytes":300}}`, 1)
			if VerifyGuardReadback([]byte(expected), []byte(observed)) != nil {
				t.Fatal("nft canonical host address refused")
			}
			if VerifyGuardWithdrawal([]byte(expected), []byte(observed), nil) != nil {
				t.Fatal("canonical host blocks safe replacement")
			}
			for _, bad := range []string{`"10.203.10.11"`, `{"prefix":{"addr":"10.203.10.10","len":24}}`, `{"prefix":{"addr":"10.203.10.10","len":32,"other":true}}`, `"::ffff:10.203.10.10"`} {
				changed := strings.Replace(expected, host, bad, 1)
				if VerifyGuardReadback([]byte(expected), []byte(changed)) == nil {
					t.Fatalf("accepted drift %s", bad)
				}
			}
		})
	}
}
