package authctx_test

import "testing"

func TestAgentPrincipalCensusDistinguishesDTO(t *testing.T) {
	cases := []struct {
		name, source      string
		literals, nodeIDs int
	}{
		{"runtime DTO", `package http; import "github.com/tunnexio/tunnex/apps/api/internal/ipsec";func f(){_ = ipsec.RuntimePrincipal{NodeID: x}}`, 0, 0},
		{"actual principal", `package http; import "github.com/tunnexio/tunnex/apps/api/internal/authctx";func f(){_ = authctx.Principal{NodeID: x}}`, 1, 1},
		{"import alias", `package http;import identity "github.com/tunnexio/tunnex/apps/api/internal/authctx";func f(){_ = identity.Principal {NodeID:x}}`, 1, 1},
		{"DTO after human", `package http;func f(){_ = Principal{UserID:x};_ = RuntimePrincipal{NodeID:x}}`, 1, 0},
		{"comments", `package http;func f(){/* authctx.Principal{NodeID:x} */_ = "Principal{NodeID:x}"}`, 0, 0},
		{"nested unrelated field", `package http;func f(){_ = Principal{Other: RuntimePrincipal{NodeID:x}}}`, 1, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, n, err := principalConstructionSites("fixture.go", []byte(tc.source))
			if err != nil || len(l) != tc.literals || len(n) != tc.nodeIDs {
				t.Fatalf("census got %d/%d want %d/%d: %v", len(l), len(n), tc.literals, tc.nodeIDs, err)
			}
		})
	}
}
