package http

import "testing"

// egress_policy_denied (S7.2 decision 2-coherence) is a DISTINCT named state from
// gateway_no_egress: the former means "the gateway CAN egress, but Zero Trust policy
// denies this device's internet egress"; the latter means "the gateway cannot egress
// at all". Conflating them would mislead an operator into changing the wrong thing.
func TestEgressPolicyDeniedDistinctFromGatewayNoEgress(t *testing.T) {
	if EgressPolicyDenied == "gateway_no_egress" {
		t.Fatal("egress_policy_denied must be a distinct code from gateway_no_egress")
	}
	if EgressPolicyDenied != "egress_policy_denied" {
		t.Fatalf("unexpected code %q", EgressPolicyDenied)
	}
}
