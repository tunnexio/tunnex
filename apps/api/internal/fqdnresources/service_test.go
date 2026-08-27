package fqdnresources

import "testing"

func TestInputValidationPreservesTheFQDNOnlyContract(t *testing.T) {
	good := Input{Name: "orders", FQDN: "BÜCHER.example.", Protocol: "tcp"}
	if err := valid(&good); err != nil || good.FQDN != "xn--bcher-kva.example" {
		t.Fatalf("normalization = %q, %v", good.FQDN, err)
	}
	for _, in := range []Input{{Name: "x", FQDN: "10.0.0.1", Protocol: "any"}, {Name: "x", FQDN: "orders.example", Protocol: "any", PortLow: intp(443)}} {
		if err := valid(&in); err == nil {
			t.Fatalf("accepted invalid input %#v", in)
		}
	}
}
func intp(v int) *int { return &v }
