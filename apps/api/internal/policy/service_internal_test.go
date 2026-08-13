package policy

import "testing"

// canonicalCIDR must mask host bits so the stored + compiled DstCIDR is canonical
// (S7.2's nftables/ipset apply rejects or mis-reads a host-bits-set prefix).
func TestCanonicalCIDR(t *testing.T) {
	cases := map[string]string{
		"10.0.5.5/24":    "10.0.5.0/24",   // host bits set -> masked
		"10.0.5.0/24":    "10.0.5.0/24",   // already canonical
		"0.0.0.0/0":      "0.0.0.0/0",     // the internet
		"10.99.0.7/32":   "10.99.0.7/32",  // host route
		"2001:db8::5/32": "2001:db8::/32", // v6 host bits set
	}
	for in, want := range cases {
		if got := canonicalCIDR(in); got != want {
			t.Errorf("canonicalCIDR(%q) = %q, want %q", in, got, want)
		}
	}
}
