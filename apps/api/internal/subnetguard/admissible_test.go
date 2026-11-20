package subnetguard

import "testing"

// TestAdmissible pins which ranges may be routed through a site at all (SSI-1, finding F1). Before this
// guard, any IPv4 prefix that happened not to overlap an existing class was approvable, including a public
// range or half the address space, and became a route on every other gateway and device.
func TestAdmissible(t *testing.T) {
	cases := []struct {
		name      string
		candidate string
		wantOK    bool
		want      Refusal
	}{
		{"host inside 10/8", "10.50.1.10/32", true, ""},
		{"subnet inside 172.16/12", "172.31.37.0/24", true, ""},
		{"subnet inside 192.168/16", "192.168.1.0/24", true, ""},
		{"shared address space", "100.64.10.0/24", true, ""},
		{"a whole private block", "10.0.0.0/8", true, ""},
		{"the whole 172.16/12 block", "172.16.0.0/12", true, ""},
		{"half the address space", "128.0.0.0/1", false, RefusalTooWide},
		{"the default route", "0.0.0.0/0", false, RefusalTooWide},
		{"a public range", "8.8.8.0/24", false, RefusalNotPrivate},
		{"a public host", "203.0.113.7/32", false, RefusalNotPrivate},
		{"link-local", "169.254.0.0/16", false, RefusalNotPrivate},
		{"loopback", "127.0.0.0/8", false, RefusalNotPrivate},
		{"multicast", "224.0.0.0/4", false, RefusalNotPrivate},
		{"wider than 10/8", "10.0.0.0/7", false, RefusalTooWide},
		{"wider than 172.16/12", "172.16.0.0/11", false, RefusalTooWide},
		{"just outside 172.16/12", "172.32.0.0/16", false, RefusalNotPrivate},
		{"wider than 192.168/16", "192.168.0.0/15", false, RefusalTooWide},
		{"wider than 100.64/10", "100.64.0.0/9", false, RefusalTooWide},
		{"just outside 100.64/10", "100.128.0.0/16", false, RefusalNotPrivate},
		{"IPv6", "fd00::/8", false, RefusalNotIPv4},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := Admissible(p(c.candidate))
			if ok != c.wantOK || got != c.want {
				t.Fatalf("Admissible(%s) = (%q, %v), want (%q, %v)", c.candidate, got, ok, c.want, c.wantOK)
			}
		})
	}
}

// TestAdmissibleMasksHostBits: a prefix written with host bits set is judged by its network, the same way
// every other seam in this package treats it.
func TestAdmissibleMasksHostBits(t *testing.T) {
	if _, ok := Admissible(p("10.50.1.10/24")); !ok {
		t.Fatal("10.50.1.10/24 is 10.50.1.0/24 and must be admissible")
	}
}
