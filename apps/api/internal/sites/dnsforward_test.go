package sites

import "testing"

// TestDNSDomainConflict — S8.4 D1-addition: within an org a domain forwards to ONE resolver; a duplicate
// (case/dot-insensitive) is a conflict refused at write time. Distinct domains + malformed input do not.
func TestDNSDomainConflict(t *testing.T) {
	existing := []string{"corp.local", "a.example.com"}
	if !DNSDomainConflict(existing, "Corp.Local.") {
		t.Fatal("a case/dot variant of an existing domain must conflict (one zone → one resolver)")
	}
	if DNSDomainConflict(existing, "other.local") {
		t.Fatal("a distinct domain must NOT conflict")
	}
	if DNSDomainConflict(existing, "a..b") {
		t.Fatal("a malformed candidate is not a domain-conflict (rejected separately as malformed)")
	}
}

func TestNormalizeDomain(t *testing.T) {
	for _, c := range []struct {
		in     string
		want   string
		wantOK bool
	}{
		{"Corp.Local.", "corp.local", true},
		{"  nas.mumbai.acme.com ", "nas.mumbai.acme.com", true},
		{"internal", "internal", true}, // F3: a single-label zone is LEGITIMATE (homelab/SMB) — the helper must accept what the CP does
		{"corp", "corp", true},
		{"", "", false},
		{"a..b", "", false},
		{"has space", "", false},
	} {
		got, ok := NormalizeDomain(c.in)
		if got != c.want || ok != c.wantOK {
			t.Fatalf("NormalizeDomain(%q) = (%q,%v), want (%q,%v)", c.in, got, ok, c.want, c.wantOK)
		}
	}
}
