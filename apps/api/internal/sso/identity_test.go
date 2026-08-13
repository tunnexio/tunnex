package sso

import "testing"

// TestDecideLinkMatrix is the executable spec of the account-linking policy —
// every combination of (local exists, local verified, IdP verified).
func TestDecideLinkMatrix(t *testing.T) {
	cases := []struct {
		name                                 string
		localExists, localVerified, idpVerif bool
		want                                 LinkAction
	}{
		{"idp unverified always rejects (no local)", false, false, false, LinkReject},
		{"idp unverified always rejects (local verified)", true, true, false, LinkReject},
		{"no local, idp verified -> create", false, false, true, LinkCreate},
		{"local verified, idp verified -> attach", true, true, true, LinkAttach},
		{"local UNVERIFIED, idp verified -> reject (takeover guard)", true, false, true, LinkReject},
	}
	for _, c := range cases {
		if got := DecideLink(c.localExists, c.localVerified, c.idpVerif); got != c.want {
			t.Errorf("%s: DecideLink(%v,%v,%v)=%s want %s",
				c.name, c.localExists, c.localVerified, c.idpVerif, got, c.want)
		}
	}
}
