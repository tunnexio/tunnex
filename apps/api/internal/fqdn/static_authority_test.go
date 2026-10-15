package fqdn

import "testing"

func TestStaticNamesOwnershipBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name     string
		selected int
		names    []string
		zones    [][]string
		want     bool
	}{
		{"nested other owner", 0, []string{"hidden.private.office.test"}, [][]string{{"office.test"}, {"private.office.test"}}, false},
		{"same profile multiple zones", 0, []string{"alias.office.test", "hidden.private.office.test"}, [][]string{{"office.test", "private.office.test"}}, true},
		{"narrow owner", 1, []string{"hidden.private.office.test"}, [][]string{{"office.test"}, {"private.office.test"}}, true},
		{"ambiguous equal suffix", 0, []string{"hidden.private.office.test"}, [][]string{{"office.test", "private.office.test"}, {"private.office.test"}}, false},
		{"label boundary", 0, []string{"not-office.test"}, [][]string{{"office.test"}}, false},
		{"missing selected profile", -1, []string{"alias.office.test"}, [][]string{{"office.test"}}, false},
		{"noncanonical authority", 0, []string{"alias.office.test"}, [][]string{{"Office.test"}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := StaticNamesOwnedByProfile(tc.selected, tc.names, tc.zones); got != tc.want {
				t.Fatalf("ownership = %v, want %v", got, tc.want)
			}
		})
	}
}
