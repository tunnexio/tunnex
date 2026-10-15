package fqdnresources

import "testing"

func TestStaticRecordMustBelongToMostSpecificProfile(t *testing.T) {
	broad := ResolverProfile{Name: "Office", ProviderHint: "on_premises", ZoneSuffixes: []string{"office.test"}, StaticRecords: []ResolverStaticRecord{{Name: "alias.office.test", Type: "CNAME", Value: "hidden.private.office.test", TTL: 300}, {Name: "hidden.private.office.test", Type: "A", Value: "10.20.0.80", TTL: 300}}}
	narrow := ResolverProfile{Name: "Private", ProviderHint: "on_premises", ZoneSuffixes: []string{"private.office.test"}, StaticRecords: []ResolverStaticRecord{{Name: "owned.private.office.test", Type: "A", Value: "10.20.0.81", TTL: 300}}}
	if err := validateProfiles([]ResolverProfile{broad, narrow}); err == nil {
		t.Fatal("broad profile accepted a record shadowed by a narrower authority")
	}
	broad.ZoneSuffixes = append(broad.ZoneSuffixes, "private.office.test")
	if err := validateProfiles([]ResolverProfile{broad}); err != nil {
		t.Fatal("same-profile multiple zones refused", err)
	}
}
