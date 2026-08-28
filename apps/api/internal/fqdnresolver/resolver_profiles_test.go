package fqdnresolver

import (
	"errors"
	"net/netip"
	"testing"
)

func TestSelectResolverProfileUsesMostSpecificLabelBoundaryAndNoFallback(t *testing.T) {
	endpoint := []ResolverEndpoint{{Address: netip.MustParseAddr("10.53.0.53"), Port: 53, Transport: "udp"}}
	profiles := []ResolverProfile{
		{ID: "11111111-1111-1111-1111-111111111111", Name: "AWS", ZoneSuffixes: []string{"internal.example.com"}, Endpoints: endpoint},
		{ID: "22222222-2222-2222-2222-222222222222", Name: "Azure", ZoneSuffixes: []string{"azure.internal.example.com"}, Endpoints: endpoint},
	}
	profile, suffix, err := selectResolverProfile("orders.azure.internal.example.com", profiles)
	if err != nil || profile.Name != "Azure" || suffix != "azure.internal.example.com" {
		t.Fatalf("selected=%#v suffix=%q err=%v", profile, suffix, err)
	}
	profile, suffix, err = selectResolverProfile("orders.internal.example.com", profiles)
	if err != nil || profile.Name != "AWS" || suffix != "internal.example.com" {
		t.Fatalf("selected=%#v suffix=%q err=%v", profile, suffix, err)
	}
	if _, _, err = selectResolverProfile("notinternal.example.com", profiles); !errors.Is(err, ErrNoMatchingProfile) {
		t.Fatalf("label-boundary miss err=%v", err)
	}
	if _, _, err = selectResolverProfile("orders.unmatched.example.net", profiles); !errors.Is(err, ErrNoMatchingProfile) {
		t.Fatalf("unmatched err=%v", err)
	}
}

func TestSelectResolverProfileRejectsEqualPrecedenceAndPreservesLegacyDefault(t *testing.T) {
	profiles := []ResolverProfile{
		{ID: "11111111-1111-1111-1111-111111111111", ZoneSuffixes: []string{"internal.example.com"}},
		{ID: "22222222-2222-2222-2222-222222222222", ZoneSuffixes: []string{"internal.example.com"}},
	}
	if _, _, err := selectResolverProfile("orders.internal.example.com", profiles); !errors.Is(err, ErrDisagreement) {
		t.Fatalf("duplicate suffix err=%v", err)
	}
	legacy := ResolverProfile{ID: "33333333-3333-3333-3333-333333333333", Name: "Legacy", LegacyDefault: true}
	profile, suffix, err := selectResolverProfile("anything.example", []ResolverProfile{legacy})
	if err != nil || profile.ID != legacy.ID || suffix != "" {
		t.Fatalf("legacy selected=%#v suffix=%q err=%v", profile, suffix, err)
	}
}
