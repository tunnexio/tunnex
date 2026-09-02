package sites

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/google/uuid"
)

func TestSelectFQDNProfileForwardsReachabilityAndConflict(t *testing.T) {
	profileA, profileB, profileChild := uuid.New(), uuid.New(), uuid.New()
	candidates := []fqdnProfileResolverEndpoint{
		// First endpoint is outside the routed set, so the next reachable endpoint
		// in this profile becomes the desktop resolver.
		{ProfileID: profileA, Domain: "Internal.Example.", ResolverIP: "10.30.0.53"},
		{ProfileID: profileA, Domain: "Internal.Example.", ResolverIP: "10.20.0.53"},
		// A second endpoint in the same profile does not make the suffix ambiguous;
		// the query's stable endpoint order selects the first reachable address.
		{ProfileID: profileA, Domain: "internal.example", ResolverIP: "10.20.0.54"},
		// A more-specific suffix is independently valid and relies on longest-match.
		{ProfileID: profileChild, Domain: "dev.internal.example", ResolverIP: "10.20.0.54"},
	}
	prefixes := []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}
	want := []DNSForward{
		{Domain: "dev.internal.example", ResolverIP: "10.20.0.54"},
		{Domain: "internal.example", ResolverIP: "10.20.0.53"},
	}
	if got := selectFQDNProfileForwards(candidates, prefixes); !reflect.DeepEqual(got, want) {
		t.Fatalf("profile forwards: got %+v want %+v", got, want)
	}

	// Equal-precedence contexts with different resolver addresses are withheld
	// fail-closed; row order must never choose a tenant DNS authority.
	candidates = append(candidates, fqdnProfileResolverEndpoint{ProfileID: profileB, Domain: "internal.example", ResolverIP: "10.20.0.99"})
	want = []DNSForward{{Domain: "dev.internal.example", ResolverIP: "10.20.0.54"}}
	if got := selectFQDNProfileForwards(candidates, prefixes); !reflect.DeepEqual(got, want) {
		t.Fatalf("conflicted suffix must be omitted: got %+v want %+v", got, want)
	}
}

func TestMergeResolverForwardsFailsClosedOnAuthorityConflict(t *testing.T) {
	legacy := []DNSForward{{Domain: "corp.example", ResolverIP: "10.20.0.53"}}
	profiles := []DNSForward{
		{Domain: "corp.example.", ResolverIP: "10.20.0.54"},
		{Domain: "dev.corp.example", ResolverIP: "10.20.0.55"},
	}
	want := []DNSForward{{Domain: "dev.corp.example", ResolverIP: "10.20.0.55"}}
	if got := mergeResolverForwardsFailClosed(legacy, profiles); !reflect.DeepEqual(got, want) {
		t.Fatalf("merged forwards: got %+v want %+v", got, want)
	}
}
