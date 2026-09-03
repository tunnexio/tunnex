package sites

import (
	"reflect"
	"testing"
)

func TestMergeResolverForwardsFailsClosedOnAuthorityConflict(t *testing.T) {
	legacy := []DNSForward{{Domain: "corp.example", ResolverIP: "10.20.0.53"}}
	profiles := []DNSForward{
		{Domain: "corp.example.", ResolverIP: "10.20.0.54"},
		{Domain: "dev.corp.example", ResolverIP: "10.20.0.55"},
	}
	want := []DNSForward{{Domain: "dev.corp.example", ResolverIP: "10.20.0.55"}}
	if got := MergeResolverForwardsFailClosed(legacy, profiles); !reflect.DeepEqual(got, want) {
		t.Fatalf("merged forwards: got %+v want %+v", got, want)
	}
}
