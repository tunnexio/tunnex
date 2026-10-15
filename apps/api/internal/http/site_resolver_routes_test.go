package http

import (
	"reflect"
	"testing"

	sitessvc "github.com/tunnexio/tunnex/apps/api/internal/sites"
)

func TestRoutedRangesCoverOnlyFinalResolverHosts(t *testing.T) {
	gateway := sitessvc.DNSForward{Domain: "private.example", ResolverIP: "10.99.0.1"}
	for _, tc := range []struct {
		name     string
		ranges   []string
		forwards []sitessvc.DNSForward
		want     []string
	}{
		{"gateway route without pool", []string{"10.180.0.0/16"}, []sitessvc.DNSForward{gateway, {Domain: "other.example", ResolverIP: gateway.ResolverIP}}, []string{"10.180.0.0/16", "10.99.0.1/32"}},
		{"already covered", []string{"10.99.0.0/24"}, []sitessvc.DNSForward{gateway}, []string{"10.99.0.0/24"}},
		{"withdrawal removes host", []string{"10.180.0.0/16"}, nil, []string{"10.180.0.0/16"}},
		{"conflict adds no route", []string{}, sitessvc.MergeResolverForwardsFailClosed([]sitessvc.DNSForward{gateway, {Domain: gateway.Domain, ResolverIP: "10.99.0.2"}}), []string{}},
		{"malformed resolver adds no route", []string{}, []sitessvc.DNSForward{{Domain: "bad.example", ResolverIP: "0.0.0.0/0"}}, []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := routedRangesWithResolverHosts(tc.ranges, tc.forwards)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ranges = %v, want %v", got, tc.want)
			}
		})
	}
}
