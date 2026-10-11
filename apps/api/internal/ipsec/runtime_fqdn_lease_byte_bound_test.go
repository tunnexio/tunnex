package ipsec

import (
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"strings"
	"testing"
)

func TestRuntimeFQDNLeaseRequestExactByteBoundary(t *testing.T) {
	var g RuntimeFQDNGrant
	_ = json.Unmarshal([]byte(fqdnLeaseDescriptorGolden), &g)
	request := RuntimeLeaseRequest{DeliveryID: uuid.MustParse("88888888-8888-4888-8888-888888888888"), DesiredRevision: 9223372036854775807, PolicyHash: strings.Repeat("a", 64), Nonce: strings.Repeat("b", 64), FQDNGrants: []RuntimeFQDNGrant{g}}
	raw, _ := json.Marshal(request)
	padding := runtimeLeaseRequestByteLimit - len(raw)
	// This synthetic oversized name isolates the transport bound from the
	// separate canonical-name validator; no such descriptor is admitted authority.
	for _, delta := range []int{-1, 0, 1} {
		t.Run(fmt.Sprint(delta), func(t *testing.T) {
			q := request
			q.FQDNGrants = append([]RuntimeFQDNGrant(nil), request.FQDNGrants...)
			q.FQDNGrants[0].Name += strings.Repeat("x", padding+delta)
			bytes, _ := json.Marshal(q)
			if len(bytes) != runtimeLeaseRequestByteLimit+delta || runtimeLeaseRequestFits(q) != (delta <= 0) {
				t.Fatal("byte-bound drift", len(bytes), delta)
			}
		})
	}
	if !runtimeLeaseRequestFits(request) {
		t.Fatal("ordinary generated v2 request rejected")
	}
}
func TestRuntimeFQDNMaterialRejectsOversizedMaximalDescriptorAggregate(t *testing.T) {
	var g RuntimeFQDNGrant
	_ = json.Unmarshal([]byte(fqdnLeaseDescriptorGolden), &g)
	g.Name = strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	g.ResolverMatchSuffix = strings.Repeat("d", 61)
	policy := RuntimePolicy{FQDNPolicyVersion: 2, Hash: strings.Repeat("a", 64)}
	for i := 1; i <= 128; i++ {
		copy := g
		copy.RuleID = fmt.Sprintf("%08x-1111-4111-8111-111111111111", i)
		policy.FQDNGrants = append(policy.FQDNGrants, copy)
	}
	delivery := RuntimeDelivery{ID: uuid.New(), DesiredRevision: 123}
	if runtimeMaterialLeaseRequestFits(delivery, policy) {
		t.Fatal("count-only admission exceeded original 128KiB body bound")
	}
	policy.FQDNGrants = policy.FQDNGrants[:1]
	if !runtimeMaterialLeaseRequestFits(delivery, policy) {
		t.Fatal("valid normal generated request rejected")
	}
	policy.FQDNPolicyVersion = 1
	if !runtimeMaterialLeaseRequestFits(delivery, policy) {
		t.Fatal("legacy admission changed")
	}
}
