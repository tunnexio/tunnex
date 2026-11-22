package ownershiplease

import (
	"reflect"
	"testing"

	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
	"github.com/tunnexio/tunnex/apps/node/internal/reconcile"
)

// K8L-9. One Service exposed on two ports is two VIP mappings with the same name and address. The resolver
// holds a single answer for that name, so the expected state must hold a single answer too. Before this, the
// readback differed in dns_answers and a gateway holding such a Service crash-looped on restart
// ("ownership full-domain readback mismatch"), found live on 2026-11-22.
func TestExpectedDNSAnswersCollapseAMultiPortService(t *testing.T) {
	mapping := func(id string, port int) nodepolicy.VIPMapping {
		return nodepolicy.VIPMapping{ServiceID: id, VIP: "100.66.0.3", Namespace: "shop", Service: "web", Protocol: "tcp", PortLow: port, PortHigh: port, DNSName: "web.shop.svc.gitops.k8s.corp.internal"}
	}
	desired := reconcile.DesiredState{Policy: &nodepolicy.Compiled{VIPMappings: []nodepolicy.VIPMapping{mapping("svc-80", 80), mapping("svc-8080", 8080)}}}
	expected := expectedDomainState(desired)

	want := []K8sDNSAnswer{{Name: "web.shop.svc.gitops.k8s.corp.internal", VIP: "100.66.0.3"}}
	if !reflect.DeepEqual(expected.DNSAnswers, want) {
		t.Fatalf("expected DNS answers = %+v, want one answer for the shared name", expected.DNSAnswers)
	}
	if len(expected.VIPMappings) != 2 {
		t.Fatalf("both port mappings must remain: %+v", expected.VIPMappings)
	}
	// What the resolver reports (one answer) now equals the expectation, so the readback matches.
	actual := canonicalDomainState(AppliedDomainState{DNSAnswers: want})
	if !reflect.DeepEqual(actual.DNSAnswers, expected.DNSAnswers) {
		t.Fatalf("resolver state %+v does not match the expectation %+v", actual.DNSAnswers, expected.DNSAnswers)
	}
	// Two different Services keep two answers.
	other := mapping("svc-api", 80)
	other.Service, other.VIP, other.DNSName = "api", "100.66.0.4", "api.shop.svc.gitops.k8s.corp.internal"
	desired.Policy.VIPMappings = append(desired.Policy.VIPMappings, other)
	if got := expectedDomainState(desired).DNSAnswers; len(got) != 2 {
		t.Fatalf("distinct Services must keep distinct answers: %+v", got)
	}
}
