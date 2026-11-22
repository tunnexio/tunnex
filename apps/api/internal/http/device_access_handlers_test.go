package http

import (
	"errors"
	"strings"
	"testing"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
)

func deviceAccessBaseline() deviceAccessFacts {
	return deviceAccessFacts{
		deviceStatus: "active", deviceAddress: "10.99.0.7",
		gatewayName: "gw", gatewayStatus: "active", gatewayFresh: true,
		destination:  "10.99.0.8",
		policy:       policyspec.AccessEvaluation{Allowed: true, Mode: "enforcing", PolicyVersion: 4, PolicyHash: "h", RuleID: "rule-1"},
		reach:        nodes.GatewayReach{PoolCIDR: "10.99.0.0/24", LocalSubnets: []string{"192.168.10.0/24"}, Routes: []string{"172.16.0.0/16"}},
		health:       &nodes.PolicyHealth{PushKnown: true, PushedHash: "h", AppliedHash: "h"},
		policyReport: true,
	}
}

func deviceAccessCodes(b accessCheckBuilder) []string {
	out := make([]string, 0, len(b.checks))
	for _, check := range b.checks {
		out = append(out, check.Code)
	}
	return out
}

func TestDeviceAccessChecksOrderAndOverall(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*deviceAccessFacts)
		codes   []string
		overall api.AgentAccessDiagnosticOverall
		blocker string
	}{
		{name: "allowed literal", mutate: func(*deviceAccessFacts) {},
			codes:   []string{"device_active", "posture_not_blocking", "gateway_reporting", "destination_ip", "route_configured", "matching_grant", "applied_policy_current"},
			overall: api.AgentAccessDiagnosticOverallAllowed},
		{name: "revoked device", mutate: func(f *deviceAccessFacts) { f.deviceStatus = "revoked" },
			codes:   []string{"device_not_active", "posture_not_blocking", "gateway_reporting", "destination_ip", "route_configured", "matching_grant", "applied_policy_current"},
			overall: api.AgentAccessDiagnosticOverallDenied, blocker: "device_not_active"},
		{name: "active without address", mutate: func(f *deviceAccessFacts) { f.deviceAddress = "" },
			codes:   []string{"device_not_active", "posture_not_blocking", "gateway_reporting", "destination_ip", "route_configured", "matching_grant", "applied_policy_current"},
			overall: api.AgentAccessDiagnosticOverallDenied, blocker: "device_not_active"},
		{name: "posture blocked", mutate: func(f *deviceAccessFacts) { f.healthBlocked = true },
			codes:   []string{"device_active", "posture_blocked", "gateway_reporting", "destination_ip", "route_configured", "matching_grant", "applied_policy_current"},
			overall: api.AgentAccessDiagnosticOverallDenied, blocker: "posture_blocked"},
		{name: "gateway stale", mutate: func(f *deviceAccessFacts) { f.gatewayFresh = false },
			codes:   []string{"device_active", "posture_not_blocking", "gateway_not_reporting", "destination_ip", "route_configured", "matching_grant", "applied_policy_current"},
			overall: api.AgentAccessDiagnosticOverallDenied, blocker: "gateway_not_reporting"},
		{name: "gateway revoked", mutate: func(f *deviceAccessFacts) { f.gatewayStatus = "revoked" },
			codes:   []string{"device_active", "posture_not_blocking", "gateway_not_reporting", "destination_ip", "route_configured", "matching_grant", "applied_policy_current"},
			overall: api.AgentAccessDiagnosticOverallDenied, blocker: "gateway_not_reporting"},
		{name: "no applied report", mutate: func(f *deviceAccessFacts) { f.policyReport = false },
			codes:   []string{"device_active", "posture_not_blocking", "gateway_reporting", "destination_ip", "route_configured", "matching_grant", "applied_policy_not_observed"},
			overall: api.AgentAccessDiagnosticOverallInconclusive, blocker: "applied_policy_not_observed"},
		{name: "applied mismatch", mutate: func(f *deviceAccessFacts) { f.health.AppliedHash = "other" },
			codes:   []string{"device_active", "posture_not_blocking", "gateway_reporting", "destination_ip", "route_configured", "matching_grant", "applied_policy_mismatch"},
			overall: api.AgentAccessDiagnosticOverallDenied, blocker: "applied_policy_mismatch"},
		{name: "no grant", mutate: func(f *deviceAccessFacts) { f.policy.Allowed, f.policy.RuleID = false, "" },
			codes:   []string{"device_active", "posture_not_blocking", "gateway_reporting", "destination_ip", "route_configured", "no_matching_grant", "applied_policy_current"},
			overall: api.AgentAccessDiagnosticOverallDenied, blocker: "no_matching_grant"},
		{name: "site subnet and remote route", mutate: func(f *deviceAccessFacts) { f.destination = "172.16.4.4" },
			codes:   []string{"device_active", "posture_not_blocking", "gateway_reporting", "destination_ip", "route_configured", "matching_grant", "applied_policy_current"},
			overall: api.AgentAccessDiagnosticOverallAllowed},
		{name: "no route", mutate: func(f *deviceAccessFacts) { f.destination = "192.0.2.10"; f.policy.Allowed = false },
			codes:   []string{"device_active", "posture_not_blocking", "gateway_reporting", "destination_ip", "route_not_configured", "no_matching_grant", "applied_policy_current"},
			overall: api.AgentAccessDiagnosticOverallDenied, blocker: "route_not_configured"},
		{name: "hostname with answers", mutate: func(f *deviceAccessFacts) {
			f.destination, f.policy.DestinationAnswers = "orders.internal.example", []string{"10.99.0.8", "192.168.10.9"}
		},
			codes:   []string{"device_active", "posture_not_blocking", "gateway_reporting", "fqdn_generation_active", "route_configured", "matching_grant", "applied_policy_current"},
			overall: api.AgentAccessDiagnosticOverallAllowed},
		{name: "hostname without answers", mutate: func(f *deviceAccessFacts) {
			f.destination, f.policy.Allowed, f.policy.RuleID = "orders.internal.example", false, ""
		},
			codes:   []string{"device_active", "posture_not_blocking", "gateway_reporting", "device_dns_not_observed", "route_destination_unresolved", "applied_policy_current"},
			overall: api.AgentAccessDiagnosticOverallInconclusive, blocker: "device_dns_not_observed"},
		{name: "off mode", mutate: func(f *deviceAccessFacts) {
			f.policy, f.health, f.policyReport = policyspec.AccessEvaluation{Allowed: true, Mode: "off"}, nil, false
		},
			codes:   []string{"device_active", "posture_not_blocking", "gateway_reporting", "destination_ip", "route_configured", "policy_not_enforcing", "applied_policy_not_required"},
			overall: api.AgentAccessDiagnosticOverallAllowed},
		{name: "compiled policy unavailable", mutate: func(f *deviceAccessFacts) {
			f.policyErr, f.policy, f.reach = errors.New("unavailable"), policyspec.AccessEvaluation{}, nodes.GatewayReach{}
		},
			codes:   []string{"device_active", "posture_not_blocking", "gateway_reporting", "destination_ip", "compiled_policy_unavailable", "applied_policy_current"},
			overall: api.AgentAccessDiagnosticOverallInconclusive, blocker: "compiled_policy_unavailable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			facts := deviceAccessBaseline()
			tc.mutate(&facts)
			b := deviceAccessChecks(facts)
			got := deviceAccessCodes(b)
			if strings.Join(got, ",") != strings.Join(tc.codes, ",") {
				t.Fatalf("codes\n got %v\nwant %v", got, tc.codes)
			}
			if len(got) < 1 || len(got) > 8 {
				t.Fatalf("check count %d is outside the published 1..8 bound", len(got))
			}
			if b.overall() != tc.overall {
				t.Fatalf("overall = %q, want %q", b.overall(), tc.overall)
			}
			blocker := ""
			if b.firstBlocker != nil {
				blocker = *b.firstBlocker
			}
			if blocker != tc.blocker {
				t.Fatalf("first blocker = %q, want %q", blocker, tc.blocker)
			}
		})
	}
}

func TestDeviceAccessRouteCheckNamesTheHomeGateway(t *testing.T) {
	for _, destination := range []string{"10.99.0.8", "192.168.10.9", "172.16.4.4", "192.0.2.10", "orders.internal.example"} {
		facts := deviceAccessBaseline()
		facts.destination = destination
		b := deviceAccessChecks(facts)
		found := false
		for _, check := range b.checks {
			if !strings.HasPrefix(check.Code, "route_") {
				continue
			}
			found = true
			if !strings.Contains(check.Message, "home gateway") {
				t.Fatalf("%s: route check %q does not state the home-gateway limit: %q", destination, check.Code, check.Message)
			}
		}
		if !found {
			t.Fatalf("%s: no route check in %v", destination, deviceAccessCodes(b))
		}
	}
}

func TestDeviceAccessRouteFactsNameTheCoveringNetwork(t *testing.T) {
	for destination, fact := range map[string]string{"10.99.0.8": "device_pool", "192.168.10.9": "gateway_site_subnet", "172.16.4.4": "gateway_route"} {
		facts := deviceAccessBaseline()
		facts.destination = destination
		check := deviceAccessChecks(facts).checks[4]
		if check.Code != "route_configured" || check.Facts == nil || (*check.Facts)[fact] == "" {
			t.Fatalf("%s: expected route_configured with fact %q, got %#v", destination, fact, check)
		}
	}
}

func TestDeviceAccessFullTunnelUnroutedDestinationIsInconclusive(t *testing.T) {
	facts := deviceAccessBaseline()
	facts.destination, facts.fullTunnel = "192.0.2.10", true
	facts.policy = policyspec.AccessEvaluation{Allowed: true, Mode: "off"}
	b := deviceAccessChecks(facts)
	route := b.checks[4]
	if route.Code != "route_not_configured" || route.Status != api.AgentAccessCheckStatusInconclusive || b.overall() != api.AgentAccessDiagnosticOverallInconclusive {
		t.Fatalf("full-tunnel default route must not be reported as a denial: %#v overall=%q", route, b.overall())
	}
}
