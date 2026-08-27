package policyspec

import (
	"testing"

	"github.com/google/uuid"
)

func TestEvaluateAccessUsesAttributedCompiledGrant(t *testing.T) {
	device := uuid.New()
	compiled := &Compiled{
		Version: 4, Mode: "enforcing",
		Subjects: []SubjectAttribution{{SrcIP: "10.99.0.7", DeviceID: device.String(), Kind: "agent"}},
		Allow: []AllowEntry{{SrcIP: "10.99.0.7", DstCIDR: "10.20.0.0/16", Protocol: ProtoTCP,
			PortLow: 443, PortHigh: 443, RuleID: "rule-1", SrcDeviceID: device.String()}},
	}
	got := EvaluateAccess(compiled, device, "10.99.0.7", "10.20.3.4", "tcp", 443)
	if !got.Allowed || got.RuleID != "rule-1" || got.PolicyHash == "" || got.PolicyVersion != 4 {
		t.Fatalf("expected exact grant match, got %+v", got)
	}
	if denied := EvaluateAccess(compiled, device, "10.99.0.7", "10.20.3.4", "udp", 443); denied.Allowed {
		t.Fatalf("protocol mismatch must deny: %+v", denied)
	}
}

func TestEvaluateAccessRefusesAddressInference(t *testing.T) {
	selected := uuid.New()
	other := uuid.New()
	compiled := &Compiled{
		Version: 4, Mode: "enforcing",
		Subjects: []SubjectAttribution{{SrcIP: "10.99.0.7", DeviceID: other.String(), Kind: "agent"}},
		Allow: []AllowEntry{{SrcIP: "10.99.0.7", DstCIDR: "0.0.0.0/0", Protocol: ProtoAny,
			RuleID: "wrong-owner", SrcDeviceID: other.String()}},
	}
	if got := EvaluateAccess(compiled, selected, "10.99.0.7", "1.1.1.1", "tcp", 443); got.Allowed {
		t.Fatalf("matching address without selected-device attribution must deny: %+v", got)
	}
}

func TestEvaluateAccessOffModeMesh(t *testing.T) {
	device := uuid.New()
	compiled := &Compiled{Version: 4, Mode: "off", Mesh: true,
		Subjects: []SubjectAttribution{{SrcIP: "10.99.0.7", DeviceID: device.String(), Kind: "agent"}}}
	if got := EvaluateAccess(compiled, device, "10.99.0.7", "10.99.0.8", "udp", 53); !got.Allowed || got.PolicyHash != "" {
		t.Fatalf("off-mode mesh should pass without enforcement hash: %+v", got)
	}
}

func TestEvaluateAccessUsesOnlyActiveFQDNGenerationAnswers(t *testing.T) {
	device := uuid.New()
	compiled := &Compiled{Version: 8, Mode: "enforcing",
		Subjects:        []SubjectAttribution{{SrcIP: "10.99.0.7", DeviceID: device.String()}},
		Allow:           []AllowEntry{{SrcIP: "10.99.0.7", DstCIDR: "8.8.8.8/32", Protocol: ProtoTCP, PortLow: 443, PortHigh: 443, SrcDeviceID: device.String()}},
		FQDNGenerations: []FQDNGeneration{{ResourceID: uuid.NewString(), Name: "api.example.com", Generation: "17", Answers: []string{"8.8.8.8/32"}}},
	}
	if got := EvaluateAccess(compiled, device, "10.99.0.7", "api.example.com", "tcp", 443); !got.Allowed || len(got.DestinationAnswers) != 1 || got.DestinationAnswers[0] != "8.8.8.8" {
		t.Fatalf("active FQDN answer must evaluate against expanded policy: %+v", got)
	}
	if got := EvaluateAccess(compiled, device, "10.99.0.7", "other.example.com", "tcp", 443); got.Allowed {
		t.Fatalf("an unbound hostname must remain default denied: %+v", got)
	}
}
