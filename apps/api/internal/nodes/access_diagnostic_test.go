package nodes

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
)

func TestEvaluateAgentAccessUsesFinalizedPolicySeam(t *testing.T) {
	org, nodeID, deviceID := uuid.New(), uuid.New(), uuid.New()
	compiled := &policyspec.Compiled{
		Version: 4, NodeID: nodeID.String(), Mode: "enforcing",
		Subjects: []policyspec.SubjectAttribution{{DeviceID: deviceID.String(), SrcIP: "10.99.0.7"}},
		Allow:    []policyspec.AllowEntry{{SrcIP: "10.99.0.7", SrcDeviceID: deviceID.String(), DstCIDR: "10.99.0.8/32", Protocol: policyspec.ProtoTCP, PortLow: 443, PortHigh: 443, RuleID: "rule-1"}},
	}
	svc := &Service{policy: fakeProvider{pol: compiled}}
	got, routes, err := svc.EvaluateAgentAccess(context.Background(), org, deviceID, sqlc.Node{ID: nodeID, OrgID: org}, "10.99.0.7", "10.99.0.8", "tcp", 443)
	if err != nil || !got.Allowed || got.RuleID != "rule-1" || got.PolicyHash != policyspec.CanonicalHash(*compiled) || len(routes) != 0 {
		t.Fatalf("exact finalized evaluation mismatch: got=%+v routes=%v err=%v", got, routes, err)
	}
}

func TestEvaluateAgentAccessTreatsNilWirePolicyAsOffMesh(t *testing.T) {
	org, nodeID, deviceID := uuid.New(), uuid.New(), uuid.New()
	svc := &Service{policy: fakeProvider{}}
	got, _, err := svc.EvaluateAgentAccess(context.Background(), org, deviceID, sqlc.Node{ID: nodeID, OrgID: org}, "10.99.0.7", "10.99.0.8", "tcp", 443)
	if err != nil || !got.Allowed || got.Mode != "off" || got.PolicyHash != "" {
		t.Fatalf("off-mode nil wire policy must explain legacy mesh: got=%+v err=%v", got, err)
	}
}

func TestEvaluateDeviceAccessSharesTheAgentEvaluation(t *testing.T) {
	org, nodeID, deviceID := uuid.New(), uuid.New(), uuid.New()
	compiled := &policyspec.Compiled{
		Version: 4, NodeID: nodeID.String(), Mode: "enforcing",
		Subjects: []policyspec.SubjectAttribution{{DeviceID: deviceID.String(), SrcIP: "10.99.0.7"}},
		Allow:    []policyspec.AllowEntry{{SrcIP: "10.99.0.7", SrcDeviceID: deviceID.String(), DstCIDR: "10.99.0.8/32", Protocol: policyspec.ProtoTCP, PortLow: 443, PortHigh: 443, RuleID: "rule-1"}},
	}
	svc := &Service{policy: fakeProvider{pol: compiled}}
	node := sqlc.Node{ID: nodeID, OrgID: org}
	agent, _, agentErr := svc.EvaluateAgentAccess(context.Background(), org, deviceID, node, "10.99.0.7", "10.99.0.8", "tcp", 443)
	got, reach, err := svc.EvaluateDeviceAccess(context.Background(), org, deviceID, node, "10.99.0.7", "10.99.0.8", "tcp", 443)
	if err != nil || agentErr != nil || !got.Allowed || got.RuleID != agent.RuleID || got.PolicyHash != agent.PolicyHash || got.PolicyHash == "" {
		t.Fatalf("device evaluation must be the agent evaluation: device=%+v agent=%+v err=%v/%v", got, agent, err, agentErr)
	}
	if len(reach.Routes) != 0 || len(reach.LocalSubnets) != 0 {
		t.Fatalf("a site-less gateway carries no site reach: %+v", reach)
	}
	denied, _, err := svc.EvaluateDeviceAccess(context.Background(), org, deviceID, node, "10.99.0.7", "10.99.0.9", "tcp", 443)
	if err != nil || denied.Allowed {
		t.Fatalf("an ungranted destination must not be allowed: %+v err=%v", denied, err)
	}
}

func TestEvaluateDeviceAccessTreatsNilWirePolicyAsOffMesh(t *testing.T) {
	org, nodeID, deviceID := uuid.New(), uuid.New(), uuid.New()
	svc := &Service{policy: fakeProvider{}}
	got, _, err := svc.EvaluateDeviceAccess(context.Background(), org, deviceID, sqlc.Node{ID: nodeID, OrgID: org}, "10.99.0.7", "10.99.0.8", "tcp", 443)
	if err != nil || !got.Allowed || got.Mode != "off" {
		t.Fatalf("off-mode nil wire policy must explain the mesh: got=%+v err=%v", got, err)
	}
	if _, _, err := svc.EvaluateDeviceAccess(context.Background(), org, deviceID, sqlc.Node{ID: nodeID, OrgID: uuid.New()}, "10.99.0.7", "10.99.0.8", "tcp", 443); err == nil {
		t.Fatal("a gateway of another organization must not be evaluated")
	}
}
