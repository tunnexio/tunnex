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
