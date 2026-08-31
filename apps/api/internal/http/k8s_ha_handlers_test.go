package http

import (
	"reflect"
	"testing"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	k8ssvc "github.com/tunnexio/tunnex/apps/api/internal/k8s"
)

func TestK8sHASettingsMapperKeepsConfigurationAndRuntimeSeparate(t *testing.T) {
	in := k8ssvc.HASettings{
		Enabled: true, Revision: 7, ActualState: "enabled", ReasonCode: "enabled",
		DeploymentReady: true, SchedulerState: "leader_operating", SchedulerReasonCodes: []string{"member_health_unknown"},
	}
	out := toAPIK8sHASettings(in)
	if !out.Enabled || out.Revision != 7 || string(out.ActualState) != "enabled" || !out.DeploymentReady || string(out.SchedulerState) != "leader_operating" ||
		!reflect.DeepEqual(out.SchedulerReasonCodes, []string{"member_health_unknown"}) {
		t.Fatalf("HA configuration/runtime projection lost fields: %+v", out)
	}
	in.SchedulerReasonCodes[0] = "mutated"
	if out.SchedulerReasonCodes[0] != "member_health_unknown" {
		t.Fatal("API response must not alias the mutable service reason slice")
	}
}

func TestK8sConnectorPoolConfigurationMapperPreservesEpochTruth(t *testing.T) {
	poolID, clusterID, preferredID, activeID, memberID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	in := k8ssvc.ConnectorPoolConfiguration{
		PoolID: poolID, ClusterID: clusterID, PreferredNodeID: preferredID, ActiveNodeID: activeID,
		Generation: 4, MembershipEpochKnown: true, MembershipEpoch: 8,
		Members: []k8ssvc.ConnectorPoolMemberConfiguration{{NodeID: memberID, AdminPriority: 100}},
	}
	out, err := toAPIK8sConnectorPoolConfiguration(in)
	if err != nil {
		t.Fatal(err)
	}
	if out.PoolId != poolID || out.ClusterId != clusterID || out.PreferredNodeId != preferredID || out.ActiveNodeId != activeID || out.Generation != 4 || out.MembershipEpoch == nil || *out.MembershipEpoch != 8 || len(out.Members) != 1 || out.Members[0].NodeId != memberID || out.Members[0].AdminPriority != 100 {
		t.Fatalf("configuration projection lost fields: %+v", out)
	}
	in.Members[0].AdminPriority = 1
	if out.Members[0].AdminPriority != 100 {
		t.Fatal("API response must not alias the mutable member slice")
	}
}

func TestConfigureK8sConnectorPoolRequestRejectsNegativeEpoch(t *testing.T) {
	epoch := int64(-1)
	_, err := configureK8sConnectorPoolRequest(api.ConfigureK8sConnectorPoolRequest{ExpectedMembershipEpoch: &epoch})
	if err == nil {
		t.Fatal("negative epoch accepted")
	}
}
