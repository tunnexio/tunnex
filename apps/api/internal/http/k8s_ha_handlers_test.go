package http

import (
	"reflect"
	"testing"

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
