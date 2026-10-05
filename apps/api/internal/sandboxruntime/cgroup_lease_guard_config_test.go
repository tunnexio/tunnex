package sandboxruntime

import "testing"

func TestActorControlPathIsOnlyAnExplicitServiceSubtree(t *testing.T) {
	for _, value := range []string{actorControlCgroup, "/tunnexsandbox.slice/tunnex-sandbox-actor.service/control", "/custom.slice/custom-actor.service/control"} {
		if !ValidActorControlCgroup(value) {
			t.Fatal("operator service subtree refused", value)
		}
	}
	for _, value := range []string{"", "/", "/sys/fs/cgroup", "/custom.slice/control", "/custom.slice/custom.service", "/custom.slice/custom.scope/control", "/custom.slice/../foreign.service/control", "/custom.slice/custom.service/control/child", "/custom.slice//custom.service/control", "/custom.slice/custom.service/control\n"} {
		if ValidActorControlCgroup(value) {
			t.Fatal("arbitrary placement accepted", value)
		}
	}
}
