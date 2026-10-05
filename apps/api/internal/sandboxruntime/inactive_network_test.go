package sandboxruntime

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestInactiveNetworkRequiresExactCreatedOrStoppedAbsence(t *testing.T) {
	id := uuid.New()
	runtimeID, hash := strings.Repeat("a", 64), strings.Repeat("b", 64)
	base := func() map[string]any {
		return map[string]any{"Id": runtimeID, "Image": "sha256:" + strings.Repeat("c", 64), "Config": map[string]any{"Labels": map[string]string{ownerLabel: id.String(), specLabel: hash}}, "State": map[string]any{"Running": false, "Pid": 0, "Status": "created"}, "NetworkSettings": map[string]any{"SandboxKey": ""}}
	}
	for _, state := range []string{"created", "configured", "exited", "stopped"} {
		t.Run(state, func(t *testing.T) {
			row := base()
			row["State"].(map[string]any)["Status"] = state
			raw, _ := json.Marshal([]any{row})
			calls := 0
			p := NewPodman(&fakeRunner{responses: func(args []string) ([]byte, error) {
				calls++
				if args[0] == "container" {
					return nil, nil
				}
				if args[0] != "inspect" {
					t.Fatal("cleanup started or mutated runtime", args)
				}
				return raw, nil
			}})
			if err := p.VerifyInactiveNetwork(context.Background(), id, runtimeID, hash); err != nil {
				t.Fatal(err)
			}
			if calls != 6 {
				t.Fatal("inactivity was not independently rechecked", calls)
			}
		})
	}
	for _, scenario := range []string{"foreign-id", "foreign-owner", "foreign-spec", "running", "pid", "namespace", "missing-running", "missing-pid", "missing-namespace", "unknown-state", "null-running", "null-pid", "null-namespace"} {
		t.Run(scenario, func(t *testing.T) {
			row := base()
			state := row["State"].(map[string]any)
			network := row["NetworkSettings"].(map[string]any)
			labels := row["Config"].(map[string]any)["Labels"].(map[string]string)
			switch scenario {
			case "foreign-id":
				row["Id"] = strings.Repeat("d", 64)
			case "foreign-owner":
				labels[ownerLabel] = uuid.NewString()
			case "foreign-spec":
				labels[specLabel] = strings.Repeat("d", 64)
			case "running":
				state["Running"] = true
			case "pid":
				state["Pid"] = 17
			case "namespace":
				network["SandboxKey"] = "/run/user/1101/netns/retained"
			case "missing-running":
				delete(state, "Running")
			case "missing-pid":
				delete(state, "Pid")
			case "missing-namespace":
				delete(network, "SandboxKey")
			case "unknown-state":
				state["Status"] = "paused"
			case "null-running":
				state["Running"] = nil
			case "null-pid":
				state["Pid"] = nil
			case "null-namespace":
				network["SandboxKey"] = nil
			}
			raw, _ := json.Marshal([]any{row})
			if err := validateInactiveNetwork(raw, id, runtimeID, hash); !errors.Is(err, ErrOwnership) {
				t.Fatal("absence inferred from incomplete/foreign provider metadata", err)
			}
		})
	}
}

func TestInactiveNetworkRejectsProviderRace(t *testing.T) {
	id := uuid.New()
	runtimeID, hash := strings.Repeat("a", 64), strings.Repeat("b", 64)
	inspections := 0
	p := NewPodman(&fakeRunner{responses: func(args []string) ([]byte, error) {
		if args[0] == "container" {
			return nil, nil
		}
		inspections++
		running := inspections >= 3
		return json.Marshal([]any{map[string]any{"Id": runtimeID, "Config": map[string]any{"Labels": map[string]string{ownerLabel: id.String(), specLabel: hash}}, "State": map[string]any{"Running": running, "Pid": 0, "Status": "created"}, "NetworkSettings": map[string]any{"SandboxKey": ""}}})
	}})
	if err := p.VerifyInactiveNetwork(context.Background(), id, runtimeID, hash); !errors.Is(err, ErrOwnership) {
		t.Fatal("provider race accepted", err)
	}
}
