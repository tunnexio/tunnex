package sandboxruntime

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
)

// VerifyInactiveNetwork proves the exact owned immutable provider resource has
// neither a process nor a retained network namespace. Running=false alone is
// insufficient. Cleanup never starts a container to recover a namespace.
func (p *Podman) VerifyInactiveNetwork(ctx context.Context, id uuid.UUID, runtimeID, specHash string) error {
	check := func() error {
		s, err := p.Inspect(ctx, id)
		if err != nil {
			return err
		}
		if s.Running || !s.Exists || s.RuntimeID != runtimeID || s.SpecHash != specHash {
			return ErrOwnership
		}
		return nil
	}
	if err := check(); err != nil {
		return err
	}
	for range 2 {
		raw, err := p.runner.Run(ctx, "inspect", "--type=container", "--format=json", runtimeID)
		if err != nil {
			return ErrUnavailable
		}
		if err = validateInactiveNetwork(raw, id, runtimeID, specHash); err != nil {
			return err
		}
	}
	return check()
}

func validateInactiveNetwork(raw []byte, id uuid.UUID, runtimeID, specHash string) error {
	var rows []struct {
		ID     string `json:"Id"`
		Config struct{ Labels map[string]string }
		State  struct {
			Running *bool
			Pid     *int
			Status  string
		}
		NetworkSettings struct{ SandboxKey *string }
	}
	if !validID(id) || !runtimeIDPattern.MatchString(runtimeID) || !runtimeIDPattern.MatchString(specHash) || json.Unmarshal(raw, &rows) != nil || len(rows) != 1 {
		return ErrOwnership
	}
	r := rows[0]
	if r.ID != runtimeID || r.Config.Labels[ownerLabel] != id.String() || r.Config.Labels[specLabel] != specHash || r.State.Running == nil || *r.State.Running || r.State.Pid == nil || *r.State.Pid != 0 || r.NetworkSettings.SandboxKey == nil || *r.NetworkSettings.SandboxKey != "" {
		return ErrOwnership
	}
	switch r.State.Status {
	case "created", "configured", "exited", "stopped":
		return nil
	default:
		return ErrOwnership
	}
}
