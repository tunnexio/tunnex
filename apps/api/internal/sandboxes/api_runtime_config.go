package sandboxes

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

// APIWorkerConfig is a nonsecret operator file. Socket mount/ACL and org/catalog
// activation are explicit deployment actions. It never carries a main key/DSN.
type APIWorkerConfig struct {
	Binding        BoundedRuntimeBinding
	Socket         string
	WorkerUID      uint32
	ProbePublicKey string
	InitialCreate  *CreateInput
	Remote         *RemoteWorkerConfig
	// Enrollment is explicitly opt-in and retains the configured organization,
	// gateway, profiles and resource envelope. The public probe is learned only
	// from the durable enrollment authority, never a health response.
	Enrollment *RunnerEnrollmentConfig
}

func LoadAPIWorkerConfig(path string) (APIWorkerConfig, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return APIWorkerConfig{}, ErrInvalid
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() > 16384 {
		return APIWorkerConfig{}, ErrInvalid
	}
	file, err := os.Open(path)
	if err != nil {
		return APIWorkerConfig{}, ErrInvalid
	}
	defer file.Close()
	current, err := file.Stat()
	if err != nil || !os.SameFile(info, current) {
		return APIWorkerConfig{}, ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(file, 16385))
	if err != nil || len(raw) > 16384 {
		return APIWorkerConfig{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var out APIWorkerConfig
	if decoder.Decode(&out) != nil || decoder.Decode(new(any)) != io.EOF || out.Binding.Validate() != nil || (out.Remote == nil && (out.WorkerUID == 0 || out.Socket != "/run/tunnex-sandbox-worker/control.sock")) || (out.Remote != nil && (out.WorkerUID != 0 || out.Socket != "" || !out.Binding.Persistent())) {
		return APIWorkerConfig{}, ErrInvalid
	}
	if out.Enrollment != nil {
		if out.Remote == nil || !out.Binding.OrganizationScoped() || out.ProbePublicKey != "" || out.InitialCreate != nil || out.Enrollment.RunnerURI != out.Remote.RunnerURI {
			return APIWorkerConfig{}, ErrInvalid
		}
		if out.Enrollment.DistributionFile != "" {
			configured, err := LoadRunnerDistributionConfig(out.Enrollment.DistributionFile, *out.Enrollment)
			if err != nil {
				return APIWorkerConfig{}, ErrInvalid
			}
			out.Enrollment = &configured
		}
		if out.Enrollment.WorkloadImageDeliveryFile != "" {
			configured, err := LoadRunnerWorkloadImageDeliveryConfig(out.Enrollment.WorkloadImageDeliveryFile, *out.Enrollment)
			if err != nil {
				return APIWorkerConfig{}, ErrInvalid
			}
			out.Enrollment = &configured
		}
	} else {
		if _, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(out.ProbePublicKey)); err != nil || len(bytes.TrimSpace(rest)) != 0 {
			return APIWorkerConfig{}, ErrInvalid
		}
	}
	return out, nil
}
func (c APIWorkerConfig) Client() (*WorkerRPCClient, error) {
	if c.Enrollment != nil {
		return nil, ErrDisabled
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(c.ProbePublicKey))
	if err != nil {
		return nil, ErrInvalid
	}
	if c.Remote != nil {
		return NewRemoteWorkerRPCClient(*c.Remote, key)
	}
	return NewWorkerRPCClient(c.Socket, c.WorkerUID, key)
}

func (c APIWorkerConfig) EnrollmentClient(authority RunnerEnrollmentRuntimeAuthority) (*WorkerRPCClient, error) {
	if c.Enrollment == nil || c.Remote == nil || !c.Binding.OrganizationScoped() || c.ProbePublicKey != "" || c.InitialCreate != nil || c.Enrollment.RunnerURI != c.Remote.RunnerURI || authority == nil {
		return nil, ErrInvalid
	}
	return NewEnrolledRemoteWorkerRPCClient(*c.Remote, authority)
}
