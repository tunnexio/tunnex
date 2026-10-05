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
	if _, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(out.ProbePublicKey)); err != nil || len(bytes.TrimSpace(rest)) != 0 {
		return APIWorkerConfig{}, ErrInvalid
	}
	return out, nil
}
func (c APIWorkerConfig) Client() (*WorkerRPCClient, error) {
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(c.ProbePublicKey))
	if err != nil {
		return nil, ErrInvalid
	}
	if c.Remote != nil {
		return NewRemoteWorkerRPCClient(*c.Remote, key)
	}
	return NewWorkerRPCClient(c.Socket, c.WorkerUID, key)
}
