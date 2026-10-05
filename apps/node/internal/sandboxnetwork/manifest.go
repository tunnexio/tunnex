package sandboxnetwork

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"

	"github.com/google/uuid"
)

// FilesystemManifests is an exclusive helper-owned root, outside workload and
// worker-writable mounts. The authenticated helper serializes requests.
type FilesystemManifests struct{ Root *os.Root }

func (s FilesystemManifests) Reserve(m Manifest) error {
	if s.Root == nil || m.Namespace.Inode == 0 || m.Namespace.OwnerUID == 0 {
		return ErrInvalid
	}
	normalized, err := Normalize(m.Plan)
	if err != nil {
		return err
	}
	m.Plan = normalized
	if _, err := s.Root.Lstat(m.Plan.Binding.OperationID.String() + ".inactive.json"); !errors.Is(err, fs.ErrNotExist) {
		return ErrOwnership
	}
	name := m.Plan.Binding.OperationID.String() + ".json"
	info, err := s.Root.Lstat(name)
	if err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 16384 {
			return ErrOwnership
		}
		file, err := s.Root.Open(name)
		if err != nil {
			return ErrUnavailable
		}
		raw, readErr := io.ReadAll(io.LimitReader(file, 16385))
		closeErr := file.Close()
		if readErr != nil || closeErr != nil || len(raw) > 16384 {
			return ErrOwnership
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		var stored Manifest
		if decoder.Decode(&stored) != nil || decoder.Decode(new(any)) != io.EOF || !stored.Matches(m.Plan, m.Namespace) {
			return ErrOwnership
		}
		return nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return ErrUnavailable
	}
	raw, err := json.Marshal(m)
	if err != nil || len(raw) > 16384 {
		return ErrInvalid
	}
	stage := "." + name + "." + uuid.NewString() + ".pending"
	file, err := s.Root.OpenFile(stage, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return ErrOwnership
	}
	defer s.Root.Remove(stage) //nolint:errcheck
	_, writeErr := file.Write(raw)
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return ErrUnavailable
	}
	if err = s.Root.Rename(stage, name); err != nil {
		return ErrUnavailable
	}
	dir, err := s.Root.Open(".")
	if err != nil {
		return ErrUnavailable
	}
	defer dir.Close()
	if dir.Sync() != nil {
		return ErrUnavailable
	}
	return nil
}
