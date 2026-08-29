package ownershiplease

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type baseAuthorityStateFile struct {
	Version  int                `json:"version"`
	State    BaseAuthorityState `json:"state"`
	Checksum string             `json:"checksum"`
}

type FileBaseAuthorityStateStore struct{ path string }

func NewFileBaseAuthorityStateStore(path string) *FileBaseAuthorityStateStore {
	return &FileBaseAuthorityStateStore{path: path}
}

func (s *FileBaseAuthorityStateStore) LoadBaseAuthorityState(_ context.Context) (BaseAuthorityState, bool, error) {
	lock, err := statePathLock(s.path)
	if err != nil {
		return BaseAuthorityState{}, false, err
	}
	lock.Lock()
	defer lock.Unlock()
	b, err := readBoundedStateFile(s.path)
	if os.IsNotExist(err) {
		return BaseAuthorityState{}, false, nil
	}
	if err != nil {
		return BaseAuthorityState{}, false, err
	}
	if err := rejectDuplicateStateKeys(b); err != nil {
		return BaseAuthorityState{}, false, err
	}
	var file baseAuthorityStateFile
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil {
		return BaseAuthorityState{}, false, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return BaseAuthorityState{}, false, fmt.Errorf("multiple base-authority state values")
		}
		return BaseAuthorityState{}, false, err
	}
	if file.Version != BaseAuthorityStateVersion || !hex64RE.MatchString(file.Checksum) {
		return BaseAuthorityState{}, false, ErrBaseAuthorityInvalid
	}
	state, err := canonicalBaseAuthorityState(file.State)
	if err != nil {
		return BaseAuthorityState{}, false, err
	}
	want, err := baseAuthorityStateChecksum(state)
	if err != nil || want != file.Checksum {
		return BaseAuthorityState{}, false, fmt.Errorf("base-authority state checksum mismatch")
	}
	return state, true, nil
}

func (s *FileBaseAuthorityStateStore) SaveBaseAuthorityState(_ context.Context, value BaseAuthorityState) error {
	state, err := canonicalBaseAuthorityState(value)
	if err != nil {
		return err
	}
	checksum, err := baseAuthorityStateChecksum(state)
	if err != nil {
		return err
	}
	b, err := json.Marshal(baseAuthorityStateFile{Version: BaseAuthorityStateVersion, State: state, Checksum: checksum})
	if err != nil {
		return err
	}
	lock, err := statePathLock(s.path)
	if err != nil {
		return err
	}
	lock.Lock()
	defer lock.Unlock()
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".base-authority-")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err = tmp.Chmod(0600); err == nil {
		var written int64
		written, err = io.Copy(tmp, bytes.NewReader(b))
		if err == nil && written != int64(len(b)) {
			err = io.ErrShortWrite
		}
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(name, s.path); err != nil {
		return err
	}
	return syncDir(dir)
}

func baseAuthorityStateChecksum(state BaseAuthorityState) (string, error) {
	b, err := json.Marshal(state)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
