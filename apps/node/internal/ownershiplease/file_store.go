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
	"sync"
)

const stateFileLimit = 1 << 20

type stateFile struct {
	Version  int    `json:"version"`
	State    State  `json:"state"`
	Checksum string `json:"checksum"`
}

// FileStateStore is an atomic local active-lease checkpoint. Durable pool
// fences live in FileFenceStore and are never removed by Clear. The checksum
// detects a parseable partial/corrupt record; lifecycle owns withdrawal.
type FileStateStore struct{ path string }

func NewFileStateStore(path string) *FileStateStore { return &FileStateStore{path: path} }

var statePathLocks sync.Map

func (s *FileStateStore) Load(_ context.Context) (State, bool, error) {
	lock, err := statePathLock(s.path)
	if err != nil {
		return State{}, false, err
	}
	lock.Lock()
	defer lock.Unlock()
	b, err := readBoundedStateFile(s.path)
	if os.IsNotExist(err) {
		return State{}, false, nil
	}
	if err != nil {
		return State{}, false, err
	}
	if err := rejectDuplicateStateKeys(b); err != nil {
		return State{}, false, err
	}
	var file stateFile
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil {
		return State{}, false, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return State{}, false, fmt.Errorf("multiple ownership lease state values")
		}
		return State{}, false, err
	}
	if file.Version != StateVersion || !hex64RE.MatchString(file.Checksum) {
		return State{}, false, fmt.Errorf("invalid ownership lease state envelope")
	}
	want, err := stateChecksum(file.State)
	if err != nil || want != file.Checksum {
		return State{}, false, fmt.Errorf("ownership lease state checksum mismatch")
	}
	if _, err := canonicalState(file.State); err != nil {
		return State{}, false, err
	}
	return file.State, true, nil
}

func (s *FileStateStore) Save(_ context.Context, state State) error {
	canonical, err := canonicalState(state)
	if err != nil {
		return err
	}
	checksum, err := stateChecksum(canonical)
	if err != nil {
		return err
	}
	b, err := json.Marshal(stateFile{Version: StateVersion, State: canonical, Checksum: checksum})
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
	tmp, err := os.CreateTemp(dir, ".ownership-lease-")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0600); err == nil {
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

func (s *FileStateStore) Clear(_ context.Context) error {
	lock, err := statePathLock(s.path)
	if err != nil {
		return err
	}
	lock.Lock()
	defer lock.Unlock()
	err = os.Remove(s.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return syncDir(filepath.Dir(s.path))
}

func stateChecksum(state State) (string, error) {
	b, err := json.Marshal(state)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func statePathLock(path string) (*sync.Mutex, error) {
	if path == "" {
		return nil, fmt.Errorf("ownership lease state path required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	value, _ := statePathLocks.LoadOrStore(filepath.Clean(abs), &sync.Mutex{})
	return value.(*sync.Mutex), nil
}

func readBoundedStateFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	b, err := io.ReadAll(io.LimitReader(file, stateFileLimit+1))
	if err != nil {
		return nil, err
	}
	if len(b) > stateFileLimit {
		return nil, fmt.Errorf("ownership lease state exceeds %d bytes", stateFileLimit)
	}
	return b, nil
}

func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func rejectDuplicateStateKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := scanStateJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple ownership lease state values")
		}
		return err
	}
	return nil
}

func scanStateJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok {
				return fmt.Errorf("ownership lease JSON key is not a string")
			}
			if _, exists := seen[name]; exists {
				return fmt.Errorf("duplicate ownership lease JSON key")
			}
			seen[name] = struct{}{}
			if err := scanStateJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		for decoder.More() {
			if err := scanStateJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		return fmt.Errorf("unexpected ownership lease JSON delimiter")
	}
}
