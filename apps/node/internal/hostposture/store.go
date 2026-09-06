package hostposture

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

const (
	journalFile          = "journal.json"
	heartbeatFile        = "heartbeat.json"
	lockFile             = "manager.lock"
	cniAuthorityFile     = "cni-authority.json"
	cniOperationLockFile = "cni-operation.lock"
	maxJournal           = 64 << 10
	maxHeartbeat         = 32 << 10
)

// Store owns the versioned hostPath record. Journal writes are durable and
// private; heartbeat writes are world-readable so the credentialless gateway
// init can consume only this bounded, non-secret handshake.
type Store struct {
	dir      string
	readOnly bool
	proofMu  sync.Mutex
	cniProof cniOwnerProof
}

func NewStore(dir string) (*Store, error) {
	store, err := openStore(dir, true)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(store.dir, 0o755); err != nil {
		return nil, fmt.Errorf("set host-posture state directory mode: %w", err)
	}
	if err := store.createCNIOperationLock(); err != nil {
		return nil, err
	}
	return store, nil
}

// OpenStore opens the credentialless gateway's read-only view without trying
// to create or chmod the hostPath mount.
func OpenStore(dir string) (*Store, error) { return openStore(dir, false) }

func openStore(dir string, create bool) (*Store, error) {
	dir = filepath.Clean(dir)
	if !filepath.IsAbs(dir) || dir == string(filepath.Separator) || dir == "." {
		return nil, fmt.Errorf("host-posture state directory must be an absolute narrow path")
	}
	if create {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create host-posture state directory: %w", err)
		}
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("host-posture state directory is not a real directory")
	}
	return &Store{dir: dir, readOnly: !create}, nil
}

func (s *Store) JournalPath() string          { return filepath.Join(s.dir, journalFile) }
func (s *Store) HeartbeatPath() string        { return filepath.Join(s.dir, heartbeatFile) }
func (s *Store) LockPath() string             { return filepath.Join(s.dir, lockFile) }
func (s *Store) CNIAuthorityPath() string     { return filepath.Join(s.dir, cniAuthorityFile) }
func (s *Store) CNIOperationLockPath() string { return filepath.Join(s.dir, cniOperationLockFile) }

func (s *Store) LoadJournal() (Journal, error) {
	var value Journal
	if err := readStrictJSON(s.JournalPath(), maxJournal, &value); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Journal{}, ErrNoJournal
		}
		return Journal{}, fmt.Errorf("read host-posture journal: %w", err)
	}
	return value, nil
}

func (s *Store) SaveJournal(value Journal) error {
	return s.atomicJSON(journalFile, value, 0o600)
}

func (s *Store) LoadHeartbeat() (Heartbeat, error) {
	var value Heartbeat
	if err := readStrictJSON(s.HeartbeatPath(), maxHeartbeat, &value); err != nil {
		return Heartbeat{}, fmt.Errorf("read host-posture heartbeat: %w", err)
	}
	return value, nil
}

func (s *Store) SaveHeartbeat(value Heartbeat) error {
	return s.atomicJSON(heartbeatFile, value, 0o644)
}

func (s *Store) atomicJSON(name string, value any, mode os.FileMode) error {
	var body bytes.Buffer
	enc := json.NewEncoder(&body)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		return fmt.Errorf("encode %s: %w", name, err)
	}
	if body.Len() > maxJournal {
		return fmt.Errorf("encoded %s exceeds bounded size", name)
	}
	tmp, err := os.CreateTemp(s.dir, "."+name+".*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary %s: %w", name, err)
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		_ = tmp.Close()
		if !ok {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(mode); err != nil {
		return fmt.Errorf("set temporary %s mode: %w", name, err)
	}
	if _, err := tmp.Write(body.Bytes()); err != nil {
		return fmt.Errorf("write temporary %s: %w", name, err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync temporary %s: %w", name, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary %s: %w", name, err)
	}
	path := filepath.Join(s.dir, name)
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refuse to replace symlink at %s", path)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect existing %s: %w", name, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("publish %s: %w", name, err)
	}
	dir, err := os.Open(s.dir)
	if err != nil {
		return fmt.Errorf("open state directory for %s sync: %w", name, err)
	}
	syncErr := dir.Sync()
	closeErr := dir.Close()
	if syncErr != nil {
		return fmt.Errorf("sync state directory after %s: %w", name, syncErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close state directory after %s: %w", name, closeErr)
	}
	ok = true
	return nil
}

func readStrictJSON(path string, max int64, value any) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > max {
		return fmt.Errorf("%s is not a bounded regular file", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	dec := json.NewDecoder(io.LimitReader(f, max+1))
	dec.DisallowUnknownFields()
	if err := dec.Decode(value); err != nil {
		return err
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("trailing JSON value")
		}
		return err
	}
	return nil
}
