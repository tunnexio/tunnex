package backup

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/packages/apptransport/restorebarrier"
	"golang.org/x/sys/unix"
)

// AppRestoreMarker is kept on the operator's filesystem, outside all restored
// database/Redis artifacts. A completion copied from a database is not a marker.
type AppRestoreMarker struct {
	Version   int       `json:"version"`
	ID        uuid.UUID `json:"id"`
	StartedAt time.Time `json:"started_at"`
}

// WithAppRestoreGuard serializes offline authority mutation with begin/recovery.
// Checking once before a DB transaction would let credential issuance cross a
// restore sweep and escape its durable revocation.
func WithAppRestoreGuard(path string, mutate func() error) error {
	if !filepath.IsAbs(path) {
		return errors.New("configured absolute restore barrier required")
	}
	unlock, err := lockMarkerDirectory(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer unlock()
	if err = restorebarrier.Check(path); err != nil {
		return err
	}
	return mutate()
}

func BeginAppRestore(path string) (AppRestoreMarker, error) {
	var out AppRestoreMarker
	if !filepath.IsAbs(path) {
		return out, errors.New("restore marker path must be absolute")
	}
	dir := filepath.Dir(path)
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil || resolved != filepath.Clean(dir) {
		return out, errors.New("restore marker directory must exist without symlinks")
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return out, errors.New("restore marker directory must be private")
	}
	unlock, err := lockMarkerDirectory(dir)
	if err != nil {
		return out, err
	}
	defer unlock()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return out, errors.New("restore marker already exists or cannot be created; retain it and recover offline")
	}
	defer f.Close()
	out = AppRestoreMarker{Version: 1, ID: uuid.New(), StartedAt: time.Now().UTC()}
	if err = json.NewEncoder(f).Encode(out); err != nil {
		return out, err
	}
	if err = f.Sync(); err != nil {
		return out, err
	}
	if err = syncMarkerDir(dir); err != nil {
		return out, err
	}
	return out, nil
}

func ReadAppRestore(path string) (AppRestoreMarker, os.FileInfo, error) {
	var out AppRestoreMarker
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 4096 {
		return out, nil, errors.New("restore marker must be a private bounded regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return out, nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return out, nil, errors.New("restore marker changed while opening")
	}
	d := json.NewDecoder(io.LimitReader(f, 4097))
	d.DisallowUnknownFields()
	if err = d.Decode(&out); err != nil {
		return out, nil, errors.New("invalid restore marker")
	}
	var extra any
	if d.Decode(&extra) != io.EOF || out.Version != 1 || out.ID == uuid.Nil || out.StartedAt.IsZero() {
		return out, nil, errors.New("invalid restore marker")
	}
	return out, info, nil
}

// FinishAppRestore must be called only after new offline recovery, full
// withdrawal wait and exact DB readback. It never removes another restore gate.
func FinishAppRestore(path string, expected uuid.UUID, original os.FileInfo) error {
	unlock, err := lockMarkerDirectory(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer unlock()
	return finishAppRestoreLocked(path, expected, original)
}

// RecoverAppRestore serializes recovery and final readback with marker release.
// Two operator commands cannot finish another command's newer restore barrier.
func RecoverAppRestore(path string, expected uuid.UUID, recover func() error) error {
	unlock, err := lockMarkerDirectory(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer unlock()
	m, identity, err := ReadAppRestore(path)
	if err != nil {
		return err
	}
	if expected == uuid.Nil || m.ID != expected {
		return errors.New("restore marker does not match this recovery")
	}
	if err = recover(); err != nil {
		return err
	}
	return finishAppRestoreLocked(path, expected, identity)
}

func finishAppRestoreLocked(path string, expected uuid.UUID, original os.FileInfo) error {
	m, current, err := ReadAppRestore(path)
	if err != nil {
		return err
	}
	if expected == uuid.Nil || m.ID != expected || original == nil || !os.SameFile(original, current) {
		return errors.New("restore marker identity changed; listeners must remain fenced")
	}
	if err = os.Remove(path); err != nil {
		return err
	}
	return syncMarkerDir(filepath.Dir(path))
}

// This stable lock is never removed. Supported begin/finish operations hold it
// across checking and unlinking so another restore cannot replace the marker.
func lockMarkerDirectory(dir string) (func(), error) {
	if !filepath.IsAbs(dir) {
		return nil, errors.New("restore marker directory must be absolute")
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil || resolved != filepath.Clean(dir) {
		return nil, errors.New("restore marker directory must exist without symlinks")
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("restore marker directory must be private")
	}
	fd, err := unix.Open(filepath.Join(dir, ".app-access-restore.lock"), unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, errors.New("cannot lock restore marker directory")
	}
	f := os.NewFile(uintptr(fd), "restore marker lock")
	info, err = f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		f.Close()
		return nil, errors.New("restore marker lock must be private and regular")
	}
	if err = unix.Flock(fd, unix.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() { unix.Flock(fd, unix.LOCK_UN); f.Close() }, nil
}

func syncMarkerDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
