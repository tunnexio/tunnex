// Package restorebarrier protects the supported offline restore procedure.
// The marker lives outside database/Redis backups; callers must also stop all
// participants. It cannot detect a raw restore that bypasses that procedure.
package restorebarrier

import (
	"errors"
	"os"
	"path/filepath"
)

// Check refuses startup while an external restore marker exists, even when its
// contents are malformed. Any inspection error except absence fails closed.
func Check(path string) error {
	if path == "" {
		return nil
	}
	if !filepath.IsAbs(path) {
		return errors.New("cannot verify App Access restore barrier")
	}
	dir := filepath.Dir(path)
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil || resolved != filepath.Clean(dir) {
		return errors.New("cannot verify App Access restore barrier")
	}
	parent, err := os.Lstat(dir)
	if err != nil || !parent.IsDir() || parent.Mode().Perm()&0077 != 0 {
		return errors.New("cannot verify App Access restore barrier")
	}
	directory, err := os.Open(dir)
	if err != nil {
		return errors.New("cannot verify App Access restore barrier")
	}
	_ = directory.Close()
	_, err = os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return errors.New("cannot verify App Access restore barrier")
	}
	return errors.New("App Access restore barrier is active; finish offline authority recovery before starting listeners")
}
