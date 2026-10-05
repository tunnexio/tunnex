package sandboxruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"

	"github.com/google/uuid"
)

var skillDirectory = regexp.MustCompile(`^skills-[a-f0-9]{64}$`)

// FilesystemAssets resolves only UUID children of an already opened, exclusive
// worker-owned root. Keep it outside all workload bind mounts. No ambient key
// directory or user-supplied filesystem path is used.
type FilesystemAssets struct{ root *os.Root }

func NewFilesystemAssets(root *os.Root) (*FilesystemAssets, error) {
	if root == nil {
		return nil, ErrInvalid
	}
	return &FilesystemAssets{root}, nil
}
func (r *FilesystemAssets) ResolveAssets(ctx context.Context, id uuid.UUID) (RuntimeAssets, error) {
	if err := ctx.Err(); err != nil {
		return RuntimeAssets{}, err
	}
	if id == uuid.Nil {
		return RuntimeAssets{}, ErrInvalid
	}
	info, err := r.root.Lstat(id.String())
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return RuntimeAssets{}, ErrUnavailable
	}
	owned, err := r.root.OpenRoot(id.String())
	if err != nil {
		return RuntimeAssets{}, ErrUnavailable
	}
	defer owned.Close()
	return ReadPublishedAssets(owned, id)
}

func ReadPublishedAssets(root *os.Root, id uuid.UUID) (RuntimeAssets, error) {
	if root == nil || id == uuid.Nil {
		return RuntimeAssets{}, ErrInvalid
	}
	info, err := root.Lstat("runtime-assets.json")
	if errors.Is(err, fs.ErrNotExist) {
		return RuntimeAssets{}, ErrMissing
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 16384 {
		return RuntimeAssets{}, ErrInvalid
	}
	file, err := root.Open("runtime-assets.json")
	if err != nil {
		return RuntimeAssets{}, ErrUnavailable
	}
	data, readErr := io.ReadAll(io.LimitReader(file, 16385))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(data) > 16384 {
		return RuntimeAssets{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var assets RuntimeAssets
	if decoder.Decode(&assets) != nil {
		return RuntimeAssets{}, ErrInvalid
	}
	if decoder.Decode(new(any)) != io.EOF {
		return RuntimeAssets{}, ErrInvalid
	}
	if err = validateAssetRoot(root, id, assets); err != nil {
		return RuntimeAssets{}, err
	}
	return assets, nil
}

func validateAssetRoot(root *os.Root, id uuid.UUID, assets RuntimeAssets) error {
	base, err := filepath.EvalSymlinks(root.Name())
	if err != nil || !filepath.IsAbs(base) || base == "/" || assets.SandboxID != id {
		return ErrInvalid
	}
	if assets.Workspace != filepath.Join(base, "workspace") || assets.SSH != filepath.Join(base, "terminal") {
		return ErrOwnership
	}
	parent := filepath.Dir(assets.Skills)
	if filepath.Dir(parent) != base || filepath.Base(assets.Skills) != "skills" || !skillDirectory.MatchString(filepath.Base(parent)) {
		return ErrOwnership
	}
	_, _, err = assetMounts(id, assets)
	return err
}

// PublishAssets persists a stable control manifest before provider creation.
// A restart reads/verifies this same identity; it never scans arbitrary paths,
// replaces a manifest, creates a runtime or redeems a bootstrap credential.
func PublishAssets(root *os.Root, assets RuntimeAssets) error {
	if root == nil {
		return ErrInvalid
	}
	if err := validateAssetRoot(root, assets.SandboxID, assets); err != nil {
		return err
	}
	existing, err := ReadPublishedAssets(root, assets.SandboxID)
	if err == nil {
		if existing != assets {
			return ErrOwnership
		}
		return nil
	}
	if !errors.Is(err, ErrMissing) {
		return err
	}
	raw, err := json.Marshal(assets)
	if err != nil {
		return ErrInvalid
	}
	stage := ".tunnex-assets-stage-" + uuid.NewString()
	file, err := root.OpenFile(stage, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return ErrUnavailable
	}
	defer root.Remove(stage) //nolint:errcheck
	_, err = file.Write(raw)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return ErrUnavailable
	}
	// Caller holds the lifecycle lease and root is exclusive to this worker.
	if err = root.Rename(stage, "runtime-assets.json"); err != nil {
		return ErrUnavailable
	}
	dir, err := root.Open(".")
	if err != nil {
		return ErrUnavailable
	}
	defer dir.Close()
	return dir.Sync()
}
