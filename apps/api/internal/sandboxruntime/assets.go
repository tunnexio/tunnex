package sandboxruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
)

const assetsLabel = "io.tunnex.sandbox.assets"

// RuntimeAssets comes only from the trusted local worker. Paths never originate
// in API bodies. The resolver owns parent directories and must serialize
// publication with the lifecycle lease; workloads only receive these mounts.
// Digest binds the already validated immutable skills/terminal manifest.
type RuntimeAssets struct {
	SandboxID              uuid.UUID
	Workspace, Skills, SSH string
	Digest                 string
	SpecHash               string
}

type AssetResolver interface {
	ResolveAssets(context.Context, uuid.UUID) (RuntimeAssets, error)
}

func NewPodmanWithAssets(runner Runner, assets AssetResolver) (*Podman, error) {
	if assets == nil {
		return nil, ErrInvalid
	}
	p := NewPodman(runner)
	p.assets = assets
	return p, nil
}

type assetMount struct {
	Type        string
	Source      string
	Destination string
	RW          bool
}

func assetMounts(id uuid.UUID, assets RuntimeAssets) ([]assetMount, string, error) {
	if id == uuid.Nil || assets.SandboxID != id || len(assets.Digest) != 64 || len(assets.SpecHash) != 64 {
		return nil, "", ErrInvalid
	}
	if decoded, err := hex.DecodeString(assets.SpecHash); err != nil || len(decoded) != 32 || strings.ToLower(assets.SpecHash) != assets.SpecHash {
		return nil, "", ErrInvalid
	}
	digest, err := hex.DecodeString(assets.Digest)
	if err != nil || len(digest) != 32 || strings.ToLower(assets.Digest) != assets.Digest {
		return nil, "", ErrInvalid
	}
	paths := []string{assets.Workspace, assets.Skills, assets.SSH}
	for i, path := range paths {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || strings.ContainsAny(path, ",\n\r\x00") {
			return nil, "", ErrInvalid
		}
		for _, earlier := range paths[:i] {
			if path == earlier || strings.HasPrefix(path, earlier+string(filepath.Separator)) || strings.HasPrefix(earlier, path+string(filepath.Separator)) {
				return nil, "", ErrInvalid
			}
		}
		// Resolve each existing path component without following a symlink. The
		// trusted resolver must retain exclusive ownership against rename races.
		for current := path; current != "/"; current = filepath.Dir(current) {
			info, err := os.Lstat(current)
			if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return nil, "", ErrInvalid
			}
			if current == path && info.Mode().Perm()&0077 != 0 {
				return nil, "", ErrInvalid
			}
		}
	}
	entries, err := os.ReadDir(assets.SSH)
	if err != nil || len(entries) != 3 {
		return nil, "", ErrInvalid
	}
	for _, file := range []string{"sshd_config", "host_key", "authorized_keys"} {
		info, err := os.Lstat(filepath.Join(assets.SSH, file))
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() < 1 || info.Size() > 65536 {
			return nil, "", ErrInvalid
		}
	}
	for _, destination := range []string{".agents", ".agents/skills"} {
		info, err := os.Lstat(filepath.Join(assets.Workspace, destination))
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
			return nil, "", ErrInvalid
		}
	}
	contentDigest, err := AssetContentDigest(assets.Skills, assets.SSH)
	if err != nil || contentDigest != assets.Digest {
		return nil, "", ErrInvalid
	}
	mounts := []assetMount{{"bind", assets.Workspace, "/workspace", true}, {"bind", assets.Skills, "/workspace/.agents/skills", false}, {"bind", assets.SSH, "/run/tunnex-ssh", false}}
	raw, err := json.Marshal(assets)
	if err != nil {
		return nil, "", ErrInvalid
	}
	hash := sha256.Sum256(raw)
	return mounts, hex.EncodeToString(hash[:]), nil
}

// AssetContentDigest validates only bounded immutable skill/SSH trees. It does
// not read a retained user's workspace or any ambient credential files.
func AssetContentDigest(skills, terminal string) (string, error) {
	hash := sha256.New()
	files, total := 0, int64(0)
	for index, directory := range []string{skills, terminal} {
		root, err := os.OpenRoot(directory)
		if err != nil {
			return "", ErrInvalid
		}
		err = fs.WalkDir(root.FS(), ".", func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return ErrInvalid
			}
			info, err := entry.Info()
			if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
				return ErrInvalid
			}
			if entry.IsDir() {
				return nil
			}
			files++
			total += info.Size()
			if !info.Mode().IsRegular() || files > 64 || info.Size() > 65536 || total > 1048576 {
				return ErrInvalid
			}
			file, err := root.Open(path)
			if err != nil {
				return ErrInvalid
			}
			body, err := io.ReadAll(io.LimitReader(file, 65537))
			closeErr := file.Close()
			if err != nil || closeErr != nil || len(body) > 65536 {
				return ErrInvalid
			}
			digest := sha256.Sum256(body)
			// Explicit structured framing prevents concatenation ambiguities.
			row, _ := json.Marshal(struct {
				Tree         int
				Path, Digest string
			}{index, path, hex.EncodeToString(digest[:])})
			_, _ = hash.Write(row)
			return nil
		})
		closeErr := root.Close()
		if err != nil || closeErr != nil {
			return "", ErrInvalid
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func sameAssetMounts(expected, actual []assetMount) bool {
	for _, wanted := range expected {
		found := 0
		for _, got := range actual {
			if got.Destination != wanted.Destination {
				continue
			}
			if got != wanted {
				return false
			}
			found++
		}
		if found != 1 {
			return false
		}
	}
	// Podman may report the two explicitly configured tmpfs mounts. Any other
	// bind/device/socket mount, including a shadowing descendant, is refused.
	for _, got := range actual {
		matched := false
		for _, wanted := range expected {
			if got == wanted {
				matched = true
			}
		}
		if !matched && !(got.Type == "tmpfs" && (got.Destination == "/tmp" || got.Destination == "/run")) {
			return false
		}
	}
	return true
}
