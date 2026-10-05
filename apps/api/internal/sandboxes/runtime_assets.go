package sandboxes

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxruntime"
)

// MaterializeRuntimeAssets composes retained workspace, inert selected skills
// and stable terminal identity through an exclusive worker-owned root. It
// never supplies the bootstrap token/runtime credential to workload mounts.
func MaterializeRuntimeAssets(root *os.Root, plan WorkspacePlan, keys []string) (sandboxruntime.RuntimeAssets, TerminalDelivery, error) {
	if root == nil || plan.SandboxID == uuid.Nil || plan.OrgID == uuid.Nil || plan.Generation < 1 || plan.RuntimeID != "" || len(plan.SpecHash) != 64 {
		return sandboxruntime.RuntimeAssets{}, TerminalDelivery{}, ErrInvalid
	}
	base, err := filepath.EvalSymlinks(root.Name())
	if err != nil || !filepath.IsAbs(base) || base == "/" {
		return sandboxruntime.RuntimeAssets{}, TerminalDelivery{}, ErrInvalid
	}
	existing, publishedErr := sandboxruntime.ReadPublishedAssets(root, plan.SandboxID)
	if publishedErr != nil && !errors.Is(publishedErr, sandboxruntime.ErrMissing) {
		return sandboxruntime.RuntimeAssets{}, TerminalDelivery{}, publishedErr
	}
	if publishedErr == nil && existing.SpecHash != plan.SpecHash {
		return sandboxruntime.RuntimeAssets{}, TerminalDelivery{}, ErrConflict
	}
	for _, directory := range []string{"workspace", "workspace/.agents", "workspace/.agents/skills"} {
		info, err := root.Lstat(directory)
		if errors.Is(err, fs.ErrNotExist) {
			err = root.Mkdir(directory, 0700)
		} else if err == nil && (!info.IsDir() || info.Mode().Perm()&0077 != 0) {
			err = ErrConflict
		}
		if err != nil {
			return sandboxruntime.RuntimeAssets{}, TerminalDelivery{}, err
		}
	}
	skills, err := MaterializeSkillBundle(root, plan.Files)
	if err != nil {
		return sandboxruntime.RuntimeAssets{}, TerminalDelivery{}, err
	}
	terminal, err := MaterializeTerminal(root, keys)
	if err != nil {
		return sandboxruntime.RuntimeAssets{}, TerminalDelivery{}, err
	}
	assets := sandboxruntime.RuntimeAssets{SandboxID: plan.SandboxID, SpecHash: plan.SpecHash, Workspace: filepath.Join(base, "workspace"), Skills: filepath.Join(base, skills.Directory, "skills"), SSH: filepath.Join(base, terminal.Directory)}
	assets.Digest, err = sandboxruntime.AssetContentDigest(assets.Skills, assets.SSH)
	if err != nil {
		return sandboxruntime.RuntimeAssets{}, TerminalDelivery{}, err
	}
	if err = sandboxruntime.PublishAssets(root, assets); err != nil {
		return sandboxruntime.RuntimeAssets{}, TerminalDelivery{}, err
	}
	return assets, terminal, nil
}
