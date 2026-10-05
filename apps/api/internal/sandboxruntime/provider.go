// Package sandboxruntime provides a small structured runtime boundary.
// A provider's Running state is not network or terminal readiness.
package sandboxruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

var ErrInvalid = errors.New("invalid sandbox runtime specification")
var ErrUnavailable = errors.New("sandbox runtime unavailable")
var ErrOwnership = errors.New("runtime resource ownership mismatch")
var ErrMissing = errors.New("sandbox runtime resource not found")
var runtimeIDPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

const ownerLabel = "io.tunnex.sandbox"
const specLabel = "io.tunnex.sandbox.spec"

type Spec struct {
	Architecture string `json:",omitempty"`
	ID           uuid.UUID
	ImageDigest  string
	MemoryMiB    int
	CPUs         int
	PIDs         int
}
type Status struct {
	RuntimeID   string
	ImageDigest string
	SpecHash    string

	Exists  bool
	Running bool
}

// Fingerprint binds every launch resource limit and immutable image identity.
// It is metadata, never a secret or proof of network readiness.
func Fingerprint(s Spec) (string, error) {
	if err := validate(s); err != nil {
		return "", err
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:]), nil
}

// Matches rejects uncertain creation adoption unless the complete identity is
// present. A matching name/owner label alone never permits a replacement start.
func Matches(s Spec, status Status) error {
	hash, err := Fingerprint(s)
	if err != nil {
		return err
	}
	if !status.Exists || !runtimeIDPattern.MatchString(status.RuntimeID) || status.ImageDigest != s.ImageDigest || status.SpecHash != hash {
		return ErrOwnership
	}
	return nil
}

type Provider interface {
	Create(context.Context, Spec) error
	Inspect(context.Context, uuid.UUID) (Status, error)
	Start(context.Context, uuid.UUID) error
	Stop(context.Context, uuid.UUID) error
	Delete(context.Context, uuid.UUID) error
}

// Runner takes argv, never shell source. stderr and raw provider errors never
// cross the user API boundary; callers use stable failure reasons.
type Runner interface {
	Run(context.Context, ...string) ([]byte, error)
}
type CommandRunner struct{}

func (CommandRunner) Run(ctx context.Context, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, "podman", args...).Output()
}

type ProviderStepError struct {
	Step  string
	Cause error
}

func (e *ProviderStepError) Error() string { return "provider operation failed: " + e.Step }
func (e *ProviderStepError) Unwrap() error { return e.Cause }

type Podman struct {
	runner     Runner
	assets     AssetResolver
	leaseGuard *ActorCgroupLeaseGuard
}

// NewActorPodman preserves the existing rootless provider while requiring a
// private lease token on every actor operation. Legacy providers are unchanged.
func NewActorPodman(runner Runner, assets AssetResolver, guard *ActorCgroupLeaseGuard) (*Podman, error) {
	if assets == nil || guard == nil {
		return nil, ErrInvalid
	}
	p := NewPodman(runner)
	p.assets, p.leaseGuard = assets, guard
	return p, nil
}

func (p *Podman) boundScope(ctx context.Context, id uuid.UUID, launch bool) (*CgroupLeaseScope, error) {
	scope, err := leaseScope(ctx, id, launch)
	if err != nil {
		return nil, err
	}
	if p.leaseGuard != nil && (scope == nil || scope.guard != p.leaseGuard) {
		return nil, ErrOwnership
	}
	return scope, nil
}

func NewPodman(runner Runner) *Podman {
	if runner == nil {
		runner = CommandRunner{}
	}
	return &Podman{runner: runner}
}
func name(id uuid.UUID) string  { return "tunnex-sandbox-" + id.String() }
func validID(id uuid.UUID) bool { return id != uuid.Nil }
func validate(s Spec) error {
	if (s.Architecture != "" && s.Architecture != "amd64") || !validID(s.ID) || !digestPattern.MatchString(s.ImageDigest) || s.MemoryMiB < 64 || s.MemoryMiB > 4096 || s.CPUs < 1 || s.CPUs > 4 || s.PIDs < 16 || s.PIDs > 512 {
		return ErrInvalid
	}
	return nil
}

func (p *Podman) Create(ctx context.Context, s Spec) error {
	if validate(s) != nil {
		return ErrInvalid
	}
	scope, err := p.boundScope(ctx, s.ID, true)
	if err != nil {
		return err
	}
	if scope != nil && scope.checkSpec(s) != nil {
		return ErrOwnership
	}
	info, err := p.runner.Run(ctx, "info", "--format", "{{.Host.Security.Rootless}}")
	if err != nil || strings.TrimSpace(string(info)) != "true" {
		return &ProviderStepError{"rootless-info", errors.Join(ErrUnavailable, err)}
	}
	image, imageErr := p.runner.Run(ctx, "image", "inspect", s.ImageDigest)
	if imageErr != nil {
		err = imageErr
		return &ProviderStepError{"image-inspect", errors.Join(ErrUnavailable, err)}
	}
	if s.Architecture != "" {
		var images []struct {
			ID           string `json:"Id"`
			Architecture string `json:"Architecture"`
			OS           string `json:"Os"`
		}
		if json.Unmarshal(image, &images) != nil || len(images) != 1 || canonicalImageID(images[0].ID) != s.ImageDigest || images[0].Architecture != s.Architecture || images[0].OS != "linux" {
			return ErrOwnership
		}
	}
	status, err := p.Inspect(ctx, s.ID)
	if err == nil && status.Exists {
		return ErrOwnership
	} // Reconciler must reconcile existing spec, never overwrite.
	if !errors.Is(err, ErrMissing) {
		return err
	}
	// Initially quarantined with no underlay, host ports, capabilities or runtime
	// socket. Network/bootstrap setup requires a separate qualified coordinator.
	fingerprint, _ := Fingerprint(s)
	args := []string{"create", "--name", name(s.ID), "--label", ownerLabel + "=" + s.ID.String(), "--label", specLabel + "=" + fingerprint, "--pull=never", "--network=none", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--user=1001:1001", "--read-only", "--read-only-tmpfs=false", "--memory", strconv.Itoa(s.MemoryMiB) + "m", "--cpus", strconv.Itoa(s.CPUs), "--pids-limit", strconv.Itoa(s.PIDs), "--tmpfs", "/tmp:rw,nosuid,nodev,size=16m", "--tmpfs", "/run:rw,nosuid,nodev,size=8m", s.ImageDigest}
	if scope != nil {
		args = append(args[:len(args)-1], "--cgroups=enabled", "--cgroup-parent", scope.record.node.Parent(), s.ImageDigest)
	}
	if p.assets != nil {
		assets, err := p.assets.ResolveAssets(ctx, s.ID)
		if err != nil {
			return ErrUnavailable
		}
		mounts, hash, err := assetMounts(s.ID, assets)
		if err != nil {
			return err
		}
		if assets.SpecHash != fingerprint {
			return ErrOwnership
		}
		args = args[:len(args)-1]
		args = append(args, "--userns=keep-id:uid=1001,gid=1001", "--label", assetsLabel+"="+hash)
		// OCI applies this only inside the new network=none namespace. The
		// workload remains unprivileged and receives no NET_BIND_SERVICE cap.
		args = append(args, "--sysctl", "net.ipv4.ip_unprivileged_port_start=0")
		// Podman 4.9 rejects uid/gid in --tmpfs. Its tmpfs mount U option
		// sets ownership to the configured container user on this fresh private
		// tmpfs only; retained host bind mounts are never recursively chowned.
		for i := 0; i+1 < len(args); i++ {
			if args[i] == "--tmpfs" && args[i+1] == "/run:rw,nosuid,nodev,size=8m" {
				args = append(args[:i], args[i+2:]...)
				break
			}
		}
		args = append(args, "--mount", "type=tmpfs,dst=/run,tmpfs-size=8388608,tmpfs-mode=0700,U=true,notmpcopyup")
		for _, mount := range mounts {
			args = append(args, "--mount", "type=bind,src="+mount.Source+",dst="+mount.Destination+",readonly="+strconv.FormatBool(!mount.RW)+",bind-nonrecursive,bind-propagation=private")
		}
		// Startup belongs to the qualified immutable image. Ubuntu keeps its Python
		// CMD; lightweight profiles can use a checked Bash entrypoint without Python.
		args = append(args, s.ImageDigest)
	}
	// Earlier info/image/assets calls must not consume the remaining lease and
	// then launch. The frozen scope independently handles a provider-call race.
	if _, err = p.boundScope(ctx, s.ID, true); err != nil {
		return err
	}
	if _, err = p.runner.Run(ctx, args...); err != nil {
		return &ProviderStepError{"container-create", errors.Join(ErrUnavailable, err)}
	}
	if scope != nil {
		if _, err := p.Inspect(ctx, s.ID); err != nil {
			return err
		}
	}
	return nil
}
func (p *Podman) Inspect(ctx context.Context, id uuid.UUID) (Status, error) {
	if !validID(id) {
		return Status{}, ErrInvalid
	}
	scope, err := p.boundScope(ctx, id, false)
	if err != nil {
		return Status{}, err
	}
	exists, err := p.runner.Run(ctx, "container", "exists", name(id))
	_ = exists
	if err != nil {
		// Podman exists uses exactly exit1 for missing. Other failures do not confer
		// permission to create a replacement or declare successful cleanup.
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 1 {
			return Status{}, ErrMissing
		}
		if errors.Is(err, ErrMissing) {
			return Status{}, ErrMissing
		}
		return Status{}, ErrUnavailable
	}
	raw, err := p.runner.Run(ctx, "inspect", "--type=container", "--format=json", name(id))
	if err != nil {
		return Status{}, ErrUnavailable
	}
	var rows []struct {
		ID     string `json:"Id"`
		Config struct{ Labels map[string]string }
		State  struct {
			Running bool
			Pid     int
		}
		HostConfig struct{ CgroupParent string }
		Image      string
		Mounts     []assetMount
	}
	if json.Unmarshal(raw, &rows) != nil || len(rows) != 1 {
		return Status{}, ErrUnavailable
	}
	if rows[0].Config.Labels[ownerLabel] != id.String() {
		return Status{}, ErrOwnership
	}
	if !runtimeIDPattern.MatchString(rows[0].ID) {
		return Status{}, ErrUnavailable
	}
	if p.assets != nil {
		assets, err := p.assets.ResolveAssets(ctx, id)
		if err != nil {
			return Status{}, ErrUnavailable
		}
		expected, hash, err := assetMounts(id, assets)
		if err != nil {
			return Status{}, err
		}
		if rows[0].Config.Labels[assetsLabel] != hash || rows[0].Config.Labels[specLabel] != assets.SpecHash || !sameAssetMounts(expected, rows[0].Mounts) {
			return Status{}, ErrOwnership
		}
	} else if rows[0].Config.Labels[assetsLabel] != "" {
		return Status{}, ErrOwnership
	}
	if scope != nil {
		if err := scope.record.node.CheckRuntime(rows[0].HostConfig.CgroupParent, rows[0].State.Pid, rows[0].State.Running); err != nil {
			if rows[0].State.Running {
				scope.guard.fail(err)
			}
			return Status{}, ErrOwnership
		}
	}
	return Status{RuntimeID: rows[0].ID, ImageDigest: canonicalImageID(rows[0].Image), SpecHash: rows[0].Config.Labels[specLabel], Exists: true, Running: rows[0].State.Running}, nil
}
func (p *Podman) action(ctx context.Context, id uuid.UUID, args ...string) error {
	launch := len(args) > 0 && args[0] == "start"
	if _, err := p.boundScope(ctx, id, launch); err != nil {
		return err
	}
	status, err := p.Inspect(ctx, id)
	if err != nil {
		return err
	}
	if !status.Exists {
		return ErrMissing
	}
	if _, err := p.boundScope(ctx, id, launch); err != nil {
		return err
	}
	if _, err = p.runner.Run(ctx, append(args, status.RuntimeID)...); err != nil {
		return ErrUnavailable
	}
	if launch && p.leaseGuard != nil {
		// The configured parent is not actual payload membership. Verify native
		// /proc placement before the actor can acknowledge a successful start.
		started, err := p.Inspect(ctx, id)
		if err != nil || !started.Running {
			return errors.Join(ErrUnavailable, err)
		}
	}
	return nil
}
func (p *Podman) Start(ctx context.Context, id uuid.UUID) error { return p.action(ctx, id, "start") }
func (p *Podman) Stop(ctx context.Context, id uuid.UUID) error {
	return p.action(ctx, id, "stop", "--time", "5")
}
func (p *Podman) Delete(ctx context.Context, id uuid.UUID) error {
	err := p.action(ctx, id, "rm", "--force")
	if errors.Is(err, ErrMissing) {
		return nil
	}
	return err
}

// Podman commonly serializes Image as an unprefixed config ID. Templates bind
// that immutable local image ID, never a mutable tag. OCI manifest verification
// belongs to preloading; its config digest must match this runtime identity.
func canonicalImageID(value string) string {
	if runtimeIDPattern.MatchString(value) {
		return "sha256:" + value
	}
	return value
}
