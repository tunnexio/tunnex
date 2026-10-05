package sandboxruntime

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
)

type fixedAssets struct{ value RuntimeAssets }

func (r fixedAssets) ResolveAssets(_ context.Context, id uuid.UUID) (RuntimeAssets, error) {
	if id != r.value.SandboxID {
		return RuntimeAssets{}, ErrOwnership
	}
	return r.value, nil
}
func fixtureAssets(t *testing.T) RuntimeAssets {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	assets := RuntimeAssets{SandboxID: uuid.New(), Workspace: filepath.Join(base, "workspace"), Skills: filepath.Join(base, "skills"), SSH: filepath.Join(base, "ssh")}
	for _, path := range []string{assets.Workspace, assets.Skills, assets.SSH, filepath.Join(assets.Workspace, ".agents"), filepath.Join(assets.Workspace, ".agents/skills")} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"sshd_config", "host_key", "authorized_keys"} {
		if err := os.WriteFile(filepath.Join(assets.SSH, name), []byte("fixture only"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	assets.Digest, err = AssetContentDigest(assets.Skills, assets.SSH)
	if err != nil {
		t.Fatal(err)
	}
	assets.SpecHash, _ = Fingerprint(Spec{ID: assets.SandboxID, ImageDigest: "sha256:" + strings.Repeat("a", 64), MemoryMiB: 256, CPUs: 1, PIDs: 128})
	return assets
}

func TestPodmanMountRecoveryVerifiesActualMountsAndContent(t *testing.T) {
	assets := fixtureAssets(t)
	mounts, assetHash, err := assetMounts(assets.SandboxID, assets)
	if err != nil {
		t.Fatal(err)
	}
	spec := Spec{ID: assets.SandboxID, ImageDigest: "sha256:" + strings.Repeat("a", 64), MemoryMiB: 256, CPUs: 1, PIDs: 128}
	specHash, _ := Fingerprint(spec)
	created := false
	actual := append([]assetMount(nil), mounts...)
	f := &fakeRunner{responses: func(args []string) ([]byte, error) {
		switch args[0] {
		case "info":
			return []byte("true"), nil
		case "image":
			return nil, nil
		case "container":
			if !created {
				return nil, ErrMissing
			}
			return nil, nil
		case "create":
			created = true
			return nil, nil
		case "inspect":
			return json.Marshal([]any{map[string]any{"Id": strings.Repeat("b", 64), "Image": spec.ImageDigest, "Config": map[string]any{"Labels": map[string]string{ownerLabel: spec.ID.String(), specLabel: specHash, assetsLabel: assetHash}}, "State": map[string]bool{"Running": true}, "Mounts": actual}})
		}
		return nil, nil
	}}
	p, err := NewPodmanWithAssets(f, fixedAssets{assets})
	if err != nil {
		t.Fatal(err)
	}
	if err = p.Create(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	args := strings.Join(f.calls[len(f.calls)-1], " ")
	for _, flag := range []string{"--network=none", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--userns=keep-id:uid=1001,gid=1001", "dst=/workspace,readonly=false", "dst=/workspace/.agents/skills,readonly=true", "dst=/run/tunnex-ssh,readonly=true", "bind-nonrecursive", "net.ipv4.ip_unprivileged_port_start=0", "type=tmpfs,dst=/run,tmpfs-size=8388608,tmpfs-mode=0700,U=true,notmpcopyup"} {
		if !strings.Contains(args, flag) {
			t.Fatalf("missing transport control %s", flag)
		}
	}
	if !strings.HasSuffix(args, spec.ImageDigest) {
		t.Fatal("qualified immutable image command was overridden")
	}
	if strings.Contains(args, "runtime-credential") || strings.Contains(args, "--publish") || strings.Contains(args, "--privileged") || strings.Contains(args, "chown") {
		t.Fatal("unexpected ambient or credential access")
	}
	if _, err = p.Inspect(context.Background(), spec.ID); err != nil {
		t.Fatal(err)
	}
	actual[1].RW = true
	if _, err = p.Inspect(context.Background(), spec.ID); !errors.Is(err, ErrOwnership) {
		t.Fatal("writable skill mount recovered", err)
	}
	actual = append([]assetMount(nil), mounts...)
	actual = append(actual, assetMount{"bind", "/var/run/podman.sock", "/host.sock", true})
	if _, err = p.Inspect(context.Background(), spec.ID); !errors.Is(err, ErrOwnership) {
		t.Fatal("extra socket mount recovered", err)
	}
	actual = append([]assetMount(nil), mounts...)
	if err = os.WriteFile(filepath.Join(assets.SSH, "authorized_keys"), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = p.Inspect(context.Background(), spec.ID); !errors.Is(err, ErrInvalid) {
		t.Fatal("changed terminal assets recovered", err)
	}
}

func TestAssetsRejectCrossIdentitySymlinksOverlapAndArgumentInjection(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*testing.T, *RuntimeAssets)
	}{
		{"identity", func(_ *testing.T, a *RuntimeAssets) { a.SandboxID = uuid.New() }},
		{"overlap", func(_ *testing.T, a *RuntimeAssets) { a.Skills = a.Workspace }},
		{"argument delimiter", func(_ *testing.T, a *RuntimeAssets) { a.Skills += " ,dst=/host" }},
		{"symlink", func(t *testing.T, a *RuntimeAssets) {
			p := a.Skills + "-link"
			if err := os.Symlink(a.Skills, p); err != nil {
				t.Fatal(err)
			}
			a.Skills = p
		}},
		{"world readable", func(t *testing.T, a *RuntimeAssets) {
			if err := os.Chmod(a.SSH, 0755); err != nil {
				t.Fatal(err)
			}
		}},
		{"credential file excluded", func(t *testing.T, a *RuntimeAssets) {
			if err := os.WriteFile(filepath.Join(a.SSH, "runtime-credential"), []byte("fixture"), 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"key symlink", func(t *testing.T, a *RuntimeAssets) {
			p := filepath.Join(a.SSH, "host_key")
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("authorized_keys", p); err != nil {
				t.Fatal(err)
			}
		}},
		{"workspace target symlink", func(t *testing.T, a *RuntimeAssets) {
			p := filepath.Join(a.Workspace, ".agents/skills")
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(a.Skills, p); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := fixtureAssets(t)
			id := a.SandboxID
			tc.change(t, &a)
			if _, _, err := assetMounts(id, a); !errors.Is(err, ErrInvalid) {
				t.Fatal("unsafe assets accepted", err)
			}
		})
	}
}
