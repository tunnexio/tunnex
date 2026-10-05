package sandboxes

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxruntime"
)

type assetsResolverFixture struct{ assets sandboxruntime.RuntimeAssets }

func (f assetsResolverFixture) ResolveAssets(_ context.Context, id uuid.UUID) (sandboxruntime.RuntimeAssets, error) {
	if id != f.assets.SandboxID {
		return sandboxruntime.RuntimeAssets{}, sandboxruntime.ErrOwnership
	}
	return f.assets, nil
}

type assetsRunnerFixture struct {
	created bool
	labels  map[string]string
	mounts  []map[string]any
	image   string
}

func (f *assetsRunnerFixture) Run(_ context.Context, args ...string) ([]byte, error) {
	switch args[0] {
	case "info":
		return []byte("true"), nil
	case "image":
		return nil, nil
	case "container":
		if !f.created {
			return nil, sandboxruntime.ErrMissing
		}
		return nil, nil
	case "create":
		f.labels = map[string]string{}
		for i, arg := range args {
			if arg == "--label" {
				parts := strings.SplitN(args[i+1], "=", 2)
				f.labels[parts[0]] = parts[1]
			}
			if arg == "--mount" {
				mount := map[string]any{"RW": true}
				for _, entry := range strings.Split(args[i+1], ",") {
					parts := strings.SplitN(entry, "=", 2)
					if len(parts) != 2 {
						continue
					}
					switch parts[0] {
					case "type":
						mount["Type"] = parts[1]
					case "src":
						mount["Source"] = parts[1]
					case "dst":
						mount["Destination"] = parts[1]
					case "readonly":
						mount["RW"] = parts[1] == "false"
					}
				}
				f.mounts = append(f.mounts, mount)
			}
		}
		f.created = true
		return nil, nil
	case "inspect":
		return json.Marshal([]any{map[string]any{"Id": strings.Repeat("b", 64), "Image": f.image, "Config": map[string]any{"Labels": f.labels}, "State": map[string]bool{"Running": false}, "Mounts": f.mounts}})
	}
	return nil, sandboxruntime.ErrUnavailable
}

func TestCreationAssetsPostgresSelectedSkillsToProviderMounts(t *testing.T) {
	f := newFixture(t)
	skill, _, err := f.store.CreateCustomSkill(f.ctx, f.org, f.user, customSkillDocument, "mounted-skill")
	if err != nil {
		t.Fatal(err)
	}
	in := f.input("assets")
	in.SelectedSkills = []SkillSelection{{skill.RevisionID, map[string]string{}}}
	sandbox, _, err := f.store.Create(f.ctx, f.org, f.user, in)
	if err != nil {
		t.Fatal(err)
	}
	base, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	if err = base.Mkdir(sandbox.Identity.ID.String(), 0700); err != nil {
		t.Fatal(err)
	}
	root, err := base.OpenRoot(sandbox.Identity.ID.String())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	probePublicKey := publicTerminalKey(t)
	assets, terminal, err := f.store.PrepareCreationAssets(f.ctx, sandbox.Identity.ID, root, probePublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err = root.WriteFile("workspace/user.txt", []byte("retained"), 0600); err != nil {
		t.Fatal(err)
	}
	again, identity, err := f.store.PrepareCreationAssets(f.ctx, sandbox.Identity.ID, root, probePublicKey)
	if err != nil || assets != again || terminal != identity {
		t.Fatal("retry changed mounts or host key", err)
	}
	runner := &assetsRunnerFixture{image: "sha256:" + strings.Repeat("a", 64)}
	resolver, err := sandboxruntime.NewFilesystemAssets(base)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := resolver.ResolveAssets(f.ctx, sandbox.Identity.ID)
	if err != nil || recovered != assets {
		t.Fatal("persisted mounts could not recover", err)
	}
	if _, err = resolver.ResolveAssets(f.ctx, uuid.New()); err == nil {
		t.Fatal("unrelated sandbox resolved assets")
	}
	provider, err := sandboxruntime.NewPodmanWithAssets(runner, resolver)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.store.ReconcileQuarantinedStart(f.ctx, sandbox.Identity.ID, provider); err != nil {
		t.Fatal("prepared assets failed provider binding", err)
	}
	binds, privateRun := 0, false
	for _, mount := range runner.mounts {
		if mount["Type"] == "bind" {
			binds++
		}
		if mount["Type"] == "tmpfs" && mount["Destination"] == "/run" && mount["RW"] == true {
			privateRun = true
		}
	}
	if len(runner.mounts) != 4 || binds != 3 || !privateRun {
		t.Fatal("workspace/skill/SSH and private runtime tmpfs composition missing")
	}
	if _, _, err = f.store.PrepareCreationAssets(f.ctx, sandbox.Identity.ID, root, probePublicKey); !errors.Is(err, ErrConflict) {
		t.Fatal("bound runtime mounts rewritten", err)
	}
	data, err := root.ReadFile("workspace/user.txt")
	if err != nil || string(data) != "retained" {
		t.Fatal("retained workspace overwritten", err)
	}
	if err = root.Remove("terminal/host_key"); err != nil {
		t.Fatal(err)
	}
	if _, err = resolver.ResolveAssets(f.ctx, sandbox.Identity.ID); err == nil {
		t.Fatal("lost host identity silently recovered")
	}
}
