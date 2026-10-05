package sandboxruntime

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"strings"
	"testing"
)

type fakeRunner struct {
	calls     [][]string
	responses func([]string) ([]byte, error)
}

func (f *fakeRunner) Run(_ context.Context, args ...string) ([]byte, error) {
	f.calls = append(f.calls, args)
	return f.responses(args)
}
func TestPodmanQuarantineAndOwnership(t *testing.T) {
	id := uuid.New()
	created := false
	f := &fakeRunner{responses: func(args []string) ([]byte, error) {
		switch args[0] {
		case "info":
			return []byte("true\n"), nil
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
			b, _ := json.Marshal([]any{map[string]any{"Id": strings.Repeat("b", 64), "Config": map[string]any{"Labels": map[string]string{ownerLabel: id.String()}}, "State": map[string]bool{"Running": true}}})
			return b, nil
		}
		return nil, nil
	}}
	p := NewPodman(f)
	spec := Spec{ID: id, ImageDigest: "sha256:" + strings.Repeat("a", 64), MemoryMiB: 256, CPUs: 1, PIDs: 128}
	if err := p.Create(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	args := strings.Join(f.calls[len(f.calls)-1], " ")
	for _, flag := range []string{"--pull=never", "--network=none", "--cap-drop=ALL", "--user=1001:1001", "--memory 256m", "--pids-limit 128", "--read-only"} {
		if !strings.Contains(args, flag) {
			t.Fatalf("missing %s: %s", flag, args)
		}
	}
	if strings.Contains(args, "--publish") || strings.Contains(args, "--privileged") || strings.Contains(args, "socket") {
		t.Fatal("unsafe provider configuration")
	}
	if err := p.Create(context.Background(), spec); !errors.Is(err, ErrOwnership) {
		t.Fatalf("existing resource overwritten: %v", err)
	}
	if err := p.Stop(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	f.responses = func(args []string) ([]byte, error) {
		if args[0] == "container" {
			return nil, nil
		}
		return []byte(`[{"Config":{"Labels":{}},"State":{"Running":true}}]`), nil
	}
	before := len(f.calls)
	if err := p.Delete(context.Background(), id); !errors.Is(err, ErrOwnership) {
		t.Fatal("unowned delete accepted")
	}
	if len(f.calls) != before+2 {
		t.Fatal("mutation attempted before ownership check")
	}
}
func TestProviderFailuresDoNotBecomeMissing(t *testing.T) {
	f := &fakeRunner{responses: func([]string) ([]byte, error) { return nil, errors.New("socket unavailable") }}
	p := NewPodman(f)
	if err := p.Delete(context.Background(), uuid.New()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unavailable delete reported success: %v", err)
	}
	if p.Create(context.Background(), Spec{}) != ErrInvalid || len(f.calls) != 1 {
		t.Fatal("invalid input reached runtime")
	}
}

func TestRuntimeRecoveryRequiresCompleteFingerprint(t *testing.T) {
	spec := Spec{ID: uuid.New(), ImageDigest: "sha256:" + strings.Repeat("a", 64), MemoryMiB: 256, CPUs: 1, PIDs: 128}
	hash, err := Fingerprint(spec)
	if err != nil {
		t.Fatal(err)
	}
	status := Status{RuntimeID: strings.Repeat("b", 64), ImageDigest: spec.ImageDigest, SpecHash: hash, Exists: true}
	if err := Matches(spec, status); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Status){
		func(s *Status) { s.SpecHash = "" },
		func(s *Status) { s.RuntimeID = "other" },
		func(s *Status) { s.ImageDigest = "sha256:" + strings.Repeat("c", 64) },
		func(s *Status) { s.Exists = false },
	} {
		changed := status
		mutate(&changed)
		if !errors.Is(Matches(spec, changed), ErrOwnership) {
			t.Fatal("uncertain runtime adopted")
		}
	}
	changed := spec
	changed.MemoryMiB = 512
	if !errors.Is(Matches(changed, status), ErrOwnership) {
		t.Fatal("resource-limit drift adopted")
	}
}

func TestPodmanInspectNormalizesImmutableLocalImageID(t *testing.T) {
	id := uuid.New()
	configID := strings.Repeat("a", 64)
	runner := &fakeRunner{responses: func(args []string) ([]byte, error) {
		if args[0] == "container" {
			return nil, nil
		}
		return json.Marshal([]any{map[string]any{"Id": strings.Repeat("b", 64), "Image": configID, "Config": map[string]any{"Labels": map[string]string{ownerLabel: id.String()}}, "State": map[string]bool{"Running": true}}})
	}}
	status, err := NewPodman(runner).Inspect(context.Background(), id)
	if err != nil || status.ImageDigest != "sha256:"+configID {
		t.Fatal("Podman local config identity mismatched", status, err)
	}
}

func TestPersistentPodmanRejectsWrongActualConfigArchitectureAndOS(t *testing.T) {
	spec := Spec{ID: uuid.New(), ImageDigest: "sha256:" + strings.Repeat("a", 64), MemoryMiB: 128, CPUs: 1, PIDs: 64, Architecture: "amd64"}
	for _, scenario := range []string{"native", "wrong-config", "wrong-architecture", "wrong-os", "malformed"} {
		t.Run(scenario, func(t *testing.T) {
			f := &fakeRunner{responses: func(args []string) ([]byte, error) {
				switch args[0] {
				case "info":
					return []byte("true\n"), nil
				case "container":
					return nil, ErrMissing
				case "image":
					image := map[string]string{"Id": spec.ImageDigest, "Architecture": "amd64", "Os": "linux"}
					switch scenario {
					case "wrong-config":
						image["Id"] = "sha256:" + strings.Repeat("b", 64)
					case "wrong-architecture":
						image["Architecture"] = "arm64"
					case "wrong-os":
						image["Os"] = "windows"
					case "malformed":
						return []byte("{}"), nil
					}
					return json.Marshal([]any{image})
				}
				return nil, nil
			}}
			err := NewPodman(f).Create(context.Background(), spec)
			if scenario == "native" {
				if err != nil {
					t.Fatal(err)
				}
				args := strings.Join(f.calls[len(f.calls)-1], " ")
				if strings.Contains(args, "python") || strings.Contains(args, "--entrypoint") || !strings.HasSuffix(args, spec.ImageDigest) {
					t.Fatal("image-specific bootstrap overwritten", args)
				}
			} else {
				if !errors.Is(err, ErrOwnership) {
					t.Fatal("foreign image accepted", err)
				}
				for _, call := range f.calls {
					if call[0] == "create" {
						t.Fatal("wrong image launched")
					}
				}
			}
		})
	}
}
