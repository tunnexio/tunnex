//go:build linux

package hostposture

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type runnerFunc func(context.Context, string, []byte, ...string) (string, error)

func (fn runnerFunc) Run(ctx context.Context, name string, args ...string) (string, error) {
	return fn(ctx, name, nil, args...)
}
func (fn runnerFunc) RunInput(ctx context.Context, name string, input []byte, args ...string) (string, error) {
	return fn(ctx, name, input, args...)
}

func writeSysctlFixture(t *testing.T, root, key, value string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(key))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(value), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRestoreSysctlsRestoresOnlyLiveTunnexDesiredValues(t *testing.T) {
	root := t.TempDir()
	receipts := desiredSysctls()
	receipts[0].Original = "0"
	receipts[1].Original = "1"
	receipts[2].Original = "2"
	writeSysctlFixture(t, root, receipts[0].Key, receipts[0].Desired)
	writeSysctlFixture(t, root, receipts[1].Key, "2") // external owner changed it after Tunnex enforcement
	writeSysctlFixture(t, root, receipts[2].Key, receipts[2].Desired)
	kernel, err := NewLinuxKernel(root, runnerFunc(func(context.Context, string, []byte, ...string) (string, error) {
		return "", errors.New("unexpected command")
	}))
	if err != nil {
		t.Fatal(err)
	}
	if err := kernel.restoreSysctls(receipts); err != nil {
		t.Fatal(err)
	}
	for i, want := range []string{"0", "2", "2"} {
		got, err := kernel.readSysctl(receipts[i].Key)
		if err != nil || got != want {
			t.Fatalf("%s=%q err=%v, want %q", receipts[i].Key, got, err, want)
		}
	}
	if !receipts[0].Restored || receipts[0].Skipped || receipts[1].Restored || !receipts[1].Skipped || !receipts[2].Restored {
		t.Fatalf("restore receipts=%+v", receipts)
	}
}

func TestDockerCleanupParserFailsClosedOnUnknownMarkedShape(t *testing.T) {
	runner := runnerFunc(func(_ context.Context, name string, _ []byte, args ...string) (string, error) {
		if name == "nft" && strings.Join(args, " ") == "-a list chain ip filter DOCKER-USER" {
			return `chain DOCKER-USER { ip saddr 10.99.0.0/24 drop comment "tunnex-site-fwd" # handle 8 }`, nil
		}
		return "", errors.New("unexpected command")
	})
	kernel, err := NewLinuxKernel(t.TempDir(), runner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kernel.dockerOwnedRules(t.Context()); err == nil || !strings.Contains(err.Error(), "unrecognized shape") {
		t.Fatalf("unknown marked rule must block cleanup: %v", err)
	}
}

func TestNFTMarkerRequiresExactlyOneRecognizedOwnerRule(t *testing.T) {
	listing := "chain tunnex_posture_owner {\n  counter packets 0 bytes 0 comment \"tunnex_host_posture_v1\" # handle 2\n}\n"
	runner := runnerFunc(func(_ context.Context, name string, _ []byte, args ...string) (string, error) {
		if name == "nft" && strings.HasPrefix(strings.Join(args, " "), "-a list chain") {
			return listing, nil
		}
		return "", errors.New("unexpected command")
	})
	kernel, _ := NewLinuxKernel(t.TempDir(), runner)
	if err := kernel.verifyNFTMarker(t.Context(), fixedArtifacts().NFTables[0]); err != nil {
		t.Fatal(err)
	}
	listing += "  counter comment \"tunnex_host_posture_v1\" # handle 3\n"
	if err := kernel.verifyNFTMarker(t.Context(), fixedArtifacts().NFTables[0]); err == nil {
		t.Fatal("duplicate marker must be ambiguous")
	}
}
