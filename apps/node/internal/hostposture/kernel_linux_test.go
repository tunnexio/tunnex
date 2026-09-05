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
	const validListing = "table ip tunnex {\n  chain tunnex_posture_owner { # handle 1\n    counter packets 0 bytes 0 comment \"tunnex_host_posture_v1\" # handle 2\n  }\n}\n"
	listing := validListing
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
	listing = strings.Replace(listing, "  }\n", "    counter packets 0 bytes 0 comment \"tunnex_host_posture_v1\" # handle 3\n  }\n", 1)
	if err := kernel.verifyNFTMarker(t.Context(), fixedArtifacts().NFTables[0]); err == nil {
		t.Fatal("duplicate marker must be ambiguous")
	}
	if err := ValidateNFTMarkerChain(strings.Replace(validListing, "table ip ", "table ip6 ", 1), NFTMarkerComment); err != nil {
		t.Fatalf("ip6 listing rejected: %v", err)
	}
}

func TestNFTMarkerRejectsForeignRulesAndMalformedHeaderTricks(t *testing.T) {
	const markerRule = `counter packets 0 bytes 0 comment "tunnex_host_posture_v1" # handle 2`
	tests := map[string]string{
		"missing table wrapper":   "chain tunnex_posture_owner { # handle 1\n  " + markerRule + "\n}\n",
		"missing chain header":    "table ip tunnex {\n  " + markerRule + "\n}\n",
		"duplicate table header":  "table ip tunnex {\n  table ip tunnex {\n  chain tunnex_posture_owner { # handle 1\n    " + markerRule + "\n  }\n}\n",
		"extra closing brace":     "table ip tunnex {\n  chain tunnex_posture_owner { # handle 1\n    " + markerRule + "\n  }\n}\n}\n",
		"foreign rule":            "table ip tunnex {\n  chain tunnex_posture_owner { # handle 1\n    " + markerRule + "\n    ip saddr 192.0.2.1 drop # handle 3\n  }\n}\n",
		"marker rule prefix":      "table ip tunnex {\n  chain tunnex_posture_owner { # handle 1\n    drop " + markerRule + "\n  }\n}\n",
		"marker rule suffix":      "table ip tunnex {\n  chain tunnex_posture_owner { # handle 1\n    " + markerRule + " accept\n  }\n}\n",
		"duplicate chain header":  "table ip tunnex {\n  chain tunnex_posture_owner { # handle 1\n  chain tunnex_posture_owner { # handle 4\n    " + markerRule + "\n  }\n}\n",
		"wrong chain header":      "table ip tunnex {\n  chain foreign { # handle 1\n    " + markerRule + "\n  }\n}\n",
		"header suffix":           "table ip tunnex {\n  chain tunnex_posture_owner { # handle 1 accept\n    " + markerRule + "\n  }\n}\n",
		"header fused comment":    "table ip tunnex {\n  chain tunnex_posture_owner { #handle 1\n    " + markerRule + "\n  }\n}\n",
		"zero header handle":      "table ip tunnex {\n  chain tunnex_posture_owner { # handle 0\n    " + markerRule + "\n  }\n}\n",
		"multiple header handles": "table ip tunnex {\n  chain tunnex_posture_owner { # handle 1 # handle 4\n    " + markerRule + "\n  }\n}\n",
		"zero rule handle":        "table ip tunnex {\n  chain tunnex_posture_owner { # handle 1\n    counter packets 0 bytes 0 comment \"tunnex_host_posture_v1\" # handle 0\n  }\n}\n",
		"multiple rule handles":   "table ip tunnex {\n  chain tunnex_posture_owner { # handle 1\n    " + markerRule + " # handle 3\n  }\n}\n",
		"non-decimal counter":     "table ip tunnex {\n  chain tunnex_posture_owner { # handle 1\n    counter packets nope bytes 0 comment \"tunnex_host_posture_v1\" # handle 2\n  }\n}\n",
		"marker substring":        "table ip tunnex {\n  chain tunnex_posture_owner { # handle 1\n    counter packets 0 bytes 0 comment \"prefix_tunnex_host_posture_v1\" # handle 2\n  }\n}\n",
		"duplicate marker token":  "table ip tunnex {\n  chain tunnex_posture_owner { # handle 1\n    counter packets 0 bytes 0 comment \"tunnex_host_posture_v1\" comment \"tunnex_host_posture_v1\" # handle 2\n  }\n}\n",
		"extra unhandled marker":  "table ip tunnex {\n  chain tunnex_posture_owner { # handle 1\n    " + markerRule + "\n    comment \"tunnex_host_posture_v1\"\n  }\n}\n",
	}
	for name, listing := range tests {
		t.Run(name, func(t *testing.T) {
			if err := ValidateNFTMarkerChain(listing, NFTMarkerComment); err == nil {
				t.Fatal("ambiguous or foreign nft listing must be rejected")
			}
		})
	}
}
