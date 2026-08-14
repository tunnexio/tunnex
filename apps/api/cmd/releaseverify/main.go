// Command releaseverify validates a signed Control Plane release descriptor.
package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/tunnexio/tunnex/apps/api/internal/release"
)

func main() {
	manifest := flag.String("manifest", "", "signed release manifest path")
	key := flag.String("public-key", os.Getenv("TUNNEX_RELEASE_PUBLIC_KEY"), "trusted Ed25519 key")
	expectedSource := flag.String("expected-source-sha", "", "require this full source SHA")
	printEnv := flag.Bool("print-env", false, "print safe image-pin environment assignments after verification")
	platform := flag.String("platform", runtime.GOARCH, "target image architecture: amd64 or arm64")
	flag.Parse()
	if *manifest == "" || *key == "" {
		fmt.Fprintln(os.Stderr, "usage: releaseverify -manifest FILE -public-key KEY")
		os.Exit(2)
	}
	s, err := release.Load(*manifest, *key)
	if err != nil {
		fmt.Fprintln(os.Stderr, "release manifest rejected:", err)
		os.Exit(1)
	}
	if *expectedSource != "" && !strings.EqualFold(*expectedSource, s.Manifest.SourceSHA) {
		fmt.Fprintln(os.Stderr, "release manifest rejected: source SHA does not match this installation")
		os.Exit(1)
	}
	if !*printEnv {
		fmt.Printf("verified version=%s source_sha=%s sequence=%d\n", s.Manifest.Version, s.Manifest.SourceSHA, s.Manifest.Sequence)
		return
	}
	if *platform != "amd64" && *platform != "arm64" {
		fmt.Fprintln(os.Stderr, "release manifest rejected: unsupported platform")
		os.Exit(1)
	}
	for _, name := range []string{"api", "web", "nginx", "node-agent", "migrate"} {
		image := s.Manifest.Images[name]
		digest := image.AMD64Digest
		if *platform == "arm64" {
			digest = image.ARM64Digest
		}
		fmt.Printf("TUNNEX_%s_IMAGE=ghcr.io/tunnexio/tunnex-%s@%s\n", strings.ToUpper(strings.ReplaceAll(name, "-", "_")), name, digest)
	}
	fmt.Printf("TUNNEX_RELEASE_SEQUENCE=%d\n", s.Manifest.Sequence)
	fmt.Printf("TUNNEX_RELEASE_VERSION=%s\n", s.Manifest.Version)
	fmt.Printf("TUNNEX_RELEASE_SOURCE_SHA=%s\n", s.Manifest.SourceSHA)
}
