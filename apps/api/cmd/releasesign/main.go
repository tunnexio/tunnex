// Command releasesign signs an immutable release manifest for a tagged release.
// The private key is supplied by CI only; it is never written to logs or artifacts.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/tunnexio/tunnex/apps/api/internal/release"
)

func main() {
	input := flag.String("manifest", "", "unsigned release manifest JSON")
	output := flag.String("output", "", "signed manifest output path (default stdout)")
	keyValue := flag.String("private-key", os.Getenv("TUNNEX_RELEASE_SIGNING_KEY"), "Ed25519 private key as hex or base64")
	kid := flag.String("kid", os.Getenv("TUNNEX_RELEASE_KEY_ID"), "release signing key identifier")
	flag.Parse()
	if *input == "" || *keyValue == "" || *kid == "" {
		fmt.Fprintln(os.Stderr, "usage: releasesign -manifest FILE -private-key KEY -kid ID [-output FILE]")
		os.Exit(2)
	}
	key, err := decodePrivateKey(*keyValue)
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid release signing key")
		os.Exit(2)
	}
	b, err := os.ReadFile(*input)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read manifest:", err)
		os.Exit(1)
	}
	var manifest release.Manifest
	if err := json.Unmarshal(b, &manifest); err != nil {
		fmt.Fprintln(os.Stderr, "decode manifest:", err)
		os.Exit(1)
	}
	canonical, err := json.Marshal(manifest)
	if err != nil {
		fmt.Fprintln(os.Stderr, "encode manifest:", err)
		os.Exit(1)
	}
	signed := release.SignedManifest{Manifest: manifest, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, canonical)), KeyID: *kid}
	out, err := json.MarshalIndent(signed, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "encode signed manifest:", err)
		os.Exit(1)
	}
	out = append(out, '\n')
	if *output == "" {
		_, _ = os.Stdout.Write(out)
		return
	}
	if err := os.WriteFile(*output, out, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "write signed manifest:", err)
		os.Exit(1)
	}
}

func decodePrivateKey(raw string) (ed25519.PrivateKey, error) {
	raw = strings.TrimSpace(raw)
	for _, decode := range []func(string) ([]byte, error){hex.DecodeString, base64.RawStdEncoding.DecodeString, base64.RawURLEncoding.DecodeString} {
		b, err := decode(raw)
		if err != nil {
			continue
		}
		if len(b) == ed25519.PrivateKeySize {
			return ed25519.PrivateKey(b), nil
		}
		if len(b) == ed25519.SeedSize {
			return ed25519.NewKeyFromSeed(b), nil
		}
	}
	return nil, fmt.Errorf("invalid key length")
}
