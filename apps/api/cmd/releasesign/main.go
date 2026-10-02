// Command releasesign signs an immutable release manifest for a tagged release.
// The private key is supplied by CI only; it is never written to logs or artifacts.
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/tunnexio/tunnex/apps/api/internal/release"
)

func main() {
	input := flag.String("manifest", "", "unsigned release manifest JSON")
	output := flag.String("output", "", "signed manifest output path (default stdout)")
	keyValue := flag.String("private-key", os.Getenv("TUNNEX_RELEASE_SIGNING_KEY"), "Ed25519 private key as hex or base64")
	kid := flag.String("kid", os.Getenv("TUNNEX_RELEASE_KEY_ID"), "release signing key identifier")
	bootstrapVerifier := flag.Bool("bootstrap-verifier", false, "sign a detached managed-agent verifier descriptor instead of release.json")
	publicKeyOutput := flag.String("public-key-output", "", "write the public verification key for publication checks")
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
	out, err := signInput(b, key, *kid, *bootstrapVerifier)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sign descriptor:", err)
		os.Exit(1)
	}
	if *publicKeyOutput != "" {
		publicKey := base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
		if err := os.WriteFile(*publicKeyOutput, []byte(publicKey+"\n"), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "write public key:", err)
			os.Exit(1)
		}
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

func signInput(b []byte, key ed25519.PrivateKey, kid string, bootstrapVerifier bool) ([]byte, error) {
	if bootstrapVerifier {
		var m release.BootstrapVerifierManifest
		d := json.NewDecoder(bytes.NewReader(b))
		d.DisallowUnknownFields()
		if err := d.Decode(&m); err != nil {
			return nil, err
		}
		if err := d.Decode(new(any)); err != io.EOF {
			return nil, fmt.Errorf("trailing descriptor data")
		}
		signed, err := release.SignBootstrapVerifier(m, key, kid)
		if err != nil {
			return nil, err
		}
		return json.MarshalIndent(signed, "", "  ")
	}
	var manifest release.Manifest
	if err := json.Unmarshal(b, &manifest); err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	signed := release.SignedManifest{Manifest: manifest, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, canonical)), KeyID: kid}
	return json.MarshalIndent(signed, "", "  ")
}
