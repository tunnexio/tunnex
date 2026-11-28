# Release signing setup checklist

This checklist is for the repository owner/operator setting up signed upgrade
artifacts. It does not create secrets or change the release workflow.

## One-time setup

1. Generate or retrieve the Tunnex Ed25519 release-signing key in a trusted
   workstation or KMS. Keep the private key offline except when loading it into
   the CI secret store.
2. Add a GitHub Actions repository secret named
   `TUNNEX_RELEASE_SIGNING_PRIVATE_KEY`. Store the private key in the exact format
   accepted by the signer (hex or base64); never paste it into chat, source,
   logs, an issue, or a release asset.
3. Keep only the corresponding public verification key in the installer and
   host-updater configuration. The public key is not confidential and must not
   be replaced by the private key.
4. Ensure the release workflow has the minimum required permission to create or
   update GitHub Release assets for tagged releases. Do not grant unrelated
   write permissions.

### macOS key generation (terminal)

This creates a 32-byte Ed25519 seed in a private temporary directory, derives
the public key without printing the seed, and copies only the private value to
the clipboard for entry into GitHub. Do not paste the private value into chat
or a shell transcript.

```sh
set -eu
umask 077
tmpdir="$(mktemp -d -t tunnex-release-key)"
trap 'rm -f "$tmpdir/seed.hex" "$tmpdir/public.hex" "$tmpdir/keygen.go"; rmdir "$tmpdir" 2>/dev/null || true' EXIT
openssl rand -hex 32 >"$tmpdir/seed.hex"
cat >"$tmpdir/keygen.go" <<'EOF'
package main
import ("crypto/ed25519"; "encoding/hex"; "os"; "strings")
func main() {
  b, err := os.ReadFile(os.Args[1]); if err != nil { panic(err) }
  seed, err := hex.DecodeString(strings.TrimSpace(string(b))); if err != nil || len(seed) != ed25519.SeedSize { panic("invalid seed") }
  key := ed25519.NewKeyFromSeed(seed)
  if err := os.WriteFile(os.Args[2], []byte(hex.EncodeToString(key[ed25519.SeedSize:])), 0600); err != nil { panic(err) }
}
EOF
go run "$tmpdir/keygen.go" "$tmpdir/seed.hex" "$tmpdir/public.hex"
printf 'Public key (safe to store in installer/updater): '
cat "$tmpdir/public.hex"
printf '\nCopying private seed to clipboard for the GitHub secret...\n'
pbcopy <"$tmpdir/seed.hex"
printf 'Paste into GitHub Actions secret TUNNEX_RELEASE_SIGNING_PRIVATE_KEY, then clear the clipboard.\n'
```

The signer accepts this 64-character hexadecimal seed and derives the Ed25519
private key. Store the displayed public value in the updater's trusted-key
configuration. After saving the GitHub secret, clear the clipboard and allow
the trap to remove the temporary files; never commit any generated key file.

## Before every release: refresh the AI model catalog

The AI Gateway bundles model names and USD prices from a pinned LiteLLM commit
(`apps/api/internal/aigateway/reference/`). New provider models are unknown
(and blocked under a daily limit, unless an operator sets a price) until the
pin moves, so refresh it in every release:

1. On the release branch, run `make ai-catalog-refresh` (or
   `make ai-catalog-refresh LITELLM_COMMIT=<40-character sha>` for a reviewed
   commit). It resolves the commit, downloads only that commit's catalog and
   license, rewrites `source.pin.json` and the README pin lines, regenerates
   every artifact, verifies them byte for byte and runs the catalog tests.
2. Review the printed summary: source and reference row counts, added,
   removed and repriced models. A large removal or a price that moved by an
   order of magnitude needs a look upstream before it ships.
3. If a guard fails (schema, provider coverage, completeness, or the reference
   set shrinking by more than 10%), stop and report it. Do not loosen a guard
   to make the refresh pass; keep the previous pin for this release instead.
4. Commit the pin, license, generated files and README together
   ("AI Gateway: refresh model catalog to LiteLLM <short sha>"). The engine
   image copies these files, so the release images carry the new prices.

## Successful-main verification

1. Merge the intended commit and allow the successful-main image publication to
   complete.
2. Confirm the workflow signs the canonical manifest with
   `TUNNEX_RELEASE_SIGNING_PRIVATE_KEY`, creates immutable
   `tunnex-build-<full-source-sha>` assets, and refreshes the signed
   `tunnex-updates` discovery descriptor.
3. Download that exact asset and verify its signature with the installed public
   key. Confirm the manifest version and source digest match the tagged commit
   and published images.
4. On a disposable local deployment, run the updater in dry-run mode. It must
   accept the signed asset without a key flag, and must fail closed for a
   missing, altered, unsigned, or wrong-version manifest.
5. Remove the test tag/release only through the normal GitHub release process
   after evidence has been recorded; never delete customer data or deployment
   volumes as part of this check.

## Security cautions

- Never commit, print, echo, or upload the private key to the repository,
  installer, container image, issue tracker, or chat.
- Rotate the key if it is exposed. Publish a planned public-key rotation path
  before using a replacement key in production.
- Treat a failed signature, unknown key, source mismatch, or image digest
  mismatch as an update blocker; do not bypass verification with an override.
- A signed manifest authenticates the release; it does not provide telemetry or
  guarantee zero outbound network traffic. Keep legal wording precise about
  the no-call-home promise.
