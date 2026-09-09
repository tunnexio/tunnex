# CLI package distribution

Status: GitHub hosting and dedicated package signing approved by user on 2026-09-09.
Branch: `tunnex-cli-publish`, base `26a36afc9be657af94127c474e173783c91318c3`.

## Verified current publication

- `tunnexio/tunnex` release `v0.1.25` is public, published 2026-09-07.
  CI run `34094731790` and Security run `34094731798` succeeded on the base SHA.
- `.github/workflows/ci.yml` job `cli-release` tests the CLI and builds static
  Linux amd64/arm64 binaries. Only tag builds upload the CLI artifact.
- `release-assets` attaches `tnx-linux-amd64`, `tnx-linux-arm64`, and
  `Tunnex-CLI-SHA256SUMS` before publishing the draft release. Existing release
  immutability and source-marker checks must be retained.
- That release also contains bootstrap installers, managed-agent binaries/unit,
  signed release metadata, and Helm archives. CI has GHCR image publication;
  this audit verified release assets and CI status, not anonymous image pulls.
- No DEB/RPM/APK/Arch packages or Homebrew metadata exist in the current release.
  The visible organization repositories are tunnex, tunnex-web, tunnex-client,
  and .github; no first-party package/tap repository was found.
- Repository secret names show release descriptor signing and website sync
  configuration, but no dedicated package-repository signing configuration.
  Secret values were not read. Organization/environment secrets and external
  package-service accounts were not exhaustively enumerated.
- GitHub Pages lookup for tunnex returned 404; no configured Pages site was
  established by this check.
- Separate `tunnexio/tunnex-client` release `v0.1.3` contains macOS universal
  PKG, Windows x64 EXE, and SHA256SUMS. Asset names do not prove signing status.

## D1 — Scope: locked by user request and branch context

Expand CLI distribution across standard package channels. Package name is
`tunnex-cli`; installed executable remains `tunnex`. Preserve existing raw asset
names and consumers. The desktop client remains owned by its separate repository;
its store/cask work requires its own packaging and signing audit.

Package installation must not enroll a device, create credentials, start a
tunnel, modify policy, or enable a service. CLI `up/down` currently invokes
host `wg-quick`; document/install suitable platform dependencies. Administrative
commands and tunnel operation have different prerequisites.

## D2 — Channel architecture: locked

Recommended first-party arrangement:

- Public `tunnexio/homebrew-tap` repository for a source-built CLI formula on
  macOS and Linux. Pin the immutable source archive/checksum and Go toolchain
  requirement; compile the CLI submodule with the release version injected.
  This supersedes S15.9 D5's cask-only deferral for the CLI. A desktop cask is
  still subject to its own signing/notarization requirements.
- Public `tunnexio/packages` repository with GitHub Pages for signed APT and
  RPM repository metadata, serving immutable package versions. Asset URLs can
  reference immutable GitHub Release packages where supported and tested.
- Dedicated package-signing identity, fingerprint and narrowly scoped CI
  credentials. Do not reuse the application release descriptor key by assumption.
- Start with GitHub URLs; a future `packages.tunnex.io` domain is optional and
  requires DNS ownership/configuration. Do not document an unprovisioned URL.

Alternative: a managed package repository service for APT/RPM hosting, retention
and signing. This needs an identified account, service choice and cost acceptance.
Tradeoff: GitHub hosting keeps the distribution within the existing organization
but makes metadata generation, signing rotation and retention our responsibility.

User disposition: proceed with the recommended GitHub-based hosting and dedicated
package signing using the existing local GitHub login. Each distribution repository
uses its own GITHUB_TOKEN; a scheduled and manually dispatchable reconciler discovers
public stable upstream releases. This avoids sharing a personal token between repos.
Publication verifies tag/source provenance and keeps package release versions immutable.

## D3 — Coverage and publication stages: locked

| Channel | Deliverable | Completion evidence |
| --- | --- | --- |
| Homebrew macOS/Linux | Source formula in first-party tap | Real brew install/test and exact version |
| Debian/Ubuntu/Mint | DEB plus signed APT index | Clean host apt update/install/upgrade/remove |
| Fedora/RHEL/Rocky/Alma/Amazon Linux | RPM plus signed RPM index | DNF/YUM install/upgrade and signature validation on supported versions |
| openSUSE | RPM, validated with zypper | Native dependency and repository install proof |
| Alpine | APK and signed index or source recipe | apk installation, signature and musl-host smoke proof |
| Arch/Manjaro | PKGBUILD/.SRCINFO, optional package archive | makepkg/install proof; AUR account for submission |
| NixOS/Nix | Reproducible package expression | nix build/check; upstream nixpkgs review for listing |
| Other Linux | Static amd64/arm64 archives and checksums | Extract/version/help on declared supported systems |

Architecture scope starts with existing amd64/arm64. Do not claim all Linux
distributions, ARM32, RISC-V, or all historical releases without actual proof.
Use a pinned nFPM version for native packages while retaining the current Go
build/release owner rather than replacing the whole workflow with GoReleaser.
Uploading a DEB/RPM is not equivalent to publishing an APT/YUM repository.

Homebrew core, Debian/Ubuntu archives, Fedora, Alpine, AUR and nixpkgs inclusion
are independently maintained channels. First-party publication can precede those
submissions; submitted is not accepted/published.

Snap requires a confinement investigation for host networking and wg-quick, plus
publisher ownership/review where applicable. Flatpak is not the first delivery
path for this host-networking CLI. Winget/Scoop/Chocolatey and a desktop Homebrew
cask belong in a client follow-up after native behavior and signing are verified;
the current Windows desktop release does not prove a supported Windows CLI.

## D4 — Release integrity and retries: locked

Build/package/test on PRs without publication credentials. Attach package assets
to the guarded draft before it becomes public. Publish repository indexes and
tap updates only after the immutable stable release succeeds. Keep downstream
channel publication independently retryable without overwriting release assets.
Serialize index updates, refuse accidental version downgrades, retain older
versions, and verify each referenced checksum before promotion. Missing signing
credentials must fail explicitly, never publish unsigned indexes as success.
APT uses a scoped Signed-By keyring; RPM checks signatures. Key rotation needs
documented overlap and operator recovery. No trusted=yes or gpgcheck=0 guidance.

## Acceptance and stop conditions

1. Commit this decision record before workflow/product code, after disposition.
2. Test package contents, architecture, executable mode, version, dependencies,
   absence of credentials/service side effects, and clean uninstall behavior.
3. Exercise checksum/signature tampering refusal and retry/downgrade paths.
4. Run applicable local gates and review the final release workflow; story-end
   multi-finder review findings are ranked and held for user disposition.
5. Publish from a new immutable release after explicit merge sign-off, then
   prove anonymous installs using each documented package-manager command.
6. Store walk evidence during the walk. Cross-compilation or metadata inspection
   is only a SUBSTITUTE for native package installation, triggered by channel
   launch readiness. Do not label untested channels supported.

The entry audit made no external changes. Implementation is now authorized.
Existing upstream v0.1.25 will not be modified; derived packages are published in
the separate packages repository against verified upstream release bytes.

## References

- https://github.com/tunnexio/tunnex/releases/tag/v0.1.25
- https://github.com/tunnexio/tunnex/actions/runs/34094731790
- https://github.com/tunnexio/tunnex-client/releases/tag/v0.1.3
- https://docs.brew.sh/How-to-Create-and-Maintain-a-Tap
- https://nfpm.goreleaser.com/docs/quick-start/
- https://wiki.debian.org/DebianRepository/UseThirdParty
- https://wiki.archlinux.org/title/Arch_User_Repository
- https://github.com/NixOS/nixpkgs/blob/master/CONTRIBUTING.md
- https://snapcraft.io/docs/explanation/security/classic-confinement/
