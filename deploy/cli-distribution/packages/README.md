# Tunnex CLI packages

Official distribution of the [Tunnex CLI](https://github.com/tunnexio/tunnex).
The package is `tunnex-cli`; the command is `tunnex`.

## Installation

### macOS and Linux with Homebrew

```sh
brew install tunnexio/tap/tunnex-cli
```

The [first-party tap](https://github.com/tunnexio/homebrew-tap) builds the CLI from
verified source. It does not require an Apple Developer ID certificate.

### Debian and Ubuntu (APT)

```sh
curl -fsS https://tunnexio.github.io/packages/tunnex.asc -o /tmp/tunnex.asc
gpg --show-keys --with-fingerprint /tmp/tunnex.asc
# Compare the fingerprint with keys/FINGERPRINT in this repository.
sudo install -m 644 /tmp/tunnex.asc /usr/share/keyrings/tunnex.asc
printf '%s\n' 'deb [signed-by=/usr/share/keyrings/tunnex.asc] https://tunnexio.github.io/packages/apt stable main' | sudo tee /etc/apt/sources.list.d/tunnex.list
sudo apt-get update
sudo apt-get install tunnex-cli
```

### Fedora, Rocky, AlmaLinux, RHEL and Amazon Linux (DNF/YUM)

```sh
sudo tee /etc/yum.repos.d/tunnex.repo >/dev/null <<'REPO'
[tunnex]
name=Tunnex CLI
baseurl=https://tunnexio.github.io/packages/rpm
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://tunnexio.github.io/packages/tunnex.asc
REPO
sudo dnf install tunnex-cli
# On systems using YUM: sudo yum install tunnex-cli
```

Verify the displayed key fingerprint against `keys/FINGERPRINT` before accepting.

### openSUSE (zypper)

```sh
curl -fsS https://tunnexio.github.io/packages/tunnex.asc -o /tmp/tunnex.asc
gpg --show-keys --with-fingerprint /tmp/tunnex.asc
# Compare the fingerprint with keys/FINGERPRINT before importing.
sudo rpm --import /tmp/tunnex.asc
sudo zypper addrepo --refresh https://tunnexio.github.io/packages/rpm tunnex
sudo zypper refresh tunnex
sudo zypper install --from tunnex tunnex-cli
```

### Alpine Linux (APK)

```sh
wget -q https://tunnexio.github.io/packages/tunnex.rsa.pub -O /tmp/tunnex.rsa.pub
# Compare sha256sum /tmp/tunnex.rsa.pub with keys/APK-SHA256SUMS.
sudo install -m 644 /tmp/tunnex.rsa.pub /etc/apk/keys/tunnex.rsa.pub
echo https://tunnexio.github.io/packages/alpine | sudo tee -a /etc/apk/repositories
sudo apk update
sudo apk add tunnex-cli
```

### Arch Linux (pacman)

```sh
curl -fsS https://tunnexio.github.io/packages/tunnex.asc -o /tmp/tunnex.asc
# Inspect and compare the fingerprint with keys/FINGERPRINT first.
sudo pacman-key --add /tmp/tunnex.asc
sudo pacman-key --lsign-key 9A565661A108388E34E4D9C6A0C5B3B1D39A8181
sudo tee -a /etc/pacman.conf >/dev/null <<'REPO'
[tunnex]
SigLevel = Required DatabaseRequired
Server = https://tunnexio.github.io/packages/arch/$arch
REPO
sudo pacman -Syu tunnex-cli
```

ARM64 artifacts target Arch Linux ARM, not upstream Arch's x86_64 distribution.

### Nix / NixOS

```sh
nix --extra-experimental-features 'nix-command flakes' profile install github:tunnexio/packages#tunnex-cli
tunnex version
```

The first-party flake supports x86_64-linux and aarch64-linux. It wraps the
verified static upstream CLI binary with a pinned checksum and package-set
revision; it is separate from an upstream nixpkgs listing.

### Build the Arch recipe locally

```sh
git clone --depth 1 https://github.com/tunnexio/packages.git tunnex-packages
cd tunnex-packages/aur/tunnex-cli-bin
makepkg -si
```

Use a regular user with Arch's build prerequisites installed. The recipe and
`.SRCINFO` are tested before publication. This is a first-party recipe, not an
AUR listing; no `yay`/AUR package availability is implied.

### Other Linux systems

[Release archives](https://github.com/tunnexio/packages/releases/latest) contain
static amd64 and arm64 executables. Verify `SHA256SUMS.asc` against the published
key, then `sha256sum --check SHA256SUMS` for downloaded release files. Extract the
matching tarball and install `tunnex` into a directory on your PATH.

## Use and updates

```sh
tunnex version
tunnex login --server https://YOUR_CONTROL_PLANE
```

Normal package-manager upgrades update the CLI. Installation/removal does not
enroll or revoke devices, change credentials, or start/stop a tunnel. Existing
configuration is retained on uninstall. For `tunnex up/down`, separately install
`wireguard-tools` and meet the host's WireGuard, routing, DNS and privilege
requirements. Kubernetes operations also have their own prerequisites.

## Verification scope

CI installs and removes packages on Ubuntu 24.04, Debian 12, Fedora 42,
Rocky Linux 9, Amazon Linux 2023, openSUSE Leap 16.0, Alpine 3.22 and Arch Linux containers, executing version/help.
Nix builds and profile installs also pass on native AMD64/ARM64; the Arch
recipe is built and installed with makepkg on AMD64. These checks prove package
installation, not live VPN/tunnel operation or every distro version.
Other compatible distributions and ARM64 packages require corresponding host
acceptance before fleet rollout. These are first-party repositories, not claims
of inclusion in Debian, Ubuntu, Fedora, Alpine, AUR or other upstream indexes.
Upstream nixpkgs, AUR, Snap and Windows store submissions are tracked separately in ROADMAP.md.

## Publication and recovery

The workflow checks every six hours and can be dispatched manually. It verifies
the upstream stable tag, source marker, exact successful tag CI, and binary
checksums. Packages are signed, installed in clean containers and tested before
publication. A new public release in this repository stores derived packages;
upstream releases are never rewritten. Existing package releases are verified and
reused on retry. Pages indexes are rebuilt from all retained package releases.

Repository storage stops at 800 MiB rather than silently deleting old versions.
Migrate package storage before that threshold or the GitHub Pages limits are
reached. CI releases are serialized and refuse version downgrades. A failed Pages
deployment is retried by dispatching the workflow; immutable packages are reused.

Private GPG and APK signing keys are separate repository Actions secrets. Public
keys and fingerprints are committed under `keys/`. The GPG key expires in three
years. Rotate before expiry: publish old and new public keys, update verification
and client trust documentation, then switch signing only after the overlap has
been distributed. Keep old keys to verify retained releases. Compromise requires
revocation and explicit client trust replacement; do not disable signature checks.

Changes to release scripts require review. Local GitHub credentials are never
stored in this repository or copied to workflow secrets.
