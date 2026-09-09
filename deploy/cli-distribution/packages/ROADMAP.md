# Additional distribution channels

First-party package publication is independent of upstream package inclusion.

- openSUSE/zypper: the signed RPM repository is available; run native zypper
  acceptance before documenting a supported install command.
- AUR: prepare and test PKGBUILD/.SRCINFO, then submit under a Tunnex-owned AUR
  identity. A GitHub login does not grant AUR account access.
- Nix/NixOS: build a source recipe with a verified vendor hash, validate with
  nixpkgs-review and submit to nixpkgs. Do not ship a placeholder hash.
- Snap: determine confinement for host wg-quick and routing, obtain publisher
  identity and any required classic-confinement review, then test enrollment and
  tunnel lifecycle before listing.
- Debian/Ubuntu, Fedora and Alpine official archives: submit native packaging
  under their contribution policies after the first-party packages are proven.
- Homebrew core: submit the tested source formula once eligibility is verified.
- Desktop Homebrew cask, Winget, Scoop and Chocolatey: work in tunnex-client,
  verify platform behavior, certificate provenance and installer metadata first.
- Flatpak: investigate only as a desktop-client distribution channel; host network
  integration needs a design and sandbox permissions review.

No upstream submission or store acceptance is implied by the first-party release.
