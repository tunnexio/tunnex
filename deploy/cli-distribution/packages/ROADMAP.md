# Additional distribution channels

First-party package publication is independent of upstream package inclusion.

- Additional distro versions: openSUSE Leap 16.0 native zypper acceptance has
  passed; add version-specific acceptance for other supported releases as needed.
- AUR: the first-party PKGBUILD/.SRCINFO is generated and tested by CI. Submit
  it under a Tunnex-owned AUR identity; GitHub login does not grant AUR access.
- Upstream nixpkgs: the first-party binary flake is independent. Prepare a
  source recipe with verified vendor hash and maintainer metadata, validate with
  nixpkgs-review, then submit for upstream review.
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
