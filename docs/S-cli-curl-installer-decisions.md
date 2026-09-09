# CLI curl installer

User requested the CP-style single curl command on 2026-09-09.

- Implement a separate POSIX `install.sh` in tunnexio/packages, served at
  https://tunnexio.github.io/packages/install.sh after native test and review.
  Keep the CP entrypoint untouched; do not advertise an unconfigured domain.
- Detect OS/architecture and the supported native package manager. Linux amd64
  and arm64 use existing signed APT, RPM, APK or pacman repositories. macOS
  delegates to the existing Homebrew formula when brew is installed.
- Pin public key bytes in the installer, retain repository/package signature
  enforcement, use HTTPS with download failures fatal. No personal credentials.
- Install only the CLI. No enrollment, tunnel activation or Docker/CP setup.
  Native package-manager upgrades remain the update path.
- Preserve conflicting existing repo configuration by refusing replacement.
  Repeated installation with our exact config is safe. Pacman uses a complete
  system upgrade to avoid unsupported partial upgrades.
- Unknown distributions/architectures fail with an actionable message; do not
  claim literally every Linux system. NixOS/immutable distributions retain their
  documented installation paths. No unverified binary fallback.
- Test native clean-container install/reinstall and key tampering refusal before
  publication; multi-finder review findings are held for user disposition.
