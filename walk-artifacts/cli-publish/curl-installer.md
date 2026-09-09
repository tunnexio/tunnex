# CLI single-command installer acceptance

Source: tunnexio/packages branch cli-curl-installer.
Reviewed head: f6af75d827eb9d2d8480bb1f8162c340777fe4d3.
PR: https://github.com/tunnexio/packages/pull/1
CI: https://github.com/tunnexio/packages/actions/runs/34316455877

Both native AMD64 and ARM64 jobs succeeded. Clean containers installed and
reinstalled through the actual installer using public signed repositories:
Ubuntu 24.04, Debian 12, Fedora 42, Rocky Linux 9, Amazon Linux 2023,
openSUSE Leap 16.0 and Alpine 3.22. Arch Linux passed on AMD64.
The smoke test asserts v0.1.25 from public current.json after both runs.
Linux refusal tests cover modified key bytes, unsupported OS/architecture,
invalid arguments and offline help. ShellCheck and POSIX syntax checks passed.

Initial native failure: Fedora minimal image lacks cmp. SHA equality checks
removed the optional utility dependency; the full final matrix passed.
Two independent reviews found no blocking defects; the SHA-comparison fix and
publication wiring received follow-up review with no blockers.

Limits: no native macOS installer, non-root sudo, legacy YUM or ARM pacman
execution proof. No live tunnel test. Arch performs a full unattended system
upgrade as stated in the README.

Publication: pending explicit merge sign-off. Pages workflow now depends on
native installer checks and copies the reviewed script to install.sh. The URL
https://tunnexio.github.io/packages/install.sh is not claimed live until the
merged workflow deploys it and public-byte verification succeeds.
