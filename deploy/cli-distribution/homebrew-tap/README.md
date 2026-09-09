# Tunnex Homebrew tap

Install the CLI on macOS or Linux:

```sh
brew install tunnexio/tap/tunnex-cli
tunnex version
```

Update using `brew update && brew upgrade tunnex-cli`.

This formula compiles the CLI from an immutable upstream source commit, with a
verified archive checksum and exact release version. It installs the `tunnex`
command. For tunnel commands, install `wireguard-tools` separately and configure
a device. Installing the CLI does not enroll a device or start a tunnel.

The update workflow checks stable upstream releases every six hours or on manual
dispatch. It verifies the tag's source marker and successful exact-source CI,
then tests a source install on macOS and Linux before publishing a formula update.
This is a first-party tap, not a homebrew/core listing or a desktop-client cask.

Linux native repositories: https://github.com/tunnexio/packages
