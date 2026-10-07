# Standalone CLI publishing

Beam publishers can use the Tunnex desktop client or the standalone `tunnex` binary. Reviewers continue to use their browser. The CLI connector opens outbound TLS connections and does not need Electron, Node.js, an active VPN, or a privileged VPN helper.

This implementation is local and unreleased. Existing published installers must not be advertised as containing these commands until a release includes them. Build the feature checkout with the repository's Go toolchain:

```sh
cd apps/cli
go build -o /tmp/tunnex-beam ./cmd/tunnex
```

Use the existing login flow against your control plane:

```sh
/tmp/tunnex-beam login --server https://cp.example.com
# For a terminal without a browser:
/tmp/tunnex-beam login --device --server https://cp.example.com
```

The device flow prints a URL and code for approval in a signed-in browser. It does not require the desktop client. Production uses a trusted HTTPS control plane; local HTTP development uses the existing development endpoint only.

Publishers can generate a ready-to-run command in **Beam → My shares → Publish using CLI**. Enter the local HTTP port, app name and link lifetime, select permitted users or groups by name, then choose **Generate command → Copy command**. The copied block includes `tunnex login --server` for the current control plane, followed by `&&` and the publish command. Complete browser sign-in with your publisher account; publishing starts only if login succeeds. Organization and reviewer UUIDs are inserted automatically. Run the command on the computer hosting the app; command generation itself does not publish or change access.

**Include login command** is selected by default. If already signed in to this control plane with your publisher account, turn it off to generate only the publish command. Signing in again replaces the local CLI login and stops shares running under the previous login.

The form uses the same audience as the CLI. In restricted mode, an administrator allows particular publisher groups and reviewer users/groups. In **Settings → Beam sharing policy → Open for all users**, every eligible member of this organization may publish and select any eligible organization user or group by name. Explicit share grants are still required; open mode does not give every member access to every app. Reviewers only need a signed-in browser. Publishers must keep the CLI or desktop client and local app running. Existing policies remain restricted until an administrator enables open mode. Turning it off restores the retained allowlists and reviews the effect on existing shares and sessions before saving.

Consumers use **Shared with me**, which lists active and paused shares. Stopped, expired and revoked shares are omitted before pagination. Publisher history stays available in **My shares**.

For a terminal-only workflow, find the organization id in your existing account and select explicit permitted reviewers. Beam must already be enabled for your publisher group, and its serving domain must pass DNS/TLS readiness:

```sh
/tmp/tunnex-beam beam policy --org ORGANIZATION_UUID
/tmp/tunnex-beam beam audience --org ORGANIZATION_UUID
/tmp/tunnex-beam beam publish \
  --org ORGANIZATION_UUID \
  --port 3000 \
  --name "Checkout review" \
  --duration 1h \
  --reviewer-user REVIEWER_UUID
```

Replace the uppercase placeholders with real UUIDs. Repeat `--reviewer-user` or `--reviewer-group` for multiple permitted reviewers. The CLI prints the HTTPS link after the connector is admitted and the local app is ready. Keep both the terminal process and local app running. Ctrl+C closes the connector and attempts to stop that exact share; an unavailable control plane can leave it offline until expiry or an explicit stop.

The default target is HTTP on `127.0.0.1`. IPv6 loopback uses `--address ::1`. A local HTTPS origin uses `--protocol https`; an additional local CA can be supplied with `--origin-ca /path/to/ca.pem`. Certificates must match the numeric loopback IP. Remote hosts and LAN destinations are refused.

| Command | Behavior |
| --- | --- |
| `beam list --org UUID` | List shares available to the current publisher; `--offset` pages results. |
| `beam get --org UUID --share UUID` | Show current state, expiry and the safe URL projection. |
| `beam pause --org UUID --share UUID` | Withdraw serving while retaining the share and its expiry. |
| `beam resume --org UUID --share UUID` | Run the original local target in the foreground using its original publishing credential. |
| `beam stop --org UUID --share UUID` | End the share permanently. |
| `beam extend --org UUID --share UUID --expires-at RFC3339` | Explicitly extend within the current policy and original lifetime ceiling. |

Resume does not extend expiry or accept a replacement target. A fresh login by the same user is a different source credential and cannot take over the original connector. Use a new share when the original credential is unavailable. Logging out, replacing the active credential, expired authority, pause/revocation, or loss of control-plane authority closes serving. Connector keys stay in process memory.

The installer/operator dependencies are shared with desktop Beam: a reachable control plane, a qualified Beam proxy, wildcard DNS and trusted HTTPS for the random share hostnames, and organization publishing policy. A publisher whose group is already authorized can publish without asking an administrator for each link. CLI publishing does not add anonymous or external guest access.

## Local qualification

The dedicated local stack and an isolated `TUNNEX_STATE_DIR` are used for CLI acceptance. Normal device approval, real connector/browser access and termination evidence are recorded in [the qualification matrix](BEAM-local-qualification.md). Packaged CLI installation and platform runtime acceptance remain release checks.
