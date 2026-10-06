# Local VS Code access (Tunnex CLI)

Local VS Code access connects VS Code Remote SSH to an enrolled private Linux account through its assigned Tunnex gateway. This is a Tunnex CLI feature, requires software on the local computer, and defaults to off. Tunnex Shield clientless access uses browser terminals and Windows desktops.

## Setup

1. Register and check the Linux server using the existing SSH setup.
2. Enable **Local VS Code access (CLI)** in its server configuration.
3. Grant the user or group access to the required Linux account.
4. Install Visual Studio Code on your Mac or Linux computer (Linux also needs its `code` command).
5. Select **Local VS Code · Requires CLI**, copy the command, and run it locally. The bootstrap installs/updates a dedicated user-local CLI to match this control plane, verifies its SHA256, and installs Remote - SSH if missing. Approve the browser request and complete MFA when prompted.

The CLI adds one managed Include to the user's SSH configuration, preserving existing entries. Each connection uses temporary files with owner-only permissions, an ephemeral SSH identity and strict pinned host verification. For a private control-plane CA, append `--ca /path/to/ca.pem`; TLS verification remains required.

## Security and lifetime

- Existing account grants, recent MFA, server readiness and gateway identity remain required. The approval cannot authorize a different account or server.
- Authorization codes expire after 30 seconds and require PKCE. Connection capabilities are single-use and cannot act as general API credentials.
- The gateway holds the target SSH certificate; the local computer does not receive it. Agent and X11 forwarding are disabled. VS Code forwarding is restricted to loopback services on the selected target.
- Grant revocation, server disablement, parent session invalidation and session expiry close the connection. Idle timeout measures encrypted transport inactivity rather than editor keystrokes.
- **Developer sessions are not recorded**, even when browser terminal recording is enabled. Tunnex audits connection admission, start and end; it does not capture edited files or commands. Administrators should enable this capability only where that visibility is acceptable.

VS Code may install its remote server in the Linux user's home directory. Targets require the enrolled Python 3/OpenSSH environment; file transfer uses the installed OpenSSH SFTP server. Remote internet access or VS Code's local-download transfer fallback may be needed for its first connection.

The initial native launch supports Mac and Linux clients connecting to Linux targets. Windows targets continue to use browser RDP. Expired sessions require fresh browser approval; editor connections do not automatically regain authority after a disconnect.

The bootstrap requires curl, an OpenSSH client, and a SHA256 tool. It uses HTTPS certificate validation and no sudo. Existing global CLI installs are preserved; editor clients are versioned by content digest under `~/.local/share/tunnex/editor-client`. Repeated runs reuse verified bytes. Docker web builds ship macOS/Linux amd64/arm64 clients from the same source. Other static-web deployments must publish those four clients and their `.sha256` files under `/editor-client/`; missing artifacts fail closed. For a private test CA, configure system trust or set `CURL_CA_BUNDLE=/path/to/ca.pem` before running; the bootstrap passes that same CA to the CLI. Never disable TLS verification.
