// Plain sentences (and a next step) for every Server Access reason code the API or gateway can return.
// The API keeps the codes; the UI never shows them (SA-UX-2 item 8). The Go test
// TestEveryServerAccessCodeHasWebText reads this file and fails when the API or gateway emits a code missing here.
type Reason = { text: string; next?: string };

const reasons: Record<string, Reason> = {
  // Session end reasons
  revoked: { text: "The session was ended from Tunnex." },
  terminal_closed: { text: "The terminal was closed." },
  gateway_closed: { text: "The gateway closed the connection.", next: "Connect again. If it keeps happening, check the gateway on the Gateways page." },
  editor_closed: { text: "The editor connection was closed." },
  editor_authorization_failed: { text: "The editor sign-in could not be completed.", next: "Start the editor connection again." },
  control_plane_restarted: { text: "The Tunnex control plane restarted, so open sessions were ended.", next: "Connect again." },
  server_access_disabled: { text: "Server Access is turned off for this installation.", next: "A server administrator can turn it on in Settings → Server Access." },
  recording_failed: { text: "The session recording failed, so the session was closed.", next: "Check recording storage in Server Access settings, then connect again." },
  recording_quota_reached: { text: "The recording storage limit was reached, so the session was closed.", next: "An administrator can raise the limit or shorten retention in Server Access settings." },
  session_expired: { text: "The session reached its maximum length.", next: "Connect again to start a new session." },
  idle_timeout: { text: "The session ended after a period without input.", next: "Connect again to start a new session." },
  mfa_required: { text: "Two-factor verification is needed for this action.", next: "Verify with your authenticator app, or set one up, and try again." },
  grant_revoked: { text: "Your access grant for this account was removed or has expired.", next: "Ask an administrator to grant access again." },
  parent_logout: { text: "You signed out, so this session ended." },
  parent_session_expired: { text: "Your sign-in expired.", next: "Sign in again and reconnect." },
  organization_disabled: { text: "Server Access is turned off for this organization.", next: "An organization administrator can turn it on in Settings → Features." },
  membership_changed: { text: "Your organization membership or role changed.", next: "Reload the page and sign in again if needed." },
  server_disabled: { text: "This server is turned off in Server Access.", next: "An administrator can enable it on the server's Accounts step." },
  server_authority_changed: { text: "This server's settings changed.", next: "Close the terminal and connect again." },
  gateway_terminal_unavailable: { text: "The gateway for this server is not running Server Access right now.", next: "Check that the gateway is online and up to date on the Gateways page." },
  gateway_authority_changed: { text: "The gateway for this server changed.", next: "Close the terminal and connect again." },
  authority_unavailable: { text: "Tunnex could not confirm access for this session, so it was closed.", next: "Connect again." },
  // Gateway → server results (account checks, sessions, setup)
  ssh_connection_failed: { text: "The SSH connection to the server failed.", next: "Check that the server is running and try again." },
  ssh_unreachable: { text: "The gateway could not reach the server.", next: "Allow TCP from the gateway to the server's SSH port in the server's firewall or cloud security rules, then run the check again." },
  ssh_authentication_failed: { text: "The server refused the SSH sign-in for this account.", next: "Run SSH setup or account sync again so the server trusts Tunnex certificates for this account." },
  ssh_host_key_mismatch: { text: "The server's SSH host key did not match the one Tunnex verified.", next: "Confirm the server was not replaced, then run SSH setup again." },
  ssh_host_key_unverified: { text: "The server's SSH host key could not be verified against the one-time authorization. Nothing was saved.", next: "Prepare setup again. If the server uses a non-default SSH host key, use Advanced: verify the host key independently." },
  ssh_pty_failed: { text: "The server refused to open a terminal for this account.", next: "Check that the account has a login shell." },
  setup_failed: { text: "Setup on the server failed before Tunnex received a reason.", next: "On the server, run sudo journalctl -t tunnex-browser-ssh -n 20 to see what setup reported. Setup needs Linux with Python 3, OpenSSH and systemd; unsupported distributions and enforcing SELinux are refused." },
  // Target setup refusals (SA-UX-3). The control plane's job message for each equals `text next` exactly
  // (TestSetupErrorMessagesMatchWebText).
  setup_not_root: { text: "Setup on the server did not run as root.", next: "Prepare setup again and run the one-time authorization command with sudo." },
  setup_unsupported_os: { text: "Automatic SSH setup supports only Linux servers.", next: "For a Windows server, register it as Windows · RDP instead." },
  setup_unsupported_distro: { text: "This Linux distribution is not supported by automatic SSH setup.", next: "Supported families: Ubuntu, Debian, RHEL, Fedora, CentOS, Rocky Linux, AlmaLinux and Amazon Linux." },
  setup_no_systemd: { text: "The server does not run systemd, which automatic SSH setup needs.", next: "Use a systemd-based Linux server." },
  setup_missing_systemctl: { text: "The server is missing systemctl, which setup needs.", next: "Install systemd on the server, then prepare setup again." },
  setup_missing_ssh_keygen: { text: "The server is missing ssh-keygen, which setup needs.", next: "Install the OpenSSH client tools (for example openssh-client), then prepare setup again." },
  setup_missing_ip: { text: "The server is missing the ip command, which setup needs.", next: "Install iproute2 (iproute on RHEL-family systems), then prepare setup again." },
  setup_no_openssh: { text: "The OpenSSH server is not installed on the server.", next: "Install the distribution's OpenSSH server package (openssh-server), then prepare setup again." },
  setup_selinux_enforcing: { text: "SELinux is enforcing on the server, which Tunnex SSH setup does not support yet. No changes were made.", next: "Use a server without enforcing SELinux; Tunnex never changes SELinux settings for you." },
  setup_unsafe_path: { text: "Setup stopped because a Tunnex SSH file or folder on the server is a symlink or not owned by root. No changes were made.", next: "Inspect /etc/tunnex-browser-ssh, /usr/local/sbin/tunnex-browser-ssh and the tunnex-browser-sshd service unit, fix their ownership, then prepare setup again." },
  setup_existing_setup: { text: "The server has a leftover Tunnex SSH service (tunnex-browser-sshd) without its configuration, so setup stopped. No changes were made.", next: "If it is not in use, run sudo systemctl disable --now tunnex-browser-sshd on the server, delete the unit file that systemctl status tunnex-browser-sshd shows, run sudo systemctl daemon-reload, then prepare setup again." },
  setup_foreign_setup: { text: "The server has Tunnex SSH files that this setup does not manage, so setup stopped. No changes were made.", next: "Inspect /etc/tunnex-browser-ssh, /usr/local/sbin/tunnex-browser-ssh and the tunnex-browser-sshd service on the server. Remove them only if they are not in use, then prepare setup again." },
  setup_identity_differs: { text: "This server is already set up for a different Tunnex server record, organization, SSH port or certificate authority. No changes were made.", next: "If that earlier setup is not in use, run sudo tunnex-browser-ssh remove on the server, then prepare setup again. If only the SSH port differs, set it back in Edit connection." },
  setup_ca_mismatch: { text: "The Tunnex certificate authority on the server does not match this organization's. No changes were made.", next: "If an earlier setup from another organization or control plane is not in use, run sudo tunnex-browser-ssh remove on the server, then prepare setup again." },
  setup_principal_conflict: { text: "An account on the server already has a different Tunnex sign-in rule, so setup stopped. No changes were made.", next: "Inspect /etc/tunnex-browser-ssh/principals on the server. If the earlier setup is not in use, run sudo tunnex-browser-ssh remove, then prepare setup again." },
  setup_ip_mismatch: { text: "The server does not own the private IP registered in Tunnex, so setup stopped to avoid configuring the wrong machine.", next: "Check that the private IP in Edit connection is an address on the server (ip -4 addr), then prepare setup again." },
  setup_port_invalid: { text: "The browser terminal SSH port must be between 1024 and 65535.", next: "Change the SSH port in Edit connection, then prepare setup again." },
  setup_port_in_use: { text: "The browser terminal SSH port is already in use on the server. No changes were made.", next: "Choose a free port in Edit connection (sudo ss -ltnp lists ports in use), then prepare setup again." },
  setup_no_eligible_accounts: { text: "The chosen accounts are not eligible Linux login accounts on the server.", next: "Choose existing non-root login accounts (system and no-login users are excluded), or discover all eligible users, then prepare setup again." },
  setup_too_many_accounts: { text: "The server has more than 16 eligible accounts; Tunnex supports at most 16 per server.", next: "Turn off Discover all eligible login users and select up to 16 accounts, then prepare setup again." },
  setup_service_failed: { text: "The dedicated SSH service on the server did not start or reload, so the changes were rolled back.", next: "On the server, run sudo journalctl -u tunnex-browser-sshd -n 50 to see why, then prepare setup again." },
  setup_authorization_expired: { text: "The one-time authorization expired before setup ran.", next: "Prepare setup again, then click Configure automatically within 15 minutes." },
  setup_installer_mismatch: { text: "The server refused the installer because it did not match the one you authorized. Nothing was run.", next: "Prepare setup again and run the new authorization command." },
  gateway_key_lost: { text: "The gateway restarted and discarded the temporary setup key.", next: "Cancel and prepare setup again." },
  failed: { text: "The check did not complete.", next: "Run the check again." },
  // Refusals (API error codes)
  account_not_allowed: { text: "This account is not registered for this server." },
  account_not_granted: { text: "You do not have access to this account on this server yet." },
  browser_channel_missing: { text: "The browser connection for this session is missing.", next: "Close the terminal and connect again." },
  channel_already_claimed: { text: "This session is already open in another browser tab or window." },
  check_already_completed: { text: "This connection check has already finished.", next: "Run a new check." },
  connection_check_required: { text: "This account has not passed a connection check yet.", next: "Run Check for this account before connecting." },
  developer_access_disabled: { text: "Developer access is not turned on for this server." },
  editor_authorization_invalid: { text: "The editor sign-in is no longer valid.", next: "Start the editor connection again." },
  editor_requires_https: { text: "Editor connections need the console to be served over HTTPS." },
  gateway_binding_mismatch: { text: "This session belongs to a different gateway.", next: "Close the terminal and connect again." },
  gateway_unavailable: { text: "The gateway for this server is offline or not enrolled.", next: "Check Gateways, then try again." },
  host_fingerprint_placeholder: { text: "That fingerprint is Tunnex's placeholder for pending host trust, not a real host key.", next: "Leave it empty and run SSH setup, or enter the fingerprint you verified on the server." },
  host_key_mismatch: { text: "The server's SSH host key does not match the pinned fingerprint.", next: "Verify the server before updating the fingerprint." },
  human_session_required: { text: "Terminal access needs a signed-in person in a browser, not an API token." },
  invalid_ca_binding: { text: "This organization's SSH certificate authority could not be verified.", next: "Contact a server administrator." },
  invalid_editor_identity: { text: "The editor identity could not be verified.", next: "Start the editor connection again." },
  invalid_editor_session: { text: "This editor session is not valid.", next: "Start the editor connection again." },
  invalid_parent_binding: { text: "Your sign-in for this session could not be verified.", next: "Sign in again and reconnect." },
  invalid_recording_event: { text: "The recording received an invalid event, so the session was closed." },
  invalid_terminal_origin: { text: "This terminal must be opened from this console's own address." },
  management_authority_changed: { text: "Your permission to manage Server Access changed.", next: "Reload the page." },
  management_required: { text: "You need permission to manage Server Access for this action." },
  parent_authority_changed: { text: "Your sign-in changed.", next: "Sign in again and reconnect." },
  parent_binding_mismatch: { text: "This session belongs to a different sign-in.", next: "Close the terminal and connect again." },
  rdp_requires_https: { text: "Remote desktop needs the console to be served over HTTPS." },
  recording_archive_integrity_failed: { text: "The archived recording failed its integrity check and cannot be opened." },
  recording_archive_legacy_destination: { text: "This recording was archived to a destination that is no longer supported for this action." },
  recording_archive_not_configured: { text: "Recording archive storage is not configured." },
  recording_archive_session_active: { text: "This session is still running.", next: "Archive it after it ends." },
  recording_disabled: { text: "Recording is not turned on for this session." },
  recording_integrity_failed: { text: "The recording failed its integrity check and cannot be opened." },
  recording_package_unavailable: { text: "This recording package is not available." },
  recording_permission_denied: { text: "You do not have permission to open this recording." },
  recording_storage_unavailable: { text: "Recording storage is unavailable, so the session cannot start or continue.", next: "Check recording storage in Server Access settings." },
  recording_unavailable: { text: "This recording is not available." },
  replay_authority_changed: { text: "Your permission to replay recordings changed.", next: "Reload the page." },
  session_ended: { text: "This session has already ended." },
  session_key_changed: { text: "The session key changed.", next: "Close the terminal and connect again." },
  session_permission_denied: { text: "You can only end your own sessions unless you manage sessions." },
  setup_expired: { text: "The setup job expired.", next: "Start the setup again." },
  ssh_setup_requires_linux: { text: "Automatic SSH setup works only for Linux servers." },
  terminal_capacity_reached: { text: "Too many terminal sessions are open right now.", next: "Close one and try again." },
  user_authority_changed: { text: "Your account changed.", next: "Sign in again and reconnect." },
  invalid_recording_storage: { text: "The recording storage settings are not valid.", next: "Check the values and save again." },
  invalid_server_access: { text: "The request was not valid for Server Access.", next: "Check the values and try again." },
  recording_package_invalid: { text: "This file is not a valid Tunnex recording package." },
  server_access_installation_invalid: { text: "The installation setting could not be saved as entered." },
  disable_before_setup: { text: "This server is enabled.", next: "Disable it before running initial SSH setup." },
  server_access_installation_changed: { text: "Someone else changed this setting.", next: "Reload and try again." },
  server_access_locked: { text: "Server Access is locked off in the control plane's environment settings, so it cannot be turned on here." },
  server_revision_changed: { text: "This server was changed by someone else.", next: "Reload and try again." },
  setup_capacity: { text: "Too many setup jobs are running.", next: "Cancel or wait for one, then try again." },
  setup_in_progress: { text: "A setup job is already running for this server." },
  setup_not_ready: { text: "Setup is not ready yet.", next: "Run the authorization command on the server first." },
  server_access_installation_unavailable: { text: "The installation setting could not be read.", next: "Try again in a moment." },
  server_access_sessions_pending_close: { text: "Active sessions are still closing.", next: "Try again in a few seconds." },
  server_access_not_found: { text: "This item no longer exists.", next: "Reload the page." },
};

/** Every code with UI text; the Go side asserts it covers what the API and gateway emit. */
export const serverAccessReasonCodes = Object.freeze(Object.keys(reasons));

const generic = "Server Access could not complete this action.";

export function serverAccessReason(reason: string): Reason {
  return reasons[reason] ?? { text: generic, next: "Try again. If it keeps happening, contact a server administrator." };
}

/** One sentence plus next step, for places that render plain text. */
export function serverAccessReasonText(reason: string): string {
  if (!reason) return "";
  const r = serverAccessReason(reason);
  return r.next ? `${r.text} ${r.next}` : r.text;
}

export function sessionReasonText(reason: string): string {
  if (!reason) return "";
  return serverAccessReason(reason).text;
}
