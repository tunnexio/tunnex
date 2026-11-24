// Plain sentences for Server Access session end reasons (the API keeps the codes).
const reasons: Record<string, string> = {
  revoked: "The session was ended from Tunnex.",
  terminal_closed: "The terminal was closed.",
  gateway_closed: "The gateway closed the connection.",
  editor_closed: "The editor connection was closed.",
  editor_authorization_failed: "The editor sign-in could not be completed.",
  control_plane_restarted: "The Tunnex control plane restarted, so open sessions were ended.",
  server_access_disabled: "Server Access was turned off for this installation by a server administrator.",
  recording_failed: "The session recording failed, so the session was closed.",
  recording_quota_reached: "The recording storage limit was reached, so the session was closed.",
  session_expired: "The session reached its maximum length.",
  idle_timeout: "The session ended after a period without input.",
  mfa_required: "MFA verification expired during the session.",
  grant_revoked: "The access grant was removed or expired.",
  parent_logout: "The user signed out.",
  parent_session_expired: "The user's sign-in expired.",
  organization_disabled: "Server Access was turned off for this organization.",
  membership_changed: "The user's organization membership or role changed.",
  server_disabled: "The server was turned off in Server Access.",
  server_authority_changed: "The server's settings changed.",
  gateway_terminal_unavailable: "The gateway stopped running Server Access.",
  gateway_authority_changed: "The gateway for this server changed.",
  ssh_connection_failed: "The SSH connection failed.",
  ssh_unreachable: "The server could not be reached from the gateway.",
  ssh_authentication_failed: "SSH authentication failed for this account.",
  ssh_host_key_mismatch: "The server's SSH host key did not match the pinned fingerprint.",
  ssh_pty_failed: "The server refused to open a terminal for this account.",
};

export function sessionReasonText(reason: string): string {
  if (!reason) return "";
  const known = reasons[reason];
  if (known) return known;
  const words = reason.replace(/_/g, " ");
  return `${words.charAt(0).toUpperCase()}${words.slice(1)}.`;
}
