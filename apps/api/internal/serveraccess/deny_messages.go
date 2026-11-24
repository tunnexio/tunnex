package serveraccess

// denyMessages turns refusal codes into sentences people can act on. The code stays the API error code
// (clients match on it); only the message is human. Every literal deny("...") must appear here
// (TestEveryDenyReasonHasAPlainSentence).
var denyMessages = map[string]string{
	"account_not_allowed":                  "This account is not registered for this server.",
	"account_not_granted":                  "You do not have current access to this account on this server. Ask an administrator for a grant.",
	"browser_channel_missing":              "The browser connection for this session is missing. Close the terminal and connect again.",
	"channel_already_claimed":              "This session is already open in another browser tab or window.",
	"check_already_completed":              "This connection check has already finished. Run a new check.",
	"connection_check_required":            "Run a connection check for this account before connecting.",
	"developer_access_disabled":            "Developer access is not turned on for this server.",
	"editor_authorization_invalid":         "The editor sign-in is no longer valid. Start the editor connection again.",
	"editor_requires_https":                "Editor connections need the console to be served over HTTPS.",
	"gateway_authority_changed":            "The gateway for this server changed. Close the terminal and connect again.",
	"gateway_binding_mismatch":             "This session belongs to a different gateway. Close the terminal and connect again.",
	"gateway_terminal_unavailable":         "The gateway for this server is not running Server Access right now. It may be offline or running an older agent, or its operator turned Server Access off on that gateway (TUNNEX_SERVER_ACCESS_ENABLED=false on the gateway, or TUNNEX_GATEWAY_SERVER_ACCESS_ENABLED=false in Docker Compose).",
	"gateway_unavailable":                  "The gateway for this server is offline or not enrolled. Check Gateways, then try again.",
	"grant_revoked":                        "Your access grant for this account was removed or has expired.",
	"host_key_mismatch":                    "The server's SSH host key does not match the pinned fingerprint. Verify the server before updating the fingerprint.",
	"human_session_required":               "Terminal access needs a signed-in person in a browser, not an API token.",
	"idle_timeout":                         "The session ended after a period without input.",
	"invalid_ca_binding":                   "This organization's SSH certificate authority could not be verified. Contact a server administrator.",
	"invalid_editor_identity":              "The editor identity could not be verified. Start the editor connection again.",
	"invalid_editor_session":               "This editor session is not valid. Start the editor connection again.",
	"invalid_parent_binding":               "Your sign-in for this session could not be verified. Sign in again and reconnect.",
	"invalid_recording_event":              "The recording received an invalid event, so the session was closed.",
	"invalid_terminal_origin":              "This terminal must be opened from this console's own address.",
	"management_authority_changed":         "Your permission to manage Server Access changed. Reload the page.",
	"management_required":                  "You need permission to manage Server Access for this action.",
	"membership_changed":                   "Your organization membership or role changed. Reload the page and sign in again if needed.",
	"mfa_required":                         "Verify MFA to continue.",
	"organization_disabled":                "Server Access is turned off for this organization. An administrator can turn it on in Settings → Features.",
	"parent_authority_changed":             "Your sign-in changed. Sign in again and reconnect.",
	"parent_binding_mismatch":              "This session belongs to a different sign-in. Close the terminal and connect again.",
	"parent_logout":                        "You signed out, so this session ended.",
	"parent_session_expired":               "Your sign-in expired. Sign in again and reconnect.",
	"rdp_requires_https":                   "Remote desktop needs the console to be served over HTTPS.",
	"recording_archive_integrity_failed":   "The archived recording failed its integrity check and cannot be opened.",
	"recording_archive_legacy_destination": "This recording was archived to a destination that is no longer supported for this action.",
	"recording_archive_not_configured":     "Recording archive storage is not configured.",
	"recording_archive_session_active":     "This session is still running. Archive it after it ends.",
	"recording_disabled":                   "Recording is not turned on for this session.",
	"recording_integrity_failed":           "The recording failed its integrity check and cannot be opened.",
	"recording_package_unavailable":        "This recording package is not available.",
	"recording_permission_denied":          "You do not have permission to open this recording.",
	"recording_quota_reached":              "The recording storage limit was reached, so the session was closed.",
	"recording_storage_unavailable":        "Recording storage is unavailable, so the session cannot start or continue.",
	"recording_unavailable":                "This recording is not available.",
	"replay_authority_changed":             "Your permission to replay recordings changed. Reload the page.",
	"server_authority_changed":             "This server's settings changed. Close the terminal and connect again.",
	"server_disabled":                      "This server is turned off in Server Access.",
	"session_ended":                        "This session has already ended.",
	"session_expired":                      "This session reached its maximum length.",
	"session_key_changed":                  "The session key changed. Close the terminal and connect again.",
	"session_permission_denied":            "You can only end your own sessions unless you manage sessions.",
	"setup_expired":                        "The setup job expired. Start the setup again.",
	"ssh_setup_requires_linux":             "Automatic SSH setup works only for Linux servers.",
	"terminal_capacity_reached":            "Too many terminal sessions are open right now. Close one and try again.",
	"user_authority_changed":               "Your account changed. Sign in again and reconnect.",
}

func denyMessage(reason string) string {
	if m, ok := denyMessages[reason]; ok {
		return m
	}
	return "Terminal access is unavailable. Close the terminal and try again."
}
