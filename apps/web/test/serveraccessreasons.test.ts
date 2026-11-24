import { describe, expect, it } from "vitest";
import { sessionReasonText } from "../src/lib/serverAccessReasons";

describe("Server Access session end reasons", () => {
  it("reads as a sentence for the reasons a session can end with", () => {
    for (const reason of ["revoked", "terminal_closed", "gateway_closed", "editor_closed", "control_plane_restarted", "server_access_disabled", "recording_failed", "recording_quota_reached", "session_expired", "idle_timeout", "mfa_required", "grant_revoked", "parent_logout", "organization_disabled", "gateway_terminal_unavailable", "ssh_connection_failed", "ssh_unreachable", "ssh_authentication_failed", "ssh_host_key_mismatch", "ssh_pty_failed", "editor_authorization_failed"]) {
      const text = sessionReasonText(reason);
      expect(text, reason).not.toContain("_");
      expect(text.endsWith("."), reason).toBe(true);
    }
    expect(sessionReasonText("server_access_disabled")).toMatch(/turned off for this installation/);
  });
  it("falls back to readable words for an unknown code and is empty for none", () => {
    expect(sessionReasonText("some_new_reason")).toBe("Some new reason.");
    expect(sessionReasonText("")).toBe("");
  });
});
