// SA-UX-3: host trust for a registered server. The control plane stores a placeholder for a Linux server whose
// trust is pending SSH setup; it is never a real fingerprint, never shown and never sent as a pin.
import type { components } from "@tunnex/shared";

type Server = components["schemas"]["ServerAccessServer"];

/** Older control planes returned this placeholder for pending servers; treat it as "no pin". */
export const PENDING_HOST_FINGERPRINT = `SHA256:${"A".repeat(43)}`;

/** The server's real pinned fingerprint, or "" when trust is pending or unknown. */
export function pinnedFingerprint(server?: Pick<Server, "host_fingerprint">): string {
  const value = server?.host_fingerprint?.trim() ?? "";
  return value === PENDING_HOST_FINGERPRINT ? "" : value;
}

/** A Linux server with no accounts and no real pin is waiting for SSH setup. */
export function hostTrustPending(server: Pick<Server, "host_fingerprint" | "os" | "accounts">): boolean {
  return (server.os ?? "linux") === "linux" && server.accounts.length === 0 && !pinnedFingerprint(server);
}

/** Why an entered fingerprint cannot be pinned, or "" when it can. */
export function fingerprintProblem(value: string): string {
  const fp = value.trim();
  if (fp === PENDING_HOST_FINGERPRINT) return "That is Tunnex's placeholder for pending host trust, not a real fingerprint.";
  if (!/^SHA256:[A-Za-z0-9+/]{43}$/.test(fp)) return "Enter the fingerprint as SHA256: followed by 43 characters, exactly as ssh-keygen prints it.";
  return "";
}
