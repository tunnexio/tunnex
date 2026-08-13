// Pure notification copy — NO electron import, so it is unit-testable in CI (where
// ELECTRON_SKIP_BINARY_DOWNLOAD makes require("electron") throw). notify.ts consumes
// this and adds the Electron Notification wiring.

// TunnelEvent is the set of tunnel transitions worth a desktop notification. These
// mirror the states the renderer already reacts to (up / down / kill-switch fail /
// revoked) — a revoked device in particular must disconnect LOUDLY, not silently.
export type TunnelEvent = "connected" | "disconnected" | "failed" | "revoked" | "pending" | "approved" | "migrated" | "migrate_retry" | "posture_warning" | "posture_blocked";

// messageFor is the pure copy map. The wording matches the renderer's TunnelControl
// states so the tray/notification and the window agree.
export function postureCheckSummary(checks: Array<{ kind: string; mode: string }> = []): string {
  const labels = [...new Set(checks.map((c) => {
    switch (c.kind) {
      case "disk_encryption":
        return "Disk encryption is not enabled or could not be verified";
      case "os_version":
        return "Your operating system is below your organization's minimum version";
      default:
        return `A required device-health check failed (${c.kind})`;
    }
  }))];
  return labels.join(". ");
}

export function messageFor(ev: TunnelEvent, failedChecks?: Array<{ kind: string; mode: string }>): { title: string; body: string } {
  switch (ev) {
    case "connected":
      return { title: "Tunnex connected", body: "Your VPN tunnel is up." };
    case "disconnected":
      return { title: "Tunnex disconnected", body: "Your VPN tunnel is down." };
    case "failed":
      return {
        title: "Tunnex tunnel failed",
        body: "The kill-switch is active — traffic is blocked until you reconnect or disconnect.",
      };
    case "revoked":
      return { title: "Tunnex device revoked", body: "An administrator revoked this device. Contact them to approve or enroll a replacement." };
    case "pending":
      return { title: "Tunnex — awaiting approval", body: "This device is waiting for an admin to approve it." };
    case "approved":
      return { title: "Tunnex device approved", body: "Your device was approved — click Connect to start the tunnel." };
    case "migrated":
      return { title: "Tunnex device replaced", body: "This device was replaced for a security update — click Connect to finish (a fresh key will be issued)." };
    case "migrate_retry":
      return { title: "Tunnex couldn't replace this device", body: "Reconnect to retry the device update. If it keeps failing, ask an admin to remove the old device." };
    case "posture_warning":
      return {
        title: "Tunnex device posture warning",
        body: `${postureCheckSummary(failedChecks) || "Your device no longer meets a recommended posture check"}. Access is still allowed, but fix it before your organization requires it.`,
      };
    case "posture_blocked":
      return {
        title: "Tunnex blocked by posture policy",
        body: `${postureCheckSummary(failedChecks) || "Your device no longer meets this network's posture requirements"}, so access was blocked. Fix it and it reconnects automatically.`,
      };
  }
}
