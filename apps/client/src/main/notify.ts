import { Notification } from "electron";
import { messageFor, type TunnelEvent } from "./notifyview";

// Re-export the pure copy so existing imports (`from "./notify"`) keep working; the
// electron-free definition lives in notifyview.ts so it stays testable in CI.
export { messageFor } from "./notifyview";
export type { TunnelEvent } from "./notifyview";

// notifyTunnel shows a native notification for a tunnel event. A no-op where the OS
// has no notification support (headless CI, unsupported desktop).
export function notifyTunnel(ev: TunnelEvent, failedChecks?: Array<{ kind: string; mode: string }>): void {
  if (!Notification.isSupported()) return;
  new Notification(messageFor(ev, failedChecks)).show();
}
