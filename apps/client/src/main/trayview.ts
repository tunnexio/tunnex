// Pure tray view-models — NO electron import, so they are unit-testable in CI (where
// ELECTRON_SKIP_BINARY_DOWNLOAD makes require("electron") throw). tray.ts consumes
// these and adds the Electron Tray wiring; the test imports only from here.

// TrayState is the tunnel state the tray reflects. It mirrors the renderer's derived
// state (including handshake-liveness: an interface that is up but has no fresh
// handshake reads "connecting", not "connected") so the tray never disagrees with the
// window, plus the operable states — failed (kill-switch) and revoked.
export type TrayState = "disconnected" | "connecting" | "connected" | "failed" | "revoked" | "pending" | "migrate_retry" | "posture_warning" | "posture_blocked";

// The tray needs an actual brand mark rather than Electron's generic filled-dot
// placeholder. The black rounded badge intentionally has no outer circle: at 16 px a
// second outline crowds the status area and made the mark look off-centre. The authored
// SVG below remains the design source; tray.ts deliberately loads the packaged PNG
// raster instead because NativeImage's SVG data-URL decoding is unreliable in the
// macOS status bar and resulted in a blank icon in RC20.
export type TrayIconVariant = "connected" | "idle";

export function trayIconSizeFor(platform: string): 16 | 20 {
  // Windows' system tray commonly lands at 20 px under its default 125% scaling;
  // macOS (and Linux) expect the compact 16 px status-item footprint.
  return platform === "win32" ? 20 : 16;
}

export function trayIconVariantFor(state: TrayState): TrayIconVariant {
  // A posture warning is still a live connection; every other state is non-live or
  // uncertain and deliberately uses the quiet gray mark.
  return state === "connected" || state === "posture_warning" ? "connected" : "idle";
}

export function trayIconAssetNamesFor(platform: string, variant: TrayIconVariant): { normal: string; retina: string } {
  // macOS consumes a 16pt status-item icon, with a 32px 2x representation. Windows
  // uses a slightly larger 20px tray footprint and therefore has its own 20/40 pair.
  const suffix = platform === "win32" ? "-win" : "";
  return { normal: `${variant}${suffix}.png`, retina: `${variant}${suffix}@2x.png` };
}

export function trayIconSvg(variant: TrayIconVariant, size = 16): string {
  const mark = variant === "connected" ? "#ee1d36" : "#d7d7da";
  const outline = variant === "connected" ? "#49494f" : "#606067";
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 32 32">
  <rect x="5" y="5" width="22" height="22" rx="6" fill="#171719" stroke="${outline}" stroke-width="0.75"/>
  <rect x="10" y="11" width="12" height="3.75" rx="1.15" fill="${mark}"/>
  <path d="M14.25 11h1.6l-1.6 3.75h-1.6Z" fill="#08080a"/>
  <path d="M13 14h6v7.35L16 25.4l-3-4.05Z" fill="${mark}"/>
  <path d="M11.3 13h9.4L16 16.9Z" fill="#08080a"/><path d="M15.35 16.1h1.3v5.55h-1.3Z" fill="#08080a"/>
  <path d="M11.3 13 16 16.9 20.7 13M16 16.9v5.55" fill="none" stroke="#fff" stroke-width="0.72" stroke-linecap="round" stroke-linejoin="round"/>
  <g fill="#fff"><circle cx="11.3" cy="13" r="1.05"/><circle cx="20.7" cy="13" r="1.05"/><circle cx="16" cy="16.9" r="1.05"/><circle cx="16" cy="22.45" r="1.05"/></g>
</svg>`;
}

// HANDSHAKE_STALE_SEC mirrors TunnelControl.tsx: a handshake older than a couple rekey
// windows (or none) means the link isn't live yet — "connecting", not "connected".
const HANDSHAKE_STALE_SEC = 180;

// trayStateFor derives the tray state from a forwarded status, matching the renderer's
// liveness logic so the two never drift. last_handshake_sec is an ABSOLUTE unix
// timestamp (0/absent = never), so age = now - it.
export function trayStateFor(s: { state: string; last_handshake_sec?: number }): TrayState {
  if (s.state === "revoked") return "revoked";
  if (s.state === "pending_approval") return "pending"; // S7.3: awaiting admin approval
  if (s.state === "migrate_failed") return "migrate_retry"; // S7.3: legacy replacement didn't complete
  if (s.state === "posture_warning") return "posture_warning"; // S15.8: warn-mode result while tunnel stays up
  if (s.state === "posture_blocked") return "posture_blocked"; // S7.5.3: server-side require-mode block
  if (s.state === "failed") return "failed";
  if (s.state === "up") {
    const nowSec = Math.floor(Date.now() / 1000);
    const age = s.last_handshake_sec ? Math.max(0, nowSec - s.last_handshake_sec) : null;
    return age != null && age <= HANDSHAKE_STALE_SEC ? "connected" : "connecting";
  }
  return "disconnected";
}

// TrayMenuModel is the view-model behind the tray menu: which status label to show and
// which actions to offer.
export interface TrayMenuModel {
  statusLabel: string;
  showConnect: boolean;
  showDisconnect: boolean;
}

export function trayMenuModel(state: TrayState): TrayMenuModel {
  switch (state) {
    case "connected":
      return { statusLabel: "Connected", showConnect: false, showDisconnect: true };
    case "connecting":
      // Interface up but no fresh handshake yet — offer only Disconnect (cancel).
      return { statusLabel: "Connecting…", showConnect: false, showDisconnect: true };
    case "failed":
      // Failed = kill-switch active. Offer BOTH: reconnect (retry) and disconnect
      // (tear down the kill-switch and go back to normal networking).
      return { statusLabel: "Tunnel failed — kill-switch active", showConnect: true, showDisconnect: true };
    case "revoked":
      // The dead config was already cleared; reconnect re-enrolls a fresh device.
      return { statusLabel: "Device revoked — reconnect to re-enroll", showConnect: true, showDisconnect: false };
    case "pending":
      // S7.3: awaiting admin approval. No connect (already enrolled + waiting); offer
      // disconnect to stop waiting (cancel). The tunnel is NOT up — nothing to tear down.
      return { statusLabel: "Awaiting admin approval…", showConnect: false, showDisconnect: true };
    case "migrate_retry":
      // S7.3: the legacy-config replacement didn't complete. Config was kept, so reconnect
      // retries it — offer connect (retry). Nothing is up, so no disconnect.
      return { statusLabel: "Couldn't replace device — reconnect to retry", showConnect: true, showDisconnect: false };
    case "posture_warning":
      return { statusLabel: "Connected — device posture warning", showConnect: false, showDisconnect: true };
    case "posture_blocked":
      // S7.5.3: a require-mode posture check disconnected the device server-side. The
      // interface is up but the gateway dropped the peer, so traffic is dead. Reconnect
      // won't help (still non-compliant) — the device auto-reconnects on the NEXT report
      // once the posture is fixed (encryption on / OS updated). Offer disconnect to tear
      // down the dead tunnel; no connect (a re-mint doesn't change posture).
      return { statusLabel: "Blocked by device posture policy — fix posture to reconnect", showConnect: false, showDisconnect: true };
    case "disconnected":
      return { statusLabel: "Not connected", showConnect: true, showDisconnect: false };
  }
}
