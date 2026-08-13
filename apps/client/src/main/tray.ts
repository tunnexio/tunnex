import { readFileSync } from "node:fs";
import { join } from "node:path";
import { app, Tray, Menu, nativeImage, type NativeImage } from "electron";
import { trayIconAssetNamesFor, trayIconVariantFor, trayMenuModel, type TrayState } from "./trayview";

// Re-export the pure view-models so existing imports (`from "./tray"`) keep working;
// the electron-free definitions live in trayview.ts so they stay testable in CI.
export { trayMenuModel, trayStateFor } from "./trayview";
export { trayIconAssetNamesFor, trayIconSizeFor, trayIconSvg, trayIconVariantFor } from "./trayview";
export type { TrayIconVariant, TrayState, TrayMenuModel } from "./trayview";

function trayIcon(state: TrayState): NativeImage {
  const { normal, retina } = trayIconAssetNamesFor(process.platform, trayIconVariantFor(state));
  const trayDir = app.isPackaged
    ? join(process.resourcesPath, "tray")
    : join(__dirname, "..", "..", "build", "tray");
  const normalPath = join(trayDir, normal);
  const retinaPath = join(trayDir, retina);
  const img = nativeImage.createFromPath(normalPath);
  if (img.isEmpty()) throw new Error(`tray_icon_missing: ${normalPath}`);
  // createFromPath reads one representation only. Add the authored 2x PNG explicitly
  // so the small macOS status item stays crisp on Retina displays.
  img.addRepresentation({ scaleFactor: 2, buffer: readFileSync(retinaPath) });
  // This deliberately is NOT a macOS template image: template masking would turn the
  // approved red connected mark into a generic black/white glyph.
  img.setTemplateImage(false);
  return img;
}

// TunnelTray is the menu-bar / system-tray surface. Main-process only; it reuses the
// existing tunnel-control callbacks (no new privileged surface) and is refreshed with
// update(state) from the same status stream the renderer sees, so the two never drift.
export class TunnelTray {
  private tray: Tray | null = null;
  private state: TrayState = "disconnected";

  constructor(
    private readonly actions: {
      onConnect: () => void;
      onDisconnect: () => void;
      onShow: () => void;
      onQuit: () => void;
    },
  ) {}

  // init constructs the OS tray. Separated from the constructor so tests can build
  // the model (trayMenuModel) without an Electron app being ready.
  init(): void {
    if (this.tray) return;
    this.tray = new Tray(trayIcon(this.state));
    this.tray.setToolTip("Tunnex");
    // Clicking the icon shows the window (in addition to the right-click menu).
    this.tray.on("click", () => this.actions.onShow());
    this.render();
  }

  update(state: TrayState): void {
    this.state = state;
    if (this.tray) this.render();
  }

  destroy(): void {
    this.tray?.destroy();
    this.tray = null;
  }

  private render(): void {
    if (!this.tray) return;
    const m = trayMenuModel(this.state);
    this.tray.setImage(trayIcon(this.state));
    const template: Electron.MenuItemConstructorOptions[] = [
      { label: `Tunnex — ${m.statusLabel}`, enabled: false },
      { type: "separator" },
    ];
    if (m.showConnect) template.push({ label: m.showDisconnect ? "Reconnect" : "Connect", click: () => this.actions.onConnect() });
    if (m.showDisconnect) template.push({ label: "Disconnect", click: () => this.actions.onDisconnect() });
    template.push({ type: "separator" }, { label: "Show Tunnex", click: () => this.actions.onShow() }, { label: "Quit", click: () => this.actions.onQuit() });
    this.tray.setContextMenu(Menu.buildFromTemplate(template));
    this.tray.setToolTip(`Tunnex — ${m.statusLabel}`);
  }
}
