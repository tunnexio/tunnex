import * as fs from "node:fs";
import * as path from "node:path";
import { app, BrowserWindow, shell, protocol, session, ipcMain, dialog, nativeImage } from "electron";
import { resolveBundlePath, looksLikeAsset, contained } from "./bundle";
import { contentTypeFor } from "./mime";
import { cspFor } from "./csp";
import { Config } from "./config";
import { buildCredentialStore, buildTunnelConfigStore } from "./store";
import { attachBearer } from "./session";
import { registerIpc } from "./ipc";
import { gracefulQuit } from "./quitguard";
import { TunnelTray } from "./tray";
import { initUpdater } from "./updater";
import { setupPageDataUrl } from "./setup";
import { initLogging, logFilePath, readLogTail } from "./logging";
import { updateStatus } from "./updateview";
import { DESKTOP_DOWNLOAD_PAGE, DESKTOP_RELEASE_ENDPOINT, releaseCheckFor } from "./releaseview";
import { windowChrome } from "./windowchrome";
import { AUTOUPDATE_ENABLED } from "./flags";
import { CLIENT_ENTRY } from "./entry";

// The SPA bundle (apps/web build). Overridable for dev; falls back to the
// packaged resources dir.
function bundleDir(): string {
  return process.env.TUNNEX_BUNDLE_DIR ?? path.join(process.resourcesPath ?? "", "web");
}

// app:// is registered standard + secure so the SPA gets a normal, secure
// origin (fetch/history/etc. behave; not the file:// footgun).
protocol.registerSchemesAsPrivileged([{ scheme: "app", privileges: { standard: true, secure: true, supportFetchAPI: true } }]);

const allowInsecure = process.argv.includes("--allow-insecure-credential-storage");

// APP-LEVEL, not per-window. On macOS the app OUTLIVES the window (window-all-closed
// does not quit on darwin; the tray keeps it alive), so the tunnel, its monitor, the
// IPC handlers (ipcMain is app-global — registering per-window throws "second handler"
// on the second window), the tray, and the stores are all app-lifetime singletons.
// The window is a detachable VIEW: `mainWindow` is the current one (or null when
// closed); IPC/status resolve it dynamically and no-op when it's gone. The VPN keeps
// running with no window — reopening re-attaches and re-reads live status.
let mainWindow: BrowserWindow | null = null;
let allowInsecureStorage = false; // captured from the store at setup for the setup page

function createWindow(config: Config): BrowserWindow {
  // ⛔ SIZED TO THE DESIGN'S CARD, NOT TO A DASHBOARD. 1100x760 was inherited from the days this
  // window loaded the web SPA; the client is a 400px column, so that width was all margin.
  const win = new BrowserWindow({
    // The window IS the card now (see ClientApp): 400 is the design's content width, and there is
    // no outer margin to add to it because there is no page for the card to sit on.
    width: 400,
    // The compact client keeps its primary state, live facts, and one action in
    // view; Settings and Logs own their internal scroll region.
    height: 740,
    // ⛔ SEAMLESS TITLE BAR ON macOS ONLY — see windowchrome.ts. The default draws a grey chrome
    // strip above the content, so a window whose whole point is to be ONE surface arrived with a
    // second one bolted to the top. Hidden-inset keeps the traffic lights and lets the page paint
    // underneath them, and the title text goes because the WORDMARK already says the name.
    //
    // ⛔ On Windows the same option removes the caption entirely — including CLOSE. Decided by a
    // pure function so that arm is tested rather than trusted.
    ...windowChrome(process.platform),
    // ⛔ NOT RESIZABLE. The card is a fixed 400px column; a resize only ever added dead margin, and
    // dragging it narrow clipped the stats grid. A window whose content cannot use the extra space
    // should not offer it.
    resizable: false,
    webPreferences: {
      preload: path.join(__dirname, "../preload/index.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });
  mainWindow = win;
  win.on("closed", () => {
    if (mainWindow === win) mainWindow = null; // drop the ref so nothing sends to a destroyed webContents
  });

  // Navigation lock: the renderer must never leave app:// (a compromised page
  // navigating to an external origin would keep the preload bridge). External
  // links go to the SYSTEM browser; new windows are denied.
  win.webContents.on("will-navigate", (e, url) => {
    if (!url.startsWith("app://")) {
      e.preventDefault();
      if (url.startsWith("http://") || url.startsWith("https://")) void shell.openExternal(url);
    }
  });
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith("http://") || url.startsWith("https://")) void shell.openExternal(url);
    return { action: "deny" };
  });

  // First run (no server configured) → the shell's setup screen; otherwise the
  // SPA served over app://.
  if (!config.getServerUrl()) {
    void win.loadURL(setupPageDataUrl(allowInsecureStorage, allowInsecure));
  } else {
    // ⛔ STEP 3 OF THE MIGRATION. The client used to load the WEB SPA's index.html — the router,
    // the sidebar, the top bar and every dashboard screen, most of it then hidden behind
    // `isDesktop()` branches. That is why the desktop app showed a login page and org settings.
    // The client's own entry mounts four regions, no router, no page.
    //
    // ⚠ AND THIS WAS NOT THE ONLY LOAD SITE — see entry.ts. `ipc.ts` loads the renderer again on
    // the first-run branch of config:setServerUrl, and it was still pointing at the dashboard.
    void win.loadURL(CLIENT_ENTRY);
  }
  return win;
}

// showWindow brings the window forward, recreating it if it was closed (macOS). Used
// by the tray so its "Show Tunnex" always works even after the window was destroyed.
function showWindow(config: Config): void {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.show();
    mainWindow.focus();
    return;
  }
  createWindow(config);
}

app.whenReady().then(() => {
  // ⛔ FIRST, BEFORE ANYTHING CAN FAIL. A logger initialised after the code that crashes records
  // everything except the crash.
  initLogging();

  // ⛔ THE DOCK ICON IN DEVELOPMENT. A PACKAGED app takes its icon from the bundle, so
  // electron-builder's `icon:` covers that — but `electron .` runs inside Electron's OWN bundle and
  // shows Electron's atom, which is what every dev screenshot has been showing. Setting it here
  // costs nothing and makes the dev app look like the product it is.
  //
  // ⚠ BEST-EFFORT AND SILENT ON FAILURE: an icon is not a reason to fail a launch, and the file is
  // absent in the packaged tree by design (it is a build resource, not an app resource).
  if (process.platform === "darwin" && app.dock) {
    try {
      const iconPath = path.join(__dirname, "..", "..", "build", "icon.png");
      if (fs.existsSync(iconPath)) {
        const img = nativeImage.createFromPath(iconPath);
        if (!img.isEmpty()) app.dock.setIcon(img);
      }
    } catch {
      /* cosmetic only */
    }
  }
  const config = new Config();
  // App-lifetime singletons — built ONCE, not per-window.
  const store = buildCredentialStore(allowInsecure);
  const tunnelStore = buildTunnelConfigStore(allowInsecure);
  allowInsecureStorage = store.available();
  // attachBearer registers a webRequest handler on the SHARED default session — must
  // run exactly once (a per-window call would stack duplicate injectors).
  attachBearer(session.defaultSession, () => config.getServerUrl(), store);

  // Serve the SPA bundle over app://. Every response carries a CSP; every path is
  // (a) lexically contained, (b) symlink-resolved and RE-checked for containment
  // (fs.readFile follows links), and (c) only extension-less paths fall back to
  // index.html — an asset 404 stays a 404 (never HTML masquerading as a script).
  protocol.handle("app", (request) => {
    const csp = cspFor(config.getServerUrl());
    const htmlHeaders = { "content-type": "text/html; charset=utf-8", "content-security-policy": csp };
    // ⛔ THE FALLBACK IS THE CLIENT ENTRY, NOT index.html (S14.20 step 4). It served the DASHBOARD's
    // entry for any extension-less path — which was right while the client loaded that dashboard and
    // is now both wrong and impossible: `index.html` is no longer packaged. An extension-less path
    // in this app can only be "/", and "/" means the client.
    const serveIndex = () => {
      const entry = resolveBundlePath(bundleDir(), "/" + CLIENT_ENTRY.split("/").pop());
      if (entry && fs.existsSync(entry)) return new Response(fs.readFileSync(entry), { headers: htmlHeaders });
      return new Response("not found", { status: 404 });
    };

    const url = new URL(request.url);
    // /api/* is NEVER in the bundle — if it reaches app:// the desktop transport
    // switch was inert (no server configured), so 404 rather than masking the
    // misconfig by serving index.html as a "200".
    if (url.pathname.startsWith("/api/")) {
      return new Response("not found", { status: 404, headers: { "content-security-policy": csp } });
    }
    const file = resolveBundlePath(bundleDir(), url.pathname);
    if (!file || !fs.existsSync(file)) {
      return looksLikeAsset(url.pathname) ? new Response("not found", { status: 404, headers: { "content-security-policy": csp } }) : serveIndex();
    }
    // Symlink re-check: resolve the real paths of BOTH the file and the root and
    // confirm the file is still in-bundle (fs.readFile follows links).
    let real: string;
    let realRoot: string;
    try {
      real = fs.realpathSync(file);
      realRoot = fs.realpathSync(bundleDir());
    } catch {
      return new Response("not found", { status: 404 });
    }
    if (!contained(realRoot, real)) {
      return new Response("forbidden", { status: 403 });
    }
    return new Response(fs.readFileSync(real), { headers: { "content-type": contentTypeFor(real), "content-security-policy": csp } });
  });
  initUpdater();

  // IPC handlers + tunnel controls: registered ONCE. They resolve the live window via
  // the getter (null-safe) so a closed window never breaks the tunnel, and vice versa.
  // Troubleshooting verbs. Verb-specific like the rest of the allowlist — `openLogs` reveals the
  // file in the OS file manager rather than reading it into the renderer, so the log never crosses
  // into a page and cannot be exfiltrated by one.
  ipcMain.handle("diag:logPath", () => logFilePath());
  ipcMain.handle("diag:openLogs", () => {
    shell.showItemInFolder(logFilePath());
  });
  ipcMain.handle("diag:readLog", () => readLogTail());
  // ⛔ THE VERSION IS THE ONE UPDATE FACT THAT IS REAL TODAY. It is also the first thing any support
  // conversation asks for, and until now the client could not tell you its own.
  ipcMain.handle("diag:appInfo", () => ({
    version: app.getVersion(),
    // `build.publish` is null in package.json — there is no release channel to query — so the
    // feed is reported as absent rather than assumed present.
    update: updateStatus(AUTOUPDATE_ENABLED, false),
  }));
  // Manual update discovery stays main-process owned. The renderer has no ability to choose an
  // endpoint or a destination URL: a compromised client page cannot turn this into an open redirect.
  ipcMain.handle("diag:checkRelease", async () => {
    try {
      const response = await fetch(DESKTOP_RELEASE_ENDPOINT, { headers: { Accept: "application/json" } });
      if (!response.ok) return { kind: "unavailable", reason: "Tunnex could not reach the desktop release service." };
      return releaseCheckFor(app.getVersion(), await response.json());
    } catch {
      return { kind: "unavailable", reason: "Tunnex could not reach the desktop release service." };
    }
  });
  ipcMain.handle("diag:openReleaseDownload", () => shell.openExternal(DESKTOP_DOWNLOAD_PAGE));
  // Export writes a COPY the user chooses the location of. The save dialog is a main-process API on
  // purpose: the renderer never learns a filesystem path it did not already have.
  ipcMain.handle("diag:exportLog", async () => {
    const res = await dialog.showSaveDialog({
      title: "Export Tunnex client log",
      defaultPath: `tunnex-client-log.txt`,
      filters: [{ name: "Text", extensions: ["txt", "log"] }],
    });
    if (res.canceled || !res.filePath) return null;
    fs.writeFileSync(res.filePath, readLogTail(Number.MAX_SAFE_INTEGER), "utf8");
    return res.filePath;
  });

  const controls = registerIpc(() => mainWindow, config, store, tunnelStore);

  // Tray: one instance for the app lifetime, subscribed to tunnel state. Its actions
  // target the singleton controls + showWindow (recreates the window if closed).
  const tray = new TunnelTray({
    onConnect: () => void controls.connect(false).catch(() => {}),
    onDisconnect: () => void controls.disconnect().catch(() => {}),
    onShow: () => showWindow(config),
    onQuit: () => app.quit(),
  });
  tray.init();
  controls.subscribe((s) => tray.update(s));
  tray.update(controls.currentState());

  // Graceful quit (S6.8): on a CLEAN exit, bring the tunnel Down BEFORE dying so the
  // helper restores routing + releases the kill-switch instantly — instead of the app
  // vanishing, the helper seeing OnPeerLost, and the internet staying blocked for the
  // dead-man window. Bounded (gracefulQuit's timeout) so a hung helper can't wedge quit.
  // teardownDone gates the REAL exit: EVERY before-quit is prevented until the graceful
  // Down actually completes, so a second Cmd-Q mid-teardown can't bypass it and quit
  // early (which would drop us onto the orphan window — review #2). `quitting` ensures the
  // teardown runs once.
  let quitting = false;
  let teardownDone = false;
  app.on("before-quit", (e) => {
    if (teardownDone) return; // teardown finished → let the app actually exit
    e.preventDefault(); // block EVERY quit attempt until Down completes
    if (quitting) return; // teardown already in flight — just keep blocking
    quitting = true;
    void gracefulQuit(
      () => controls.disconnect(),
      () => {
        teardownDone = true;
        app.quit();
      },
    );
  });

  createWindow(config);

  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow(config);
  });
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});
