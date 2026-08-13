import log from "electron-log";
import { autoUpdater } from "electron-updater";
import { AUTOUPDATE_ENABLED } from "./flags";

// Auto-update is SCAFFOLDED but INERT until S6.5 signing (AUTOUPDATE_ENABLED,
// pinned false by a unit test). macOS auto-update (Squirrel.Mac) cannot function
// on an unsigned app, and shipping an unsigned auto-updater is a security
// anti-pattern — so the plumbing exists and is wired, but checkForUpdates is
// NEVER called here. S6.5 flips the flag once the certs land and the feed is real.
export function initUpdater(): void {
  autoUpdater.logger = log;
  autoUpdater.autoDownload = false;
  if (!AUTOUPDATE_ENABLED) {
    log.info("auto-update scaffolded but INERT (enabled at S6.5 once signing lands)");
    return;
  }
  // S6.5: set the real feed and enable. Intentionally unreachable until then.
  autoUpdater.checkForUpdatesAndNotify().catch((e) => log.warn("update check failed", e));
}
