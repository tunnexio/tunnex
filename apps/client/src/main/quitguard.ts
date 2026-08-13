// gracefulQuit runs a BOUNDED graceful teardown before the app process exits.
//
// Why (S6.8): on a clean quit — Cmd-Q, tray Quit, or the last window closing on
// non-macOS — the app must tell the helper to come Down FIRST, so the helper restores
// normal routing + releases the kill-switch immediately. If the app just dies instead,
// the helper only sees its owner IPC socket drop (Supervisor.OnPeerLost), fails closed,
// and holds the block for the dead-man window — blackholing the user's internet for
// seconds after a deliberate quit. Calling disconnect() closes that gap to ~instant.
//
// It is bounded by timeoutMs so a hung/again-crashed helper can NEVER block quit, and it
// swallows any disconnect error (sync throw or rejection) — quit must always proceed.
// Pure + electron-free so it is unit-tested without the Electron runtime (CI makes
// `require("electron")` throw).
export function gracefulQuit(
  disconnect: () => Promise<void>,
  quit: () => void,
  timeoutMs = 3000,
): Promise<void> {
  // Promise.resolve().then(disconnect) converts a SYNC throw from disconnect into a
  // rejection so the .catch below always neutralizes it.
  const down = Promise.resolve()
    .then(disconnect)
    .catch(() => {});
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<void>((resolve) => {
    timer = setTimeout(resolve, timeoutMs);
  });
  // clearTimeout in finally so a fast happy-path disconnect doesn't leave the timer
  // pending for the full timeoutMs (a dangling handle that keeps the event loop alive).
  return Promise.race([down, timeout]).finally(() => {
    if (timer !== undefined) clearTimeout(timer);
    quit();
  });
}
