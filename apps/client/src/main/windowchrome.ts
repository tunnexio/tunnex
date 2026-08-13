/**
 * Window chrome, decided per platform — in an electron-free module so it can be RUN in a test.
 *
 * ⛔ `titleBarStyle: "hiddenInset"` IS A macOS OPTION, AND ON WINDOWS IT WOULD HAVE REMOVED THE
 * WINDOW CONTROLS.
 *
 * Electron treats an unrecognised `titleBarStyle` as `hidden` on Windows: no caption, no minimise,
 * no CLOSE. The app would have opened as a box a user cannot close without Task Manager — on a
 * platform this project ships to and gates merges on (`client (windows-latest)`), and on a machine
 * nobody here would have opened before release.
 *
 * > **A COSMETIC OPTION ON ONE PLATFORM IS A FUNCTIONAL ONE ON ANOTHER.** The seamless title bar was
 * > asked for from a macOS screenshot, and macOS is the only place the request even parses.
 *
 * The decision is a pure function so the Windows arm is asserted rather than assumed — nobody was
 * going to notice this by looking at a `new BrowserWindow({...})` literal.
 */
export type WindowChrome = {
  /** Omitted entirely off macOS — the default frame is what Windows and Linux should get. */
  titleBarStyle?: "hiddenInset";
  /** Painted before the renderer draws; without it a dark app flashes white on launch. */
  backgroundColor: string;
  /** Empty on macOS: the wordmark already says it. Elsewhere the frame is the only place it appears. */
  title: string;
};

/** --tnx-bg. Hardcoded here for the same reason the setup page hardcodes it: no bundle yet. */
export const WINDOW_BG = "#0A0A0A";

export function windowChrome(platform: NodeJS.Platform): WindowChrome {
  if (platform === "darwin") {
    return { titleBarStyle: "hiddenInset", backgroundColor: WINDOW_BG, title: "" };
  }
  // ⚠ TITLE KEPT OFF macOS. With a real title bar, an empty title is a nameless window in the
  // taskbar and the alt-tab switcher — the duplicate the founder removed only exists on macOS,
  // where the wordmark and the title bar are both on screen at once.
  return { backgroundColor: WINDOW_BG, title: "Tunnex" };
}
