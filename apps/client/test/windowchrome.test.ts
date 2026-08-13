import { test } from "node:test";
import assert from "node:assert/strict";
import { windowChrome, WINDOW_BG } from "../src/main/windowchrome";

// ⛔ THE WINDOWS ARM IS THE REASON THIS FILE EXISTS.
//
// `titleBarStyle: "hiddenInset"` is a macOS option. On Windows, Electron falls back to `hidden`:
// no caption, no minimise, NO CLOSE. Asking for a seamless title bar from a macOS screenshot would
// have shipped a Windows window that cannot be closed without Task Manager — on a platform that
// gates merges here (`client (windows-latest)`) and that nobody would have opened before release.
test("⛔ Windows and Linux keep their real title bar — hiddenInset would remove CLOSE", () => {
  for (const p of ["win32", "linux"] as const) {
    const c = windowChrome(p);
    assert.equal(c.titleBarStyle, undefined, `${p} must get the default frame`);
  }
});

test("macOS gets the seamless bar and no title text — the wordmark already says it", () => {
  const c = windowChrome("darwin");
  assert.equal(c.titleBarStyle, "hiddenInset");
  assert.equal(c.title, "");
});

test("⛔ off macOS the title is NOT empty — a nameless window in alt-tab is worse than a duplicate", () => {
  // The duplication the founder removed only exists on macOS, where the wordmark and the title bar
  // are visible at the same time. With a real title bar, an empty title is an unnamed entry in the
  // taskbar and the switcher.
  assert.equal(windowChrome("win32").title, "Tunnex");
});

test("every platform paints a dark background before first paint", () => {
  // Without it the window flashes WHITE on launch — more visible on a dark app than any chrome.
  for (const p of ["darwin", "win32", "linux"] as const) {
    assert.equal(windowChrome(p).backgroundColor, WINDOW_BG);
  }
});
