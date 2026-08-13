import { test } from "node:test";
import assert from "node:assert/strict";

import { CLIENT_ENTRY, postServerUrlAction } from "../src/main/entry";

// ⛔ THIS FILE EXISTS BECAUSE A SOURCE CENSUS FOUND A BUG A SOURCE CENSUS HAD MISSED.
//
// Step 3 flipped the renderer entry from the web dashboard to the client's own page, and reported
// it as a one-line change. There were TWO load sites. The second — `config:setServerUrl` on the
// wasUnset branch — is the FIRST-RUN path: setup screen, server URL, load. It still said
// `index.html`, so a fresh install landed on the web dashboard and only a SECOND launch reached
// the client.
//
// It survived because nothing could run it. `ipc.ts` imports `electron` at module scope, and client
// tests import no Electron at runtime (CI sets ELECTRON_SKIP_BINARY_DOWNLOAD, which makes
// `require("electron")` throw), so `config:setServerUrl` has never been executed by a test.
//
// > **A BRANCH NO TEST CAN REACH IS NOT UNDER-TESTED, IT IS UNTESTED** — and "we have a census over
// > it" is not a substitute, because the census is the instrument that missed it the first time.
//
// So the decision moved into an electron-free module, which is this repo's standing answer to that
// constraint (trayview / notifyview did the same). It can now be RUN rather than scanned.

test("first run LOADS the client entry — reload cannot change origin from the setup data: URL", () => {
  const act = postServerUrlAction(true);
  assert.equal(act.kind, "load");
  assert.equal(act.kind === "load" && act.url, CLIENT_ENTRY);
});

test("⛔ first run does NOT load the web dashboard — the exact regression that shipped", () => {
  const act = postServerUrlAction(true);
  assert.ok(
    act.kind === "load" && !act.url.endsWith("/index.html"),
    "the first-run path is loading the web SPA's index.html again",
  );
  assert.ok(
    act.kind === "load" && act.url.endsWith("/client.html"),
    "the first-run path must load the client's own entry",
  );
});

test("a later URL change RELOADS — it must not re-navigate to the entry", () => {
  // Not a cosmetic difference: a load would discard renderer state on every server-URL edit,
  // where a reload picks up the new auth/config state in place.
  assert.deepEqual(postServerUrlAction(false), { kind: "reload" });
});

test("the entry is an app:// URL — the navigation lock rejects anything else", () => {
  // main/index.ts refuses any navigation that does not start with app://. An entry that failed this
  // would be blocked by the client's own security guard and render as a dead window.
  assert.ok(CLIENT_ENTRY.startsWith("app://"), CLIENT_ENTRY);
});

// ── updates ──────────────────────────────────────────────────────────────────────────────────────
import { canCheckForUpdates, updateStatus } from "../src/main/updateview";
import { compareVersions, releaseCheckFor } from "../src/main/releaseview";
import { AUTOUPDATE_ENABLED } from "../src/main/flags";

test("⛔ this build cannot check for updates, and the reason is the SIGNING one", () => {
  // Squirrel.Mac cannot verify an unsigned app, so an unsigned auto-updater is a remote-code
  // channel with no signature check on the far end. security.test.ts pins the flag false.
  const s = updateStatus(AUTOUPDATE_ENABLED, false);
  assert.equal(s.kind, "disabled");
  assert.equal(canCheckForUpdates(s), false);
  assert.match(s.kind === "disabled" ? s.detail : "", /signed|notariz/i);
});

test("⛔ signing alone is NOT enough — build.publish is null, so there is no feed", () => {
  // The second missing piece, and the one that would still be missing on the day the certs land.
  const s = updateStatus(true, false);
  assert.equal(s.kind, "no_feed");
  assert.equal(canCheckForUpdates(s), false);
});

test("both present is the only state that permits a check", () => {
  assert.equal(canCheckForUpdates(updateStatus(true, true)), true);
});

test("manual release discovery compares rc versions and never trusts malformed data", () => {
  assert.equal(compareVersions("0.3.0-rc17", "0.3.0-rc16"), 1);
  assert.equal(compareVersions("0.3.0", "0.3.0-rc17"), 1);
  assert.deepEqual(releaseCheckFor("0.3.0-rc16", { version: "0.3.0-rc17" }), {
    kind: "available",
    version: "0.3.0-rc17",
  });
  assert.equal(releaseCheckFor("0.3.0-rc17", { version: "not-a-version" }).kind, "unavailable");
});

// ── the setup screen ─────────────────────────────────────────────────────────────────────────────
import { setupPageDataUrl } from "../src/main/setup";

test("⛔ the first-run screen uses the DEFAULT theme, not the violet one", () => {
  // It hardcoded #7c5cff (the `violet` theme's accent) and #0b0b12 — neither is the default, where
  // --tnx-accent is #C9C9C4 and --tnx-bg is #0A0A0A. The first screen a user ever saw was painted
  // from a palette the rest of the product never uses.
  const page = decodeURIComponent(setupPageDataUrl(true, false));
  assert.ok(!/#7c5cff/i.test(page), "the violet accent is still hardcoded on the setup screen");
  assert.ok(!/#0b0b12/i.test(page), "the old page background is still hardcoded");
  assert.match(page, /#0A0A0A/i); // --tnx-bg
  assert.match(page, /max-width:440px/); // the client's card
  assert.match(page, /border-radius:18px/);
});

test("the first-run screen carries the brand and the tagline", () => {
  const page = decodeURIComponent(setupPageDataUrl(true, false));
  assert.match(page, /<svg/, "the mark is missing from the first screen");
  assert.match(page, /Connect Everything\./);
  assert.match(page, /Trust Nothing\./);
});

test("⛔ the insecure-storage warning still reaches the screen it warns about", () => {
  // The restyle must not drop the one thing this page says that is not cosmetic.
  const page = decodeURIComponent(setupPageDataUrl(false, false));
  assert.match(page, /No OS keychain is available/);
  assert.match(page, /allow-insecure-credential-storage/);
});
