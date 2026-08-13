import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { BRAND_WORDMARK_SVG } from "../src/main/brandmark";

// ⛔ THE ONE THING THAT MAKES A DUPLICATED ASSET ACCEPTABLE.
//
// The first-run screen is a data: URL built before any bundle exists, so it cannot import from
// apps/web/src/assets. The mark is therefore copied into brandmark.ts — and a copied asset that
// nothing compares is a second logo that will differ from the first on the day someone re-exports
// one of them, in a screen nobody looks at twice.
// ⛔ LINE ENDINGS ARE NOT CONTENT, AND THIS GUARD FAILED ON WINDOWS FOR SAYING THEY WERE.
//
// The first version compared the two byte-for-byte. It passed on macOS and failed on
// `client (windows-latest)`, because git checks the `.svg` out with CRLF there while the embedded
// TypeScript string is LF — so the test was reporting a difference in **checkout policy** as a
// difference in **artwork**.
//
// > **A DRIFT CHECK MUST COMPARE THE THING THAT CAN DRIFT.** Byte-identity is the strictest
// > comparison available and it was the wrong one: it is strict about something the repository
// > deliberately varies per platform, which makes it noisy where it should be silent and says
// > nothing extra where it matters.
const eol = (s: string) => s.replace(/\r\n/g, "\n");

test("the embedded mark matches the asset it was copied from, modulo line endings", () => {
  const asset = readFileSync(
    join(__dirname, "..", "..", "web", "src", "assets", "tunnex-wordmark.svg"),
    "utf8",
  ).trim();
  assert.equal(
    eol(BRAND_WORDMARK_SVG),
    eol(asset),
    "apps/client/src/main/brandmark.ts has drifted from apps/web/src/assets/tunnex-wordmark.svg — " +
      "re-copy it rather than editing one of the two.",
  );
});
