import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { stripJsComments } from "./support/source";

// ⛔ AN UNSHIPPED SURFACE MUST BE PROVEN UNSHIPPED, NOT ASSUMED.
//
// The visual gallery is a dev/test-only route behind `VITE_VISUAL_GALLERY`. If that flag ever defaulted on,
// or the guard were removed, a debug surface would ship to every self-hosted install — and nothing else in
// the build would complain, because the route works perfectly.

const app = stripJsComments(
  readFileSync(
    fileURLToPath(new URL("../src/App.tsx", import.meta.url)),
    "utf8",
  ),
);

describe("the visual gallery is build-flagged OFF", () => {
  it("the route is guarded by an env flag, not by a comment", () => {
    expect(app).toMatch(/import\.meta\.env\.VITE_VISUAL_GALLERY === "1"/);
    expect(app).toContain('path="/__visual"');
  });

  it("the flag is NOT set in any committed env file — it is opt-in per build", () => {
    // A default-on flag is the same defect as no flag. This asserts the absence of a committed default.
    for (const f of [".env", ".env.production", ".env.local"]) {
      let contents = "";
      try {
        contents = readFileSync(
          fileURLToPath(new URL(`../${f}`, import.meta.url)),
          "utf8",
        );
      } catch {
        continue; // absent is correct
      }
      expect(contents, `${f} sets the gallery flag`).not.toMatch(
        /VITE_VISUAL_GALLERY\s*=\s*1/,
      );
    }
  });
});
