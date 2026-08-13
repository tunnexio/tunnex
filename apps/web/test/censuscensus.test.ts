import { describe, expect, it } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { stripJsComments } from "./support/source";

// ⛔ THE CENSUS OVER THE CENSUSES.
//
// The rule — *a census over source strips comments first* — was learned three times this epic and
// applied three times by hand, AFTER each check had already been reported green. A rule enforced by
// remembering it is a rule that fails on the fourth instance, and this file exists because there was
// going to be a fourth.
//
// ⚠ AND THE THIRD INSTANCE WAS NOT THE WORST ONE. Retrofitting the rule across the suite found
// `visualgallery.test.ts`, whose assertion is literally named
//
//     "the route is guarded by an env flag, NOT BY A COMMENT"
//
// and which read `App.tsx` raw — so a comment mentioning the flag satisfied it. **The test named the
// exact failure mode it was open to.** Naming a hazard in prose is not a defence against it; that is
// the same shape as writing "I could not reproduce this" in the commit that ships the remedy.
//
// So: any test that reads app source must read it through `./support/source`, or be REGISTERED here
// with a reason. The register is the escape hatch and it is deliberately narrow — an exemption costs
// a sentence that someone else can disagree with.

const TEST_DIR = __dirname;

/**
 * Files that read from disk but are NOT censuses over source, each with why.
 *
 * ⚠ "It reads a path, not a body" is the only reason accepted so far. A file that inspects CONTENT
 * and claims exemption is the case this register exists to make visible.
 */
const EXEMPT: Record<string, string> = {
  "screencensus.test.ts":
    "reads DIRECTORY ENTRIES only (readdirSync over pages/) and never opens a file — there is no body to carry a comment.",
  "censuscensus.test.ts":
    "this file — it reads the test tree itself, and stripping comments from a test would hide the very import it is checking for.",
};

function testFiles(): string[] {
  return readdirSync(TEST_DIR).filter(
    (f) => f.endsWith(".test.ts") || f.endsWith(".test.tsx"),
  );
}

/** Does this test open a file's CONTENTS? `readdirSync` alone is a path read, not a source read. */
function readsSource(body: string): boolean {
  return /\breadFileSync\s*\(/.test(body);
}

describe("⛔ every census over source strips comments first", () => {
  const files = testFiles();

  it("finds the test files at all (vacuity floor)", () => {
    // Without this, a broken glob makes every assertion below pass over an empty list — the exact
    // failure this repo has now filed five times.
    expect(files.length).toBeGreaterThanOrEqual(20);
  });

  it("finds tests that actually read source (vacuity floor)", () => {
    const readers = files.filter((f) =>
      readsSource(readFileSync(join(TEST_DIR, f), "utf8")),
    );
    expect(readers.length).toBeGreaterThanOrEqual(8);
  });

  for (const f of testFiles()) {
    const raw = readFileSync(join(TEST_DIR, f), "utf8");
    if (!readsSource(raw)) continue;
    if (EXEMPT[f]) {
      it(`${f} is registered exempt, and the reason is real`, () => {
        expect(EXEMPT[f]!.length).toBeGreaterThan(40);
        // The one exemption reason accepted: it never opens a body. Assert that, do not trust it.
        if (f !== "censuscensus.test.ts") {
          expect(
            readsSource(raw),
            `${f} claims exemption but calls readFileSync`,
          ).toBe(false);
        }
      });
      continue;
    }

    it(`${f} reads source through the shared stripper`, () => {
      // ⛔ Checked against the STRIPPED body of the test itself: a test that merely MENTIONS
      // support/source in a comment has not imported it. The rule applied to its own enforcement.
      const body = stripJsComments(raw);
      expect(
        /from\s+["']\.\/support\/source["']/.test(body),
        `${f} calls readFileSync but does not import from ./support/source. A raw read makes the ` +
          `census match its own prose: the comment explaining a thing contains the string the ` +
          `census hunts for, so it reports the thing present when only its description is. ` +
          `Import a stripper for the right language, or register an exemption in EXEMPT.`,
      ).toBe(true);
    });
  }
});

describe("the strippers do what they claim", () => {
  it("removes a line comment and a block comment, and keeps a URL", () => {
    const src = [
      '// import.meta.env.VITE_VISUAL_GALLERY === "1"',
      "/* client.html */",
      'const u = "https://tunnex.io/client.html";',
      "const flag = 1;",
    ].join("\n");
    const out = stripJsComments(src);
    expect(out).not.toContain("VITE_VISUAL_GALLERY");
    expect(out).toContain("https://tunnex.io/client.html"); // the mid-line `//` survives
    expect(out).toContain("const flag = 1;");
  });

  it("⛔ a `/*` INSIDE a line comment does not open a phantom block and eat the code below", () => {
    // The exact shape that bit on day two: entry.ts documents itself with the glob
    // `app://tunnex/` + star + `.html` in a `//` comment. Block-first stripping treated that as a
    // block opener, ran to the next close, and swallowed the constant underneath — so a census
    // searching for the constant found ZERO in a file that plainly contains one.
    const src = [
      "// scans for app://tunnex/" + "*" + ".html across the tree",
      "/** doc */",
      'export const CLIENT_ENTRY = "app://tunnex/client.html";',
    ].join("\n");
    expect(stripJsComments(src)).toContain("CLIENT_ENTRY");
    expect(stripJsComments(src)).toContain("app://tunnex/client.html");
  });

  it("⛔ the block stripper is not fooled by a comment that spans the interesting line", () => {
    expect(
      stripJsComments(
        '/*\nloadURL("app://tunnex/client.html")\n*/\nconst x=1;',
      ),
    ).not.toContain("client.html");
  });
});
