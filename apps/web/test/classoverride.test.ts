import { describe, expect, it } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { stripJsComments } from "./support/source";

/**
 * ⛔ A CALLER'S className CANNOT OVERRIDE A CLASS THE COMPONENT ALREADY BAKES IN — it is a coin flip.
 *
 * Tailwind emits one rule per utility. When a component's base contains `w-full` and a caller passes
 * `w-32`, BOTH rules exist and the winner is whichever the generated stylesheet orders LAST — which is
 * source order in the stylesheet, not attribute order in the JSX. So the "override" works or does not
 * depending on the build, and nothing in the type system or the test suite can see it.
 *
 * > **IT FAILS SILENTLY AND ASYMMETRICALLY: the same line can be right in one build and wrong in the next.**
 *
 * Found twice before this test existed — `Button.size` was added for it, and then two posture `<Select>`s
 * shipped `className="w-32"` and rendered FULL WIDTH, turning a three-option choice into something that
 * read as a text field. The fix both times was the same: a real prop that SWAPS the class so only one of
 * them exists.
 *
 * This census is over the class FAMILIES each component bakes in. It is not a general "no className"
 * rule — passing `mt-2` or `text-warn` to a Button is fine, because the base says nothing about either.
 */
const SRC = join(__dirname, "..", "src");

/** Families each component sets on itself. Adding one here without adding a prop is the bug. */
const BAKED: Record<string, string[]> = {
  Select: ["w-"],
  Input: ["w-"],
  Button: ["px-", "py-", "text-"],
};

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((e) => {
    const p = join(dir, e);
    return statSync(p).isDirectory() ? files(p) : /\.tsx?$/.test(p) ? [p] : [];
  });
}

describe("no caller overrides a baked-in utility class", () => {
  it("⛔ EVERY SUCH OVERRIDE IS A COIN FLIP — use the component's own prop", () => {
    const bad: string[] = [];
    for (const f of files(SRC)) {
      // ⚠ ui.tsx DEFINES the bases, so its own occurrences are the subject, not violations.
      if (f.endsWith("ui.tsx")) continue;
      const src = stripJsComments(readFileSync(f, "utf8"));
      for (const [comp, families] of Object.entries(BAKED)) {
        const re = new RegExp(`<${comp}\\b((?:[^>"]|"[^"]*")*?)>`, "gs");
        for (const m of src.matchAll(re)) {
          const cls = /className="([^"]*)"/.exec(m[1])?.[1];
          if (!cls) continue;
          for (const c of cls.split(/\s+/)) {
            if (families.some((fam) => c.startsWith(fam))) {
              bad.push(
                `${f.replace(SRC, "src")}: <${comp} className="…${c}…">`,
              );
            }
          }
        }
      }
    }
    expect(bad).toEqual([]);
  });
});
