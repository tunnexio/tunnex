import { describe, expect, it } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { stripJsComments } from "./support/source";
import tokens from "../../../packages/shared/generated/tokens.palette.json";

/**
 * ⛔ AN INVENTED TAILWIND COLOUR CLASS RENDERS NOTHING, SILENTLY, AND LOOKS LIKE A DESIGN CHOICE.
 *
 * Found the hard way: `bg-surface-1` is not a token. Tailwind emitted no rule for it, so a dropdown panel and
 * the DataTable's sticky header both rendered **fully transparent** — page content showing straight through
 * them, text on text. It shipped, because:
 *
 *  · TypeScript cannot see inside a className string,
 *  · every test passed (jsdom does not apply a stylesheet),
 *  · and the build succeeded — an unknown utility is not an error, it is simply absent.
 *
 * > **THE FAILURE MODE OF A TYPO IN A CLASS NAME IS INVISIBILITY, NOT A CRASH** — and invisibility is the one
 * > outcome no automated check in this repo was looking for.
 *
 * This test reads the GENERATED palette and fails on any colour utility naming a family that does not exist
 * in it. It cannot catch every CSS mistake; it catches the one that has already cost a shipped screen.
 */
const SRC = join(__dirname, "..", "src");

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((e) => {
    const p = join(dir, e);
    return statSync(p).isDirectory() ? files(p) : /\.tsx?$/.test(p) ? [p] : [];
  });
}

// ⚠ `border-b-2` is a WIDTH utility, not a colour — the segment after `border` is a direction. Listing them
// keeps the census over its actual subject; without this it reports a false hit on correct code, and a census
// that cries wolf is one people start ignoring.
const BORDER_SIDES = new Set(["b", "t", "l", "r", "x", "y", "s", "e"]);

// ⚠ Tailwind's OWN palette needs no list here: scoping the census to `ourFamilies` already excludes it.
// The first draft carried a hand-maintained BUILTIN set, which was a second place to keep correct.

describe("colour utilities name real tokens", () => {
  /**
   * ⛔ THE FULL UTILITY, NOT THE FAMILY — and the first version of this test checked the family, which made
   * it VACUOUS AGAINST THE VERY BUG THAT PROMPTED IT. `surface` is a real family, so `bg-surface-1` passed;
   * the shade is where the typo lived. Caught by mutating the fix back out and watching the census stay
   * green, which is the only reason it is not still wrong.
   *
   * > **A GUARD WRITTEN FOR A HAZARD IS NOT A GUARD AGAINST THE HAZARD** — the same law the malformed-peer-key
   * > defect minted, reached from the CSS side.
   */
  const ourFamilies = new Set(Object.keys(tokens.colors));
  const valid = new Set<string>();
  for (const [family, v] of Object.entries(
    tokens.colors as Record<string, unknown>,
  )) {
    if (typeof v === "string") {
      valid.add(family);
      continue;
    }
    for (const shade of Object.keys(v as Record<string, unknown>)) {
      valid.add(shade === "DEFAULT" ? family : `${family}-${shade}`);
    }
  }

  it("⛔ NO COMPONENT USES A COLOUR UTILITY THAT RESOLVES TO NOTHING", () => {
    const bad: string[] = [];
    for (const f of files(SRC)) {
      // ⛔ COMMENTS STRIPPED FIRST. This file's own prose names `bg-surface-1` as the defect it exists to
      // catch, so a raw read would make the census match its own explanation. (The repo's census-census
      // enforces this, and caught it here.)
      const src = stripJsComments(readFileSync(f, "utf8"));
      // ⚠ THE LOOKAHEAD MUST EXCLUDE `-` TOO. Without it the pattern backtracks on `bg-ink-950/80`,
      // matches the prefix `bg-ink`, and reports a false hit on correct code — which it did, on three files,
      // before this character was added.
      for (const m of src.matchAll(
        /\b(?:bg|text|border|ring|from|to|via|fill|stroke)-([a-z]+(?:-[a-z0-9]+)?)\b(?![\w/[-])/g,
      )) {
        const name = m[1];
        const family = name.split("-")[0];
        // ⚠ ONLY UTILITIES WHOSE FAMILY IS OURS. `text-` is overloaded — `text-xl` is a font SIZE, and
        // `border-b` is a side. Validating everything named `text-*` reports 500 false hits, and a census
        // that cries wolf is one people stop reading. Ours is the exact set the palette defines.
        if (!ourFamilies.has(family)) continue;
        if (BORDER_SIDES.has(family)) continue;
        if (!valid.has(name)) bad.push(`${f.replace(SRC, "src")}: ${m[0]}`);
      }
    }
    expect(bad).toEqual([]);
  });
});
