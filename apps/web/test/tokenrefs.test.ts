import { describe, expect, it } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { stripCssComments, stripJsComments } from "./support/source";

const HERE = dirname(fileURLToPath(import.meta.url));

// ⛔ EVERY `var(--tnx-*)` MUST NAME A TOKEN THAT EXISTS.
//
// THE DEFECT THIS CLOSES, found on a founder's screen and not by any gate. `NodeLink` rendered
// `fill="var(--tnx-accent-500)"`. There is no `--tnx-accent-500` — the token is `--tnx-accent`. CSS does not
// error on an undefined custom property: `var()` with no fallback resolves to the *initial* value, so the
// fill silently became BLACK. Two enormous black discs on a dark panel.
//
// ⚠ AND IT HAD BEEN SHIPPING SINCE S14.3 IN A SECOND PLACE: the Donut's `neutral` slice used
// `var(--tnx-ink-600)`, which also does not exist. Every neutral slice on the Overview — a screen already
// reviewed and approved — has been rendering black.
//
// WHY NOTHING CAUGHT IT:
//   · tsc          a string is a string
//   · 438 tests    jsdom does not resolve custom properties, and none asserted colour
//   · the build    Tailwind never sees an arbitrary `var()` inside a JSX attribute
//   · the gallery  a black disc on a near-black panel looks like a deliberate dark dot
//
// THE CLASS: A TYPO IN A STRING THAT THE PLATFORM TREATS AS VALID. The same shape as the pf-anchor
// double-escape and the `NET :=` default — no error anywhere, just a silently wrong result.

function walk(dir: string, out: string[] = []): string[] {
  for (const e of readdirSync(dir)) {
    const p = join(dir, e);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (/\.(ts|tsx|css)$/.test(e)) out.push(p);
  }
  return out;
}

const SRC = join(HERE, "../src");
const TOKENS = join(HERE, "../../../packages/shared/generated/tokens.css");

function definedTokens(): Set<string> {
  const css = stripCssComments(readFileSync(TOKENS, "utf8"));
  return new Set(css.match(/--tnx-[a-z0-9-]+(?=\s*:)/g) ?? []);
}

function referencedTokens(): Map<string, string[]> {
  const refs = new Map<string, string[]>();
  for (const f of walk(SRC)) {
    const body = stripJsComments(readFileSync(f, "utf8"));
    for (const m of body.matchAll(/var\((--tnx-[a-z0-9-]+)\)/g)) {
      const name = m[1]!;
      refs.set(name, [...(refs.get(name) ?? []), f.replace(SRC, "src")]);
    }
  }
  return refs;
}

describe("⛔ CSS custom-property references are held to the generated token set", () => {
  const defined = definedTokens();
  const referenced = referencedTokens();

  it("the parse is non-trivial — a census over zero tokens cannot fail", () => {
    // Both sides, so neither a broken regex nor an empty source can make this vacuously green.
    expect(defined.size).toBeGreaterThanOrEqual(20);
    expect(referenced.size).toBeGreaterThanOrEqual(3);
  });

  it("every var(--tnx-*) in src names a token that EXISTS", () => {
    const dead = [...referenced.entries()]
      .filter(([name]) => !defined.has(name))
      .map(([name, files]) => `${name}  (${[...new Set(files)].join(", ")})`);
    expect(
      dead,
      `dead token references — CSS resolves these to the INITIAL value (usually black), silently:\n  ${dead.join("\n  ")}`,
    ).toEqual([]);
  });
});
