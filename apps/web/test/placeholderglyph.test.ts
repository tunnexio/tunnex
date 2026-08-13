import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { stripJsComments } from "./support/source";

// ⛔ THE EM-DASH IS BANNED AS A PLACEHOLDER GLYPH, AND THAT RULE WAS ALREADY RESOLVED ONCE.
//
// S14.5 (docs/laws.md → WHEN ONE RULE REQUIRES REWRITING THE EXPRESSION OF ANOTHER): `hubsetview` rendered
// `"—"` as an absent-marker under the honesty rule, the copy rule bans the glyph outright, and it resolved to
// `"n/a"` — because an em-dash "is not READ as 'we have no value' by anyone who has not been told that it
// means that. It reads as a dash, as a minus, or as NOTHING AT ALL to a screen reader."
//
// ⛔ IT REGRESSED ANYWAY, on THREE merged screens, and `Kubernetes.tsx` carried a WRITTEN EXEMPTION for
// exactly the case the law had decided. That law's own closing line predicted it: "the reflex in that moment
// is to claim an exemption for the older rule."
//
//   A RULE RESOLVED IN PROSE REGRESSED IN CODE. THIS TEST IS THE DIFFERENCE.
//
// SCOPE, deliberately narrow: only the em-dash used AS A VALUE — `? "—"`, `?? "—"`, `: "—"`, `{"—"}`. Prose
// em-dashes inside sentences are a SEPARATE obligation (the global sweep + lint rule at EPIC 14 close,
// docs/DEFERRAL-REGISTER.md) and are NOT this test's business. Conflating them is what let a resolved rule
// ride an unresolved one's schedule.
//
// One intentionally visible exception exists: the desktop client's labelled connection-metrics table uses
// `—` for an unavailable measurement. This was a founder-approved desktop convention: it preserves the
// fixed telemetry grid without inventing a number, and every row has its metric label plus an icon. It is
// not available to arbitrary product surfaces.

const SRC = join(__dirname, "..", "src");

function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((e) => {
    const p = join(dir, e);
    return statSync(p).isDirectory()
      ? walk(p)
      : p.endsWith(".ts") || p.endsWith(".tsx")
        ? [p]
        : [];
  });
}

// The em-dash standing alone as a rendered VALUE. Comments are stripped first: `postureview.ts` documents a
// past fix by quoting the old code, and a guard that fails on its own changelog teaches people to delete
// the changelog.
const AS_A_VALUE = /(\?\?|\?|:)\s*"—"|\{\s*"—"\s*\}|>\s*—\s*</;
const CLIENT_METRICS = join(SRC, "client", "ClientApp.tsx");
const APPROVED_CLIENT_METRIC_VALUE = /value: .*"—"|(?:stats|displayStats)\.rate === null \? "—"/;

describe("the em-dash is never a placeholder value", () => {
  const files = walk(SRC);

  it("scans a non-trivial number of files (vacuity floor)", () => {
    // Without this the test passes the day `walk` breaks, reporting "no violations" about zero files.
    expect(files.length).toBeGreaterThan(50);
  });

  it("⛔ no source file renders an em-dash as a value outside labelled client metrics", () => {
    const offenders: string[] = [];
    for (const f of files) {
      const src = stripJsComments(readFileSync(f, "utf8"));
      src.split("\n").forEach((line, i) => {
        if (
          AS_A_VALUE.test(line) &&
          !(f === CLIENT_METRICS && APPROVED_CLIENT_METRIC_VALUE.test(line))
        )
          offenders.push(`${f.replace(SRC, "src")}:${i + 1}  ${line.trim()}`);
      });
    }
    expect(offenders).toEqual([]);
  });
});
