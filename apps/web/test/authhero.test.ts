import { describe, expect, it } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import {
  FORBIDDEN_CLAIMS,
  GENERIC_202_NOTE,
  HERO_HEADLINE,
  MESH_NODES,
  TRUST_BADGES,
  recoveryCountLabel,
  recoveryWarning,
} from "../src/lib/authhero";
import { stripJsComments } from "./support/source";

// ⛔ THE WIREFRAME'S TRUST BADGES ASSERTED TWO THINGS WE DO NOT HAVE, ON THE MOST-VIEWED PAGE.
//
//   "SOC 2 Type II certified"  — MEASURED: zero mentions of SOC 2 anywhere in this repository
//                                outside the wireframe. No audit, no report, no auditor.
//   "SSO + SCIM enterprise ready" — SCIM is explicitly OUT of v1, deferred to S7.5.2b (D4).
//
// A claim on a login page is a product surface, and the render floor applies to it: do not state
// more than the system can support. This is the same test the epic applied to its own headline.
/** Remove // and block comments so the scan judges rendered text, not documentation about it. */

describe("TRUST_BADGES", () => {
  it("⛔ makes no compliance claim we cannot evidence", () => {
    const all = TRUST_BADGES.map((b) => b.text)
      .join(" | ")
      .toLowerCase();
    for (const c of FORBIDDEN_CLAIMS) {
      expect(all, `badge set must not claim ${c}`).not.toContain(
        c.toLowerCase(),
      );
    }
  });

  it("⛔ the forbidden set is not empty and names SOC 2 and SCIM specifically", () => {
    // Vacuity floor: an empty forbidden list would make the assertion above pass against anything.
    expect(FORBIDDEN_CLAIMS.length).toBeGreaterThanOrEqual(5);
    expect(FORBIDDEN_CLAIMS).toContain("SOC 2");
    expect(FORBIDDEN_CLAIMS).toContain("SCIM");
  });

  it("every badge carries the reason it is TRUE", () => {
    // A future edit then has to defeat an argument rather than delete a string.
    expect(TRUST_BADGES.length).toBeGreaterThan(0);
    for (const b of TRUST_BADGES) expect(b.why.length).toBeGreaterThan(25);
  });

  it("⛔ no forbidden claim appears anywhere in the app source", () => {
    // The badge list is not the only place a claim can be typed. This is the census half: a string
    // asserting compliance must not exist in ANY rendered source, however it got there.
    const SRC = join(__dirname, "..", "src");
    const files: string[] = [];
    const walk = (d: string) => {
      for (const e of readdirSync(d)) {
        const p = join(d, e);
        if (statSync(p).isDirectory()) walk(p);
        else if (p.endsWith(".ts") || p.endsWith(".tsx")) files.push(p);
      }
    };
    walk(SRC);
    expect(files.length).toBeGreaterThan(20); // floor: an empty walk proves nothing
    const offenders: string[] = [];
    for (const f of files) {
      // ⛔ COMMENTS ARE STRIPPED, FILES ARE NOT EXEMPTED.
      //
      // This first ran and caught AuthLayout.tsx, on the comment EXPLAINING the cut. The tempting
      // fix was another file exemption — and an exemption list is how a census quietly becomes the
      // codebase. A claim in a comment is not rendered and not a claim; a claim in a string is.
      // So strip comments and keep every file in scope, which leaves the census strict about the
      // thing that actually reaches a user.
      // authhero.ts DECLARES the forbidden strings as data — the list cannot scan itself.
      if (f.endsWith("authhero.ts")) continue;
      const body = stripJsComments(readFileSync(f, "utf8"));
      for (const c of FORBIDDEN_CLAIMS) {
        if (new RegExp(`\\b${c.replace(/\s/g, "\\s*")}\\b`, "i").test(body)) {
          offenders.push(`${f.replace(SRC, "src")} :: ${c}`);
        }
      }
    }
    expect(offenders).toEqual([]);
  });
});

describe("the hero copy", () => {
  it("carries the design's headline and its six mesh nodes", () => {
    expect(HERO_HEADLINE).toBe("Connect everything. Trust nothing.");
    expect(MESH_NODES).toHaveLength(6);
    expect(MESH_NODES).toContain("Kubernetes");
    expect(MESH_NODES).toContain("On-prem");
  });

  it("⛔ states the generic-202 as a property, not as reassurance", () => {
    expect(GENERIC_202_NOTE).toMatch(/whether or not an account exists/i);
    expect(GENERIC_202_NOTE).toMatch(/neither confirms nor denies/i);
  });
});

// ⛔ CARDINALITY ONLY — the schema says "never the codes (nothing recoverable)".
describe("recoveryWarning", () => {
  it("is silent above the threshold — a warning that always shows is not a warning", () => {
    expect(recoveryWarning(10)).toBeNull();
    expect(recoveryWarning(4)).toBeNull();
  });

  it("warns quietly at 3 and loudly at the last one", () => {
    expect(recoveryWarning(3)?.loud).toBe(false);
    expect(recoveryWarning(1)?.loud).toBe(true);
    expect(recoveryWarning(1)?.text).toMatch(/last one/i);
  });

  it("⛔ says what happens at zero, rather than just that it is zero", () => {
    const w = recoveryWarning(0);
    expect(w?.loud).toBe(true);
    expect(w?.text).toMatch(/administrator/i); // the way out, named
  });

  it("the count line always says the codes are not re-shown", () => {
    expect(recoveryCountLabel(2)).toMatch(/never re-shown/i);
    expect(recoveryCountLabel(1)).toMatch(/^1 recovery code /); // singular
  });
});
