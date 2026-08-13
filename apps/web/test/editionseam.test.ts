import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  ENTERPRISE_PATHS,
  isEnterprisePath,
  isEnterprise,
  gate,
} from "../src/lib/edition";
import { stripYamlComments } from "./support/source";

// ⛔ THE SWEEP, MADE STRUCTURAL.
//
// The edition-vs-failure conflation was fixed once, at one call site, and was STILL LIVE two cards over. A fix
// at a call site does not reach the call sites beside it — only an enumeration finds the rest, and only a
// census keeps the enumeration true.

const spec = stripYamlComments(
  readFileSync(
    fileURLToPath(new URL("../../../openapi/openapi.yaml", import.meta.url)),
    "utf8",
  ),
);

/** Parse the spec the way the sweep did: an operation is enterprise if it says so in its OWN block. */
function specEnterprisePaths(): Set<string> {
  const lines = spec.split("\n");
  const out = new Set<string>();
  let path: string | null = null;
  let inOp = false;
  let buf: string[] = [];
  const flush = () => {
    if (inOp && path) {
      const blk = buf.join("\n");
      // ⛔ WIDENED, S14.5 — AND THE NARROW VERSION MISSED THREE GENUINELY-GATED ENDPOINTS.
      //
      // It was `/summary:.*\(enterprise\)/`, which requires the word ALONE inside its parentheses. The spec
      // does not consistently write it that way:
      //
      //   "Approve a pending device (peer + grants land org-wide within seconds, enterprise)"
      //   "Reject a pending device (revoked, tunnel address freed, enterprise)"
      //   "Self-report device posture facts (owner only; server evaluates, enterprise)"
      //
      // All three call `deviceApprovalEditionRequired()` / gate on `deviceHealthEnabled` in the handler —
      // they are REALLY enterprise — and none was registered, because the parenthetical carried other words.
      //
      // THIS IS THE CENSUS FAILING ITS OWN LAW: *an absence found by one encoding is not an absence.* The
      // instrument built to stop the edition class had the edition class inside it.
      //
      // Now: the word `enterprise` anywhere in the summary, on a word boundary. Wider means occasional false
      // positives, which are visible and cheap (a red naming a path), against silent false negatives, which
      // are the entire failure mode.
      if (
        blk.includes("edition_required") ||
        /summary:.*\benterprise\b/i.test(blk)
      )
        out.add(path);
    }
    inOp = false;
    buf = [];
  };
  for (const l of lines) {
    const p = /^ {2}(\/\S+):\s*$/.exec(l);
    if (p) {
      flush();
      path = p[1]!;
      continue;
    }
    if (/^ {4}(get|post|put|patch|delete):\s*$/.test(l)) {
      flush();
      inOp = true;
      continue;
    }
    if (inOp) {
      if (/^ {4}\S/.test(l) || /^ {2}\S/.test(l)) flush();
      else buf.push(l);
    }
  }
  flush();
  return out;
}

describe("ENTERPRISE_PATHS is held to the SPEC, not to memory", () => {
  const fromSpec = specEnterprisePaths();

  it("the spec parse is non-trivial — a census over zero paths cannot fail", () => {
    expect(fromSpec.size).toBeGreaterThanOrEqual(20);
  });

  it("EVERY enterprise path in the spec is registered here", () => {
    // ⛔ THIS IS THE STRUCTURAL HALF. Add an enterprise endpoint to the spec and this goes red until it is
    // registered — so a new enterprise card cannot reach a screen without passing through the seam.
    const missing = [...fromSpec].filter((p) => !isEnterprisePath(p));
    expect(
      missing,
      `enterprise in the spec but NOT registered:\n  ${missing.join("\n  ")}`,
    ).toEqual([]);
  });

  it("nothing is registered that the spec does not gate — the set must not drift wider either", () => {
    // A set that over-claims is its own defect: it would render an OPEN capability as absent for open-edition
    // orgs, which is the same lie pointing the other way.
    const extra = ENTERPRISE_PATHS.filter((p) => !fromSpec.has(p));
    expect(
      extra,
      `registered but NOT enterprise in the spec:\n  ${extra.join("\n  ")}`,
    ).toEqual([]);
  });
});

describe("gate() — the render decision, taken at the seam", () => {
  const ENT = "/api/v1/organizations/{orgId}/policies";
  const OPEN = "/api/v1/organizations/{orgId}/nodes";

  it("open edition + enterprise endpoint = ABSENT, never failed", () => {
    // The exact defect: the open edition rendered "could not load" IN RED for a feature it was never sold.
    expect(gate("open", ENT, null)).toEqual({ state: "absent" });
    expect(gate("open", ENT, { state: "failed" })).toEqual({ state: "absent" });
  });

  it("UNKNOWN edition is treated as not-enterprise — no flash before /meta answers", () => {
    expect(gate("unknown", ENT, null)).toEqual({ state: "absent" });
  });

  it("enterprise edition passes the real result through", () => {
    expect(gate("enterprise", ENT, { state: "ok", data: 3 })).toEqual({
      state: "ok",
      data: 3,
    });
    expect(gate("enterprise", ENT, { state: "failed" })).toEqual({
      state: "failed",
    });
  });

  it("a NON-enterprise endpoint is never absented, whatever the edition", () => {
    expect(gate("open", OPEN, { state: "failed" })).toEqual({
      state: "failed",
    });
    expect(gate("open", OPEN, { state: "ok", data: 1 })).toEqual({
      state: "ok",
      data: 1,
    });
  });

  it("a still-loading gated call reads as loading, not absent, on enterprise", () => {
    expect(gate("enterprise", ENT, null)).toEqual({ state: "loading" });
  });

  it("isEnterprise treats unknown as NOT enterprise", () => {
    expect(isEnterprise("unknown")).toBe(false);
    expect(isEnterprise("open")).toBe(false);
    expect(isEnterprise("enterprise")).toBe(true);
  });
});
