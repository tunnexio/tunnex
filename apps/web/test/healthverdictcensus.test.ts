import { describe, expect, it } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { stripJsComments } from "./support/source";

// ⛔ THE CENSUS THAT STOPS THE FOURTH INSTANCE.
//
// A revoked gateway rendered the literal word "healthy", in green, on the deployed dashboard. It had been
// fixed twice already — Gateways.tsx at EPIC 11, sitesview.ts at S13.1 — and both fixes were made AT THE SITE
// WHERE THE BUG WAS SEEN, so it returned at the next consumer.
//
// The census that produced S14.21 found SEVEN sites forming a health verdict about a gateway: four guarded
// `revoked`, three did not, and the three that did carried THE SAME LINE COPY-PASTED. A rule restated at each
// site is not enforced, it is remembered.
//
// > **THE VERDICT IS FORMED IN ONE PLACE. A RAW `policy_degraded` READ ANYWHERE ELSE IS A SECOND PLACE.**
//
// ⚠ THIS CENSUS CANNOT CLOSE THE CLASS, ONLY WATCH IT. `policy_degraded` is a generated field and stays
// readable; the widened signature ENABLES correct sourcing and cannot FORCE it. What this test does is make a
// new raw read VISIBLE at the moment it is added, which is the difference between a defect and a decision.

const SRC = join(__dirname, "..", "src");

/** The one module allowed to read the raw signal: it is where the verdict is formed. */
const VERDICT_OWNER = "lib/healthview.ts";

function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((e) => {
    const p = join(dir, e);
    return statSync(p).isDirectory()
      ? sources(p)
      : /\.tsx?$/.test(p)
        ? [p]
        : [];
  });
}

describe("⛔ the gateway health verdict is formed in ONE place", () => {
  const files = sources(SRC);

  it("finds the source tree (vacuity floor)", () => {
    expect(files.length).toBeGreaterThanOrEqual(40);
  });

  it("the verdict owner still exists and still reads the raw signal", () => {
    // If this stops being true the census is pointing at nothing and every assertion below passes free.
    const owner = stripJsComments(
      readFileSync(join(SRC, VERDICT_OWNER), "utf8"),
    );
    expect(owner).toMatch(/policy_degraded/);
    expect(owner).toMatch(/status === "revoked"/);
  });

  it("⛔ NO OTHER MODULE READS policy_degraded RAW — that read is a second verdict", () => {
    // Comments stripped first: the prose explaining this rule quotes the field name, and a census that
    // counted its own explanation would be the shape this repo has filed three times.
    const offenders = files
      .filter((f) => !f.endsWith(VERDICT_OWNER.replace("/", "/")))
      .filter((f) =>
        /\bn(ode)?\.policy_degraded\b/.test(
          stripJsComments(readFileSync(f, "utf8")),
        ),
      )
      .map((f) => f.replace(SRC, "src"));
    expect(
      offenders,
      `these modules read policy_degraded directly instead of calling policyHealthBadge: ` +
        `${offenders.join(", ")}. A raw read bypasses the revoked guard, which is how a decommissioned ` +
        `gateway ends up labelled "healthy". Route it through the verdict, or add it here with a reason.`,
    ).toEqual([]);
  });

  it("⛔ no caller re-states the revoked guard — a restated rule is a remembered one", () => {
    // The three correct sites carried this line verbatim. That was the tell that the callee did not own
    // the rule; if it reappears, the callee has stopped owning it again.
    const restaters = files
      .filter((f) => !f.endsWith(VERDICT_OWNER.replace("/", "/")))
      .filter((f) =>
        /status\s*===\s*"revoked"\s*\?\s*null\s*:\s*policyHealthBadge/.test(
          stripJsComments(readFileSync(f, "utf8")),
        ),
      )
      .map((f) => f.replace(SRC, "src"));
    expect(
      restaters,
      "the revoked guard is being restated at a call site again",
    ).toEqual([]);
  });
});
