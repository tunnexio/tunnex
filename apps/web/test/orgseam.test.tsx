import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { stripJsComments } from "./support/source";

// ⛔ THE ORG SEAM CENSUS (S12.5).
//
// Fourteen files independently fetched `GET /api/v1/organizations` and independently took index zero. They
// did not get there by copy-paste — they got there because **there was nowhere else to get an org from**,
// and each author solved the same problem the same obvious way.
//
// > ## ⛔ **A MISSING SEAM IS NOT A GAP IN THE CODE. IT IS A GAP EVERY FUTURE CALL SITE FALLS INTO,
// > ## EXACTLY LIKE THE FOURTEEN BEFORE IT.**
//
// So the seam alone does not fix this. The seam plus something that notices when a page stops using it does.
//
// ⚠ THE SUBJECT IS THE CAPABILITY, NOT THE STRING. It would be easy — and useless — to grep for `[0]`.
// `[0]` is shape: it appears legitimately all over this codebase (`live[0]`, `ms[0]`, `members[0]`), and a
// page can reintroduce this defect without writing it at all (`.find(() => true)`, `.at(0)`, `.shift()`).
// The capability is **"which organization does this screen act on"**, and there is exactly one legitimate
// answer to it. So the census asks: **who reads the org list?** Anyone who does, other than the seam, is
// answering that question for themselves (docs/laws.md: a census whose subject is a proxy drifts out from
// under it silently).

const WEB_SRC = join(__dirname, "..", "src");

/** Every file that mentions the organizations collection endpoint. */
function filesReadingTheOrgList(): string[] {
  const hits: string[] = [];
  let scanned = 0;

  const walk = (dir: string) => {
    for (const entry of readdirSync(dir)) {
      const p = join(dir, entry);
      if (statSync(p).isDirectory()) {
        walk(p);
        continue;
      }
      if (!/\.tsx?$/.test(p)) continue;
      scanned++;
      // ⛔ STRIPPED, NOT RAW — and the repo's census-of-censuses caught this file reading raw source
      // before a human did. THIS VERY FILE explains the endpoint it hunts for, in prose, several times.
      // A raw read would have matched its own comments and reported `test/orgseam.test.tsx` as a page
      // picking its own organization: the census accusing its own explanation.
      //
      // ⭐ THE GENERAL FORM IS WORSE THAN THE INSTANCE. Any census that greps source will, sooner or
      // later, describe what it looks for — and from that moment it reports the description as the thing.
      const src = stripJsComments(readFileSync(p, "utf8"));
      // The READ of the collection. `POST "/api/v1/organizations"` (create) and every
      // `"/api/v1/organizations/{orgId}/..."` scoped route are different endpoints and are not in scope.
      if (/GET\(\s*\n?\s*"\/api\/v1\/organizations",?\s*\n?\s*\)/.test(src)) {
        hits.push(p.slice(WEB_SRC.length + 1));
      }
    }
  };
  walk(WEB_SRC);

  // ⛔ THE VACUITY FLOOR. A census that scans nothing reports a clean bill of health forever — and this one
  // is a regex away from matching nothing at all if the client's call style changes.
  expect(scanned).toBeGreaterThan(20);
  return hits.sort();
}

// ⭐ THE TWO LEGITIMATE READERS, EACH WITH ITS REASON. Anything else is a page picking its own tenant.
const ALLOWED: Record<string, string> = {
  "lib/useOrg.tsx":
    "IS the seam. Reads the list once for the whole shell and hands out the selected org.",
  "App.tsx":
    "RequireOrg / RequireNoOrg — asks WHETHER you have any organization, never WHICH. It routes the " +
    "onboarding funnel and runs BEFORE the provider mounts, so it cannot read from it.",
  "pages/CreateOrg.tsx":
    "Re-reads after a 201 to confirm read-your-writes before handing off to the shell. It is not " +
    "selecting a tenant to act on; it is verifying the one it just made exists.",
};

describe("the org seam", () => {
  it("is the only thing that reads the organization list", () => {
    const readers = filesReadingTheOrgList();
    const rogue = readers.filter((f) => !(f in ALLOWED));

    expect(
      rogue,
      `⛔ A SCREEN IS PICKING ITS OWN ORGANIZATION.\n\n` +
        `These files read GET /api/v1/organizations directly:\n` +
        rogue.map((f) => `  ${f}`).join("\n") +
        `\n\nWhichever org they choose will NOT follow the switcher, so a user in more than one ` +
        `organization sees this screen bound to a tenant they did not select — silently, and only on ` +
        `this screen. Read \`useOrg()\` instead.\n\n` +
        `If the file genuinely needs the whole list for some other reason, add it to ALLOWED with the ` +
        `reason, so the next reader can tell a decision from an oversight.`,
    ).toEqual([]);
  });

  // ⛔ SET EQUALITY THE OTHER WAY. A stale allowance is indistinguishable from a live one, and an
  // allowance for a file that no longer reads the list would silently permit a future file at that path.
  it("has no stale allowances", () => {
    const readers = new Set(filesReadingTheOrgList());
    const stale = Object.keys(ALLOWED).filter((f) => !readers.has(f));
    expect(
      stale,
      `⚠ ALLOWANCE FOR A FILE THAT NO LONGER READS THE ORG LIST: ${stale.join(", ")}`,
    ).toEqual([]);
  });

  // ⭐ PROVE THE CENSUS REJECTS. Without this, every assertion above is one broken regex away from
  // passing unconditionally, and nobody would know which.
  it("rejects a file that reads the list", () => {
    const readers = filesReadingTheOrgList();
    expect(readers).toContain("lib/useOrg.tsx"); // positive control: the matcher does match real code
    expect(readers).not.toContain("pages/Devices.tsx"); // and it does not match a migrated page
  });
});
