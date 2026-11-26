import { describe, expect, it } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { stripJsComments } from "./support/source";
import { BEAM_AUDIT_ACTIONS, beamActionLabel } from "../src/lib/beam";
import { BEAM_ACTION_FAMILY, auditActionLabel, auditActionQuery } from "../src/lib/auditview";

// LS-UX-4 P26: "Local Sharing activity" is every beam.* action, whatever its target type
// (policy, project and installation changes are not beam_share targets), and each one reads as words.
describe("Local Sharing audit family", () => {
  it("is sent as action_prefix and labelled", () => {
    expect(BEAM_ACTION_FAMILY).toBe("beam.*");
    expect(auditActionQuery(BEAM_ACTION_FAMILY)).toEqual({ action_prefix: "beam." });
    expect(auditActionLabel(BEAM_ACTION_FAMILY)).toBe("All Local Sharing activity");
    expect(auditActionLabel("beam.policy.updated")).toBe("Sharing policy changed");
  });
});

describe("Local Sharing audit labels cover every action the API writes", () => {
  it("has a label for each beam.* action in the API and its migrations", () => {
    const api = join(__dirname, "..", "..", "api");
    const dir = join(api, "internal", "beam");
    const go = readdirSync(dir).filter(name => name.endsWith(".go") && !name.endsWith("_test.go")).map(name => join(dir, name));
    const sql = readdirSync(join(api, "db", "migrations")).filter(name => name.endsWith(".up.sql")).map(name => join(api, "db", "migrations", name));
    const written = new Set<string>();
    for (const file of [...go, ...sql]) {
      const raw = readFileSync(file, "utf8");
      const text = file.endsWith(".go") ? stripJsComments(raw) : raw.replace(/--.*$/gm, "");
      // Literal actions ('beam.project.saved' in SQL strings) and the audit helper, which prefixes "beam.".
      for (const match of text.matchAll(/['"`](beam\.[a-z_]+(?:\.[a-z_]+)*)['"`]/g)) written.add(match[1]);
      for (const match of text.matchAll(/\baudit\(ctx, tx, [\w.]+, [\w.]+, "([a-z_]+\.[a-z_]+)"/g)) written.add(`beam.${match[1]}`);
      // Dynamic suffixes: "share."+in.Action (lifecycle actions) and "share."+state (background endings).
      if (/"share\."\+in\.Action/.test(text)) for (const match of text.matchAll(/case "([a-z_]+)":/g)) if (["pause", "resume", "stop", "extend"].includes(match[1])) written.add(`beam.share.${match[1]}`);
      // Only the assignments in the block that ends with that audit call (the background sweep).
      const sweep = text.indexOf('"share."+state');
      if (sweep >= 0) for (const match of text.slice(Math.max(0, sweep - 1500), sweep).matchAll(/\bstate = "([a-z_]+)"/g)) written.add(`beam.share.${match[1]}`);
    }
    expect(written.size).toBeGreaterThanOrEqual(15);
    for (const action of written) expect(BEAM_AUDIT_ACTIONS).toContain(action);
    for (const action of BEAM_AUDIT_ACTIONS) {
      expect(action.startsWith("beam.")).toBe(true);
      expect(beamActionLabel(action)).toMatch(/^[A-Z]/);
      expect(auditActionLabel(action)).toBe(beamActionLabel(action));
    }
  });
});
