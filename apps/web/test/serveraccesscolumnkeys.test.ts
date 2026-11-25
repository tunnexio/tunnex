import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { stripCssComments, stripJsComments } from "./support/source";

// SA-UX-4: the Server Access Grants and Sessions tables size columns by column key. A positional width moved
// onto the wrong column once (blank, 40px Started column); this guard keeps positions out and keys honest.
const src = join(__dirname, "..", "src");
const css = stripCssComments(readFileSync(join(src, "server-access-workspace.css"), "utf8"));
const rules = [...css.matchAll(/([^{}]+)\{([^}]*)\}/g)].map((m) => ({ selector: m[1].trim(), body: m[2] }));
const keysOf = (file: string) => new Set([...stripJsComments(readFileSync(join(src, "components", file), "utf8")).matchAll(/\{\s*key:\s*"([a-z_-]+)",\s*header:/g)].map((m) => m[1]));
const tables = [
  { table: ".sa-grants-table", file: "ServerAccountGrants.tsx", sized: ["subject", "status", "expires", "actions"] },
  { table: ".sa-session-table", file: "ServerSessions.tsx", sized: ["user", "status", "recording", "started", "time", "actions"] },
];

describe("Server Access table widths are keyed by column", () => {
  for (const { table, file, sized } of tables) {
    const own = rules.filter((r) => r.selector.includes(table));
    const keys = keysOf(file);
    it(`${table} has no positional column rule`, () => {
      expect(own.length).toBeGreaterThan(0);
      for (const r of own) expect(r.selector).not.toMatch(/:nth-(last-)?(child|of-type)\(/);
    });
    it(`${table} sizes each intended column by a key that ${file} defines`, () => {
      expect(keys.size).toBeGreaterThan(0);
      const named = new Set(own.flatMap((r) => [...r.selector.matchAll(/data-column="([a-z_-]+)"/g)].map((m) => m[1])));
      for (const key of named) expect(keys.has(key), `${table} styles unknown column "${key}"`).toBe(true);
      for (const key of sized) expect(own.some((r) => r.selector.includes(`th[data-column="${key}"]`) && /width:/.test(r.body)), `${table} has no width for "${key}"`).toBe(true);
    });
  }
});
