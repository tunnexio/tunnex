import { describe, expect, it } from "vitest";
import { mergeOrgForwards } from "../src/lib/dnsview";
import type { DNSForward, Loaded, Site } from "../src/lib/api";

const site = (id: string, name: string): Site =>
  ({
    id,
    name,
    link_transport: "wireguard",
    created_at: "2026-01-01T00:00:00Z",
  }) as Site;

const ok = (rows: DNSForward[]): Loaded<DNSForward[]> => ({
  ok: true,
  data: rows,
});
const fail = (e: string): Loaded<DNSForward[]> => ({ ok: false, error: e });
const fwd = (domain: string, resolver_ip: string) =>
  ({ domain, resolver_ip }) as DNSForward;

describe("⛔ THE ORG-WIDE VIEW EXISTS TO SHOW AN ORG-WIDE INVARIANT", () => {
  it("finds a conflict that NO per-site view could show", () => {
    // Each site's own list is individually valid. The violation only exists BETWEEN them, which is why the
    // per-site rendering this replaces could never surface it.
    const v = mergeOrgForwards([
      { site: site("a", "eu-lan"), res: ok([fwd("*.corp", "10.1.0.53")]) },
      { site: site("b", "ap-lan"), res: ok([fwd("*.corp", "10.2.0.53")]) },
    ]);
    expect(v.conflicts).toEqual(["*.corp"]);
    expect(v.conflictsAreComplete).toBe(true);
  });

  it("two sites forwarding a zone to the SAME resolver is duplication, not a conflict", () => {
    // The server permits it. Reporting it as a conflict would train the operator to ignore the indicator.
    const v = mergeOrgForwards([
      { site: site("a", "eu-lan"), res: ok([fwd("*.corp", "10.1.0.53")]) },
      { site: site("b", "ap-lan"), res: ok([fwd("*.corp", "10.1.0.53")]) },
    ]);
    expect(v.conflicts).toEqual([]);
  });

  it("both states of the emptiness question are observed, not just the clean one", () => {
    // Mechanism 9: a test that only ever sees `conflicts: []` cannot tell the detector from a constant.
    const clean = mergeOrgForwards([
      { site: site("a", "eu-lan"), res: ok([fwd("*.eu.corp", "10.1.0.53")]) },
    ]);
    expect(clean.conflicts).toEqual([]);
    expect(clean.conflictsAreComplete).toBe(true);
  });
});

describe("⛔ A PARTIAL LOAD IS NEVER RENDERED AS A COMPLETE ONE", () => {
  it("a failed site is NAMED and the conflict verdict is marked incomplete", () => {
    // The defect this closes: a failed fetch shortens the list, and a short list on THIS view reads as
    // "no conflict" — on the one screen whose purpose is to show conflicts.
    const v = mergeOrgForwards([
      { site: site("a", "eu-lan"), res: ok([fwd("*.corp", "10.1.0.53")]) },
      { site: site("b", "ap-lan"), res: fail("503") },
    ]);
    expect(v.failedSites).toEqual(["ap-lan"]);
    expect(v.conflictsAreComplete).toBe(false);
    // And critically: it did NOT report a clean bill of health.
    expect(v.conflicts).toEqual([]); // nothing FOUND …
    expect(v.conflictsAreComplete).toBe(false); // … but nothing CLAIMED either
  });

  it("every site failing is not an empty org", () => {
    const v = mergeOrgForwards([
      { site: site("a", "eu-lan"), res: fail("503") },
      { site: site("b", "ap-lan"), res: fail("503") },
    ]);
    expect(v.rows).toEqual([]);
    expect(v.failedSites).toEqual(["eu-lan", "ap-lan"]);
    expect(v.conflictsAreComplete).toBe(false);
  });

  it("a genuinely empty org IS complete — absence of zones is a real answer", () => {
    const v = mergeOrgForwards([{ site: site("a", "eu-lan"), res: ok([]) }]);
    expect(v.rows).toEqual([]);
    expect(v.failedSites).toEqual([]);
    expect(v.conflictsAreComplete).toBe(true);
  });
});

describe("ordering is stable", () => {
  it("sorts by domain then site, so the render does not reshuffle between loads", () => {
    const v = mergeOrgForwards([
      { site: site("b", "zz-lan"), res: ok([fwd("*.b", "10.0.0.1")]) },
      {
        site: site("a", "aa-lan"),
        res: ok([fwd("*.b", "10.0.0.1"), fwd("*.a", "10.0.0.2")]),
      },
    ]);
    expect(v.rows.map((r) => `${r.domain}@${r.siteName}`)).toEqual([
      "*.a@aa-lan",
      "*.b@aa-lan",
      "*.b@zz-lan",
    ]);
  });
});
