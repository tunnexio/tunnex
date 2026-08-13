import { describe, expect, it } from "vitest";
import {
  attributeRanges,
  attributionClass,
  attributionLabel,
  canonicalCidr,
  FANOUT_TRIPWIRE,
  fanOutExceedsTripwire,
  forwardsEmptyCopy,
  sortForwards,
  type SubnetFetch,
} from "../src/lib/routedrangesview";
import type { Site, SiteSubnet } from "../src/lib/api";

// ⛔ MECHANISM ⑨ — ONE-SIDED OBSERVATION — IS THE THING THIS FILE IS WRITTEN AGAINST.
//
// The S14.6 `aria-pressed` mutation survived because the test only ever observed the UNSELECTED value: a
// test that sees one value of a two-valued thing cannot tell the variable from the constant, and mutation
// testing inherits that blind spot rather than catching it.
//
// Every two-valued thing below is therefore asserted at BOTH values IN THE SAME TEST, so the assertion
// depends on the difference and not on one arm's literal.

const site = (id: string, name: string): Site =>
  ({ id, name }) as unknown as Site;

const subnet = (
  siteId: string,
  cidr: string,
  status: "approved" | "pending" = "approved",
): SiteSubnet =>
  ({ id: `${siteId}-${cidr}`, site_id: siteId, cidr, status }) as SiteSubnet;

const SITES = [site("s1", "Sydney"), site("s2", "Frankfurt")];

describe("canonicalCidr", () => {
  it("masks host bits off, and is the identity on an already-canonical range", () => {
    // BOTH SIDES IN ONE ASSERTION. A function that simply returned its input unchanged would pass a
    // canonical-only test; a function that always masked to /0 would pass a non-canonical-only test.
    expect(canonicalCidr("10.20.0.1/24")).toBe("10.20.0.0/24");
    expect(canonicalCidr("10.20.0.0/24")).toBe("10.20.0.0/24");
  });

  it("handles the bit-shift edges where a signed int32 would go negative", () => {
    // `0xffffffff << 0` is fine, but `<< 32` is a no-op and `<< 31` yields a NEGATIVE int32 in JS. Without
    // the `>>> 0` in the implementation these come back as garbage octets, not as a wrong-but-plausible CIDR.
    expect(canonicalCidr("10.20.30.40/0")).toBe("0.0.0.0/0");
    expect(canonicalCidr("10.20.30.40/1")).toBe("0.0.0.0/1");
    expect(canonicalCidr("172.16.5.9/32")).toBe("172.16.5.9/32");
    expect(canonicalCidr("192.168.1.130/25")).toBe("192.168.1.128/25");
  });

  it("returns null rather than a plausible-looking string for anything that is not an IPv4 CIDR", () => {
    // Null matters: the caller falls back to the RAW string as the join key. A lenient parse that guessed
    // would make two different inputs collide on one key and attribute a range to the wrong site.
    for (const bad of [
      "10.20.0.0", // no prefix
      "10.20.0.0/33", // prefix out of range
      "10.20.0.0/", // empty prefix
      "10.20.0/24", // three octets
      "10.20.0.0.0/24", // five octets
      "10.20.0.256/24", // octet out of range
      "fd00::/8", // IPv6 — not silently accepted
      "", // empty
    ])
      expect(canonicalCidr(bad), bad).toBeNull();
  });
});

describe("attributeRanges", () => {
  it("is `loading` before the fan-out resolves, and NOT loading after — null is not the same as empty", () => {
    const ranges = ["10.20.0.0/24"];

    // THE DISTINCTION THE UNION EXISTS FOR, ASSERTED AS A DIFFERENCE.
    const inFlight = attributeRanges(ranges, SITES, null);
    const resolvedEmpty = attributeRanges(ranges, SITES, []);

    expect(inFlight[0].attribution.kind).toBe("loading");
    expect(resolvedEmpty[0].attribution.kind).toBe("unmatched");
    // If the implementation collapsed null and [] the two would be equal — so assert they are not.
    expect(inFlight[0].attribution.kind).not.toBe(
      resolvedEmpty[0].attribution.kind,
    );
  });

  it("attributes a range to the site that advertises it, by canonical form on BOTH sides", () => {
    // The stored subnet here is NON-CANONICAL, which the live `cidr` column would in fact reject today. It is
    // used deliberately: this test's job is to prove the join does not DEPEND on that column type, because a
    // migration to `text` would otherwise break attribution silently.
    const fanOut: SubnetFetch[] = [
      { ok: true, siteId: "s1", subnets: [subnet("s1", "10.20.0.1/24")] },
      { ok: true, siteId: "s2", subnets: [] },
    ];
    const [row] = attributeRanges(["10.20.0.0/24"], SITES, fanOut);
    expect(row.attribution).toEqual({
      kind: "site",
      siteId: "s1",
      siteName: "Sydney",
    });
  });

  it("does NOT attribute a range to a PENDING subnet, while the same site's APPROVED subnet does attribute", () => {
    // Both arms, one test. Dropping the status filter makes the first expectation fail; hard-coding a skip
    // makes the second fail.
    const fanOut: SubnetFetch[] = [
      {
        ok: true,
        siteId: "s1",
        subnets: [
          subnet("s1", "10.30.0.0/24", "pending"),
          subnet("s1", "10.20.0.0/24", "approved"),
        ],
      },
    ];
    const rows = attributeRanges(
      ["10.20.0.0/24", "10.30.0.0/24"],
      SITES,
      fanOut,
    );
    expect(rows[0].attribution.kind).toBe("site");
    expect(rows[1].attribution.kind).toBe("unmatched");
  });

  it("degrades EVERY unmatched row to `unknown` when ANY site's fetch failed — a negative needs a complete census", () => {
    const ranges = ["10.20.0.0/24", "10.99.0.0/24"];
    const complete: SubnetFetch[] = [
      { ok: true, siteId: "s1", subnets: [subnet("s1", "10.20.0.0/24")] },
      { ok: true, siteId: "s2", subnets: [] },
    ];
    const partial: SubnetFetch[] = [
      { ok: true, siteId: "s1", subnets: [subnet("s1", "10.20.0.0/24")] },
      { ok: false, siteId: "s2" }, // s2 might own 10.99.0.0/24 — we cannot say it does not.
    ];

    // The MATCHED row is unaffected: a positive answer stays knowable, because finding it required only the
    // site that answered.
    expect(attributeRanges(ranges, SITES, complete)[0].attribution.kind).toBe(
      "site",
    );
    expect(attributeRanges(ranges, SITES, partial)[0].attribution.kind).toBe(
      "site",
    );

    // The UNMATCHED row flips, and this is the whole point: "no site advertises this" is a claim about
    // having asked every site.
    expect(attributeRanges(ranges, SITES, complete)[1].attribution.kind).toBe(
      "unmatched",
    );
    expect(attributeRanges(ranges, SITES, partial)[1].attribution.kind).toBe(
      "unknown",
    );
  });

  it("renders the site id when the subnet names a site `listSites` did not return", () => {
    // Honest over reassuring: falling back to "Unknown site" would be indistinguishable from the `unknown`
    // arm, which means something completely different (we could not ask).
    const fanOut: SubnetFetch[] = [
      { ok: true, siteId: "s9", subnets: [subnet("s9", "10.20.0.0/24")] },
    ];
    const [row] = attributeRanges(["10.20.0.0/24"], SITES, fanOut);
    expect(row.attribution).toEqual({
      kind: "site",
      siteId: "s9",
      siteName: "s9",
    });
  });

  it("preserves the API's order and the exact served string, which is what a device receives", () => {
    const ranges = ["10.20.0.0/24", "10.10.0.0/16", "192.168.4.0/22"];
    const rows = attributeRanges(ranges, SITES, []);
    expect(rows.map((r) => r.range)).toEqual(ranges);
  });

  it("N=0 ranges yields no rows in every fan-out state", () => {
    expect(attributeRanges([], SITES, null)).toEqual([]);
    expect(attributeRanges([], [], [])).toEqual([]);
  });
});

describe("attributionLabel / attributionClass", () => {
  it("gives all four arms a distinct label — no two states read the same", () => {
    const labels = [
      attributionLabel({ kind: "site", siteId: "s1", siteName: "Sydney" }),
      attributionLabel({ kind: "loading" }),
      attributionLabel({ kind: "unknown" }),
      attributionLabel({ kind: "unmatched" }),
    ];
    expect(new Set(labels).size).toBe(4);
    // ⛔ AND NONE OF THEM IS BLANK. A blank cell is the reassuring-empty shape this union exists to prevent;
    // an arm that returned "" would still be four distinct values if the others differ.
    for (const l of labels) expect(l.trim()).not.toBe("");
  });

  it("recedes every non-answer and only every non-answer", () => {
    const answered = attributionClass({
      kind: "site",
      siteId: "s1",
      siteName: "Sydney",
    });
    for (const a of [
      { kind: "loading" } as const,
      { kind: "unknown" } as const,
      { kind: "unmatched" } as const,
    ])
      expect(attributionClass(a)).not.toBe(answered);
  });
});

describe("fanOutExceedsTripwire", () => {
  it("is false AT the threshold and true one past it", () => {
    // Both sides of the boundary. `>=` instead of `>` fails the first; a constant fails one or the other.
    expect(fanOutExceedsTripwire(FANOUT_TRIPWIRE)).toBe(false);
    expect(fanOutExceedsTripwire(FANOUT_TRIPWIRE + 1)).toBe(true);
    expect(fanOutExceedsTripwire(0)).toBe(false);
  });
});

describe("forwardsEmptyCopy", () => {
  it("never says forwards are unconfigured, in either branch: empty means UNREACHABLE", () => {
    // Proof the guard can fire, rather than a regex nobody has watched reject: the exact sentence it forbids.
    expect("No forwarded zones are configured.").toMatch(
      /\bno\b[^.]*\b(forwards?|zones?)\b[^.]*\bconfigured\b/i,
    );

    // The gate is the whole subtlety: a forward is withheld when its resolver is outside every routed range.
    // Copy claiming "none configured" sends an admin to configure one that already exists.
    for (const copy of [forwardsEmptyCopy(0), forwardsEmptyCopy(3)]) {
      // `[^.]*` deliberately: the SECOND sentence of the non-empty branch says zones may well BE configured,
      // which is the honest clarification. The banned claim is "no zones are configured" WITHIN one sentence.
      expect(copy).not.toMatch(
        /\bno\b[^.]*\b(forwards?|zones?)\b[^.]*\bconfigured\b/i,
      );
      expect(copy.toLowerCase()).toContain("reachable");
    }
  });

  it("distinguishes 'nothing is routed' from 'nothing reachable' — the two have different fixes", () => {
    expect(forwardsEmptyCopy(0)).not.toBe(forwardsEmptyCopy(1));
    expect(forwardsEmptyCopy(0)).toMatch(/no ranges are routed/i);
  });
});

describe("sortForwards", () => {
  it("sorts by domain then resolver, and does not mutate its input", () => {
    const input = [
      { domain: "corp.local", resolver_ip: "10.20.0.53" },
      { domain: "aws.internal", resolver_ip: "10.10.0.2" },
      { domain: "corp.local", resolver_ip: "10.20.0.10" },
    ];
    const snapshot = JSON.stringify(input);
    expect(
      sortForwards(input).map((f) => `${f.domain}@${f.resolver_ip}`),
    ).toEqual([
      "aws.internal@10.10.0.2",
      "corp.local@10.20.0.10",
      "corp.local@10.20.0.53",
    ]);
    expect(JSON.stringify(input)).toBe(snapshot);
  });
});

// ── THE ADDRESS-SPACE MAP ───────────────────────────────────────────────────────────────────────────────

import {
  allocationLabel,
  BLOCKS,
  mapAddressSpace,
  nextFreeRange,
  parseCidr,
  utilisationLabel,
  type Allocation,
} from "../src/lib/routedrangesview";

const a = (
  cidr: string,
  kind: Allocation["kind"] = "approved",
): Allocation => ({
  cidr,
  kind,
  label: `${kind}:${cidr}`,
});

describe("mapAddressSpace — the three defects the panel was cut and rebuilt for", () => {
  it("⛔ ①: a /24 lights its cell PARTIAL, a /16 lights it FULL — the two are distinguishable", () => {
    // The handoff keyed 10.20.0.0/24 by its second octet, painting a 65,536-address block for a 256-address
    // LAN. Both cases in ONE test, so a model returning a constant fails whichever it is not.
    const partial = mapAddressSpace([a("10.31.0.0/24")]).blocks[0];
    const full = mapAddressSpace([a("10.31.0.0/16")]).blocks[0];
    expect(partial.lit[0].index).toBe(31);
    expect(full.lit[0].index).toBe(31);
    expect(partial.lit[0].state).toBe("partial");
    expect(full.lit[0].state).toBe("full");
  });

  it("⛔ ②: 172.16 and 192.168 ranges are DRAWN, each in its own block's geometry", () => {
    const m = mapAddressSpace([
      a("10.10.0.0/16"),
      a("172.20.0.0/16"),
      a("192.168.4.0/24"),
    ]);
    expect(m.blocks.map((b) => b.block.key)).toEqual(["10", "172", "192"]);
    expect(m.blocks[0].lit[0].index).toBe(10);
    expect(m.blocks[1].lit[0].index).toBe(4);
    expect(m.blocks[2].lit[0].index).toBe(4);
  });

  it("⛔ ③: the DEVICE POOL and CLUSTER VIPs occupy cells — a dark cell must mean genuinely free", () => {
    // THE DEFECT THE FOUNDER'S QUESTION EXPOSED. The live pool is 10.99.0.0/24; drawing only site subnets
    // left cell 99 dark, i.e. "yours to take", and the server refuses it.
    const m = mapAddressSpace([
      a("10.10.0.0/16"),
      a("10.99.0.0/24", "pool"),
      a("10.77.0.0/16", "vip"),
    ]).blocks[0];
    expect(m.lit.map((c) => c.index)).toEqual([10, 77, 99]);
    expect(m.lit.map((c) => c.kind)).toEqual(["approved", "vip", "pool"]);
    expect(m.counts).toEqual({ approved: 1, pending: 0, pool: 1, vip: 1 });
  });

  it("a range outside every RFC1918 block goes to offMap and keeps its label", () => {
    const m = mapAddressSpace([a("10.10.0.0/16"), a("203.0.113.0/24")]);
    expect(m.offMap.map((x) => x.cidr)).toEqual(["203.0.113.0/24"]);
    expect(m.blocks).toHaveLength(1);
  });

  it("an unparseable CIDR is reported, not skipped", () => {
    const m = mapAddressSpace([a("fd00::/8"), a("garbage")]);
    expect(m.unparseable.map((x) => x.cidr)).toEqual(["fd00::/8", "garbage"]);
    expect(m.blocks).toEqual([]);
  });

  it("a range COARSER than one cell fills every cell it spans, and a /8 does not run past the block", () => {
    expect(mapAddressSpace([a("10.0.0.0/12")]).blocks[0].lit).toHaveLength(16);
    const whole = mapAddressSpace([a("10.0.0.0/8")]).blocks[0];
    expect(whole.lit).toHaveLength(256);
    expect(whole.lit[255].index).toBe(255);
    expect(whole.utilised).toBe(1);
  });

  it("the STRONGER claim wins a shared cell — both directions", () => {
    // Precedence approved > pool > vip > pending. A cell that is partly the device pool must not read as
    // merely pending: the pool is the harder constraint to discover.
    const poolOverPending = mapAddressSpace([
      a("10.5.1.0/24", "pending"),
      a("10.5.2.0/24", "pool"),
    ]).blocks[0];
    expect(poolOverPending.lit[0].kind).toBe("pool");
    // And order must not decide it — the reverse input gives the same answer.
    const reversed = mapAddressSpace([
      a("10.5.2.0/24", "pool"),
      a("10.5.1.0/24", "pending"),
    ]).blocks[0];
    expect(reversed.lit[0].kind).toBe("pool");
    // FULL still beats PARTIAL independently of kind.
    expect(
      mapAddressSpace([a("10.7.0.0/24"), a("10.7.0.0/16")]).blocks[0].lit[0]
        .state,
    ).toBe("full");
  });

  it("utilisation counts ROUTED addresses only; `claimed` counts everything", () => {
    // Two distinct numbers, and conflating them is the trap: a pending range is withheld and the pool is not
    // routed LAN traffic, so folding them into "utilised" would overstate what goes down the tunnel — while
    // ignoring them in "claimed" would understate what a new range must avoid.
    const m = mapAddressSpace([
      a("10.1.0.0/16"),
      a("10.2.0.0/16", "pending"),
      a("10.3.0.0/16", "pool"),
    ]).blocks[0];
    expect(m.utilised).toBeCloseTo(1 / 256, 10);
    expect(m.claimed).toBeCloseTo(3 / 256, 10);
    // Measured in ADDRESSES, not lit cells: counting cells would score a /24 and a /16 identically.
    expect(mapAddressSpace([a("10.1.0.0/24")]).blocks[0].utilised).toBeCloseTo(
      1 / 65536,
      10,
    );
  });

  it("N=0 draws nothing rather than an empty grid", () => {
    expect(mapAddressSpace([])).toEqual({
      blocks: [],
      offMap: [],
      unparseable: [],
    });
  });
});

describe("nextFreeRange — the answer the picture cannot give", () => {
  const block = BLOCKS[0]; // 10.0.0.0/8

  it("skips every occupied range REGARDLESS OF CLASS", () => {
    // A suggestion computed from site subnets alone would name the pool's range and be refused. This is the
    // assertion that keeps the feature from being worse than nothing.
    const allocs = [a("10.0.0.0/16"), a("10.1.0.0/24", "pool")];
    // 10.1.0.0/24 is taken, so the first free /24 is the one after it.
    expect(nextFreeRange(allocs, block, 24)).toBe("10.1.1.0/24");
  });

  it("⛔ finds a /24 INSIDE a partly-used /16 — where the grid is one zoom level too coarse", () => {
    // THE WHOLE REASON THIS IS ARITHMETIC AND NOT A CELL SCAN. Cell 0 is full and cell 1 is only PARTLY used
    // (one /24 of 256). A cell-based search sees both as "lit" and answers 10.2.0.0/24 — wasting the 255
    // usable /24s inside cell 1. The correct answer is inside a cell the picture draws as occupied.
    const allocs = [a("10.0.0.0/16"), a("10.1.0.0/24")];
    const answer = nextFreeRange(allocs, block, 24);
    expect(answer).toBe("10.1.1.0/24");
    expect(answer).not.toBe("10.2.0.0/24"); // what a cell scan would have said
  });

  it("does NOT skip a free cell just because a later one is used", () => {
    // The inverse, and it caught a wrong expectation in this very file: with only 10.1.0.0/24 taken, the
    // first free /24 is 10.0.0.0/24 — the block does not start at the first ALLOCATION.
    expect(nextFreeRange([a("10.1.0.0/24")], block, 24)).toBe("10.0.0.0/24");
  });

  it("returns an ALIGNED network address, never merely the first free one", () => {
    // 10.0.0.0/24 taken -> the next free ADDRESS is 10.0.1.0, which happens to be aligned for a /24 but NOT
    // for a /16. A /16 must snap up to 10.1.0.0.
    expect(nextFreeRange([a("10.0.0.0/24")], block, 16)).toBe("10.1.0.0/16");
    expect(nextFreeRange([a("10.0.0.0/24")], block, 24)).toBe("10.0.1.0/24");
  });

  it("merges adjacent and overlapping claims rather than stepping into the seam", () => {
    const allocs = [
      a("10.0.0.0/16"),
      a("10.1.0.0/16"),
      a("10.1.0.0/24", "pool"),
    ];
    expect(nextFreeRange(allocs, block, 16)).toBe("10.2.0.0/16");
  });

  it("returns null when the block is full, and null for a prefix the block cannot hold", () => {
    // Null over a plausible-looking wrong answer, in both directions.
    expect(nextFreeRange([a("10.0.0.0/8")], block, 24)).toBeNull();
    expect(nextFreeRange([], block, 4)).toBeNull();
    // And a genuinely empty block answers with its very first range.
    expect(nextFreeRange([], block, 16)).toBe("10.0.0.0/16");
  });

  it("works in the other blocks, at their own scales", () => {
    expect(nextFreeRange([a("172.16.0.0/16")], BLOCKS[1], 16)).toBe(
      "172.17.0.0/16",
    );
    expect(nextFreeRange([a("192.168.0.0/24")], BLOCKS[2], 24)).toBe(
      "192.168.1.0/24",
    );
  });

  it("ignores allocations belonging to a DIFFERENT block", () => {
    // A 192.168 range must not push the 10/8 cursor. The containment filter is what prevents it.
    expect(nextFreeRange([a("192.168.0.0/16")], block, 16)).toBe("10.0.0.0/16");
  });
});

describe("parseCidr", () => {
  it("returns the network address as an UNSIGNED int32", () => {
    // 172.x and 192.168.x have the high bit set; a signed int32 goes negative and every containment check
    // silently fails, so both blocks would come back empty.
    expect(parseCidr("10.0.0.0/8")).toEqual({ addr: 0x0a000000, prefix: 8 });
    expect(parseCidr("192.168.4.0/24")).toEqual({
      addr: 0xc0a80400,
      prefix: 24,
    });
    expect(parseCidr("172.16.0.0/12")!.addr).toBeGreaterThan(0);
  });

  it("rejects what canonicalCidr rejects rather than re-implementing validation", () => {
    expect(parseCidr("nope")).toBeNull();
    expect(parseCidr("10.0.0.0/33")).toBeNull();
  });
});

describe("the block table itself", () => {
  it("every block's cell count matches its own arithmetic", () => {
    // TRUE-BY-STRUCTURE avoided: the constants are checked against the prefixes, not restated.
    for (const b of BLOCKS)
      expect(b.cells, b.label).toBe(Math.pow(2, b.cellPrefix - b.prefix));
  });
});

describe("utilisationLabel / allocationLabel", () => {
  it("never prints a bare 0.0% for a real allocation, and says 0 for a real zero", () => {
    // A /24 in a /8 is 0.0000015%; toFixed(1) renders "0.0%", which reads as NOTHING IS ROUTED beside a lit
    // cell — the numeric form of the reassuring-empty defect. The two cases mean different things.
    expect(
      utilisationLabel(mapAddressSpace([a("10.1.0.0/24")]).blocks[0]),
    ).toBe("<0.1% of /8");
    expect(utilisationLabel(mapAddressSpace([a("10.0.0.0/8")]).blocks[0])).toBe(
      "100.0% of /8",
    );
    expect(
      utilisationLabel(
        mapAddressSpace([a("10.1.0.0/16", "pending")]).blocks[0],
      ),
    ).toBe("0% of /8");
  });

  it("names only the kinds actually present", () => {
    expect(allocationLabel(mapAddressSpace([a("10.1.0.0/16")]).blocks[0])).toBe(
      "1 routed",
    );
    expect(
      allocationLabel(
        mapAddressSpace([
          a("10.1.0.0/16"),
          a("10.2.0.0/16", "pending"),
          a("10.3.0.0/24", "pool"),
        ]).blocks[0],
      ),
    ).toBe("1 routed · 1 pending · 1 pool");
  });
});
