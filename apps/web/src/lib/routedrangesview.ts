import type { DNSForward, Site, SiteSubnet } from "./api";

// ── S14.7 — ROUTED RANGES, THE VIEW MODEL ───────────────────────────────────────────────────────────────
//
// `/routed-ranges` serves a DEVICE-FACING projection: approved CIDRs, canonical + sorted, and the DNS
// forwards reachable through them. It does NOT serve `site_id`. Attribution is therefore JOINED CLIENT-SIDE
// from a per-site `listSiteSubnets` fan-out — see `attributionState` for what that costs and when it stops
// being acceptable.
//
// Everything here is pure. The screen does the fetching; this file decides what the screen is allowed to
// claim, and — more to the point — what it must NOT claim while the answer is still in flight.

// ⛔ THE IN-FLIGHT STATE IS A FIRST-CLASS VALUE, NOT A FALSY DEFAULT.
//
// The ranges table renders IMMEDIATELY from one request; the SITE column fills in as the N-site fan-out
// lands. If in-flight rendered as blank it would be indistinguishable from "we looked and found no site" —
// the reassuring-empty shape, at row level, on the column the screen exists to add.
//
// So the union has four arms and NONE of them is the absence of the others.
export type Attribution =
  | { kind: "site"; siteId: string; siteName: string }
  | { kind: "loading" }
  // The fan-out failed for the site that would have owned this row. NOT "no site" — "we could not ask".
  | { kind: "unknown" }
  // We asked every site, every answer came back, and no approved subnet matches this range.
  | { kind: "unmatched" };

export type RangeRow = {
  /** The canonical CIDR exactly as the API sorted and emitted it — the string a device receives. */
  range: string;
  attribution: Attribution;
};

// canonicalCidr masks host bits off an IPv4 CIDR, or returns null if it is not one.
//
// ⛔ WHY THIS EXISTS WHEN THE JOIN IS ALREADY SAFE. `site_subnets.cidr` is the POSTGRES `cidr` type, which
// REJECTS host bits at the column — measured in S14.7 §2 with a real INSERT into the real table, not with a
// cast. So both sides are already canonical and a naive string join would work today.
//
// It exists because the REASON it works lives in a column type two layers away, in a different language, in
// a different repository directory. A migration to `text` would break the attribution join SILENTLY: rows
// would render `unmatched`, which is a legible-looking state that means something else entirely. Normalising
// here makes the join depend on nothing but itself.
//
// `routedranges.go:211` already sets this precedent server-side (`ss.Cidr.Masked() == cidr.Masked()`).
export function canonicalCidr(raw: string): string | null {
  const trimmed = raw.trim();
  const slash = trimmed.lastIndexOf("/");
  if (slash < 0) return null;
  const host = trimmed.slice(0, slash);
  const prefixText = trimmed.slice(slash + 1);
  if (!/^\d{1,2}$/.test(prefixText)) return null;
  const prefix = Number(prefixText);
  if (prefix > 32) return null;

  const octets = host.split(".");
  if (octets.length !== 4) return null;
  const bytes: number[] = [];
  for (const octet of octets) {
    if (!/^\d{1,3}$/.test(octet)) return null;
    const value = Number(octet);
    if (value > 255) return null;
    bytes.push(value);
  }

  // Mask as a 32-bit unsigned value. `>>> 0` because JS bitwise ops yield SIGNED int32, so a /0 or /1 mask
  // on 10.x would otherwise come back negative and every octet would be wrong.
  const addr =
    ((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]) >>> 0;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const masked = (addr & mask) >>> 0;
  return `${(masked >>> 24) & 255}.${(masked >>> 16) & 255}.${(masked >>> 8) & 255}.${masked & 255}/${prefix}`;
}

/** One site's fan-out result. `ok:false` is why `unknown` exists as an attribution. */
export type SubnetFetch =
  | { ok: true; siteId: string; subnets: SiteSubnet[] }
  | { ok: false; siteId: string };

/**
 * attributeRanges joins served ranges to the sites that advertise them.
 *
 * `fanOut === null` means the fan-out has not resolved yet — every row is `loading`. That is distinct from
 * `fanOut === []`, which means there are no sites at all, and every row is genuinely `unmatched`.
 */
export function attributeRanges(
  ranges: string[],
  sites: Site[],
  fanOut: SubnetFetch[] | null,
): RangeRow[] {
  if (fanOut === null)
    return ranges.map((range) => ({ range, attribution: { kind: "loading" } }));

  const siteName = new Map(sites.map((s) => [s.id, s.name]));

  // ⛔ ANY failed site poisons the whole NEGATIVE answer, not just its own rows.
  //
  // A range's owner is discovered by finding it in some site's subnet list. If ANY site's list is missing, a
  // range we did not match might be owned by exactly that site — so "no match" is not knowable. `unmatched`
  // is a claim about every site having been asked; degrade to `unknown` if even one was not.
  const anyFailed = fanOut.some((f) => !f.ok);

  const owner = new Map<string, string>();
  for (const fetched of fanOut) {
    if (!fetched.ok) continue;
    for (const subnet of fetched.subnets) {
      // Pending subnets are NOT routed. `/routed-ranges` is approved-only, so a pending subnet can never be
      // the owner of a served range — and attributing one would claim traffic flows where it does not.
      if (subnet.status !== "approved") continue;
      const key = canonicalCidr(subnet.cidr) ?? subnet.cidr;
      // First writer wins; a duplicate CIDR across sites is refused by the disjointness validator at both
      // seams (S8.1 #1), so this is defensive rather than a real branch.
      if (!owner.has(key)) owner.set(key, subnet.site_id);
    }
  }

  return ranges.map((range) => {
    const key = canonicalCidr(range) ?? range;
    const siteId = owner.get(key);
    if (siteId !== undefined)
      return {
        range,
        attribution: {
          kind: "site",
          siteId,
          // A site the fan-out reached but that `listSites` did not return is a real, if unlikely, race.
          // Rendering the id is honest; rendering "Unknown site" would look like the `unknown` arm.
          siteName: siteName.get(siteId) ?? siteId,
        },
      };
    return {
      range,
      attribution: { kind: anyFailed ? "unknown" : "unmatched" },
    };
  });
}

/** The SITE cell's text. Exported so the test asserts the STRING, not a class name. */
export function attributionLabel(a: Attribution): string {
  switch (a.kind) {
    case "site":
      return a.siteName;
    case "loading":
      return "Loading…";
    case "unknown":
      return "Could not load";
    case "unmatched":
      return "No site advertises this";
  }
}

/** Recessive styling for every non-answer, so a row with real attribution is the one that reads loudest. */
export function attributionClass(a: Attribution): string {
  return a.kind === "site" ? "text-ink-body" : "text-slate-400 italic";
}

// ⛔ THE FAN-OUT TRIPWIRE. N sites = N+1 requests, parallel, once per visit. Fine at 20. At ~50 it is nine
// sequential waves against the browser's ~6-per-origin cap — noticeable, still one page load. At 200 it is
// not acceptable.
//
// THE REAL FIX IS `site_id` ON `RoutedRange`, AND IT IS NOT THIS SCREEN'S TO MAKE: `/routed-ranges` is a
// device-facing projection, and adding an org-structure field to it needs a ruling on whether a device
// should learn site topology. Deferred with a named trigger (docs/DEFERRAL-REGISTER.md).
//
// So the threshold is exported and ASSERTED, rather than living in a comment the next reader has to find.
export const FANOUT_TRIPWIRE = 50;

export function fanOutExceedsTripwire(siteCount: number): boolean {
  return siteCount > FANOUT_TRIPWIRE;
}

// ── DNS FORWARDS: THE GATED EMPTY STATE ─────────────────────────────────────────────────────────────────
//
// ⛔ `forwards` IS GATED, AND ITS EMPTINESS MEANS SOMETHING NARROWER THAN IT LOOKS. A forward is returned
// only when its `resolver_ip` falls INSIDE a routed range — the control plane never hands a device a
// resolver it cannot reach (S8.4: "never a SERVFAIL generator").
//
// So empty means "none REACHABLE". It does NOT mean "none configured", and copy that says the latter would
// send an admin to configure a forward that already exists.
export function forwardsEmptyCopy(rangeCount: number): string {
  return rangeCount === 0
    ? "No forwarded zones are reachable, because no ranges are routed yet."
    : "No forwarded zones are currently reachable from a routed range. Zones may well be configured: a resolver that sits outside every routed range is withheld rather than handed over as a dead lookup.";
}

/** Sorted for a stable render; the API does not promise an order on `forwards`. */
export function sortForwards(forwards: DNSForward[]): DNSForward[] {
  return [...forwards].sort(
    (a, b) =>
      a.domain.localeCompare(b.domain) ||
      a.resolver_ip.localeCompare(b.resolver_ip),
  );
}

// ── THE ADDRESS-SPACE MAP ───────────────────────────────────────────────────────────────────────────────
//
// FOUNDER-OVERRIDDEN: cut in the S14.7 commit-one, ruled back in. The cut had two reasons and BOTH ARE REAL
// DEFECTS IN THE WIREFRAME, so the panel is built with them closed rather than reproduced:
//
//   ① A /24 LIT A WHOLE /16 CELL (`alloc = { 20: 'pending' }` keys 10.20.0.0/24 by its second octet), so a
//     256-address LAN painted a 65,536-address block. CLOSED: `partial` cells render INSET.
//
//   ② THE GRID DOMAIN WAS HARD-CODED 10.0.0.0/8, so a customer on 172.16/12 or 192.168/16 saw their ranges
//     VANISH. Our seed is all 10.x, so it would have looked perfect. CLOSED: one grid per RFC1918 block that
//     has content, plus an explicit OFF-MAP list.
//
// ⛔ AND A THIRD DEFECT, FOUND BY ASKING WHAT THE PANEL IS FOR. A map of allocated space is read to answer
// "what can I use next" — so a DARK CELL IS A CLAIM THAT THE SPACE IS FREE. The server refuses an
// overlapping range by checking FOUR classes (`subnetguard`: site_subnet, pool, vip_range, reserved) and the
// first build drew ONE of them. The live device pool is 10.99.0.0/24; cell 99 rendered dark, i.e. "yours to
// take", and the server would refuse it.
//
//   `reserved` is measured as DEAD — `WithReserved` has no callers outside its own definition — so the
//   reachable set is THREE: site subnets, the device pool, and K8s VIP ranges. That is what is drawn.
//
// THE PRINCIPLE: THE MAP MUST DRAW EVERYTHING THE VALIDATOR ENFORCES, OR ITS EMPTY SPACE IS A LIE.

/** What occupies address space. Every kind here is a class `subnetguard` refuses a collision with. */
export type AllocKind = "approved" | "pending" | "pool" | "vip";

export type Allocation = {
  cidr: string;
  kind: AllocKind;
  /** Who owns it — a site name, "device pool", a cluster name. The map's most useful label. */
  label: string;
};

export type Block = {
  key: string;
  label: string;
  base: number;
  prefix: number;
  cellPrefix: number;
  cells: number;
  cols: number;
};

// ⛔ `cols` IS SQUARE, NOT 32-WIDE, AND THAT IS A LAYOUT FIX WITH A REASON. The handoff drew 256 cells as
// 32x8 — a 4:1 letterbox 108px tall — beside a call-out list that grows 40px PER RANGE. At the handoff's
// three ranges the two were roughly level; at our eight the list is 320px and the grid still 108px, so the
// connectors trailed 250px into empty space and read as OVERFLOWING the drawing.
//
// A SHAPE CHOSEN AT N=3 IS NOT A SHAPE THAT SURVIVES N=8. Square (16x16) puts the grid's aspect ratio in the
// same family as the list's, so the two columns stay level as the list grows.
export const BLOCKS: Block[] = [
  {
    key: "10",
    label: "10.0.0.0/8",
    base: 0x0a000000,
    prefix: 8,
    cellPrefix: 16,
    cells: 256,
    cols: 16,
  },
  {
    key: "172",
    label: "172.16.0.0/12",
    base: 0xac100000,
    prefix: 12,
    cellPrefix: 16,
    cells: 16,
    cols: 4,
  },
  {
    key: "192",
    label: "192.168.0.0/16",
    base: 0xc0a80000,
    prefix: 16,
    cellPrefix: 24,
    cells: 256,
    cols: 16,
  },
];

export type CellState = "partial" | "full";

export type Cell = {
  index: number;
  state: CellState;
  /** The kind shown when a cell holds more than one. See KIND_RANK. */
  kind: AllocKind;
  allocs: Allocation[];
};

export type BlockMap = {
  block: Block;
  lit: Cell[];
  /** Fraction of the block's addresses occupied by ROUTED traffic (approved subnets only). */
  utilised: number;
  /** Fraction occupied by ANYTHING — the number that matters when picking a new range. */
  claimed: number;
  counts: Record<AllocKind, number>;
};

// Precedence when one cell holds several kinds. Highest wins the cell's colour: a cell that is partly the
// device pool must not read as merely pending, because the pool is the harder constraint to discover.
const KIND_RANK: Record<AllocKind, number> = {
  approved: 4,
  pool: 3,
  vip: 2,
  pending: 1,
};

export function parseCidr(
  raw: string,
): { addr: number; prefix: number } | null {
  const canonical = canonicalCidr(raw);
  if (canonical === null) return null;
  const [host, prefixText] = canonical.split("/");
  const b = host.split(".").map(Number);
  return {
    addr: ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0,
    prefix: Number(prefixText),
  };
}

const size = (prefix: number) => Math.pow(2, 32 - prefix);

function inBlock(addr: number, prefix: number, block: Block): boolean {
  if (prefix < block.prefix) return false;
  const mask =
    block.prefix === 0 ? 0 : (0xffffffff << (32 - block.prefix)) >>> 0;
  return (addr & mask) >>> 0 === block.base;
}

export function mapAddressSpace(allocations: Allocation[]): {
  blocks: BlockMap[];
  offMap: Allocation[];
  unparseable: Allocation[];
} {
  const offMap: Allocation[] = [];
  const unparseable: Allocation[] = [];
  const acc = new Map<
    string,
    {
      cells: Map<number, Cell>;
      routedAddrs: number;
      claimedAddrs: number;
      counts: Record<AllocKind, number>;
    }
  >();

  for (const alloc of allocations) {
    const parsed = parseCidr(alloc.cidr);
    if (parsed === null) {
      unparseable.push(alloc);
      continue;
    }
    const block = BLOCKS.find((b) => inBlock(parsed.addr, parsed.prefix, b));
    if (block === undefined) {
      offMap.push(alloc);
      continue;
    }
    let entry = acc.get(block.key);
    if (entry === undefined) {
      entry = {
        cells: new Map(),
        routedAddrs: 0,
        claimedAddrs: 0,
        counts: { approved: 0, pending: 0, pool: 0, vip: 0 },
      };
      acc.set(block.key, entry);
    }
    entry.counts[alloc.kind] += 1;
    entry.claimedAddrs += size(parsed.prefix);
    // ⛔ ONLY APPROVED SUBNETS ARE "UTILISED". A pending range is withheld and a pool is not routed LAN
    // traffic, so folding them in would overstate what actually goes down the tunnel.
    if (alloc.kind === "approved") entry.routedAddrs += size(parsed.prefix);

    const first = Math.floor(
      (parsed.addr - block.base) / size(block.cellPrefix),
    );
    if (parsed.prefix > block.cellPrefix) {
      upsert(entry.cells, first, "partial", alloc);
      continue;
    }
    const span = size(parsed.prefix) / size(block.cellPrefix);
    for (let i = 0; i < span && first + i < block.cells; i++)
      upsert(entry.cells, first + i, "full", alloc);
  }

  const blocks: BlockMap[] = [];
  for (const block of BLOCKS) {
    const entry = acc.get(block.key);
    if (entry === undefined) continue;
    blocks.push({
      block,
      lit: [...entry.cells.values()].sort((a, b) => a.index - b.index),
      utilised: entry.routedAddrs / size(block.prefix),
      claimed: entry.claimedAddrs / size(block.prefix),
      counts: entry.counts,
    });
  }
  return { blocks, offMap, unparseable };
}

function upsert(
  cells: Map<number, Cell>,
  index: number,
  state: CellState,
  alloc: Allocation,
) {
  const existing = cells.get(index);
  if (existing === undefined) {
    cells.set(index, { index, state, kind: alloc.kind, allocs: [alloc] });
    return;
  }
  existing.allocs.push(alloc);
  if (state === "full") existing.state = "full";
  if (KIND_RANK[alloc.kind] > KIND_RANK[existing.kind])
    existing.kind = alloc.kind;
}

// ── "WHAT DO I USE NEXT" ────────────────────────────────────────────────────────────────────────────────
//
// ⛔ THE ANSWER IS COMPUTED BY INTERVAL ARITHMETIC, NOT FROM THE GRID, and that difference is the point.
//
// A /16 cell cannot say which /24s inside it are free — the grid is one zoom level too coarse for the size
// most customers actually deploy. Arithmetic has no resolution limit, so this stays exact where the picture
// cannot: it will happily suggest a /24 inside a half-used /16 and be right.
//
// AND IT IS COMPUTED AGAINST EVERY ALLOCATION CLASS. A suggestion derived from site subnets alone would
// confidently name ranges the server rejects — worse than no feature, because it comes with a number.

/**
 * The first free, correctly-aligned block of the requested prefix, or null if the block is full.
 *
 * `null` is also returned for a request the block cannot satisfy (a /8 inside a /12), rather than a
 * plausible-looking wrong answer.
 */
export function nextFreeRange(
  allocations: Allocation[],
  block: Block,
  prefix: number,
): string | null {
  if (prefix < block.prefix || prefix > 32) return null;
  const want = size(prefix);
  const blockEnd = block.base + size(block.prefix);

  // Merge every claim in this block into disjoint occupied intervals. Disjointness is server-enforced
  // between real allocations, but merging is what makes the walk below correct regardless.
  const taken: Array<[number, number]> = [];
  for (const a of allocations) {
    const p = parseCidr(a.cidr);
    if (p === null || !inBlock(p.addr, p.prefix, block)) continue;
    taken.push([p.addr, p.addr + size(p.prefix)]);
  }
  taken.sort((x, y) => x[0] - y[0]);
  const merged: Array<[number, number]> = [];
  for (const [lo, hi] of taken) {
    const last = merged[merged.length - 1];
    if (last !== undefined && lo <= last[1]) last[1] = Math.max(last[1], hi);
    else merged.push([lo, hi]);
  }

  // Walk the gaps, snapping each candidate UP to its own alignment — a CIDR must start on a multiple of its
  // own size, so the first free address is usually not a legal network address.
  let cursor = block.base;
  for (const [lo, hi] of [
    ...merged,
    [blockEnd, blockEnd] as [number, number],
  ]) {
    const candidate = Math.ceil(cursor / want) * want;
    if (candidate + want <= lo && candidate + want <= blockEnd)
      return `${toDotted(candidate)}/${prefix}`;
    cursor = Math.max(cursor, hi);
  }
  return null;
}

function toDotted(addr: number): string {
  return [
    Math.floor(addr / 16777216) % 256,
    Math.floor(addr / 65536) % 256,
    Math.floor(addr / 256) % 256,
    addr % 256,
  ].join(".");
}

/** "0.4% of /8" — computed, and never a bare "0.0%" for a real allocation. */
export function utilisationLabel(m: BlockMap): string {
  const pct = m.utilised * 100;
  const shown = pct === 0 ? "0" : pct < 0.1 ? "<0.1" : pct.toFixed(1);
  return `${shown}% of /${m.block.prefix}`;
}

/** "6 routed · 2 pending · 1 pool" — only the kinds actually present. */
export function allocationLabel(m: BlockMap): string {
  const NAMES: Array<[AllocKind, string]> = [
    ["approved", "routed"],
    ["pending", "pending"],
    ["pool", "pool"],
    ["vip", "cluster VIP"],
  ];
  const parts = NAMES.filter(([k]) => m.counts[k] > 0).map(
    ([k, name]) => `${m.counts[k]} ${name}`,
  );
  return parts.length === 0 ? "nothing allocated" : parts.join(" · ");
}

/** The per-kind short word shown on a call-out row. */
export const KIND_LABEL: Record<AllocKind, string> = {
  approved: "ROUTED",
  pending: "PENDING",
  pool: "POOL",
  vip: "VIP",
};
