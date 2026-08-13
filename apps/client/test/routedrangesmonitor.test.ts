import { test } from "node:test";
import assert from "node:assert/strict";

import { RoutedRangesMonitor, canonRanges, canonForwards, canonDial } from "../src/main/routedrangesmonitor";
import type { ResolverForward } from "../src/main/helperclient";
import type { DialTarget } from "../src/main/deviceconfig";

// mk builds a monitor whose poll returns rangesSeq[i] (an Error throws) with EMPTY forwards, and records
// every applied ranges set. Forwards-tier tests use mkF.
function mk(base: string[], rangesSeq: Array<string[] | Error>) {
  const applied: string[][] = [];
  let i = 0;
  const api = {
    routedConfig: async () => {
      const v = rangesSeq[Math.min(i++, rangesSeq.length - 1)];
      if (v instanceof Error) throw v;
      return { ranges: v, forwards: [], dial: null };
    },
  };
  const m = new RoutedRangesMonitor(
    "org",
    base,
    api,
    async (s) => {
      applied.push(s);
    },
    async () => {},
  );
  return { m, applied };
}

// mkF builds a monitor whose poll returns a FIXED range set with fwdSeq[i] forwards, recording every
// applied forward set. applyForwards throws when failForwards is true. Ranges are constant (base only) so
// the ranges tier stays quiet and the forwards tier is exercised in isolation.
function mkF(base: string[], fwdSeq: Array<ResolverForward[] | Error>, failForwards = false) {
  const fwdApplied: ResolverForward[][] = [];
  let i = 0;
  let fail = failForwards;
  const api = {
    routedConfig: async () => {
      const v = fwdSeq[Math.min(i++, fwdSeq.length - 1)];
      if (v instanceof Error) throw v;
      return { ranges: [] as string[], forwards: v, dial: null };
    },
  };
  const m = new RoutedRangesMonitor(
    "org",
    base,
    api,
    async () => {},
    async (f) => {
      if (fail) {
        fail = false;
        throw new Error("resolver refused");
      }
      fwdApplied.push(f);
    },
  );
  return { m, fwdApplied };
}

const FWD = (domain: string, ip: string): ResolverForward => ({ domain, resolver_ip: ip });

test("canonRanges dedups + sorts (order-free compare — the peersEqual lesson)", () => {
  assert.deepEqual(canonRanges(["10.2.0.0/16", "10.1.0.0/16", "10.2.0.0/16", ""]), ["10.1.0.0/16", "10.2.0.0/16"]);
});

test("empty ranges = unchanged, ZERO helper calls (D5 empty-channel client half)", async () => {
  const { m, applied } = mk(["10.99.0.0/24"], [[]]);
  assert.equal(await m.checkOnce(), "unchanged");
  assert.equal(applied.length, 0, "an empty-ranges org must not emit a pointless helper call");
});

test("no-churn: N identical polls = exactly ONE apply", async () => {
  const { m, applied } = mk(["10.99.0.0/24"], [["192.168.5.0/24"], ["192.168.5.0/24"], ["192.168.5.0/24"]]);
  assert.equal(await m.checkOnce(), "applied"); // first change
  assert.equal(await m.checkOnce(), "unchanged"); // identical → no call
  assert.equal(await m.checkOnce(), "unchanged");
  assert.equal(applied.length, 1);
});

test("full-sweep: declare appears, remove disappears, stable core in EVERY applied set", async () => {
  const { m, applied } = mk(["10.99.0.0/24"], [["192.168.5.0/24"], []]);
  await m.checkOnce(); // declare
  assert.deepEqual(applied[0], ["10.99.0.0/24", "192.168.5.0/24"], "applied = base ∪ ranges");
  await m.checkOnce(); // remove → back to base only (full-sweep, not accumulated)
  assert.deepEqual(applied[1], ["10.99.0.0/24"]);
  for (const s of applied) assert.ok(s.includes("10.99.0.0/24"), "the pool (stable core) is never dropped");
});

test("fail-static: a poll THROW keeps the last-applied set (no strip-to-baked)", async () => {
  const { m, applied } = mk(["10.99.0.0/24"], [["192.168.5.0/24"], new Error("CP blip"), ["192.168.5.0/24"]]);
  assert.equal(await m.checkOnce(), "applied");
  assert.equal(await m.checkOnce(), "inconclusive"); // blip → keep, no apply
  assert.equal(applied.length, 1, "a CP blip must not un-route the office LAN");
  assert.equal(await m.checkOnce(), "unchanged"); // recovered, same ranges → still no re-apply
  assert.equal(applied.length, 1);
});

test("apply failure keeps lastApplied → retries on the next poll", async () => {
  const base = ["10.99.0.0/24"];
  let fail = true;
  const applied: string[][] = [];
  const api = { routedConfig: async () => ({ ranges: ["192.168.5.0/24"], forwards: [], dial: null }) };
  const m = new RoutedRangesMonitor(
    "org",
    base,
    api,
    async (s) => {
      if (fail) {
        fail = false;
        throw new Error("helper refused");
      }
      applied.push(s);
    },
    async () => {},
  );
  assert.equal(await m.checkOnce(), "inconclusive"); // apply threw → not advanced
  assert.equal(applied.length, 0);
  assert.equal(await m.checkOnce(), "applied"); // retry succeeds
  assert.deepEqual(applied[0], ["10.99.0.0/24", "192.168.5.0/24"]);
});

test("immediate first poll: start() applies within the first tick, then schedules the 30s cadence (ruling A)", async () => {
  const applied: string[][] = [];
  const delays: number[] = [];
  const api = { routedConfig: async () => ({ ranges: ["192.168.5.0/24"], forwards: [], dial: null }) };
  const m = new RoutedRangesMonitor(
    "org",
    ["10.99.0.0/24"],
    api,
    async (s) => {
      applied.push(s);
    },
    async () => {},
    30_000,
    300_000,
    (_cb, ms) => {
      delays.push(ms);
      return 0 as unknown as ReturnType<typeof setTimeout>; // capture the delay; never actually fire
    },
    () => {},
  );
  m.start();
  await new Promise((r) => setImmediate(r)); // drain the immediate loop's checkOnce
  assert.equal(applied.length, 1, "the first poll must fire IMMEDIATELY, not after a full interval");
  assert.equal(delays[0], 30_000, "the NEXT poll is scheduled at the steady cadence");
  m.stop();
});

test("canonForwards folds order/case-invariant (DNS tier no-churn compare)", () => {
  assert.equal(
    canonForwards([FWD("Corp.Local", "10.20.0.53"), FWD("app.internal", "10.20.0.9")]),
    canonForwards([FWD("app.internal", "10.20.0.9"), FWD("corp.local", "10.20.0.53")]),
  );
});

test("forwards tier: applies on change, no-churn on repeat (Slice 3 DNS handoff)", async () => {
  const { m, fwdApplied } = mkF(["10.99.0.0/24"], [[FWD("corp.local", "10.20.0.53")], [FWD("corp.local", "10.20.0.53")]]);
  assert.equal(await m.checkOnce(), "applied");
  assert.deepEqual(fwdApplied[0], [FWD("corp.local", "10.20.0.53")], "the gated forward is handed to set_resolvers");
  assert.equal(await m.checkOnce(), "unchanged"); // identical → no second resolver call
  assert.equal(fwdApplied.length, 1);
});

test("forwards tier: empty forwards = unchanged, ZERO resolver calls (lastForwards seeded empty)", async () => {
  const { m, fwdApplied } = mkF(["10.99.0.0/24"], [[]]);
  assert.equal(await m.checkOnce(), "unchanged");
  assert.equal(fwdApplied.length, 0, "an org with no reachable forwards must not emit a set_resolvers call");
});

test("forwards tier fail-static is INDEPENDENT: a resolver-write throw keeps last, retries — routes untouched", async () => {
  // First apply throws (failForwards) → inconclusive, lastForwards NOT advanced; next poll (same set) retries.
  const { m, fwdApplied } = mkF(["10.99.0.0/24"], [[FWD("corp.local", "10.20.0.53")], [FWD("corp.local", "10.20.0.53")]], true);
  assert.equal(await m.checkOnce(), "inconclusive"); // resolver write threw → keep, no advance
  assert.equal(fwdApplied.length, 0, "a resolver-write failure must not drop DNS to a wrong/empty answer");
  assert.equal(await m.checkOnce(), "applied"); // retry succeeds
  assert.deepEqual(fwdApplied[0], [FWD("corp.local", "10.20.0.53")]);
});

test("#5 full-tunnel: resolver tier applies, routes tier is SKIPPED (no set_allowed_ips call)", async () => {
  const applied: string[][] = [];
  const fwdApplied: ResolverForward[][] = [];
  const api = { routedConfig: async () => ({ ranges: ["192.168.5.0/24"], forwards: [FWD("corp.local", "10.20.0.53")], dial: null }) };
  const m = new RoutedRangesMonitor(
    "org",
    ["0.0.0.0/0", "::/0"], // full-tunnel base
    api,
    async (s) => {
      applied.push(s);
    },
    async (f) => {
      fwdApplied.push(f);
    },
    undefined,
    undefined,
    undefined,
    undefined,
    false, // routesEnabled = false (full-tunnel)
  );
  assert.equal(await m.checkOnce(), "applied");
  assert.equal(applied.length, 0, "full-tunnel must issue NO route (set_allowed_ips) calls");
  assert.deepEqual(fwdApplied[0], [FWD("corp.local", "10.20.0.53")], "full-tunnel STILL applies DNS forwards (1.1.1.1 can't answer internal zones)");
});

test("stop abandons an in-flight poll's result (no apply after disconnect)", async () => {
  const { m, applied } = mk(["10.99.0.0/24"], [["192.168.5.0/24"]]);
  const p = m.checkOnce();
  m.stop();
  assert.equal(await p, "skipped");
  assert.equal(applied.length, 0);
});

// --- WF-A dial tier -----------------------------------------------------------------------------------
const DIAL = (endpoint: string, pubkey: string): DialTarget => ({ endpoint, pubkey });

// mkD builds a monitor exercising the DIAL tier in isolation: fixed empty ranges/forwards, dialSeq[i] as
// the poll's dial, seeded from `seed` (the minted peer). Records every re-home (endpoint,pubkey). applyDial
// throws once when failDial is set. dialEnabled defaults true (split-tunnel); pass false for the full-tunnel
// gate test.
function mkD(seed: DialTarget | null, dialSeq: Array<DialTarget | null | Error>, opts: { failDial?: boolean; dialEnabled?: boolean } = {}) {
  const rehomed: Array<{ endpoint: string; pubkey: string }> = [];
  let i = 0;
  let fail = opts.failDial ?? false;
  const api = {
    routedConfig: async () => {
      const v = dialSeq[Math.min(i++, dialSeq.length - 1)];
      if (v instanceof Error) throw v;
      return { ranges: [] as string[], forwards: [] as ResolverForward[], dial: v };
    },
  };
  const m = new RoutedRangesMonitor(
    "org",
    ["10.99.0.0/24"],
    api,
    async () => {},
    async () => {},
    undefined,
    undefined,
    undefined,
    undefined,
    true, // routesEnabled
    "dev-1", // deviceId
    async (endpoint, pubkey) => {
      if (fail) {
        fail = false;
        throw new Error("re-home refused");
      }
      rehomed.push({ endpoint, pubkey });
    },
    opts.dialEnabled ?? true,
    seed,
  );
  return { m, rehomed };
}

test("canonDial: a null dial folds to '' (never a change → zero re-homes)", () => {
  assert.equal(canonDial(null), "");
  assert.equal(canonDial(DIAL("gw-a:51820", "KA")), "gw-a:51820|KA");
});

test("dial tier no-churn: first poll returning the SEEDED (minted) hub = unchanged, ZERO set_gateway_peer", async () => {
  const seed = DIAL("gw-a:51820", "KA");
  const { m, rehomed } = mkD(seed, [seed, seed, seed]);
  assert.equal(await m.checkOnce(), "unchanged");
  assert.equal(await m.checkOnce(), "unchanged");
  assert.equal(rehomed.length, 0, "the device already dials the active hub — a re-home would be a pointless privileged call");
});

test("dial tier re-homes on active-hub move: applies set_gateway_peer(new), then no-churn on repeat", async () => {
  const seed = DIAL("gw-a:51820", "KA"); // minted on hub A
  const newHub = DIAL("gw-b:51820", "KB"); // failover promoted hub B
  const { m, rehomed } = mkD(seed, [newHub, newHub]);
  assert.equal(await m.checkOnce(), "applied");
  assert.deepEqual(rehomed[0], { endpoint: "gw-b:51820", pubkey: "KB" }, "re-homes onto the NEW active hub");
  assert.equal(await m.checkOnce(), "unchanged"); // same new hub → no second swap
  assert.equal(rehomed.length, 1);
});

test("dial tier: a NULL dial keeps the current peer (single-gateway / server blip never swaps away)", async () => {
  const seed = DIAL("gw-a:51820", "KA");
  const { m, rehomed } = mkD(seed, [null, null]);
  assert.equal(await m.checkOnce(), "unchanged");
  assert.equal(rehomed.length, 0, "a null dial must NEVER tear down the peer to nothing — keep the current hub");
});

test("dial tier fail-static is INDEPENDENT: a re-home throw keeps lastDial, retries — routes/forwards untouched", async () => {
  const seed = DIAL("gw-a:51820", "KA");
  const newHub = DIAL("gw-b:51820", "KB");
  const { m, rehomed } = mkD(seed, [newHub, newHub], { failDial: true });
  assert.equal(await m.checkOnce(), "inconclusive"); // re-home threw → keep, no advance
  assert.equal(rehomed.length, 0, "a failed re-home must not read as applied");
  assert.equal(await m.checkOnce(), "applied"); // retry succeeds
  assert.deepEqual(rehomed[0], { endpoint: "gw-b:51820", pubkey: "KB" });
});

test("dial tier flag mechanic: dialEnabled=false skips the tier entirely (no set_gateway_peer)", async () => {
  // Post-D-WFA-4 the client passes dialEnabled=true for BOTH modes (the helper refuses where its carve-out
  // is absent). This pins the FLAG mechanic itself: when off, the tier is inert regardless of a moved hub.
  const seed = DIAL("gw-a:51820", "KA");
  const newHub = DIAL("gw-b:51820", "KB");
  const { m, rehomed } = mkD(seed, [newHub], { dialEnabled: false });
  assert.equal(await m.checkOnce(), "unchanged");
  assert.equal(rehomed.length, 0, "dialEnabled=false must make the dial tier inert");
});

test("dial tier drives full-tunnel too (D-WFA-4): dialEnabled=true re-homes on a hub move; helper owns any refusal", async () => {
  // The full-tunnel base shape no longer gates the dial tier at the client — the carve-out makes the
  // control path independent, so the client drives the re-home and the HELPER refuses (fail-static) only
  // where its carve-out is absent (Windows). Here the apply succeeds → applied.
  const seed = DIAL("gw-a:51820", "KA");
  const newHub = DIAL("gw-b:51820", "KB");
  const { m, rehomed } = mkD(seed, [newHub], { dialEnabled: true });
  assert.equal(await m.checkOnce(), "applied");
  assert.deepEqual(rehomed[0], { endpoint: "gw-b:51820", pubkey: "KB" });
});
