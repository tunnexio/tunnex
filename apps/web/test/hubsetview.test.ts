import { describe, it, expect } from "vitest";
import { failoverNotices, hubSetView, formatBytes, roughDuration, spanWords, unobservedHubs } from "../src/lib/hubsetview";
import type { HubSet } from "../src/lib/api";

const now = Date.parse("2026-07-20T12:00:00Z");
const fresh = "2026-07-20T11:59:50Z"; // 10s ago
const stale = "2026-07-20T11:00:00Z"; // 1h ago

describe("hubSetView (S8.6 HA surface view-model)", () => {
  it("null for an unpinned org (no HA hub set → no surface)", () => {
    expect(hubSetView(null, now)).toBeNull();
    expect(hubSetView({ generation: 0, failover: { stale_after_seconds: 240, demote_after_seconds: 90, restore_after_seconds: 150 }, members: [] }, now)).toBeNull();
  });

  it("ordered role (primary=members[0]) + generation as the version tag", () => {
    const hs: HubSet = {
      generation: 7, failover: { stale_after_seconds: 240, demote_after_seconds: 90, restore_after_seconds: 150 },
      members: [
        {
          node_id: "a",
          role: "primary", liveness: "fresh",
          hub_priority: 1,
          metrics: { last_handshake_at: fresh, rx_bytes: 2048, tx_bytes: 0 },
        },
        { node_id: "b", role: "standby", liveness: "fresh", hub_priority: 2 },
      ],
    };
    const v = hubSetView(hs, now)!;
    expect(v.generation).toBe(7);
    expect(v.members[0].role).toBe("primary");
    expect(v.members[1].role).toBe("standby");
  });

  it("render-floor: idle-reporting shows 0 B (honest); NOT-reporting shows — (absent, never 0)", () => {
    const hs: HubSet = {
      generation: 3, failover: { stale_after_seconds: 240, demote_after_seconds: 90, restore_after_seconds: 150 },
      members: [
        {
          node_id: "a",
          role: "primary", liveness: "fresh",
          hub_priority: 1,
          metrics: { last_handshake_at: fresh, rx_bytes: 0, tx_bytes: 0 },
        }, // idle
        { node_id: "b", role: "standby", liveness: "unobserved", hub_priority: 2 }, // NOT reporting (no metrics)
      ],
    };
    const v = hubSetView(hs, now)!;
    expect(v.members[0].reporting).toBe(true);
    expect(v.members[0].rx).toBe("0 B"); // idle link — a row with zeroes is honest
    expect(v.members[0].warm).toBe(true);
    expect(v.members[1].reporting).toBe(false);
    expect(v.members[1].rx).toBe("n/a"); // not reporting: absent, NOT "0 B"
    expect(v.members[1].tx).toBe("n/a");
    expect(v.members[1].handshakeAge).toBe("n/a");
    expect(v.members[1].warm).toBeNull(); // unknown ≠ cold
  });

  it("warm is the SERVED verdict (SSI-12), never recomputed from the handshake age", () => {
    const one = (liveness: "fresh" | "stale", at: string): HubSet => ({
      generation: 1, failover: { stale_after_seconds: 35, demote_after_seconds: 20, restore_after_seconds: 150 },
      members: [{ node_id: "a", role: "primary", liveness, silent_seconds: 5, hub_priority: 1, metrics: { last_handshake_at: at, rx_bytes: 5, tx_bytes: 5 } }],
    });
    expect(hubSetView(one("stale", fresh), now)!.members[0].warm).toBe(false); // young handshake, frozen counter
    expect(hubSetView(one("fresh", stale), now)!.members[0].warm).toBe(true); // old handshake, still receiving
  });

  it("promotion in effect: the acting primary ≠ the configured primary (lowest pin) → demoted flag on the config primary", () => {
    // b is pinned #1 (configured primary) but STALE; the active order made a (#2) primary → a failover.
    const hs: HubSet = {
      generation: 9, failover: { stale_after_seconds: 240, demote_after_seconds: 90, restore_after_seconds: 150 },
      members: [
        {
          node_id: "a",
          role: "primary", liveness: "fresh",
          hub_priority: 2,
          metrics: { last_handshake_at: fresh, rx_bytes: 1, tx_bytes: 1 },
        },
        {
          node_id: "b",
          role: "standby", liveness: "fresh",
          hub_priority: 1,
          metrics: { last_handshake_at: stale, rx_bytes: 1, tx_bytes: 1 },
        },
      ],
    };
    const v = hubSetView(hs, now)!;
    expect(v.promotionInEffect).toBe(true);
    expect(v.members[0].demoted).toBe(false); // a is acting primary, not demoted
    expect(v.members[1].demoted).toBe(true); // b (configured #1) was demoted for staleness
  });

  it("no promotion when the acting primary IS the configured primary", () => {
    const hs: HubSet = {
      generation: 4, failover: { stale_after_seconds: 240, demote_after_seconds: 90, restore_after_seconds: 150 },
      members: [
        { node_id: "a", role: "primary", liveness: "fresh", hub_priority: 1 },
        { node_id: "b", role: "standby", liveness: "fresh", hub_priority: 2 },
      ],
    };
    const v = hubSetView(hs, now)!;
    expect(v.promotionInEffect).toBe(false);
    expect(v.members.every((m) => !m.demoted)).toBe(true);
  });
});

describe("formatBytes", () => {
  it("scales units + keeps a raw small count in bytes", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(2048)).toBe("2.0 KB");
    expect(formatBytes(5 * 1024 * 1024)).toBe("5.0 MB");
  });
});

// SSI-9 (finding F13): a hub is demoted only on another gateway's testimony, and gateways of the same
// network do not peer. The Failover tab must say when nobody could be watching.
describe("unobservedHubs", () => {
  const aws = { id: "aws", gatewayIds: ["gw-1", "gw-2"], approvedRanges: 2 };
  const gcp = { id: "gcp", gatewayIds: ["gw-3"], approvedRanges: 1 };

  it("reports a same-network pair with no other network as unobserved", () => {
    expect(unobservedHubs(["gw-1", "gw-2"], [aws])).toEqual(["gw-1", "gw-2"]);
  });

  it("is satisfied by one gateway in another network", () => {
    expect(unobservedHubs(["gw-1", "gw-2"], [aws, gcp])).toEqual([]);
  });

  it("does not count another network that has no active gateway", () => {
    expect(unobservedHubs(["gw-1", "gw-2"], [aws, { id: "empty", gatewayIds: [], approvedRanges: 1 }])).toEqual(["gw-1", "gw-2"]);
  });

  it("reports a hub whose own network has no approved range: nobody dials it", () => {
    expect(unobservedHubs(["gw-1"], [{ ...aws, approvedRanges: 0 }, gcp])).toEqual(["gw-1"]);
  });

  it("reports a hub bound to no network", () => {
    expect(unobservedHubs(["gw-9", "gw-3"], [aws, gcp])).toEqual(["gw-9"]);
  });

  it("judges hubs in different networks each by its own neighbours", () => {
    expect(unobservedHubs(["gw-1", "gw-3"], [aws, gcp])).toEqual([]);
  });
});

// SSI-11 / SSI-12 — the tab shows the controller's served verdict and states the pending ruling.
describe("failover verdict and notices (SSI-11, SSI-12)", () => {
  const failover = { stale_after_seconds: 35, demote_after_seconds: 20, restore_after_seconds: 150 };
  type Verdict = "fresh" | "stale" | "unobserved";
  const member = (id: string, role: "primary" | "standby", prio: number, liveness: Verdict, silent?: number) => ({
    node_id: id, role, hub_priority: prio, liveness,
    ...(silent == null ? {} : { silent_seconds: silent, metrics: { last_handshake_at: new Date(now - 60_000).toISOString(), rx_bytes: 1, tx_bytes: 1 } }),
  });
  const hs = (generation: number, ...members: ReturnType<typeof member>[]): HubSet => ({ generation, failover, members });

  it("the badge is the SERVED verdict: a young handshake does not make a stale hub look alive", () => {
    // handshake 60s old (the helper), verdict stale: the receive counter froze. The old code said Recent.
    const v = hubSetView(hs(1, member("a", "primary", 1, "stale", 50), member("b", "standby", 2, "fresh", 4)), now)!;
    expect(v.members[0].warm).toBe(false);
    expect(v.members[1].warm).toBe(true);
  });

  it("unobserved is neither warm nor cold, and gets no notice", () => {
    const v = hubSetView(hs(1, member("a", "primary", 1, "unobserved"), member("b", "standby", 2, "fresh", 4)), now)!;
    expect(v.members[0].warm).toBeNull();
    expect(failoverNotices(v)).toEqual([]);
  });

  it("a stale acting hub with an answering standby: pending, with the time left", () => {
    const v = hubSetView(hs(1, member("a", "primary", 1, "stale", 40), member("b", "standby", 2, "fresh", 4)), now)!;
    expect(failoverNotices(v)).toEqual([{ kind: "pending", nodeId: "a", ageMs: 40_000, remainingMs: 15_000 }]);
  });

  it("time left never goes negative when the ruling is overdue", () => {
    const v = hubSetView(hs(1, member("a", "primary", 1, "stale", 900), member("b", "standby", 2, "fresh", 4)), now)!;
    expect(failoverNotices(v)[0]).toMatchObject({ kind: "pending", remainingMs: 0 });
  });

  it("no standby answering: says there is nothing to promote, promises no takeover", () => {
    const v = hubSetView(hs(1, member("a", "primary", 1, "stale", 60), member("b", "standby", 2, "stale", 70)), now)!;
    expect(failoverNotices(v).map((n) => n.kind)).toEqual(["no_standby", "no_standby"]);
  });

  it("a demoted hub answering again: recovering, with the hold time", () => {
    // b acts as primary (served first), a is the configured primary and demoted.
    const v = hubSetView(hs(2, member("b", "primary", 2, "fresh", 3), member("a", "standby", 1, "fresh", 5)), now)!;
    expect(v.members[1].demoted).toBe(true);
    expect(failoverNotices(v)).toEqual([{ kind: "recovering", nodeId: "a", restoreAfterMs: 150_000 }]);
  });

  it("a demoted hub still silent: no notice, the promotion banner already says it", () => {
    const v = hubSetView(hs(2, member("b", "primary", 2, "fresh", 3), member("a", "standby", 1, "stale", 900)), now)!;
    expect(failoverNotices(v)).toEqual([]);
  });

  it("nothing for a hub nobody can observe", () => {
    const v = hubSetView(hs(1, member("a", "primary", 1, "stale", 60), member("b", "standby", 2, "fresh", 4)), now)!;
    expect(failoverNotices(v, ["a"])).toEqual([]);
  });

  it("words the spans plainly", () => {
    expect(roughDuration(0)).toBe("within a minute");
    expect(roughDuration(60_000)).toBe("in about 1 minute");
    expect(roughDuration(150_000)).toBe("in about 2.5 minutes");
    expect(spanWords(45_000)).toBe("45 seconds");
    expect(spanWords(330_000)).toBe("5.5 minutes");
    expect(spanWords(240_000)).toBe("4 minutes");
  });
});
