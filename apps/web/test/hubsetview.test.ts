import { describe, it, expect } from "vitest";
import { hubSetView, formatBytes } from "../src/lib/hubsetview";
import type { HubSet } from "../src/lib/api";

const now = Date.parse("2026-07-20T12:00:00Z");
const fresh = "2026-07-20T11:59:50Z"; // 10s ago
const stale = "2026-07-20T11:00:00Z"; // 1h ago

describe("hubSetView (S8.6 HA surface view-model)", () => {
  it("null for an unpinned org (no HA hub set → no surface)", () => {
    expect(hubSetView(null, now)).toBeNull();
    expect(hubSetView({ generation: 0, members: [] }, now)).toBeNull();
  });

  it("ordered role (primary=members[0]) + generation as the version tag", () => {
    const hs: HubSet = {
      generation: 7,
      members: [
        {
          node_id: "a",
          role: "primary",
          hub_priority: 1,
          metrics: { last_handshake_at: fresh, rx_bytes: 2048, tx_bytes: 0 },
        },
        { node_id: "b", role: "standby", hub_priority: 2 },
      ],
    };
    const v = hubSetView(hs, now)!;
    expect(v.generation).toBe(7);
    expect(v.members[0].role).toBe("primary");
    expect(v.members[1].role).toBe("standby");
  });

  it("render-floor: idle-reporting shows 0 B (honest); NOT-reporting shows — (absent, never 0)", () => {
    const hs: HubSet = {
      generation: 3,
      members: [
        {
          node_id: "a",
          role: "primary",
          hub_priority: 1,
          metrics: { last_handshake_at: fresh, rx_bytes: 0, tx_bytes: 0 },
        }, // idle
        { node_id: "b", role: "standby", hub_priority: 2 }, // NOT reporting (no metrics)
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

  it("warm reflects the handshake clock: fresh → true, stale → false", () => {
    const hs: HubSet = {
      generation: 1,
      members: [
        {
          node_id: "a",
          role: "primary",
          hub_priority: 1,
          metrics: { last_handshake_at: stale, rx_bytes: 5, tx_bytes: 5 },
        },
      ],
    };
    expect(hubSetView(hs, now)!.members[0].warm).toBe(false);
  });

  it("promotion in effect: the acting primary ≠ the configured primary (lowest pin) → demoted flag on the config primary", () => {
    // b is pinned #1 (configured primary) but STALE; the active order made a (#2) primary → a failover.
    const hs: HubSet = {
      generation: 9,
      members: [
        {
          node_id: "a",
          role: "primary",
          hub_priority: 2,
          metrics: { last_handshake_at: fresh, rx_bytes: 1, tx_bytes: 1 },
        },
        {
          node_id: "b",
          role: "standby",
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
      generation: 4,
      members: [
        { node_id: "a", role: "primary", hub_priority: 1 },
        { node_id: "b", role: "standby", hub_priority: 2 },
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
