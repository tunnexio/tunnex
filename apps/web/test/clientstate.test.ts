import { describe, expect, it } from "vitest";
import {
  CLIENT_STATES,
  PREVIEW_DISCLAIMER,
  formatBytes,
  formatDuration,
  formatRate,
  parsePreviewState,
  postureCheckSummary,
  stateView,
  trayAppearance,
} from "../src/lib/clientstate";

// ⛔ TEN STATES FROM THE BLOCK, PLUS ONE OF OURS.
describe("CLIENT_STATES", () => {
  it("carries every state the design names, and `failed` which it omits", () => {
    for (const s of [
      "connected",
      "connecting",
      "disconnected",
      "revoked",
      "posture_warning",
      "posture_blocked",
      "migrate_failed",
      "pending_approval",
      "helper_outdated",
      "kill_switch",
      "expired_creds",
    ] as const) {
      expect(CLIENT_STATES).toContain(s);
    }
    // Ours. A design's missing state is usually the FAILURE state — a designer drawing a healthy
    // product has nothing to look at when drawing it.
    expect(CLIENT_STATES).toContain("failed");
    expect(CLIENT_STATES).toContain("signed_out");
    expect(CLIENT_STATES).toHaveLength(13);
  });

  it("every state has a view — the switch is exhaustive", () => {
    for (const s of CLIENT_STATES) {
      const v = stateView(s);
      expect(v.label.length).toBeGreaterThan(3);
      // The detail must SAY something, not restate the label.
      expect(v.detail.length).toBeGreaterThan(25);
      expect(v.detail.toLowerCase()).not.toBe(v.label.toLowerCase());
    }
  });
});

// ⛔ "THE ICON IS NEVER GREEN WHILE THE TUNNEL IS DEAD" — the block's own rule, and the only one it
// states outright. Everything that is not a live tunnel is grey or red.
describe("trayAppearance", () => {
  it("⛔ is solid ONLY for connected", () => {
    for (const s of CLIENT_STATES) {
      expect(trayAppearance(s) === "solid").toBe(s === "connected");
    }
  });

  it("pulses only while connecting", () => {
    expect(trayAppearance("connecting")).toBe("pulsing");
  });

  it("⛔ is RED for exactly the two states where access changed without the user asking", () => {
    const red = CLIENT_STATES.filter((s) => trayAppearance(s) === "red");
    expect(red.sort()).toEqual(["kill_switch", "revoked"]);
  });

  it("posture states never render as a healthy green tunnel", () => {
    // The trap: it is a "policy" state, so it reads as benign. The tunnel is still dead.
    expect(trayAppearance("posture_blocked")).toBe("grey");
    expect(trayAppearance("posture_warning")).toBe("warning");
  });
});

// ⛔ A NOTIFICATION ON EVERY TRANSITION TRAINS PEOPLE TO DISMISS THEM, which costs exactly the two
// that matter. The block fires them for revoked and kill-switch.
describe("notifications", () => {
  it("fires for access-changing states and posture verdicts", () => {
    const notifying = CLIENT_STATES.filter((s) => stateView(s).notify);
    expect(notifying.sort()).toEqual(["kill_switch", "posture_blocked", "posture_warning", "revoked"]);
  });
});

// ⛔ NULL ACTION MEANS NO BUTTON. Offering "Connect" on a revoked device is a control that cannot
// work — worse than none.
describe("the primary verb", () => {
  it("is absent where the user genuinely cannot act", () => {
    for (const s of [
      "revoked",
      "posture_blocked",
      "pending_approval",
      "helper_outdated",
    ] as const) {
      expect(stateView(s).action, `${s} must offer no button`).toBeNull();
    }
  });

  it("is present where pressing it does something", () => {
    for (const s of [
      "connected",
      "connecting",
      "disconnected",
      "failed",
      "migrate_failed",
      "kill_switch",
      "expired_creds",
    ] as const) {
      expect(stateView(s).action, `${s} needs a verb`).toBeTruthy();
    }
  });

  it("⛔ expired creds sends the user to the BROWSER — never an in-app password field", () => {
    // The block: "MFA touches the client only via browser re-auth … NEVER an in-app password field."
    const a = stateView("expired_creds").action!;
    expect(a).toMatch(/browser/i);
    expect(a).not.toMatch(/password/i);
  });

  it("⛔ the kill-switch verb RESTORES ROUTING, and the surface must still SAY so", () => {
    // The label is now one word by founder rule, so the fact cannot live there — but it is not
    // optional. On this state "Disconnect" does NOT mean "drop the tunnel": the tunnel is already
    // down and the button lifts a BLOCK. A user who reads the button alone would think pressing it
    // makes things worse. The explanation moved into `detail`; it did not disappear.
    const v = stateView("kill_switch");
    expect(v.action).toBe("Disconnect");
    expect(v.detail).toMatch(/restore normal routing/i);
    expect(v.detail).toMatch(/blocked/i);
  });
});

describe("formatting", () => {
  it("⛔ renders n/a for unknown, never 0 — a zero nobody measured is a claim", () => {
    expect(formatBytes(null)).toBe("n/a");
    expect(formatRate(undefined)).toBe("n/a");
    expect(formatDuration(null)).toBe("n/a");
    expect(formatDuration(-1)).toBe("n/a");
  });

  it("scales bytes and keeps duration readable", () => {
    expect(formatBytes(0)).toBe("0.00 B");
    expect(formatBytes(2252)).toBe("2.20 KB");
    expect(formatDuration(65)).toBe("1:05");
    expect(formatDuration(3725)).toBe("1:02:05");
  });
});

describe("postureCheckSummary", () => {
  it("names each failed server-evaluated posture check", () => {
    const summary = postureCheckSummary([
      { kind: "disk_encryption", mode: "require" },
      { kind: "os_version", mode: "warn" },
    ]);
    expect(summary).toMatch(/disk encryption/i);
    expect(summary).toMatch(/operating system/i);
  });

  it("does not hide an unknown future check", () => {
    expect(postureCheckSummary([{ kind: "future_check", mode: "require" }])).toMatch(/future_check/);
  });
});

describe("parsePreviewState", () => {
  it("accepts only real states", () => {
    expect(parsePreviewState("?state=kill_switch")).toBe("kill_switch");
    expect(parsePreviewState("?state=nonsense")).toBeNull();
    expect(parsePreviewState("")).toBeNull();
  });

  it("⛔ the disclaimer says the preview proves the RENDER, not the transition", () => {
    expect(PREVIEW_DISCLAIMER).toMatch(/not reached by a real transition/i);
  });
});

// ⛔ THE MESH IS CUT (founder-directed); THE PLOT STAYED AND ITS SAMPLES ARE NOW REAL.
//
// The old graph was fed by `pushSample`, which invented values from `Math.random` — a 14% chance of
// a burst, otherwise a low idle band. Beside it every stat field read `n/a`. A plot of invented data
// next to an honest `n/a` is worse than either alone: the `n/a` says "not measured", the curve says
// "measured", and the one that looks like evidence is the one that is lying.
import {
  drawGraph,
  pushRate,
  rateBetween,
  THROUGHPUT_WINDOW,
} from "../src/client/throughput";

describe("throughput samples are measured, not generated", () => {
  it("⛔ a rate is a DELTA between two counter readings — no source reports bytes/sec", () => {
    const r = rateBetween(
      { bytes: 1000, at: 1_000 },
      { bytes: 3000, at: 3_000 },
    );
    expect(r).toBe(1000); // 2000 bytes over 2 seconds
  });

  it("⛔ a counter that went BACKWARDS is a rebuilt interface, not negative traffic", () => {
    // `wg show` counters reset when the tunnel is torn down and brought back. A naive delta would
    // draw a large negative spike at exactly the moment a reconnect succeeds.
    expect(
      rateBetween({ bytes: 9_000, at: 1_000 }, { bytes: 12, at: 2_000 }),
    ).toBe(0);
  });

  it("the first reading has no baseline, so it reports 0 rather than guessing", () => {
    expect(rateBetween(null, { bytes: 5_000, at: 1_000 })).toBe(0);
  });

  it("a zero or backwards clock cannot produce an infinite rate", () => {
    expect(
      rateBetween({ bytes: 0, at: 2_000 }, { bytes: 100, at: 2_000 }),
    ).toBe(0);
    expect(
      rateBetween({ bytes: 0, at: 2_000 }, { bytes: 100, at: 1_000 }),
    ).toBe(0);
  });

  it("caps the window at 64 samples so the plot scrolls rather than rescaling", () => {
    let h: number[] = [];
    for (let i = 0; i < 200; i++) h = pushRate(h, i);
    expect(h).toHaveLength(THROUGHPUT_WINDOW);
    expect(h[h.length - 1]).toBe(199); // newest last
  });

  it("never stores a negative sample", () => {
    expect(pushRate([], -5)[0]).toBe(0);
  });

  it("⛔ an all-idle session does not divide by zero", () => {
    // Normalisation is against the session peak; a flat zero series must draw a flat line, not NaN.
    const calls: number[] = [];
    const ctx = {
      clearRect() {},
      beginPath() {},
      moveTo() {},
      closePath() {},
      fill() {},
      stroke() {},
      lineTo(_x: number, y: number) {
        calls.push(y);
      },
      createLinearGradient: () => ({ addColorStop() {} }),
      strokeStyle: "",
      fillStyle: "",
      lineWidth: 0,
    } as unknown as CanvasRenderingContext2D;
    drawGraph(ctx, 100, 50, [0, 0, 0, 0]);
    expect(calls.every((y) => Number.isFinite(y))).toBe(true);
  });
});

describe("⛔ every byte value carries exactly two decimals", () => {
  it("no unit and no magnitude is an exception", () => {
    // The first attempt scaled precision to magnitude (2 decimals under 10, 1 under 100, none
    // above) and left raw BYTES returning the number verbatim. A rate is a division, so it is
    // almost never integral, and 256 B/s rendered as `256.2562562562563 B/s` — sixteen significant
    // figures, wide enough to push the row off a 440px card.
    //
    // > **A FORMATTING RULE WITH AN EXCEPTION WILL BE BROKEN BY WHICHEVER VALUE TAKES THE
    // > EXCEPTION**, and the value that took this one was the only one recomputed every second.
    expect(formatBytes(256.2562562562563)).toBe("256.26 B");
    expect(formatBytes(Math.round(45.3 * 1024 * 1024))).toBe("45.30 MB");
    expect(formatBytes(1536)).toBe("1.50 KB");
    expect(formatBytes(Math.round(512.7 * 1024))).toBe("512.70 KB");
    expect(formatBytes(999)).toBe("999.00 B");
    expect(formatRate(300.46948356807513)).toBe("300.47 B/s");
    // The invariant behind all of the above, stated once.
    for (const n of [0, 1, 999, 1024, 1536, 1048576, 12345678901]) {
      expect(formatBytes(n)).toMatch(/^\d+\.\d{2} (B|KB|MB|GB|TB)$/);
    }
  });

  it("absent is still n/a, never 0 — a zero nobody measured is a claim", () => {
    expect(formatBytes(null)).toBe("n/a");
    expect(formatRate(undefined)).toBe("n/a");
  });
});
