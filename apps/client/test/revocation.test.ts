import { test } from "node:test";
import assert from "node:assert/strict";

import { RevocationMonitor, REVOKE_POLL_MS, REVOKE_BACKOFF_MAX_MS } from "../src/main/revocation";

// A fake device API whose deviceExists is scripted per test: a boolean returns that
// existence, an Error is thrown (the inconclusive path).
function fakeApi(script: () => boolean | Error) {
  return {
    calls: 0,
    async deviceExists(_id: string): Promise<boolean> {
      this.calls++;
      const r = script();
      if (r instanceof Error) throw r;
      return r;
    },
  };
}

test("revocation: a definitive gone tears down exactly once", async () => {
  const api = fakeApi(() => false); // device gone
  let teardowns = 0;
  const m = new RevocationMonitor("dev-1", "org-1", api, () => {
    teardowns++;
  });
  assert.equal(await m.checkOnce(), "torn-down");
  assert.equal(teardowns, 1);
  // Fire-once: a subsequent probe must NOT re-fire (fired latch), even though the
  // device is still reported gone.
  assert.equal(await m.checkOnce(), "skipped");
  assert.equal(teardowns, 1);
});

test("revocation: a present device is kept (no teardown)", async () => {
  const api = fakeApi(() => true);
  let teardowns = 0;
  const m = new RevocationMonitor("dev-1", "org-1", api, () => {
    teardowns++;
  });
  assert.equal(await m.checkOnce(), "kept");
  assert.equal(await m.checkOnce(), "kept");
  assert.equal(teardowns, 0);
});

test("revocation: a throw is inconclusive — never tears down, backs off", async () => {
  const api = fakeApi(() => new Error("network"));
  let teardowns = 0;
  // Small base so the backoff math is easy to assert.
  const m = new RevocationMonitor("dev-1", "org-1", api, () => { teardowns++; }, 1000, 8000);

  // Every throw KEEPS the tunnel (fail-safe) and doubles the next delay, capped.
  assert.equal(await m.checkOnce(), "inconclusive");
  assert.equal(backoffOf(m), 1000); // first backoff = base
  assert.equal(await m.checkOnce(), "inconclusive");
  assert.equal(backoffOf(m), 2000);
  assert.equal(await m.checkOnce(), "inconclusive");
  assert.equal(backoffOf(m), 4000);
  assert.equal(await m.checkOnce(), "inconclusive");
  assert.equal(backoffOf(m), 8000); // capped at maxMs
  assert.equal(await m.checkOnce(), "inconclusive");
  assert.equal(backoffOf(m), 8000); // stays capped
  assert.equal(teardowns, 0); // NEVER tore down on a blip
});

test("revocation: a healthy probe after backoff returns to steady cadence", async () => {
  let ok = false;
  const api = fakeApi(() => (ok ? true : new Error("network")));
  const m = new RevocationMonitor("dev-1", "org-1", api, () => {}, 1000, 8000);
  await m.checkOnce(); // throw → backoff 1000
  await m.checkOnce(); // throw → backoff 2000
  assert.equal(backoffOf(m), 2000);
  ok = true;
  assert.equal(await m.checkOnce(), "kept");
  assert.equal(backoffOf(m), 0); // backoff reset → steady cadence
});

test("revocation: stop() mid-probe abandons the result (no teardown behind the user)", async () => {
  let release!: () => void;
  const gate = new Promise<void>((r) => (release = r));
  const api = {
    async deviceExists(): Promise<boolean> {
      await gate; // hold the probe open until we stop()
      return false; // would be a teardown if not abandoned
    },
  };
  let teardowns = 0;
  const m = new RevocationMonitor("dev-1", "org-1", api, () => { teardowns++; });
  const p = m.checkOnce();
  m.stop(); // user disconnects while the probe is in flight
  release();
  assert.equal(await p, "skipped");
  assert.equal(teardowns, 0); // the in-flight gone-result was abandoned, not acted on
});

test("revocation: no probes overlap and none run while stopped (self-scheduling loop)", async () => {
  let inFlight = 0;
  let maxConcurrent = 0;
  const api = {
    async deviceExists(): Promise<boolean> {
      inFlight++;
      maxConcurrent = Math.max(maxConcurrent, inFlight);
      await Promise.resolve();
      inFlight--;
      return true;
    },
  };
  // Drive the loop with a synchronous fake timer so several ticks run back-to-back;
  // the self-scheduling design must still never overlap two probes.
  const pending: Array<() => void> = [];
  const m = new RevocationMonitor(
    "dev-1",
    "org-1",
    api,
    () => {},
    10,
    100,
    (cb) => {
      pending.push(cb);
      return 0 as unknown as ReturnType<typeof setTimeout>;
    },
    () => {},
  );
  m.start();
  // Fire a handful of scheduled ticks.
  for (let i = 0; i < 5 && pending.length; i++) {
    const cb = pending.shift()!;
    cb();
    await Promise.resolve();
    await Promise.resolve();
  }
  assert.equal(maxConcurrent, 1); // never two probes at once
  assert.ok(api.deviceExists); // touch api so the closure isn't flagged unused
  m.stop();
});

test("revocation: start() is idempotent even mid-probe (no second concurrent loop)", async () => {
  let scheduled = 0;
  const pending: Array<() => void> = [];
  const api = { async deviceExists(): Promise<boolean> { return true; } };
  const m = new RevocationMonitor(
    "dev-1",
    "org-1",
    api,
    () => {},
    10,
    100,
    (cb) => {
      scheduled++;
      pending.push(cb);
      return scheduled as unknown as ReturnType<typeof setTimeout>;
    },
    () => {},
  );
  m.start();
  assert.equal(scheduled, 1); // first schedule armed
  // A second start() while the first probe is in flight (timer transiently null) must
  // NOT arm a second loop — the running-flag guard, not a timer-presence check.
  const cb = pending.shift()!; // simulate the timer firing → loop() nulls timer, awaits probe
  cb();
  m.start(); // re-entrant start during the in-flight probe
  await Promise.resolve();
  await Promise.resolve();
  // Only the loop's own reschedule should have armed a new timer — not a second start.
  assert.equal(scheduled, 2);
  m.stop();
});

test("revocation: exported cadence constants are the documented values", () => {
  assert.equal(REVOKE_POLL_MS, 30_000);
  assert.equal(REVOKE_BACKOFF_MAX_MS, 300_000);
});

// backoffOf reads the private backoff for assertion only (0 = steady cadence). Kept
// in the test, not the class, so production carries no test-only surface.
function backoffOf(m: RevocationMonitor): number {
  // @ts-expect-error — private field read for the test.
  return m.backoff as number;
}

// THE REGRESSION RED (S7.3 fold #4/#6 → #1/#2): a LEGACY config (blank orgId, from a
// pre-orgId build) must still detect a revocation. The monitor passes "" through; device
// (deviceStatus) falls back to the all-orgs scan, so a gone device fires teardown — instead
// of the malformed-URL throw that would have made revocation SILENTLY never fire.
