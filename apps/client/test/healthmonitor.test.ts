import { test } from "node:test";
import assert from "node:assert/strict";

import { HealthMonitor, HEALTH_REPORT_BASE_MS } from "../src/main/healthmonitor";
import type { HealthFacts, HealthReportResult } from "../src/main/deviceconfig";

const compliant: HealthReportResult = { state: "compliant", blocked: false, failed_checks: [] };
const blocked: HealthReportResult = {
  state: "noncompliant",
  blocked: true,
  failed_checks: [{ kind: "disk_encryption", mode: "require" }],
};

// A fake reportHealth scripted per test: a result/terminal string returns it, an
// Error is thrown (the inconclusive path). Captures the facts each call sent.
function fakeApi(script: () => HealthReportResult | "unsupported" | "gone" | Error) {
  return {
    calls: 0,
    sent: [] as HealthFacts[],
    async reportHealth(_id: string, _org: string, facts: HealthFacts): Promise<HealthReportResult | "unsupported" | "gone"> {
      this.calls++;
      this.sent.push(facts);
      const r = script();
      if (r instanceof Error) throw r;
      return r;
    },
  };
}

const goodFacts: HealthFacts = { platform: "macos", os_version: "14.5", disk_encrypted: true };

function mk(api: ReturnType<typeof fakeApi>, collect: () => Promise<HealthFacts> = async () => goodFacts) {
  const results: HealthReportResult[] = [];
  const m = new HealthMonitor("dev-1", "org-1", api, collect, (r) => {
    results.push(r);
  });
  return { m, results };
}

test("health: a report round-trips facts and surfaces the result", async () => {
  const api = fakeApi(() => compliant);
  const { m, results } = mk(api);
  assert.equal(await m.reportOnce(), "reported");
  assert.deepEqual(api.sent, [goodFacts]);
  assert.deepEqual(results, [compliant]);
});

test("health: reporting is periodic, not fire-once — a blocked verdict keeps reporting", async () => {
  const api = fakeApi(() => blocked);
  const { m, results } = mk(api);
  assert.equal(await m.reportOnce(), "reported");
  assert.equal(await m.reportOnce(), "reported"); // still reports: a later compliant report is the unblock path
  assert.deepEqual(results, [blocked, blocked]);
});

test("health: an indeterminate fact is sent ABSENT, never guessed", async () => {
  const api = fakeApi(() => compliant);
  const { m } = mk(api, async () => ({ platform: "macos", os_version: "14.5" })); // no disk fact
  assert.equal(await m.reportOnce(), "reported");
  assert.equal(api.sent.length, 1);
  assert.ok(!("disk_encrypted" in api.sent[0]), "absent fact must not be fabricated");
});

test("health: a collector throw skips the cycle — nothing dishonest is sent", async () => {
  const api = fakeApi(() => compliant);
  const { m } = mk(api, async () => {
    throw new Error("helper unreachable");
  });
  assert.equal(await m.reportOnce(), "skipped");
  assert.equal(api.calls, 0);
});

test("health: empty os_version skips (nothing useful to report)", async () => {
  const api = fakeApi(() => compliant);
  const { m } = mk(api, async () => ({ platform: "other", os_version: "" }));
  assert.equal(await m.reportOnce(), "skipped");
  assert.equal(api.calls, 0);
});

test("health: 403 open-edition is TERMINAL — stops cleanly, no retry loop", async () => {
  const api = fakeApi(() => "unsupported");
  const { m } = mk(api);
  assert.equal(await m.reportOnce(), "unsupported");
  assert.equal(await m.reportOnce(), "skipped"); // terminal: further cycles are no-ops
  assert.equal(api.calls, 1);
});

test("health: device gone is TERMINAL — teardown paths own that transition", async () => {
  const api = fakeApi(() => "gone");
  const { m } = mk(api);
  assert.equal(await m.reportOnce(), "gone");
  assert.equal(await m.reportOnce(), "skipped");
  assert.equal(api.calls, 1);
});

test("health: a server throw is inconclusive — keep reporting with capped backoff", async () => {
  let fail = true;
  const api = fakeApi(() => (fail ? new Error("blip") : compliant));
  const { m, results } = mk(api);
  assert.equal(await m.reportOnce(), "inconclusive");
  fail = false;
  assert.equal(await m.reportOnce(), "reported"); // a blip never terminates the loop
  assert.deepEqual(results, [compliant]);
});

test("health [4]: an early-phase (pre-first-report) blip retries FAST, not at 10-min base", async () => {
  const scheduled: Array<{ cb: () => void; ms: number }> = [];
  let fail = true;
  const api = fakeApi(() => (fail ? new Error("blip") : compliant));
  const settle = () => new Promise((r) => setImmediate(r));
  const m = new HealthMonitor(
    "dev-1",
    "org-1",
    api,
    async () => goodFacts,
    undefined,
    HEALTH_REPORT_BASE_MS, // 10 min base
    30 * 60_000,
    0, // no jitter
    15_000, // first/early delay
    (cb, ms) => {
      scheduled.push({ cb, ms });
      return 0 as unknown as ReturnType<typeof setTimeout>;
    },
    () => {},
  );
  m.start();
  assert.equal(scheduled[0].ms, 15_000); // early first report

  // Fire the first report; it blips BEFORE any success (early phase). The NEXT delay
  // must be the short early-retry (15s), not the 10-min base — else the device sits
  // 'unknown' for a full interval, the exact thing the 15s early report exists to avoid.
  scheduled[0].cb();
  await settle();
  assert.equal(api.calls, 1);
  assert.equal(scheduled[1].ms, 15_000);

  // Now let a report SUCCEED, then blip again: post-first-success uses the base backoff.
  fail = false;
  scheduled[1].cb();
  await settle();
  assert.equal(scheduled[2].ms, HEALTH_REPORT_BASE_MS); // steady cadence after first success
  fail = true;
  scheduled[2].cb();
  await settle();
  assert.equal(scheduled[3].ms, HEALTH_REPORT_BASE_MS); // post-success blip → base backoff, not early-retry
});

test("health: stop during the awaited report abandons the result", async () => {
  const api = {
    calls: 0,
    sent: [] as HealthFacts[],
    async reportHealth(): Promise<HealthReportResult | "unsupported" | "gone"> {
      this.calls++;
      m.stop(); // simulate a disconnect racing the in-flight report
      return compliant;
    },
  };
  const results: HealthReportResult[] = [];
  const m = new HealthMonitor("dev-1", "org-1", api, async () => goodFacts, (r) => {
    results.push(r);
  });
  assert.equal(await m.reportOnce(), "skipped");
  assert.deepEqual(results, []); // never surfaces a result after stop
});

test("health: start/stop lifecycle with injected timers — first report early, steady cadence after", async () => {
  const scheduled: Array<{ cb: () => void; ms: number }> = [];
  const api = fakeApi(() => compliant);
  const m = new HealthMonitor(
    "dev-1",
    "org-1",
    api,
    async () => goodFacts,
    undefined,
    HEALTH_REPORT_BASE_MS,
    30 * 60_000,
    0, // no jitter, deterministic
    15_000,
    (cb, ms) => {
      scheduled.push({ cb, ms });
      return 0 as unknown as ReturnType<typeof setTimeout>;
    },
    () => {},
  );
  m.start();
  assert.equal(scheduled.length, 1);
  assert.equal(scheduled[0].ms, 15_000); // early first report
  scheduled[0].cb();
  await new Promise((r) => setImmediate(r)); // let the async loop settle
  assert.equal(api.calls, 1);
  assert.equal(scheduled.length, 2);
  assert.equal(scheduled[1].ms, HEALTH_REPORT_BASE_MS); // steady cadence (jitter 0)
  m.stop();
  scheduled[1].cb();
  await new Promise((r) => setImmediate(r));
  assert.equal(api.calls, 1); // stopped: no further reports
});
