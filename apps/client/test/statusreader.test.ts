import { test } from "node:test";
import assert from "node:assert/strict";

import { projectTransportStatus, SingleFlightStatusReader } from "../src/main/statusreader";

function deferred<T>(): {
  promise: Promise<T>;
  resolve(value: T): void;
  reject(error: Error): void;
} {
  let resolve!: (value: T) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<T>((onResolve, onReject) => {
    resolve = onResolve;
    reject = onReject;
  });
  return { promise, resolve, reject };
}

test("concurrent status reads share one helper call and one in-flight Promise", async () => {
  const helper = deferred<{ state: string }>();
  let helperCalls = 0;
  const reader = new SingleFlightStatusReader(async () => {
    helperCalls += 1;
    return await helper.promise;
  });

  const reads = Array.from({ length: 2_000 }, () => reader.read());
  assert.equal(new Set(reads).size, 1, "callers must share one Promise rather than enter an internal queue");
  await Promise.resolve();
  assert.equal(helperCalls, 1, "an arbitrarily large pending wave must issue one helper request");

  helper.resolve({ state: "up" });
  const results = await Promise.all(reads);
  assert.equal(results.length, 2_000);
  assert.ok(results.every((result) => result.state === "up"));
});

test("a rejected status flight releases the slot for exactly one next flight", async () => {
  const first = deferred<{ state: string }>();
  const second = deferred<{ state: string }>();
  let helperCalls = 0;
  const reader = new SingleFlightStatusReader(() => {
    helperCalls += 1;
    return helperCalls === 1 ? first.promise : second.promise;
  });

  const firstA = reader.read();
  const firstB = reader.read();
  assert.equal(firstA, firstB);
  const rejectedA = assert.rejects(firstA, /helper unavailable/);
  const rejectedB = assert.rejects(firstB, /helper unavailable/);
  await Promise.resolve();
  assert.equal(helperCalls, 1);

  first.reject(new Error("helper unavailable"));
  await Promise.all([rejectedA, rejectedB]);

  const nextWave = Array.from({ length: 1_000 }, () => reader.read());
  assert.equal(new Set(nextWave).size, 1, "rejection must release one slot, not replay every queued caller");
  assert.notEqual(nextWave[0], firstA);
  await Promise.resolve();
  assert.equal(helperCalls, 2, "the next wave must start one fresh helper request");

  second.resolve({ state: "down" });
  const results = await Promise.all(nextWave);
  assert.ok(results.every((result) => result.state === "down"));
});

test("a synchronous reader throw also releases the single-flight slot", async () => {
  let helperCalls = 0;
  const reader = new SingleFlightStatusReader(async () => {
    helperCalls += 1;
    if (helperCalls === 1) throw new Error("sync-shaped failure");
    return { state: "up" };
  });

  await assert.rejects(reader.read(), /sync-shaped failure/);
  assert.deepEqual(await reader.read(), { state: "up" });
  assert.equal(helperCalls, 2);
});

test("a failed transport clears posture synthesis before status readback", async () => {
  type Status =
    | { state: "posture_blocked"; failed_checks: string[] }
    | { state: "failed" };
  let synthetic: Status | null = { state: "posture_blocked", failed_checks: ["disk_encryption"] };
  let transport: Status = { state: "failed" };

  const projected = projectTransportStatus(synthetic, transport);
  synthetic = projected.synthetic;
  transport = projected.transport;
  const reader = new SingleFlightStatusReader(async () => synthetic ?? transport);

  assert.equal(synthetic, null, "cleanup-required transport truth must supersede the posture overlay");
  assert.deepEqual(await reader.read(), { state: "failed" });
});
