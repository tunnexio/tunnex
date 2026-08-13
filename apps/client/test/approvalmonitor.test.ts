import { test } from "node:test";
import assert from "node:assert/strict";

import { ApprovalMonitor, APPROVAL_POLL_MS } from "../src/main/approvalmonitor";

// A fake device API whose deviceStatus is scripted per test: a status string returns
// it, an Error is thrown (the inconclusive path).
function fakeApi(script: () => "pending" | "active" | "gone" | Error) {
  return {
    calls: 0,
    async deviceStatus(_id: string): Promise<"active" | "pending" | "gone"> {
      this.calls++;
      const r = script();
      if (r instanceof Error) throw r;
      return r;
    },
  };
}

function mk(api: { deviceStatus: (id: string) => Promise<"active" | "pending" | "gone"> }) {
  const events: string[] = [];
  const m = new ApprovalMonitor(
    "dev-1",
    "org-1",
    api,
    () => { events.push("approved"); },
    () => { events.push("rejected"); },
  );
  return { m, events };
}

test("approval: pending keeps waiting — no transition, calm", async () => {
  const api = fakeApi(() => "pending");
  const { m, events } = mk(api);
  assert.equal(await m.checkOnce(), "waiting");
  assert.equal(await m.checkOnce(), "waiting");
  assert.deepEqual(events, []); // never transitions while pending
});

test("approval: active fires onApproved exactly once, then stops", async () => {
  const api = fakeApi(() => "active");
  const { m, events } = mk(api);
  assert.equal(await m.checkOnce(), "approved");
  assert.deepEqual(events, ["approved"]);
  // Fire-once: a subsequent probe must not re-fire.
  assert.equal(await m.checkOnce(), "skipped");
  assert.deepEqual(events, ["approved"]);
});

test("approval: gone (rejected) fires onRejected exactly once", async () => {
  const api = fakeApi(() => "gone");
  const { m, events } = mk(api);
  assert.equal(await m.checkOnce(), "rejected");
  assert.deepEqual(events, ["rejected"]);
  assert.equal(await m.checkOnce(), "skipped");
  assert.deepEqual(events, ["rejected"]);
});

test("approval: a throw is INCONCLUSIVE — never reads as rejected, backs off", async () => {
  const api = fakeApi(() => new Error("network blip"));
  const { m, events } = mk(api);
  // A blip while awaiting must NEVER transition (the deviceExists empty-orgs lesson).
  assert.equal(await m.checkOnce(), "inconclusive");
  assert.equal(await m.checkOnce(), "inconclusive");
  assert.deepEqual(events, []); // NEVER rejected/approved on a transient error
});

test("approval: a blip then approval still transitions (recovers)", async () => {
  let phase: "blip" | "active" = "blip";
  const api = fakeApi(() => (phase === "blip" ? new Error("blip") : "active"));
  const { m, events } = mk(api);
  assert.equal(await m.checkOnce(), "inconclusive");
  assert.deepEqual(events, []);
  phase = "active";
  assert.equal(await m.checkOnce(), "approved");
  assert.deepEqual(events, ["approved"]);
});

test("approval: stop() abandons — a probe after stop does nothing", async () => {
  const api = fakeApi(() => "active");
  const { m, events } = mk(api);
  m.stop();
  assert.equal(await m.checkOnce(), "skipped");
  assert.deepEqual(events, []);
});

test("approval: base poll cadence is the exported constant", () => {
  assert.equal(APPROVAL_POLL_MS, 30_000);
});
