import { test } from "node:test";
import assert from "node:assert/strict";

import { signOutPreservingDevice } from "../src/main/sessionlifecycle";

test("normal sign-out ends the session and never needs a device revoke action", async () => {
  const events: string[] = [];
  await signOutPreservingDevice({
    retireLifecycle: () => events.push("retire"),
    stopMonitors: () => events.push("stop"),
    clearSynthesizedState: () => events.push("clear-synth"),
    downTunnel: async () => { events.push("down"); },
    emitDisconnected: () => events.push("disconnected"),
    logoutSession: async () => { events.push("logout"); },
  });
  assert.deepEqual(events, ["down", "retire", "stop", "clear-synth", "disconnected", "logout"]);
});

test("tunnel teardown refusal aborts sign-out before lifecycle, monitor, or credential effects", async () => {
  let loggedOut = false;
  const events: string[] = [];
  await assert.rejects(signOutPreservingDevice({
    retireLifecycle: () => events.push("retire"),
    stopMonitors: () => events.push("stop"),
    clearSynthesizedState: () => events.push("clear-synth"),
    downTunnel: async () => { throw new Error("helper unavailable"); },
    emitDisconnected: () => events.push("disconnected"),
    logoutSession: async () => { loggedOut = true; },
  }), /helper unavailable/);
  assert.equal(loggedOut, false);
  assert.deepEqual(events, []);
});
