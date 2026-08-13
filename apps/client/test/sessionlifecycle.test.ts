import { test } from "node:test";
import assert from "node:assert/strict";

import { signOutPreservingDevice } from "../src/main/sessionlifecycle";

test("normal sign-out ends the session and never needs a device revoke action", async () => {
  const events: string[] = [];
  await signOutPreservingDevice({
    stopMonitors: () => events.push("stop"),
    clearSynthesizedState: () => events.push("clear-synth"),
    downTunnel: async () => { events.push("down"); },
    emitDisconnected: () => events.push("disconnected"),
    logoutSession: async () => { events.push("logout"); },
  });
  assert.deepEqual(events, ["stop", "clear-synth", "down", "disconnected", "logout"]);
});

test("normal sign-out still logs out when tunnel teardown fails", async () => {
  let loggedOut = false;
  await signOutPreservingDevice({
    stopMonitors: () => {},
    clearSynthesizedState: () => {},
    downTunnel: async () => { throw new Error("helper unavailable"); },
    emitDisconnected: () => {},
    logoutSession: async () => { loggedOut = true; },
  });
  assert.equal(loggedOut, true);
});
