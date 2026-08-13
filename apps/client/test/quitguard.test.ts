import { test } from "node:test";
import assert from "node:assert/strict";

import { gracefulQuit } from "../src/main/quitguard";

// gracefulQuit lives in an electron-free module so it imports cleanly in CI (where
// require("electron") throws). It must ALWAYS quit — after a clean disconnect, after a
// disconnect error, and after a hung disconnect (via the timeout) — so a teardown
// problem can never wedge the app's exit.

test("gracefulQuit: disconnects then quits on the happy path", async () => {
  const calls: string[] = [];
  await gracefulQuit(
    async () => {
      calls.push("disconnect");
    },
    () => calls.push("quit"),
    1000,
  );
  assert.deepEqual(calls, ["disconnect", "quit"]); // Down BEFORE quit
});

test("gracefulQuit: still quits when disconnect rejects", async () => {
  let quit = false;
  await gracefulQuit(
    async () => {
      throw new Error("helper gone");
    },
    () => {
      quit = true;
    },
    1000,
  );
  assert.ok(quit, "quit must proceed even if disconnect rejects");
});

test("gracefulQuit: still quits when disconnect throws synchronously", async () => {
  let quit = false;
  await gracefulQuit(
    () => {
      throw new Error("sync boom");
    },
    () => {
      quit = true;
    },
    1000,
  );
  assert.ok(quit, "a sync throw must not block quit");
});

test("gracefulQuit: quits via the timeout when disconnect hangs", async () => {
  let quit = false;
  const start = Date.now();
  await gracefulQuit(
    () => new Promise<void>(() => {}), // never resolves
    () => {
      quit = true;
    },
    50, // short timeout for the test
  );
  assert.ok(quit, "a hung disconnect must not block quit past the timeout");
  assert.ok(Date.now() - start >= 45, "quit should wait for (roughly) the timeout");
});
