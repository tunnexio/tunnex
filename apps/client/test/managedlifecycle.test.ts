import { test } from "node:test";
import assert from "node:assert/strict";

import {
  CredentialSnapshot,
  ManagedLifecycleCoordinator,
  ManagedLifecycleOperation,
  StaleManagedLeaseError,
} from "../src/main/managedlifecycle";

const credential = (token: string, server = "https://t.example"): CredentialSnapshot => ({
  server,
  token,
  fingerprint: "fingerprint-1",
  expiresAt: "2999-01-01T00:00:00Z",
});

test("serial is FIFO and lifecycle operations never overlap", async () => {
  let releaseFirst!: () => void;
  let markFirstEntered!: () => void;
  const firstEntered = new Promise<void>((resolve) => { markFirstEntered = resolve; });
  const holdFirst = new Promise<void>((resolve) => { releaseFirst = resolve; });
  const events: string[] = [];
  let inFlight = 0;
  let maximumInFlight = 0;
  const coordinator = new ManagedLifecycleCoordinator(() => credential("token-a"));

  const first = coordinator.serial(async () => {
    inFlight += 1;
    maximumInFlight = Math.max(maximumInFlight, inFlight);
    events.push("first:start");
    markFirstEntered();
    await holdFirst;
    events.push("first:end");
    inFlight -= 1;
  });
  const second = coordinator.serial(async () => {
    inFlight += 1;
    maximumInFlight = Math.max(maximumInFlight, inFlight);
    events.push("second");
    inFlight -= 1;
  });

  await firstEntered;
  assert.deepEqual(events, ["first:start"]);
  releaseFirst();
  await Promise.all([first, second]);
  assert.deepEqual(events, ["first:start", "first:end", "second"]);
  assert.equal(maximumInFlight, 1);
});

test("advance and invalidate produce unique epochs and stale guards", async () => {
  let stored: CredentialSnapshot | null = credential("token-a");
  const coordinator = new ManagedLifecycleCoordinator(() => stored);
  const captured = await coordinator.capture(async () => "user-a");
  const active = await coordinator.serial((owner) => owner.advance(captured));

  assert.notEqual(active.epoch, captured.epoch);
  assert.throws(() => coordinator.assertCurrent(captured), StaleManagedLeaseError);
  coordinator.assertCurrent(active);

  await coordinator.serial((owner) => owner.invalidate());
  assert.throws(() => coordinator.assertCurrent(active), StaleManagedLeaseError);
  const next = await coordinator.capture(async () => "user-a");
  assert.equal(new Set([captured.epoch, active.epoch, next.epoch]).size, 3);

  stored = null;
  assert.throws(() => coordinator.assertCurrent(next), StaleManagedLeaseError);
});

test("changing any credential field invalidates an otherwise identical lease", async () => {
  const changes: Array<(stored: CredentialSnapshot) => CredentialSnapshot> = [
    (stored) => ({ ...stored, server: "https://other.example" }),
    (stored) => ({ ...stored, token: "token-b" }),
    (stored) => ({ ...stored, fingerprint: "fingerprint-2" }),
    (stored) => ({ ...stored, expiresAt: "2998-01-01T00:00:00Z" }),
  ];

  for (const change of changes) {
    let stored = credential("token-a");
    const coordinator = new ManagedLifecycleCoordinator(() => stored);
    const lease = await coordinator.capture(async () => "user-a");
    stored = change(stored);
    assert.throws(() => coordinator.assertCurrent(lease), StaleManagedLeaseError);
  }
});

test("capture rejects A when the store becomes B during fixed-token user resolution", async () => {
  let stored = credential("token-a");
  const coordinator = new ManagedLifecycleCoordinator(() => stored);
  let resolverToken = "";

  await assert.rejects(
    coordinator.capture(async (fixed) => {
      resolverToken = fixed.token;
      stored = { ...stored, token: "token-b", fingerprint: "fingerprint-2" };
      return "user-a";
    }),
    StaleManagedLeaseError,
  );
  assert.equal(resolverToken, "token-a");
});

test("login replacement refuses a valid session and otherwise downs before invalidate/stop/save", async () => {
  let stored = credential("token-a");
  const coordinator = new ManagedLifecycleCoordinator(() => stored);
  const oldLease = await coordinator.capture(async () => "user-a");
  const refusedEvents: string[] = [];

  await assert.rejects(coordinator.replaceLogin({
    resolveServer: () => "https://t.example",
    sessionIsValid: async (fixed) => {
      refusedEvents.push(`valid:${fixed.token}`);
      return true;
    },
    stopMonitors: () => { refusedEvents.push("stop"); },
    downTunnel: async () => { refusedEvents.push("down"); },
    publishDown: () => { refusedEvents.push("publish-down"); },
    saveCredential: () => { refusedEvents.push("save"); },
  }), /managed session is already active/);
  assert.deepEqual(refusedEvents, ["valid:token-a"]);
  coordinator.assertCurrent(oldLease);

  const replacementEvents: string[] = [];
  const result = await coordinator.replaceLogin({
    resolveServer: () => "https://t.example",
    sessionIsValid: async (fixed) => {
      replacementEvents.push(`valid:${fixed.token}`);
      return false;
    },
    stopMonitors: () => {
      assert.throws(() => coordinator.assertCurrent(oldLease), StaleManagedLeaseError);
      replacementEvents.push("stop");
    },
    downTunnel: async () => { replacementEvents.push("down"); },
    publishDown: () => {
      coordinator.assertCurrent(oldLease);
      replacementEvents.push("publish-down");
    },
    saveCredential: (server) => {
      replacementEvents.push(`save:${server}`);
      stored = credential("token-b");
      return "saved-b";
    },
  });

  assert.equal(result, "saved-b");
  assert.deepEqual(replacementEvents, ["valid:token-a", "down", "publish-down", "stop", "save:https://t.example"]);
});

test("login resolves its server after a queued server change commits", async () => {
  let server = "https://a.example";
  const coordinator = new ManagedLifecycleCoordinator(() => null);
  let markChangeEntered!: () => void;
  let releaseChange!: () => void;
  const changeEntered = new Promise<void>((resolve) => { markChangeEntered = resolve; });
  const holdChange = new Promise<void>((resolve) => { releaseChange = resolve; });
  const events: string[] = [];

  const serverChange = coordinator.serial(async () => {
    markChangeEntered();
    await holdChange;
    server = "https://b.example";
    events.push("server:b");
  });
  await changeEntered;

  const login = coordinator.replaceLogin({
    resolveServer: () => {
      events.push(`resolve:${server}`);
      return server;
    },
    sessionIsValid: async () => false,
    stopMonitors: () => { events.push("stop"); },
    downTunnel: async () => { events.push("down"); },
    publishDown: () => { events.push("publish-down"); },
    saveCredential: (resolvedServer) => {
      events.push(`save:${resolvedServer}`);
      return resolvedServer;
    },
  });

  releaseChange();
  await serverChange;
  assert.equal(await login, "https://b.example");
  assert.deepEqual(events, [
    "server:b",
    "resolve:https://b.example",
    "down",
    "publish-down",
    "stop",
    "save:https://b.example",
  ]);
});

test("credential drift during session validation performs zero replacement effects", async () => {
  const original = credential("token-a");
  let stored = original;
  const coordinator = new ManagedLifecycleCoordinator(() => stored);
  const oldLease = await coordinator.capture(async () => "user-a");
  const effects = { stop: 0, down: 0, save: 0 };

  await assert.rejects(coordinator.replaceLogin({
    resolveServer: () => "https://t.example",
    sessionIsValid: async (fixed) => {
      stored = { ...fixed, token: "token-b" };
      return false;
    },
    stopMonitors: () => { effects.stop += 1; },
    downTunnel: async () => { effects.down += 1; },
    publishDown: () => {},
    saveCredential: () => { effects.save += 1; },
  }), StaleManagedLeaseError);

  assert.deepEqual(effects, { stop: 0, down: 0, save: 0 });
  stored = original;
  coordinator.assertCurrent(oldLease);
});

test("login publishes confirmed down before invalidation and preserves it when credential save fails", async () => {
  const stored = credential("token-a");
  const coordinator = new ManagedLifecycleCoordinator(() => stored);
  const oldLease = await coordinator.capture(async () => "user-a");
  const events: string[] = [];

  await assert.rejects(coordinator.replaceLogin({
    resolveServer: () => "https://t.example",
    sessionIsValid: async () => false,
    downTunnel: async () => { events.push("down"); },
    publishDown: () => {
      coordinator.assertCurrent(oldLease);
      events.push("publish-down");
    },
    stopMonitors: () => {
      assert.throws(() => coordinator.assertCurrent(oldLease), StaleManagedLeaseError);
      events.push("stop");
    },
    saveCredential: () => {
      events.push("save");
      throw new Error("login cancelled");
    },
  }), /login cancelled/);

  assert.deepEqual(events, ["down", "publish-down", "stop", "save"]);
  assert.throws(() => coordinator.assertCurrent(oldLease), StaleManagedLeaseError);
});

test("a throwing FIFO operation releases the next waiter", async () => {
  const coordinator = new ManagedLifecycleCoordinator(() => credential("token-a"));
  const events: string[] = [];
  const failed = coordinator.serial(() => {
    events.push("failed");
    throw new Error("boom");
  });
  const next = coordinator.serial(() => {
    events.push("next");
    return "recovered";
  });

  await assert.rejects(failed, /boom/);
  assert.equal(await next, "recovered");
  assert.deepEqual(events, ["failed", "next"]);
});

test("an escaped serial-operation capability expires with its FIFO turn", async () => {
  const coordinator = new ManagedLifecycleCoordinator(() => credential("token-a"));
  let escaped!: ManagedLifecycleOperation;
  await coordinator.serial((owner) => { escaped = owner; });

  assert.throws(() => escaped.invalidate(), /managed lifecycle operation is no longer active/);
});

test("guarded work owns the FIFO until it finishes and invalidation queues behind it", async () => {
  const stored = credential("token-a");
  const coordinator = new ManagedLifecycleCoordinator(() => stored);
  const captured = await coordinator.capture(async () => "user-a");
  const active = await coordinator.serial((owner) => owner.advance(captured));
  let markGuardEntered!: () => void;
  let releaseGuard!: () => void;
  const guardEntered = new Promise<void>((resolve) => { markGuardEntered = resolve; });
  const holdGuard = new Promise<void>((resolve) => { releaseGuard = resolve; });
  const events: string[] = [];

  const guarded = coordinator.guarded(active, async () => {
    events.push("guard:start");
    markGuardEntered();
    await holdGuard;
    events.push("guard:end");
  });
  await guardEntered;
  const invalidation = coordinator.serial((owner) => {
    events.push("invalidate");
    owner.invalidate();
  });
  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.deepEqual(events, ["guard:start"], "invalidation must not enter during a guarded effect");

  releaseGuard();
  await Promise.all([guarded, invalidation]);
  assert.deepEqual(events, ["guard:start", "guard:end", "invalidate"]);

  let staleEffect = 0;
  assert.equal(await coordinator.guarded(active, () => { staleEffect += 1; }), undefined);
  assert.equal(staleEffect, 0);
});

test("a stale monitor lease performs zero server, helper, store, or notification effects", async () => {
  const stored = credential("token-a");
  const coordinator = new ManagedLifecycleCoordinator(() => stored);
  const stale = await coordinator.capture(async () => "user-a");
  await coordinator.serial((owner) => owner.invalidate());
  const effects = { server: 0, helper: 0, store: 0, notification: 0 };

  const result = await coordinator.guarded(stale, async () => {
    effects.server += 1;
    effects.helper += 1;
    effects.store += 1;
    effects.notification += 1;
    return "mutated";
  });

  assert.equal(result, undefined);
  assert.deepEqual(effects, { server: 0, helper: 0, store: 0, notification: 0 });
});

test("a terminal callback fences queued work for the same lease before its effects", async () => {
  const stored = credential("token-a");
  const coordinator = new ManagedLifecycleCoordinator(() => stored);
  const captured = await coordinator.capture(async () => "user-a");
  const active = await coordinator.serial((owner) => owner.advance(captured));
  const events: string[] = [];

  const terminal = coordinator.terminal(active, () => {
    events.push("terminal");
    assert.throws(() => coordinator.assertCurrent(active), StaleManagedLeaseError);
  });
  const queued = coordinator.guarded(active, () => {
    events.push("stale-effect");
  });

  assert.equal(await terminal, undefined);
  assert.equal(await queued, undefined);
  assert.deepEqual(events, ["terminal"]);
});

test("a stale terminal callback performs zero effects and does not advance the current lease", async () => {
  const stored = credential("token-a");
  const coordinator = new ManagedLifecycleCoordinator(() => stored);
  const stale = await coordinator.capture(async () => "user-a");
  const current = await coordinator.serial((owner) => owner.advance(stale));
  let effects = 0;

  assert.equal(await coordinator.terminal(stale, () => { effects += 1; }), undefined);
  assert.equal(effects, 0);
  coordinator.assertCurrent(current);
});
