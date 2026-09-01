import { test } from "node:test";
import assert from "node:assert/strict";

import {
  ManagedLifecycleCoordinator,
  StaleManagedLeaseError,
  type CredentialSnapshot,
  type ManagedLease,
  type ManagedLifecycleOperation,
} from "../src/main/managedlifecycle";
import {
  buildManagedConnectPreparation,
  runManagedConnectFlow,
  runManagedDisconnectFlow,
  runManagedRemoveFlow,
  runTerminalRevocationFlow,
  type FixedManagedConnectContext,
  type ManagedConnectProviderArguments,
  type TerminalRevocationProblems,
} from "../src/main/managedlifecycleflows";

const credential = (token: string, server: string): CredentialSnapshot => ({
  server,
  token,
  fingerprint: `fingerprint-${token}`,
  expiresAt: "2999-01-01T00:00:00Z",
});

function deferred(): { promise: Promise<void>; resolve(): void } {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => { resolve = done; });
  return { promise, resolve };
}

interface ConnectSpec {
  readonly label: string;
  readonly token: string;
  readonly server: string;
  readonly userId: string;
  readonly organizationId: string;
  readonly ownerId: string;
  readonly fullTunnel: boolean;
}

interface ConnectApi {
  readonly ownerId: string;
}

interface FixedConfig {
  readonly userId: string;
  readonly organizationId: string;
  readonly ownerId: string;
  readonly fullTunnel: boolean;
  readonly token: string;
}

test("queued A/B connects keep one fixed user, organization, owner/provider, and mode tuple", async () => {
  const a: ConnectSpec = {
    label: "A",
    token: "token-a",
    server: "https://a.example",
    userId: "user-a",
    organizationId: "org-a",
    ownerId: "owner-a",
    fullTunnel: false,
  };
  const b: ConnectSpec = {
    label: "B",
    token: "token-b",
    server: "https://b.example",
    userId: "user-b",
    organizationId: "org-b",
    ownerId: "owner-b",
    fullTunnel: true,
  };
  let stored = credential(a.token, a.server);
  const coordinator = new ManagedLifecycleCoordinator(() => stored);
  const holdA = deferred();
  const aUpEntered = deferred();
  const events: string[] = [];

  const enqueue = (spec: ConnectSpec): Promise<FixedConfig> => coordinator.serial((owner) =>
    runManagedConnectFlow<FixedManagedConnectContext<ConnectApi>, FixedConfig, FixedConfig, FixedConfig>(owner, {
      proveAndPrepare: async () => {
        events.push(`${spec.label}:proof`);
        stored = credential(spec.token, spec.server);
        const lease = await coordinator.capture(async (fixed) => {
          assert.equal(fixed.token, spec.token);
          assert.equal(fixed.server, spec.server);
          return spec.userId;
        });
        return buildManagedConnectPreparation({
          lease,
          organizationId: spec.organizationId,
          fullTunnel: spec.fullTunnel,
          origin: spec.server,
          api: { ownerId: spec.ownerId },
          resolveConfig: async (arguments_) => {
            events.push(`${spec.label}:provider`);
            return {
              userId: arguments_.userId,
              organizationId: arguments_.organizationId,
              ownerId: arguments_.api.ownerId,
              fullTunnel: arguments_.fullTunnel,
              token: arguments_.credential.token,
            };
          },
        });
      },
      quiesceExisting: () => { events.push(`${spec.label}:quiesce`); },
      publishQuiesced: () => { events.push(`${spec.label}:confirmed-down`); },
      prepareRuntime: (connection) => {
        events.push(`${spec.label}:runtime`);
        assert.equal(connection.lease.userId, spec.userId);
      },
      installHelper: () => { events.push(`${spec.label}:helper`); },
      up: async (provider, connection) => {
        events.push(`${spec.label}:up`);
        assert.equal(provider, connection.configProvider);
        assert.equal(connection.organizationId, spec.organizationId);
        assert.equal(connection.context.origin, spec.server);
        assert.equal(connection.context.api.ownerId, spec.ownerId);
        assert.equal(connection.fullTunnel, spec.fullTunnel);
        const fixed = await provider();
        if (spec.label === "A") {
          aUpEntered.resolve();
          await holdA.promise;
        }
        return fixed;
      },
      onUpError: (error) => { throw error; },
      publish: (connection, fixed) => {
        events.push(`${spec.label}:publish`);
        assert.deepEqual(fixed, {
          userId: spec.userId,
          organizationId: spec.organizationId,
          ownerId: spec.ownerId,
          fullTunnel: spec.fullTunnel,
          token: spec.token,
        });
        assert.equal(connection.lease.credential.token, spec.token);
        return fixed;
      },
    }));

  const connectA = enqueue(a);
  await aUpEntered.promise;
  const connectB = enqueue(b);
  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.equal(events.some((event) => event.startsWith("B:")), false);

  holdA.resolve();
  const [resultA, resultB] = await Promise.all([connectA, connectB]);
  assert.equal(resultA.token, "token-a");
  assert.equal(resultB.token, "token-b");
  assert.deepEqual(events, [
    "A:proof", "A:quiesce", "A:confirmed-down", "A:runtime", "A:helper", "A:up", "A:provider", "A:publish",
    "B:proof", "B:quiesce", "B:confirmed-down", "B:runtime", "B:helper", "B:up", "B:provider", "B:publish",
  ]);
});

test("the preparation builder snapshots caller variables before its provider runs", async () => {
  const sourceLease = {
    epoch: 7,
    credential: credential("token-a", "https://a.example"),
    userId: "user-a",
  } as ManagedLease;
  const apiA = { ownerId: "owner-a" };
  const apiB = { ownerId: "owner-b" };
  const observed: Array<ManagedConnectProviderArguments<{ ownerId: string }>> = [];
  const input = {
    lease: sourceLease,
    organizationId: "org-a",
    fullTunnel: false,
    origin: "https://a.example",
    api: apiA,
    resolveConfig: async (arguments_: ManagedConnectProviderArguments<{ ownerId: string }>): Promise<FixedConfig> => {
      observed.push(arguments_);
      return {
        userId: arguments_.userId,
        organizationId: arguments_.organizationId,
        ownerId: arguments_.api.ownerId,
        fullTunnel: arguments_.fullTunnel,
        token: arguments_.credential.token,
      };
    },
  };

  const prepared = buildManagedConnectPreparation(input);

  // Reassign every caller-owned field and mutate the source lease after build.
  // The provider must still receive the one tuple that passed proof.
  input.lease = {
    epoch: 8,
    credential: credential("token-b", "https://b.example"),
    userId: "user-b",
  };
  input.organizationId = "org-b";
  input.fullTunnel = true;
  input.origin = "https://b.example";
  input.api = apiB;
  input.resolveConfig = async () => { throw new Error("replacement resolver must not run"); };
  (sourceLease as { epoch: number }).epoch = 99;
  (sourceLease as { userId: string }).userId = "mutated-user";
  (sourceLease.credential as { token: string }).token = "mutated-token";

  assert.deepEqual(await prepared.configProvider(), {
    userId: "user-a",
    organizationId: "org-a",
    ownerId: "owner-a",
    fullTunnel: false,
    token: "token-a",
  });
  assert.equal(prepared.lease.epoch, 7);
  assert.equal(prepared.context.origin, "https://a.example");
  assert.equal(prepared.context.api, apiA);
  assert.equal(observed.length, 1);
  assert.equal(observed[0].lease, prepared.lease);
  assert.equal(observed[0].credential, prepared.lease.credential);
  assert.ok(Object.isFrozen(prepared));
  assert.ok(Object.isFrozen(prepared.lease));
  assert.ok(Object.isFrozen(prepared.lease.credential));
  assert.ok(Object.isFrozen(prepared.context));
  assert.ok(Object.isFrozen(observed[0]));
});

test("the preparation builder rejects an origin outside its credential snapshot", () => {
  const lease = {
    epoch: 1,
    credential: credential("token-a", "https://a.example"),
    userId: "user-a",
  } as ManagedLease;
  assert.throws(() => buildManagedConnectPreparation({
    lease,
    organizationId: "org-a",
    fullTunnel: false,
    origin: "https://b.example",
    api: { ownerId: "owner-a" },
    resolveConfig: async () => ({}),
  }), /origin does not match credential/);
});

test("failed connect proof performs zero runtime, helper, up, error, or publish effects", async () => {
  const stored = credential("token-a", "https://a.example");
  const coordinator = new ManagedLifecycleCoordinator(() => stored);
  const lease = await coordinator.capture(async () => "user-a");
  const effects = { runtime: 0, helper: 0, up: 0, error: 0, publish: 0 };

  await assert.rejects(coordinator.serial((owner) =>
    runManagedConnectFlow<Record<string, never>, Record<string, never>, string, string>(owner, {
      proveAndPrepare: async () => { throw new Error("owner proof failed"); },
      quiesceExisting: () => { throw new Error("must not quiesce"); },
      publishQuiesced: () => { throw new Error("must not publish down"); },
      prepareRuntime: () => { effects.runtime += 1; },
      installHelper: () => { effects.helper += 1; },
      up: async () => { effects.up += 1; return "up"; },
      onUpError: () => { effects.error += 1; return "error"; },
      publish: () => { effects.publish += 1; return "published"; },
    })), /owner proof failed/);

  assert.deepEqual(effects, { runtime: 0, helper: 0, up: 0, error: 0, publish: 0 });
  coordinator.assertCurrent(lease);
});

test("failed prior-session quiesce preserves the old lease and performs no new-session effects", async () => {
  const stored = credential("token-a", "https://a.example");
  const coordinator = new ManagedLifecycleCoordinator(() => stored);
  const lease = await coordinator.capture(async () => "user-a");
  const effects = { down: 0, runtime: 0, helper: 0, up: 0, error: 0, publish: 0 };

  await assert.rejects(coordinator.serial((owner) =>
    runManagedConnectFlow<Record<string, never>, Record<string, never>, string, string>(owner, {
      proveAndPrepare: async () => ({
        lease,
        organizationId: "org-a",
        fullTunnel: false,
        configProvider: async () => ({}),
        context: {},
      }),
      quiesceExisting: () => { throw new Error("down refused"); },
      publishQuiesced: () => { effects.down += 1; },
      prepareRuntime: () => { effects.runtime += 1; },
      installHelper: () => { effects.helper += 1; },
      up: async () => { effects.up += 1; return "up"; },
      onUpError: () => { effects.error += 1; return "error"; },
      publish: () => { effects.publish += 1; return "published"; },
    })), /down refused/);

  assert.deepEqual(effects, { down: 0, runtime: 0, helper: 0, up: 0, error: 0, publish: 0 });
  coordinator.assertCurrent(lease);
});

test("post-quiesce helper failure is reported after invalidation with no up or publish", async () => {
  const stored = credential("token-a", "https://a.example");
  const coordinator = new ManagedLifecycleCoordinator(() => stored);
  const lease = await coordinator.capture(async () => "user-a");
  const events: string[] = [];

  const result = await coordinator.serial((owner) =>
    runManagedConnectFlow<Record<string, never>, Record<string, never>, string, string>(owner, {
      proveAndPrepare: async () => ({
        lease,
        organizationId: "org-a",
        fullTunnel: false,
        configProvider: async () => ({}),
        context: {},
      }),
      quiesceExisting: () => { events.push("quiesce"); },
      publishQuiesced: () => { events.push("confirmed-down"); },
      prepareRuntime: (connection) => {
        coordinator.assertCurrent(connection.lease);
        events.push("stop-old-monitors");
      },
      installHelper: () => { events.push("helper"); throw new Error("helper failed"); },
      up: async () => { events.push("up"); return "up"; },
      onUpError: (error) => {
        events.push(`error:${(error as Error).message}`);
        return "failed";
      },
      publish: () => { events.push("publish"); return "published"; },
    }));

  assert.equal(result, "failed");
  assert.deepEqual(events, ["quiesce", "confirmed-down", "stop-old-monitors", "helper", "error:helper failed"]);
  assert.throws(() => coordinator.assertCurrent(lease), StaleManagedLeaseError);
});

test("failed remove proof performs zero stop, down, revoke, or clear effects", async () => {
  const stored = credential("token-a", "https://a.example");
  const coordinator = new ManagedLifecycleCoordinator(() => stored);
  const lease = await coordinator.capture(async () => "user-a");
  const effects = { stop: 0, down: 0, revoke: 0, clear: 0 };

  await assert.rejects(coordinator.serial((owner) =>
    runManagedRemoveFlow<Record<string, never>, void>(owner, {
      proveOwner: async () => { throw new Error("owner proof failed"); },
      quiesceExisting: () => { effects.down += 1; },
      stopMonitors: () => { effects.stop += 1; },
      revokeAndClear: () => { effects.revoke += 1; effects.clear += 1; },
    })), /owner proof failed/);

  assert.deepEqual(effects, { stop: 0, down: 0, revoke: 0, clear: 0 });
  coordinator.assertCurrent(lease);
});

test("absent managed device is a false no-op before invalidation, stop, down, revoke, or clear", async () => {
  const stored = credential("token-a", "https://a.example");
  const coordinator = new ManagedLifecycleCoordinator(() => stored);
  const lease = await coordinator.capture(async () => "user-a");
  const effects = { stop: 0, down: 0, revoke: 0, clear: 0 };

  const removed = await coordinator.serial((owner) =>
    runManagedRemoveFlow<Record<string, never>, boolean>(owner, {
      proveOwner: async () => null,
      quiesceExisting: () => { effects.down += 1; },
      stopMonitors: () => { effects.stop += 1; },
      revokeAndClear: () => { effects.revoke += 1; effects.clear += 1; return true; },
    }));

  assert.equal(removed, false);
  assert.deepEqual(effects, { stop: 0, down: 0, revoke: 0, clear: 0 });
  coordinator.assertCurrent(lease);
});

test("successful remove orders proof, helper quiesce, invalidation, stop, revoke, then clear", async () => {
  const stored = credential("token-a", "https://a.example");
  const coordinator = new ManagedLifecycleCoordinator(() => stored);
  const lease = await coordinator.capture(async () => "user-a");
  const events: string[] = [];

  const removed = await coordinator.serial((owner) => {
    const observedOwner: ManagedLifecycleOperation = {
      advance: (candidate) => {
        events.push("invalidate");
        return owner.advance(candidate);
      },
      invalidate: () => owner.invalidate(),
    };
    return runManagedRemoveFlow<{ deviceId: string }, boolean>(observedOwner, {
      proveOwner: async () => {
        events.push("proof");
        return { lease, context: { deviceId: "device-a" } };
      },
      quiesceExisting: () => {
        coordinator.assertCurrent(lease);
        events.push("down");
      },
      stopMonitors: (removal) => {
        assert.throws(() => coordinator.assertCurrent(lease), StaleManagedLeaseError);
        coordinator.assertCurrent(removal.lease);
        events.push("stop");
      },
      revokeAndClear: (removal) => {
        assert.equal(removal.context.deviceId, "device-a");
        events.push("revoke");
        events.push("clear");
        return true;
      },
    });
  });

  assert.equal(removed, true);
  assert.deepEqual(events, ["proof", "down", "invalidate", "stop", "revoke", "clear"]);
});

test("remove teardown refusal preserves the current lease and performs zero stop, revoke, or clear", async () => {
  const stored = credential("token-a", "https://a.example");
  const coordinator = new ManagedLifecycleCoordinator(() => stored);
  const lease = await coordinator.capture(async () => "user-a");
  const effects = { stop: 0, revoke: 0, clear: 0 };

  await assert.rejects(coordinator.serial((owner) =>
    runManagedRemoveFlow<Record<string, never>, boolean>(owner, {
      proveOwner: async () => ({ lease, context: {} }),
      quiesceExisting: () => { throw new Error("down refused"); },
      stopMonitors: () => { effects.stop += 1; },
      revokeAndClear: () => { effects.revoke += 1; effects.clear += 1; return true; },
    })), /down refused/);

  coordinator.assertCurrent(lease);
  assert.deepEqual(effects, { stop: 0, revoke: 0, clear: 0 });
});

test("disconnect refusal preserves the current lease, monitors, and visible state", async () => {
  const stored = credential("token-a", "https://a.example");
  const coordinator = new ManagedLifecycleCoordinator(() => stored);
  const lease = await coordinator.capture(async () => "user-a");
  const effects = { stop: 0, down: 0, notify: 0 };

  await assert.rejects(coordinator.serial((owner) =>
    runManagedDisconnectFlow(owner, {
      quiesceExisting: async () => { throw new Error("cleanup required"); },
      stopMonitors: () => { effects.stop += 1; },
      publishDown: () => { effects.down += 1; },
      notifyDisconnected: () => { effects.notify += 1; },
    })), /cleanup required/);

  coordinator.assertCurrent(lease);
  assert.deepEqual(effects, { stop: 0, down: 0, notify: 0 });
});

test("successful disconnect owns down, invalidation, monitor stop, publication, and notification order", async () => {
  const stored = credential("token-a", "https://a.example");
  const coordinator = new ManagedLifecycleCoordinator(() => stored);
  const lease = await coordinator.capture(async () => "user-a");
  const events: string[] = [];

  await coordinator.serial((owner) => {
    const observedOwner: ManagedLifecycleOperation = {
      advance: (candidate) => owner.advance(candidate),
      invalidate: () => {
        events.push("invalidate");
        return owner.invalidate();
      },
    };
    return runManagedDisconnectFlow(observedOwner, {
      quiesceExisting: async () => {
        coordinator.assertCurrent(lease);
        events.push("down");
      },
      stopMonitors: () => {
        assert.throws(() => coordinator.assertCurrent(lease), StaleManagedLeaseError);
        events.push("stop");
      },
      publishDown: () => { events.push("publish-down"); },
      notifyDisconnected: () => { events.push("notify"); },
    });
  });

  assert.deepEqual(events, ["down", "invalidate", "stop", "publish-down", "notify"]);
});

test("terminal teardown refusal forces fail-closed and never publishes a false revoked state", async () => {
  const events: string[] = [];

  const result = await runTerminalRevocationFlow({
    stopMonitors: () => { events.push("stop"); },
    downTunnel: async () => {
      events.push("down");
      throw new Error("tunnel_down_failed");
    },
    forceFailClosed: () => { events.push("fail-closed"); },
    retainTerminalRecord: () => { events.push("retain-record"); },
    publishRevoked: () => { events.push("revoked"); },
    publishFailed: () => { events.push("failed"); },
    reportProblems: () => { events.push("report"); },
  });

  assert.equal(result.outcome, "failed");
  assert.ok(result.problems.cleanupError instanceof Error);
  assert.deepEqual(events, ["stop", "down", "fail-closed", "failed", "retain-record", "report"]);
});

test("terminal teardown success records and publishes revoked only after confirmed down", async () => {
  const events: string[] = [];

  const result = await runTerminalRevocationFlow({
    stopMonitors: () => { events.push("stop"); },
    downTunnel: async () => { events.push("down"); },
    forceFailClosed: () => { events.push("fail-closed"); },
    retainTerminalRecord: () => { events.push("retain-record"); },
    publishRevoked: () => { events.push("revoked"); },
    publishFailed: () => { events.push("failed"); },
    reportProblems: () => { events.push("report"); },
  });

  assert.equal(result.outcome, "revoked");
  assert.deepEqual(result.problems, {});
  assert.deepEqual(events, ["stop", "down", "revoked", "retain-record"]);
});

test("terminal transport truth publishes before a blocked recovery-record write", async () => {
  const events: string[] = [];
  const retentionStarted = deferred();
  const releaseRetention = deferred();

  const flow = runTerminalRevocationFlow({
    stopMonitors: () => { events.push("stop"); },
    downTunnel: async () => { events.push("down"); },
    forceFailClosed: () => { events.push("fail-closed"); },
    publishRevoked: () => { events.push("revoked"); },
    publishFailed: () => { events.push("failed"); },
    retainTerminalRecord: async () => {
      events.push("retain-start");
      retentionStarted.resolve();
      await releaseRetention.promise;
      events.push("retain-finish");
    },
    reportProblems: () => { events.push("report"); },
  });

  await retentionStarted.promise;
  assert.deepEqual(events, ["stop", "down", "revoked", "retain-start"]);
  releaseRetention.resolve();
  assert.equal((await flow).outcome, "revoked");
  assert.deepEqual(events, ["stop", "down", "revoked", "retain-start", "retain-finish"]);
});

test("terminal teardown refusal publishes failed and reports cleanup plus throwing retention", async () => {
  const events: string[] = [];
  const cleanupError = new Error("tunnel_down_failed");
  const retentionError = new Error("encrypted store unavailable");
  const reports: TerminalRevocationProblems[] = [];

  const result = await runTerminalRevocationFlow({
    stopMonitors: () => { events.push("stop"); },
    downTunnel: async () => {
      events.push("down");
      throw cleanupError;
    },
    forceFailClosed: () => { events.push("fail-closed"); },
    retainTerminalRecord: () => {
      events.push("retain-record");
      throw retentionError;
    },
    publishRevoked: () => { events.push("revoked"); },
    publishFailed: () => { events.push("failed"); },
    reportProblems: (problems) => {
      events.push("report");
      reports.push(problems);
    },
  });

  assert.equal(result.outcome, "failed");
  assert.equal(result.problems.cleanupError, cleanupError);
  assert.equal(result.problems.retentionError, retentionError);
  assert.equal(reports[0]?.cleanupError, cleanupError);
  assert.equal(reports[0]?.retentionError, retentionError);
  assert.deepEqual(events, ["stop", "down", "fail-closed", "failed", "retain-record", "report"]);
});

test("terminal teardown success publishes revoked even when terminal retention throws", async () => {
  const events: string[] = [];
  const retentionError = new Error("encrypted store unavailable");
  const reports: TerminalRevocationProblems[] = [];

  const result = await runTerminalRevocationFlow({
    stopMonitors: () => { events.push("stop"); },
    downTunnel: async () => { events.push("down"); },
    forceFailClosed: () => { events.push("fail-closed"); },
    retainTerminalRecord: () => {
      events.push("retain-record");
      throw retentionError;
    },
    publishRevoked: () => { events.push("revoked"); },
    publishFailed: () => { events.push("failed"); },
    reportProblems: (problems) => {
      events.push("report");
      reports.push(problems);
    },
  });

  assert.equal(result.outcome, "revoked");
  assert.equal(result.problems.retentionError, retentionError);
  assert.equal(reports[0]?.retentionError, retentionError);
  assert.deepEqual(events, ["stop", "down", "revoked", "retain-record", "report"]);
});

test("terminal teardown treats even an undefined thrown value as cleanup failure", async () => {
  const published: string[] = [];

  const result = await runTerminalRevocationFlow({
    stopMonitors: () => {},
    downTunnel: async () => { throw undefined; },
    forceFailClosed: () => {},
    retainTerminalRecord: () => {},
    publishRevoked: () => { published.push("revoked"); },
    publishFailed: () => { published.push("failed"); },
    reportProblems: () => {},
  });

  assert.equal(result.outcome, "failed");
  assert.equal(Object.prototype.hasOwnProperty.call(result.problems, "cleanupError"), true);
  assert.deepEqual(published, ["failed"]);
});
