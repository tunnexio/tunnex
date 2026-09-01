import { test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import fs from "node:fs";

import { encodeFrame, FrameDecoder, HelperConnection, MAX_MESSAGE_BYTES, PROTOCOL_VERSION, type ResolverForward, type TunnelConfig, type TunnelStatus } from "../src/main/helperclient";
import { projectTransportStatus, SingleFlightStatusReader } from "../src/main/statusreader";
import { helperSocketPath, TunnelController } from "../src/main/tunnel";

const delay = (ms: number) => new Promise((r) => setTimeout(r, ms));

function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void } {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

// A platform-appropriate ephemeral IPC endpoint for the socket round-trip tests: a
// NAMED PIPE on Windows (a unix-socket path errors EACCES there), a unix socket
// elsewhere. Mirrors helperSocketPath's per-platform choice.
function testEndpoint(tag: string): string {
  return process.platform === "win32"
    ? `\\\\.\\pipe\\tnx-test-${tag}-${process.pid}`
    : path.join(os.tmpdir(), `tnx-test-${tag}-${process.pid}.sock`);
}

// The framing MUST match apps/helper/ipc.go (4-byte BE length + JSON body). These
// tests pin the wire contract on the TS side so the two can't silently diverge.
test("encodeFrame writes a 4-byte big-endian length prefix", () => {
  const frame = encodeFrame({ a: 1 });
  const body = Buffer.from(JSON.stringify({ a: 1 }), "utf8");
  assert.equal(frame.readUInt32BE(0), body.length);
  assert.deepEqual(frame.subarray(4), body);
});

test("FrameDecoder reassembles a message split across chunks", () => {
  const frame = encodeFrame({ version: PROTOCOL_VERSION, verb: "status" });
  const dec = new FrameDecoder();
  // Feed it one byte at a time — nothing yields until the full frame arrives.
  for (let i = 0; i < frame.length - 1; i++) {
    assert.equal(dec.push(frame.subarray(i, i + 1)).length, 0);
  }
  const out = dec.push(frame.subarray(frame.length - 1));
  assert.equal(out.length, 1);
  assert.deepEqual(out[0], { version: PROTOCOL_VERSION, verb: "status" });
});

test("FrameDecoder yields multiple messages from one chunk", () => {
  const two = Buffer.concat([encodeFrame({ n: 1 }), encodeFrame({ n: 2 })]);
  const out = new FrameDecoder().push(two);
  assert.deepEqual(out, [{ n: 1 }, { n: 2 }]);
});

test("oversize frames are rejected before allocation, both directions", () => {
  const big = "x".repeat(MAX_MESSAGE_BYTES + 1);
  assert.throws(() => encodeFrame({ big }), /MAX_MESSAGE_BYTES/);
  // A hostile length prefix (> cap) must throw on decode without allocating it.
  const evil = Buffer.alloc(4);
  evil.writeUInt32BE(MAX_MESSAGE_BYTES + 1, 0);
  assert.throws(() => new FrameDecoder().push(evil), /MAX_MESSAGE_BYTES/);
});

test("helperSocketPath is platform-specific", () => {
  assert.equal(helperSocketPath("win32"), "\\\\.\\pipe\\tunnex-helper");
  assert.equal(helperSocketPath("darwin"), "/var/run/tunnex/helper.sock");
});

// The helper reports runtime stats but NOT the tunnel address (it's config), so
// MAIN attaches it — this is what lets the UI show "Your IP". Guard the plumb.
test("TunnelController attaches the config's tunnel address to forwarded status", async () => {
  const sockPath = testEndpoint("addr");
  try { fs.unlinkSync(sockPath); } catch { /* fresh */ }
  const server = net.createServer((sock) => {
    const dec = new FrameDecoder();
    sock.on("data", (chunk: Buffer) => {
      // The helper never sends `address`; main must add it.
      for (const _ of dec.push(chunk)) sock.write(encodeFrame({ version: PROTOCOL_VERSION, ok: true, status: { state: "up", last_handshake_sec: 3 } }));
    });
  });
  await new Promise<void>((r) => server.listen(sockPath, r));
  try {
    const cfg = { address: "10.99.0.2/32" } as unknown as TunnelConfig;
    const ctrl = new TunnelController(sockPath);
    const up = await ctrl.up(async () => cfg);
    assert.equal(up.address, "10.99.0.2/32", "main must attach the config's tunnel address");
    await ctrl.down();
  } finally {
    server.close();
    try { fs.unlinkSync(sockPath); } catch { /* gone */ }
  }
});

test("TunnelController requires invocation-local providers and rejects overlapping up calls", async () => {
  const sockPath = testEndpoint("provider");
  try { fs.unlinkSync(sockPath); } catch { /* fresh */ }
  const configs: TunnelConfig[] = [];
  const server = net.createServer((sock) => {
    const dec = new FrameDecoder();
    sock.on("data", (chunk: Buffer) => {
      for (const msg of dec.push(chunk)) {
        const req = msg as { verb: string; config?: TunnelConfig };
        if (req.verb === "tunnel_up" && req.config) configs.push(req.config);
        const state = req.verb === "tunnel_down" ? "down" : "up";
        sock.write(encodeFrame({ version: PROTOCOL_VERSION, ok: true, status: { state } }));
      }
    });
  });
  await new Promise<void>((r) => server.listen(sockPath, r));
  try {
    const configA = {
      private_key: "a-private",
      peer_public_key: "a-peer",
      endpoint: "a.example:51820",
      address: "10.99.0.2/32",
      allowed_ips: ["10.2.0.0/16"],
    } satisfies TunnelConfig;
    const configB = {
      private_key: "b-private",
      peer_public_key: "b-peer",
      endpoint: "b.example:51820",
      address: "10.99.0.3/32",
      allowed_ips: ["10.3.0.0/16"],
    } satisfies TunnelConfig;
    const pendingA = deferred<TunnelConfig>();
    let overlappingProviderCalls = 0;
    const ctrl = new TunnelController(sockPath);

    const upA = ctrl.up(() => pendingA.promise);
    await assert.rejects(
      ctrl.up(async () => {
        overlappingProviderCalls += 1;
        return configB;
      }),
      /tunnel_up_in_progress/,
    );
    assert.equal(overlappingProviderCalls, 0, "a rejected overlap must not resolve or mutate from its provider");

    pendingA.resolve(configA);
    assert.equal((await upA).address, configA.address);
    await ctrl.down();
    assert.equal((await ctrl.up(async () => configB)).address, configB.address);

    assert.deepEqual(
      configs.map(({ address, endpoint, allowed_ips }) => ({ address, endpoint, allowed_ips })),
      [
        { address: configA.address, endpoint: configA.endpoint, allowed_ips: configA.allowed_ips },
        { address: configB.address, endpoint: configB.endpoint, allowed_ips: configB.allowed_ips },
      ],
      "each accepted invocation must send only its own provider's config",
    );
    await ctrl.down();
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
    try { fs.unlinkSync(sockPath); } catch { /* gone */ }
  }
});

test("TunnelController down is zero-wire while inactive and a refusal stays observable and retryable", async () => {
  const sockPath = testEndpoint("down-state");
  try { fs.unlinkSync(sockPath); } catch { /* fresh */ }
  let connections = 0;
  let downAttempts = 0;
  const serverSockets: net.Socket[] = [];
  const server = net.createServer((sock) => {
    connections += 1;
    serverSockets.push(sock);
    const dec = new FrameDecoder();
    sock.on("data", (chunk: Buffer) => {
      for (const msg of dec.push(chunk)) {
        const req = msg as { verb: string };
        if (req.verb === "tunnel_down") {
          downAttempts += 1;
          sock.write(encodeFrame(downAttempts === 1
            ? { version: PROTOCOL_VERSION, ok: false, code: "teardown_refused", error: "down denied" }
            : { version: PROTOCOL_VERSION, ok: true, status: { state: "down" } }));
        } else if (req.verb === "status") {
          sock.write(encodeFrame({ version: PROTOCOL_VERSION, ok: true }));
        } else {
          sock.write(encodeFrame({ version: PROTOCOL_VERSION, ok: true, status: { state: "up" } }));
        }
      }
    });
  });
  await new Promise<void>((resolve) => server.listen(sockPath, resolve));

  const realSetInterval = globalThis.setInterval;
  const realClearInterval = globalThis.clearInterval;
  const heartbeatTicks: Array<() => Promise<void>> = [];
  globalThis.setInterval = ((callback: () => Promise<void>) => {
    heartbeatTicks.push(callback);
    return { unref() { /* fake timer */ } } as unknown as ReturnType<typeof setInterval>;
  }) as unknown as typeof setInterval;
  globalThis.clearInterval = (() => { /* fake timer */ }) as typeof clearInterval;

  try {
    const statuses: TunnelStatus[] = [];
    const ctrl = new TunnelController(sockPath, (status) => statuses.push(status));
    await ctrl.down();
    assert.equal(connections, 0, "an inactive controller must not connect to the helper during down");

    const config = { address: "10.99.0.2/32" } as unknown as TunnelConfig;
    await ctrl.up(async () => config);
    assert.equal(connections, 1);
    await assert.rejects(ctrl.down(), /teardown_refused: down denied/);
    assert.equal(downAttempts, 1);
    assert.equal(heartbeatTicks.length, 1, "a failed cleanup must never resume an Up heartbeat");
    assert.deepEqual(statuses, [{ state: "failed" }], "cleanup-required must replace stale Connected immediately");
    assert.deepEqual(ctrl.baseAllowedIPs(), [], "failed cleanup must not retain a publishable route cache");
    assert.deepEqual(await ctrl.status(), { state: "down" }, "the legacy absent-status display fallback remains stable");

    await ctrl.down();
    assert.equal(downAttempts, 2, "an absent status payload must not retire the real teardown retry");
    await ctrl.down();
    assert.equal(downAttempts, 2, "a successful retry must retire active ownership");
  } finally {
    globalThis.setInterval = realSetInterval;
    globalThis.clearInterval = realClearInterval;
    serverSockets.forEach((socket) => socket.destroy());
    await new Promise<void>((resolve) => server.close(() => resolve()));
    try { fs.unlinkSync(sockPath); } catch { /* gone */ }
  }
});

test("posture synthesis cannot mask a down refusal or its later Failed status read", async () => {
  const sockPath = testEndpoint("posture-down-failed");
  try { fs.unlinkSync(sockPath); } catch { /* fresh */ }
  const serverSockets: net.Socket[] = [];
  let downAttempts = 0;
  const server = net.createServer((sock) => {
    serverSockets.push(sock);
    const dec = new FrameDecoder();
    sock.on("data", (chunk: Buffer) => {
      for (const msg of dec.push(chunk)) {
        const req = msg as { verb: string };
        if (req.verb === "tunnel_up") {
          sock.write(encodeFrame({ version: PROTOCOL_VERSION, ok: true, status: { state: "up" } }));
        } else if (req.verb === "tunnel_down") {
          downAttempts += 1;
          sock.write(encodeFrame(downAttempts === 1
            ? { version: PROTOCOL_VERSION, ok: false, code: "tunnel_down_failed", error: "cleanup failed" }
            : { version: PROTOCOL_VERSION, ok: true, status: { state: "down" } }));
        } else if (req.verb === "status") {
          sock.write(encodeFrame({ version: PROTOCOL_VERSION, ok: true, status: { state: "failed" } }));
        } else if (req.verb === "set_resolvers") {
          sock.write(encodeFrame({ version: PROTOCOL_VERSION, ok: true }));
        }
      }
    });
  });
  await new Promise<void>((resolve) => server.listen(sockPath, resolve));

  type PostureSynthetic = { state: "posture_blocked"; failed_checks: string[] };
  let synthetic: PostureSynthetic | null = null;
  let transport: TunnelStatus | null = null;
  const ctrl = new TunnelController(sockPath, (status) => {
    const projected = projectTransportStatus<TunnelStatus, PostureSynthetic>(synthetic, status);
    synthetic = projected.synthetic;
    transport = projected.transport;
  });
  try {
    transport = await ctrl.up(async () => ({ address: "10.99.0.2/32" }) as TunnelConfig);
    synthetic = { state: "posture_blocked", failed_checks: ["disk_encryption"] };

    await assert.rejects(ctrl.down(), /tunnel_down_failed: cleanup failed/);
    assert.equal(synthetic, null, "the refusal's Failed callback must clear the posture overlay immediately");
    assert.equal(transport?.state, "failed");

    const statusReader = new SingleFlightStatusReader(async () => {
      if (synthetic) return synthetic;
      const status = await ctrl.status();
      const projected = projectTransportStatus<TunnelStatus, PostureSynthetic>(synthetic, status);
      synthetic = projected.synthetic;
      transport = projected.transport;
      return status;
    });
    assert.deepEqual(await statusReader.read(), { state: "failed" });
    assert.equal(synthetic, null, "a successful Failed read must not resurrect the posture overlay");

    await ctrl.down();
    assert.equal(downAttempts, 2, "cleanup remains retryable after the truthful Failed read");
  } finally {
    (ctrl as unknown as { conn: HelperConnection }).conn.close();
    serverSockets.forEach((socket) => socket.destroy());
    await new Promise<void>((resolve) => server.close(() => resolve()));
    try { fs.unlinkSync(sockPath); } catch { /* gone */ }
  }
});

test("TunnelController failClosed retains a wired cleanup retry after terminal teardown refusal", async () => {
  const sockPath = testEndpoint("terminal-cleanup-retry");
  try { fs.unlinkSync(sockPath); } catch { /* fresh */ }
  const serverSockets: net.Socket[] = [];
  let connections = 0;
  let downAttempts = 0;
  const server = net.createServer((sock) => {
    connections += 1;
    serverSockets.push(sock);
    const dec = new FrameDecoder();
    sock.on("data", (chunk: Buffer) => {
      for (const msg of dec.push(chunk)) {
        const req = msg as { verb: string };
        if (req.verb === "tunnel_up") {
          sock.write(encodeFrame({ version: PROTOCOL_VERSION, ok: true, status: { state: "up" } }));
        } else if (req.verb === "set_resolvers") {
          sock.write(encodeFrame({ version: PROTOCOL_VERSION, ok: true }));
        } else if (req.verb === "tunnel_down") {
          downAttempts += 1;
          sock.write(encodeFrame(downAttempts === 1
            ? { version: PROTOCOL_VERSION, ok: false, code: "tunnel_down_failed", error: "backend cleanup failed" }
            : { version: PROTOCOL_VERSION, ok: true, status: { state: "down" } }));
        }
      }
    });
  });
  await new Promise<void>((resolve) => server.listen(sockPath, resolve));

  const statuses: TunnelStatus[] = [];
  const ctrl = new TunnelController(sockPath, (status) => statuses.push(status));
  try {
    await ctrl.up(async () => ({ address: "10.99.0.2/32" }) as TunnelConfig);
    await assert.rejects(ctrl.down(), /tunnel_down_failed: backend cleanup failed/);

    ctrl.failClosed();
    assert.deepEqual(statuses, [{ state: "failed" }], "terminal force-close must not duplicate the existing failed transition");

    await ctrl.down();
    assert.equal(connections, 2, "cleanup retry must reconnect after the terminal path closes the owner socket");
    assert.equal(downAttempts, 2, "cleanup-required must retain the real tunnel_down recovery handle");
    await ctrl.down();
    assert.equal(downAttempts, 2, "confirmed cleanup retires the handle to zero-wire inactive");
  } finally {
    (ctrl as unknown as { conn: HelperConnection }).conn.close();
    serverSockets.forEach((socket) => socket.destroy());
    await new Promise<void>((resolve) => server.close(() => resolve()));
    try { fs.unlinkSync(sockPath); } catch { /* gone */ }
  }
});

test("TunnelController surfaces helper loss after a refused down", async () => {
  const sockPath = testEndpoint("down-refusal-loss");
  try { fs.unlinkSync(sockPath); } catch { /* fresh */ }
  const serverSockets: net.Socket[] = [];
  const server = net.createServer((sock) => {
    serverSockets.push(sock);
    const dec = new FrameDecoder();
    sock.on("data", (chunk: Buffer) => {
      for (const msg of dec.push(chunk)) {
        const req = msg as { verb: string };
        sock.write(encodeFrame(req.verb === "tunnel_down"
          ? { version: PROTOCOL_VERSION, ok: false, code: "teardown_refused", error: "down denied" }
          : { version: PROTOCOL_VERSION, ok: true, status: { state: "up" } }));
      }
    });
  });
  await new Promise<void>((resolve) => server.listen(sockPath, resolve));

  const statuses: TunnelStatus[] = [];
  const ctrl = new TunnelController(sockPath, (status) => statuses.push(status));
  try {
    await ctrl.up(async () => ({ address: "10.99.0.2/32" }) as TunnelConfig);
    await assert.rejects(ctrl.down(), /teardown_refused: down denied/);

    const connection = (ctrl as unknown as { conn: { sock: net.Socket | null } }).conn;
    const socket = connection.sock;
    assert.ok(socket);
    const closeHandler = socket.listeners("close")[0] as (() => void) | undefined;
    assert.ok(closeHandler);
    closeHandler();

    assert.deepEqual(statuses, [{ state: "failed" }], "loss of the still-owned socket must remain a visible fail-closed transition");
  } finally {
    (ctrl as unknown as { conn: HelperConnection }).conn.close();
    serverSockets.forEach((socket) => socket.destroy());
    await new Promise<void>((resolve) => server.close(() => resolve()));
    try { fs.unlinkSync(sockPath); } catch { /* gone */ }
  }
});

test("TunnelController does not report fail-closed for loss of an inactive status-only socket", async () => {
  const sockPath = testEndpoint("inactive-status-loss");
  try { fs.unlinkSync(sockPath); } catch { /* fresh */ }
  const serverSockets: net.Socket[] = [];
  let requests = 0;
  const server = net.createServer((sock) => {
    serverSockets.push(sock);
    const dec = new FrameDecoder();
    sock.on("data", (chunk: Buffer) => {
      for (const _ of dec.push(chunk)) {
        requests += 1;
        sock.destroy();
      }
    });
  });
  await new Promise<void>((resolve) => server.listen(sockPath, resolve));

  const statuses: TunnelStatus[] = [];
  const ctrl = new TunnelController(sockPath, (status) => statuses.push(status));
  try {
    await assert.rejects(ctrl.status(), /helper connection closed/);
    await new Promise<void>((resolve) => setImmediate(resolve));
    assert.deepEqual(statuses, [], "a read-only socket is not tunnel ownership and cannot fail a tunnel that is already inactive");
    await ctrl.down();
    assert.equal(requests, 1, "an inconclusive status read must not invent a wired cleanup obligation");
  } finally {
    (ctrl as unknown as { conn: HelperConnection }).conn.close();
    serverSockets.forEach((socket) => socket.destroy());
    await new Promise<void>((resolve) => server.close(() => resolve()));
    try { fs.unlinkSync(sockPath); } catch { /* gone */ }
  }
});

for (const helperState of ["up", "failed"] as const) {
  test(`TunnelController adopts fresh helper ${helperState} truth as a wired cleanup obligation`, async () => {
    const sockPath = testEndpoint(`fresh-${helperState}`);
    try { fs.unlinkSync(sockPath); } catch { /* fresh */ }
    const serverSockets: net.Socket[] = [];
    let downAttempts = 0;
    const server = net.createServer((sock) => {
      serverSockets.push(sock);
      const dec = new FrameDecoder();
      sock.on("data", (chunk: Buffer) => {
        for (const msg of dec.push(chunk)) {
          const req = msg as { verb: string };
          if (req.verb === "status") {
            sock.write(encodeFrame({ version: PROTOCOL_VERSION, ok: true, status: { state: helperState } }));
          } else if (req.verb === "tunnel_down") {
            downAttempts += 1;
            sock.write(encodeFrame({ version: PROTOCOL_VERSION, ok: true, status: { state: "down" } }));
          } else if (req.verb === "set_resolvers") {
            sock.write(encodeFrame({ version: PROTOCOL_VERSION, ok: true }));
          }
        }
      });
    });
    await new Promise<void>((resolve) => server.listen(sockPath, resolve));

    const ctrl = new TunnelController(sockPath);
    try {
      assert.equal((await ctrl.status()).state, helperState);
      await ctrl.down();
      assert.equal(downAttempts, 1, "non-down helper truth must prevent a fresh controller's down from becoming zero-wire");
      await ctrl.down();
      assert.equal(downAttempts, 1, "confirmed cleanup must retire the adopted recovery handle");
    } finally {
      (ctrl as unknown as { conn: HelperConnection }).conn.close();
      serverSockets.forEach((socket) => socket.destroy());
      await new Promise<void>((resolve) => server.close(() => resolve()));
      try { fs.unlinkSync(sockPath); } catch { /* gone */ }
    }
  });
}

test("TunnelController rejects up when owner loss follows tunnel_up success before publish", async () => {
  const sockPath = testEndpoint("up-owner-loss");
  try { fs.unlinkSync(sockPath); } catch { /* fresh */ }
  const serverSockets: net.Socket[] = [];
  let downAttempts = 0;
  const server = net.createServer((sock) => {
    serverSockets.push(sock);
    const dec = new FrameDecoder();
    sock.on("data", (chunk: Buffer) => {
      for (const msg of dec.push(chunk)) {
        const req = msg as { verb: string };
        if (req.verb === "tunnel_up") {
          sock.write(encodeFrame({ version: PROTOCOL_VERSION, ok: true, status: { state: "up" } }));
        } else if (req.verb === "set_resolvers") {
          // The helper accepted tunnel_up, then its owner socket died during the
          // final setup await. applyResolvers is fail-static, but up itself must
          // not donate the already-stale success to IPC.
          sock.destroy();
        } else if (req.verb === "tunnel_down") {
          downAttempts += 1;
          sock.write(encodeFrame({ version: PROTOCOL_VERSION, ok: true, status: { state: "down" } }));
        }
      }
    });
  });
  await new Promise<void>((resolve) => server.listen(sockPath, resolve));

  const statuses: TunnelStatus[] = [];
  const ctrl = new TunnelController(sockPath, (status) => statuses.push(status));
  try {
    const config = {
      private_key: "private",
      peer_public_key: "peer",
      endpoint: "gateway.example:51820",
      address: "10.99.0.2/32",
      allowed_ips: ["10.20.0.0/16"],
      dns_forwards: [{ domain: "corp.example", resolver_ip: "10.20.0.53" }],
    } satisfies TunnelConfig;
    await assert.rejects(ctrl.up(async () => config), /tunnel_owner_lost_during_up/);
    assert.deepEqual(statuses, [{ state: "failed" }], "the owner loss is terminal and the stale up result is never returned");
    assert.equal((ctrl as unknown as { heartbeat: unknown }).heartbeat, null, "a lost startup generation must not arm a heartbeat");
    await ctrl.down();
    assert.equal(downAttempts, 1, "owner loss remains cleanup-required and later down reconnects to the helper");
  } finally {
    (ctrl as unknown as { conn: HelperConnection }).conn.close();
    serverSockets.forEach((socket) => socket.destroy());
    await new Promise<void>((resolve) => server.close(() => resolve()));
    try { fs.unlinkSync(sockPath); } catch { /* gone */ }
  }
});

test("TunnelController keeps a partial tunnel_up failure cleanup-required until a wired down succeeds", async () => {
  const sockPath = testEndpoint("partial-up-cleanup");
  try { fs.unlinkSync(sockPath); } catch { /* fresh */ }
  const serverSockets: net.Socket[] = [];
  let downAttempts = 0;
  const server = net.createServer((sock) => {
    serverSockets.push(sock);
    const dec = new FrameDecoder();
    sock.on("data", (chunk: Buffer) => {
      for (const msg of dec.push(chunk)) {
        const req = msg as { verb: string };
        if (req.verb === "tunnel_up") {
          sock.write(encodeFrame({ version: PROTOCOL_VERSION, ok: false, code: "tunnel_up_failed", error: "partial bring-up" }));
        } else if (req.verb === "tunnel_down") {
          downAttempts += 1;
          sock.write(encodeFrame({ version: PROTOCOL_VERSION, ok: true, status: { state: "down" } }));
        }
      }
    });
  });
  await new Promise<void>((resolve) => server.listen(sockPath, resolve));

  const statuses: TunnelStatus[] = [];
  const ctrl = new TunnelController(sockPath, (status) => statuses.push(status));
  try {
    const config = {
      address: "10.99.0.2/32",
      allowed_ips: ["10.20.0.0/16"],
    } as TunnelConfig;
    await assert.rejects(ctrl.up(async () => config), /tunnel_up_failed: partial bring-up/);
    assert.deepEqual(statuses, [{ state: "failed" }], "a partial up must immediately replace stale Down/Connected truth");
    assert.deepEqual(ctrl.baseAllowedIPs(), [], "a rejected provisional config cannot leak route state");

    await ctrl.down();
    assert.equal(downAttempts, 1, "cleanup-required must reconnect/send tunnel_down instead of returning zero-wire");
    await ctrl.down();
    assert.equal(downAttempts, 1, "only confirmed cleanup returns ownership to inactive");
  } finally {
    (ctrl as unknown as { conn: HelperConnection }).conn.close();
    serverSockets.forEach((socket) => socket.destroy());
    await new Promise<void>((resolve) => server.close(() => resolve()));
    try { fs.unlinkSync(sockPath); } catch { /* gone */ }
  }
});

test("TunnelController returns typed clean pre-arm refusals to inactive and clears provisional caches", async (t) => {
  for (const scenario of [
    { slug: "endpoint", code: "endpoint_unresolved", error: "pre-arm resolution" },
    { slug: "uninstall", code: "helper_uninstalling", error: "helper terminal fence" },
  ]) {
    await t.test(scenario.code, async () => {
      const sockPath = testEndpoint(`clean-refusal-${scenario.slug}`);
      try { fs.unlinkSync(sockPath); } catch { /* fresh */ }
      const serverSockets: net.Socket[] = [];
      let downAttempts = 0;
      const server = net.createServer((sock) => {
        serverSockets.push(sock);
        const dec = new FrameDecoder();
        sock.on("data", (chunk: Buffer) => {
          for (const msg of dec.push(chunk)) {
            const req = msg as { verb: string };
            if (req.verb === "tunnel_up") {
              sock.write(encodeFrame({ version: PROTOCOL_VERSION, ok: false, code: scenario.code, error: scenario.error }));
            } else if (req.verb === "tunnel_down") {
              downAttempts += 1;
              sock.write(encodeFrame({ version: PROTOCOL_VERSION, ok: true, status: { state: "down" } }));
            }
          }
        });
      });
      await new Promise<void>((resolve) => server.listen(sockPath, resolve));

      const statuses: TunnelStatus[] = [];
      const ctrl = new TunnelController(sockPath, (status) => statuses.push(status));
      try {
        const config = {
          address: "10.99.0.2/32",
          allowed_ips: ["10.20.0.0/16"],
        } as TunnelConfig;
        await assert.rejects(ctrl.up(async () => config), new RegExp(`${scenario.code}: ${scenario.error}`));
        assert.deepEqual(statuses, [], "a proved pre-arm refusal must not invent a kill-switch state");
        assert.deepEqual(ctrl.baseAllowedIPs(), [], "clean refusal must clear provisional route state");

        await ctrl.down();
        assert.equal(downAttempts, 0, "proved clean pre-arm refusal returns to zero-wire inactive");
      } finally {
        (ctrl as unknown as { conn: HelperConnection }).conn.close();
        serverSockets.forEach((socket) => socket.destroy());
        await new Promise<void>((resolve) => server.close(() => resolve()));
        try { fs.unlinkSync(sockPath); } catch { /* gone */ }
      }
    });
  }
});

test("TunnelController treats a compensated PF arm refusal as clean pre-arm", async () => {
  const sockPath = testEndpoint("pf-arm-clean-refusal");
  try { fs.unlinkSync(sockPath); } catch { /* fresh */ }
  const serverSockets: net.Socket[] = [];
  let downAttempts = 0;
  const server = net.createServer((sock) => {
    serverSockets.push(sock);
    const dec = new FrameDecoder();
    sock.on("data", (chunk: Buffer) => {
      for (const msg of dec.push(chunk)) {
        const req = msg as { verb: string };
        if (req.verb === "tunnel_up") {
          sock.write(encodeFrame({ version: PROTOCOL_VERSION, ok: false, code: "pf_arm_failed", error: "compensated pre-arm refusal" }));
        } else if (req.verb === "tunnel_down") {
          downAttempts += 1;
          sock.write(encodeFrame({ version: PROTOCOL_VERSION, ok: true, status: { state: "down" } }));
        }
      }
    });
  });
  await new Promise<void>((resolve) => server.listen(sockPath, resolve));

  const statuses: TunnelStatus[] = [];
  const ctrl = new TunnelController(sockPath, (status) => statuses.push(status));
  try {
    const config = {
      address: "10.99.0.2/32",
      allowed_ips: ["10.20.0.0/16"],
    } as TunnelConfig;
    await assert.rejects(ctrl.up(async () => config), /pf_arm_failed: compensated pre-arm refusal/);
    assert.deepEqual(statuses, [], "a helper-certified compensated PF refusal must not publish Failed");
    assert.deepEqual(ctrl.baseAllowedIPs(), [], "clean PF refusal must clear provisional route state");

    await ctrl.down();
    assert.equal(downAttempts, 0, "helper-certified compensated PF refusal returns to zero-wire inactive");
  } finally {
    (ctrl as unknown as { conn: HelperConnection }).conn.close();
    serverSockets.forEach((socket) => socket.destroy());
    await new Promise<void>((resolve) => server.close(() => resolve()));
    try { fs.unlinkSync(sockPath); } catch { /* gone */ }
  }
});

test("TunnelController suppresses a held heartbeat response after down invalidates its session", async () => {
  const sockPath = testEndpoint("stale-heartbeat");
  try { fs.unlinkSync(sockPath); } catch { /* fresh */ }
  const statusSeen = deferred<void>();
  const downSeen = deferred<void>();
  const serverSockets: net.Socket[] = [];
  let responseSocket: net.Socket | null = null;
  const server = net.createServer((sock) => {
    serverSockets.push(sock);
    const dec = new FrameDecoder();
    sock.on("data", (chunk: Buffer) => {
      for (const msg of dec.push(chunk)) {
        const req = msg as { verb: string };
        responseSocket = sock;
        if (req.verb === "tunnel_up") {
          sock.write(encodeFrame({ version: PROTOCOL_VERSION, ok: true, status: { state: "up" } }));
        } else if (req.verb === "status") {
          statusSeen.resolve();
        } else if (req.verb === "tunnel_down") {
          downSeen.resolve();
        }
      }
    });
  });
  await new Promise<void>((resolve) => server.listen(sockPath, resolve));

  const realSetInterval = globalThis.setInterval;
  const realClearInterval = globalThis.clearInterval;
  let heartbeatTick: (() => Promise<void>) | null = null;
  globalThis.setInterval = ((callback: () => Promise<void>) => {
    heartbeatTick = callback;
    return { unref() { /* fake timer */ } } as unknown as ReturnType<typeof setInterval>;
  }) as unknown as typeof setInterval;
  globalThis.clearInterval = (() => { /* fake timer */ }) as typeof clearInterval;

  try {
    const statuses: string[] = [];
    const ctrl = new TunnelController(sockPath, (status) => statuses.push(status.state));
    const config = { address: "10.99.0.2/32" } as unknown as TunnelConfig;
    await ctrl.up(async () => config);

    const tick = heartbeatTick as (() => Promise<void>) | null;
    assert.ok(tick, "up must install a heartbeat callback");
    const heartbeat = tick();
    await statusSeen.promise;

    const down = ctrl.down();
    await downSeen.promise;
    const replySocket = responseSocket as net.Socket | null;
    assert.ok(replySocket);
    replySocket.write(encodeFrame({ version: PROTOCOL_VERSION, ok: true, status: { state: "up" } }));
    await heartbeat;
    assert.deepEqual(statuses, [], "a pre-down heartbeat must have zero post-invalidation UI effect");

    replySocket.write(encodeFrame({ version: PROTOCOL_VERSION, ok: true, status: { state: "down" } }));
    await down;
    assert.deepEqual(statuses, []);
  } finally {
    globalThis.setInterval = realSetInterval;
    globalThis.clearInterval = realClearInterval;
    serverSockets.forEach((socket) => socket.destroy());
    await new Promise<void>((resolve) => server.close(() => resolve()));
    try { fs.unlinkSync(sockPath); } catch { /* gone */ }
  }
});

// A helper stub that RECORDS every verb it receives, so the resolver plumbing can be
// asserted at the wire. Replies ok to everything (down → state "down").
function recordingHelper(): { server: net.Server; verbs: string[]; requests: Array<{ verb: string; resolvers?: ResolverForward[] }> } {
  const verbs: string[] = [];
  const requests: Array<{ verb: string; resolvers?: ResolverForward[] }> = [];
  const server = net.createServer((sock) => {
    const dec = new FrameDecoder();
    sock.on("data", (chunk: Buffer) => {
      for (const msg of dec.push(chunk)) {
        const req = msg as { verb: string; resolvers?: ResolverForward[] };
        verbs.push(req.verb);
        requests.push({ verb: req.verb, resolvers: req.resolvers });
        const state = req.verb === "tunnel_down" ? "down" : "up";
        sock.write(encodeFrame({ version: PROTOCOL_VERSION, ok: true, status: { state } }));
      }
    });
  });
  return { server, verbs, requests };
}

// INERT RED (S8.4): a device with NO dns_forwards makes ZERO set_resolvers calls on
// up AND on down — zero files, zero behavior delta against every existing install.
test("TunnelController with no dns_forwards never calls set_resolvers", async () => {
  const sockPath = testEndpoint("dnsinert");
  try { fs.unlinkSync(sockPath); } catch { /* fresh */ }
  const { server, verbs } = recordingHelper();
  await new Promise<void>((r) => server.listen(sockPath, r));
  try {
    const cfg = { address: "10.99.0.2/32" } as unknown as TunnelConfig; // no dns_forwards
    const ctrl = new TunnelController(sockPath);
    await ctrl.up(async () => cfg);
    await ctrl.down();
    assert.equal(verbs.includes("set_resolvers"), false, "no forwards ⇒ no set_resolvers call");
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
    try { fs.unlinkSync(sockPath); } catch { /* gone */ }
  }
});

// ACTIVE RED (S8.4): dns_forwards present ⇒ set_resolvers carries them on up, and down
// sweeps with an EMPTY desired set (full-sweep withdraw).
test("TunnelController installs then sweeps dns_forwards via set_resolvers", async () => {
  const sockPath = testEndpoint("dnsactive");
  try { fs.unlinkSync(sockPath); } catch { /* fresh */ }
  const { server, requests } = recordingHelper();
  await new Promise<void>((r) => server.listen(sockPath, r));
  try {
    const fwds: ResolverForward[] = [{ domain: "corp.local", resolver_ip: "10.20.0.53" }];
    const cfg = { address: "10.99.0.2/32", dns_forwards: fwds } as unknown as TunnelConfig;
    const ctrl = new TunnelController(sockPath);
    await ctrl.up(async () => cfg);
    await ctrl.down();
    const sets = requests.filter((r) => r.verb === "set_resolvers");
    assert.equal(sets.length, 2, "one install on up, one sweep on down");
    assert.deepEqual(sets[0].resolvers, fwds, "up installs the desired set");
    assert.deepEqual(sets[1].resolvers, [], "down sweeps to empty (full withdraw)");
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
    try { fs.unlinkSync(sockPath); } catch { /* gone */ }
  }
});

test("TunnelController never restores Up resolvers or heartbeat after a down cleanup failure", async () => {
  const sockPath = testEndpoint("dns-refusal-restore");
  try { fs.unlinkSync(sockPath); } catch { /* fresh */ }
  const resolverWrites: ResolverForward[][] = [];
  const serverSockets: net.Socket[] = [];
  let downAttempts = 0;
  const server = net.createServer((sock) => {
    serverSockets.push(sock);
    const dec = new FrameDecoder();
    sock.on("data", (chunk: Buffer) => {
      for (const msg of dec.push(chunk)) {
        const req = msg as { verb: string; resolvers?: ResolverForward[] };
        if (req.verb === "set_resolvers") {
          resolverWrites.push(req.resolvers ?? []);
          sock.write(encodeFrame({ version: PROTOCOL_VERSION, ok: true }));
        } else if (req.verb === "tunnel_down") {
          downAttempts += 1;
          sock.write(encodeFrame(downAttempts === 1
            ? { version: PROTOCOL_VERSION, ok: false, code: "teardown_refused", error: "down denied" }
            : { version: PROTOCOL_VERSION, ok: true, status: { state: "down" } }));
        } else {
          sock.write(encodeFrame({ version: PROTOCOL_VERSION, ok: true, status: { state: "up", rx_bytes: 29 } }));
        }
      }
    });
  });
  await new Promise<void>((resolve) => server.listen(sockPath, resolve));

  const realSetInterval = globalThis.setInterval;
  const realClearInterval = globalThis.clearInterval;
  const heartbeatTicks: Array<() => Promise<void>> = [];
  globalThis.setInterval = ((callback: () => Promise<void>) => {
    heartbeatTicks.push(callback);
    return { unref() { /* fake timer */ } } as unknown as ReturnType<typeof setInterval>;
  }) as unknown as typeof setInterval;
  globalThis.clearInterval = (() => { /* fake timer */ }) as typeof clearInterval;

  const statuses: TunnelStatus[] = [];
  const ctrl = new TunnelController(sockPath, (status) => statuses.push(status));
  try {
    const baked: ResolverForward[] = [{ domain: "corp.example", resolver_ip: "10.20.0.53" }];
    const routed: ResolverForward[] = [
      { domain: "svc.internal", resolver_ip: "10.30.0.53" },
      { domain: "db.internal", resolver_ip: "10.40.0.53" },
    ];
    const config = {
      address: "10.99.0.2/32",
      dns_forwards: baked,
    } as unknown as TunnelConfig;

    await ctrl.up(async () => config);
    await ctrl.setResolvers(routed); // routed monitor supersedes the baked set
    await assert.rejects(ctrl.down(), /teardown_refused: down denied/);

    assert.deepEqual(
      resolverWrites,
      [baked, routed, []],
      "cleanup failure must not reinstall resolver state for an Up tunnel the helper no longer claims",
    );
    assert.equal(heartbeatTicks.length, 1, "cleanup-required never resumes an Up heartbeat");
    assert.deepEqual(statuses, [{ state: "failed" }]);

    await ctrl.down();
    assert.equal(downAttempts, 2, "cleanup-required remains available for an exact retry");
    assert.deepEqual(resolverWrites, [baked, routed, [], []]);
  } finally {
    globalThis.setInterval = realSetInterval;
    globalThis.clearInterval = realClearInterval;
    (ctrl as unknown as { conn: HelperConnection }).conn.close();
    serverSockets.forEach((socket) => socket.destroy());
    await new Promise<void>((resolve) => server.close(() => resolve()));
    try { fs.unlinkSync(sockPath); } catch { /* gone */ }
  }
});

test("TunnelController still runs authoritative tunnel_down when the resolver pre-sweep fails", async () => {
  const sockPath = testEndpoint("dns-refusal-failclosed");
  try { fs.unlinkSync(sockPath); } catch { /* fresh */ }
  const serverSockets: net.Socket[] = [];
  let resolverWrites = 0;
  let downAttempts = 0;
  const server = net.createServer((sock) => {
    serverSockets.push(sock);
    const dec = new FrameDecoder();
    sock.on("data", (chunk: Buffer) => {
      for (const msg of dec.push(chunk)) {
        const req = msg as { verb: string };
        if (req.verb === "set_resolvers") {
          resolverWrites += 1;
          sock.write(encodeFrame(resolverWrites === 3
            ? { version: PROTOCOL_VERSION, ok: false, code: "resolver_restore_failed", error: "not restored" }
            : { version: PROTOCOL_VERSION, ok: true }));
        } else if (req.verb === "tunnel_down") {
          downAttempts += 1;
          sock.write(encodeFrame({ version: PROTOCOL_VERSION, ok: true, status: { state: "down" } }));
        } else {
          sock.write(encodeFrame({ version: PROTOCOL_VERSION, ok: true, status: { state: "up" } }));
        }
      }
    });
  });
  await new Promise<void>((resolve) => server.listen(sockPath, resolve));

  const realSetInterval = globalThis.setInterval;
  const realClearInterval = globalThis.clearInterval;
  let heartbeatCount = 0;
  globalThis.setInterval = ((_: () => Promise<void>) => {
    heartbeatCount += 1;
    return { unref() { /* fake timer */ } } as unknown as ReturnType<typeof setInterval>;
  }) as unknown as typeof setInterval;
  globalThis.clearInterval = (() => { /* fake timer */ }) as typeof clearInterval;

  const statuses: TunnelStatus[] = [];
  const ctrl = new TunnelController(sockPath, (status) => statuses.push(status));
  try {
    const config = {
      address: "10.99.0.2/32",
      dns_forwards: [{ domain: "corp.example", resolver_ip: "10.20.0.53" }],
    } as unknown as TunnelConfig;
    await ctrl.up(async () => config);
    // Make the latest exact state originate from the routed monitor, then make
    // the optional resolver pre-sweep fail. Backend Down is still authoritative.
    await ctrl.setResolvers([{ domain: "svc.internal", resolver_ip: "10.30.0.53" }]);
    await ctrl.down();

    assert.deepEqual(statuses, [], "confirmed authoritative down is not a failed tunnel");
    assert.equal(heartbeatCount, 1, "cleanup never resumes heartbeat ownership");
    assert.equal(resolverWrites, 3, "the failed pre-sweep was attempted exactly once");
    assert.equal(downAttempts, 1, "tunnel_down still runs after the pre-sweep refusal");
    await ctrl.down();
    assert.equal(downAttempts, 1, "confirmed cleanup returns to zero-wire inactive");
  } finally {
    globalThis.setInterval = realSetInterval;
    globalThis.clearInterval = realClearInterval;
    (ctrl as unknown as { conn: HelperConnection }).conn.close();
    serverSockets.forEach((socket) => socket.destroy());
    await new Promise<void>((resolve) => server.close(() => resolve()));
    try { fs.unlinkSync(sockPath); } catch { /* gone */ }
  }
});

// R3 RED (S8.4 fold): an old/Windows helper that REFUSES set_resolvers (ok:false — resolvers_unsupported /
// unknown_verb) must NOT latch resolversActive true; otherwise every future down() emits a redundant empty
// sweep forever. After a refused install, down() sends NO set_resolvers.
test("TunnelController does not redundant-sweep after a refused set_resolvers", async () => {
  const sockPath = testEndpoint("dnsunsup");
  try { fs.unlinkSync(sockPath); } catch { /* fresh */ }
  const requests: Array<{ verb: string }> = [];
  const server = net.createServer((sock) => {
    const dec = new FrameDecoder();
    sock.on("data", (chunk: Buffer) => {
      for (const msg of dec.push(chunk)) {
        const req = msg as { verb: string; resolvers?: ResolverForward[] };
        requests.push({ verb: req.verb });
        if (req.verb === "set_resolvers") {
          sock.write(encodeFrame({ version: PROTOCOL_VERSION, ok: false, code: "resolvers_unsupported", error: "not supported" }));
        } else {
          const state = req.verb === "tunnel_down" ? "down" : "up";
          sock.write(encodeFrame({ version: PROTOCOL_VERSION, ok: true, status: { state } }));
        }
      }
    });
  });
  await new Promise<void>((r) => server.listen(sockPath, r));
  try {
    const cfg = { address: "10.99.0.2/32", dns_forwards: [{ domain: "corp.local", resolver_ip: "10.20.0.53" }] } as unknown as TunnelConfig;
    const ctrl = new TunnelController(sockPath);
    await ctrl.up(async () => cfg);   // set_resolvers REFUSED (unsupported) → must clear the latch
    await ctrl.down();
    const sets = requests.filter((r) => r.verb === "set_resolvers");
    assert.equal(sets.length, 1, "a refused install must not latch a redundant down sweep");
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
    try { fs.unlinkSync(sockPath); } catch { /* gone */ }
  }
});

test("HelperConnection: persistent round-trip, intentional close is quiet, unexpected close fires onLost", async () => {
  const sockPath = testEndpoint("helper");
  try { fs.unlinkSync(sockPath); } catch { /* fresh */ }

  const serverSockets: net.Socket[] = [];
  const server = net.createServer((sock) => {
    serverSockets.push(sock);
    const dec = new FrameDecoder();
    sock.on("data", (chunk: Buffer) => {
      for (const msg of dec.push(chunk)) {
        const req = msg as { verb: string };
        const state = req.verb === "tunnel_down" ? "down" : "up";
        sock.write(encodeFrame({ version: PROTOCOL_VERSION, ok: true, status: { state } }));
      }
    });
  });
  await new Promise<void>((r) => server.listen(sockPath, r));

  try {
    // Persistent round-trip: two requests over ONE held connection, FIFO-matched.
    let lost = false;
    const conn = new HelperConnection(sockPath, () => { lost = true; });
    const up = await conn.request({ version: PROTOCOL_VERSION, auth_mode: "path_check", verb: "tunnel_up" });
    assert.equal(up.ok, true);
    assert.equal(up.status?.state, "up");
    const st = await conn.request({ version: PROTOCOL_VERSION, auth_mode: "path_check", verb: "status" });
    assert.equal(st.status?.state, "up");

    // Intentional close → onLost must NOT fire (this is graceful, not app-death).
    conn.close();
    await delay(50);
    assert.equal(lost, false, "intentional close must be quiet");

    // Reconnect, then simulate HELPER DEATH (server destroys the socket) → onLost.
    let lost2 = false;
    const conn2 = new HelperConnection(sockPath, () => { lost2 = true; });
    await conn2.request({ version: PROTOCOL_VERSION, auth_mode: "path_check", verb: "status" });
    serverSockets.forEach((s) => s.destroy());
    await delay(50);
    assert.equal(lost2, true, "unexpected drop must fire onLost (helper death)");
    conn2.close();
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
    try { fs.unlinkSync(sockPath); } catch { /* gone */ }
  }
});

test("HelperConnection ignores an old socket close callback after reconnect", async () => {
  const sockPath = testEndpoint("late-close");
  try { fs.unlinkSync(sockPath); } catch { /* fresh */ }
  const secondRequestSeen = deferred<net.Socket>();
  const serverSockets: net.Socket[] = [];
  let connectionNumber = 0;
  const server = net.createServer((sock) => {
    serverSockets.push(sock);
    connectionNumber += 1;
    const thisConnection = connectionNumber;
    const dec = new FrameDecoder();
    sock.on("data", (chunk: Buffer) => {
      for (const _ of dec.push(chunk)) {
        if (thisConnection === 1) {
          sock.write(encodeFrame({ version: PROTOCOL_VERSION, ok: true, status: { state: "up" } }));
        } else {
          secondRequestSeen.resolve(sock);
        }
      }
    });
  });
  await new Promise<void>((resolve) => server.listen(sockPath, resolve));

  let lost = 0;
  const conn = new HelperConnection(sockPath, () => { lost += 1; });
  try {
    await conn.request({ version: PROTOCOL_VERSION, auth_mode: "path_check", verb: "status" });
    const oldSocket = (conn as unknown as { sock: net.Socket | null }).sock;
    assert.ok(oldSocket);
    const staleCloseHandler = oldSocket.listeners("close")[0] as (() => void) | undefined;
    assert.ok(staleCloseHandler, "the first socket must own a close handler");
    const oldClosed = new Promise<void>((resolve) => oldSocket.once("close", () => resolve()));

    conn.close();
    await oldClosed;
    assert.equal(lost, 0, "the intentional first close must be quiet");

    const second = conn.request({ version: PROTOCOL_VERSION, auth_mode: "path_check", verb: "status" });
    const secondServerSocket = await secondRequestSeen.promise;

    // Replay the old socket's callback only after the new request is pending.
    // A socket-unscoped callback would null the new socket, reject its waiter,
    // and falsely report helper loss.
    staleCloseHandler();
    assert.equal(lost, 0, "an old socket callback must not report loss for the new socket");
    secondServerSocket.write(encodeFrame({ version: PROTOCOL_VERSION, ok: true, status: { state: "up" } }));
    assert.equal((await second).status?.state, "up", "the new socket's waiter must survive the old callback");
  } finally {
    conn.close();
    serverSockets.forEach((socket) => socket.destroy());
    await new Promise<void>((resolve) => server.close(() => resolve()));
    try { fs.unlinkSync(sockPath); } catch { /* gone */ }
  }
});

test("HelperConnection timeout poisons one FIFO socket before a late response can reach another request", async () => {
  const sockPath = testEndpoint("timeout-poison");
  try { fs.unlinkSync(sockPath); } catch { /* fresh */ }
  const firstTwoSeen = deferred<void>();
  const serverSockets: net.Socket[] = [];
  let connectionNumber = 0;
  let firstRequestCount = 0;
  const server = net.createServer((sock) => {
    serverSockets.push(sock);
    connectionNumber += 1;
    const thisConnection = connectionNumber;
    const dec = new FrameDecoder();
    sock.on("data", (chunk: Buffer) => {
      for (const _ of dec.push(chunk)) {
        if (thisConnection === 1) {
          firstRequestCount += 1;
          if (firstRequestCount === 2) firstTwoSeen.resolve();
          continue; // hold A and B past A's deadline
        }
        sock.write(encodeFrame({ version: PROTOCOL_VERSION, ok: true, status: { state: "up", last_handshake_sec: 333 } }));
      }
    });
  });
  await new Promise<void>((resolve) => server.listen(sockPath, resolve));

  let lost = 0;
  const conn = new HelperConnection(sockPath, () => { lost += 1; });
  try {
    const requestA = conn.request({ version: PROTOCOL_VERSION, auth_mode: "path_check", verb: "status" }, 100);
    const requestB = conn.request({ version: PROTOCOL_VERSION, auth_mode: "path_check", verb: "posture_status" }, 300);
    const aRejected = assert.rejects(requestA, /helper request timed out/);
    const bRejected = assert.rejects(requestB, /helper request timed out/);

    await firstTwoSeen.promise;
    const oldSocket = (conn as unknown as { sock: net.Socket | null }).sock;
    assert.ok(oldSocket);
    const staleDataHandler = oldSocket.listeners("data")[0] as ((chunk: Buffer) => void) | undefined;
    assert.ok(staleDataHandler);
    await Promise.all([aRejected, bRejected]);

    const requestC = conn.request({ version: PROTOCOL_VERSION, auth_mode: "path_check", verb: "status" }, 1000);
    await new Promise<void>((resolve) => setImmediate(resolve));
    staleDataHandler(encodeFrame({ version: PROTOCOL_VERSION, ok: true, status: { state: "up", last_handshake_sec: 111 } }));

    assert.equal((await requestC).status?.last_handshake_sec, 333, "a late A response must not resolve B or a request on the replacement socket");
    assert.equal(connectionNumber, 2, "the first timeout must force the next request onto a new socket");
    assert.equal(lost, 1, "poisoning the current persistent socket is a single helper-loss event");
  } finally {
    conn.close();
    serverSockets.forEach((socket) => socket.destroy());
    await new Promise<void>((resolve) => server.close(() => resolve()));
    try { fs.unlinkSync(sockPath); } catch { /* gone */ }
  }
});
