import { test } from "node:test";
import assert from "node:assert/strict";

import { parseWgConf } from "../src/main/wgconf";
import { TunnelConfigStore, importedProfileOrigin } from "../src/main/tunnelstore";
import { resolveTunnelConfig, discardTunnelConfigForOrigin, removeManagedTunnelConfigForOrigin, migrateLegacyConfig, DeviceRevokedError, PendingApprovalError, cpEndpointFromOrigin, type DeviceApi } from "../src/main/deviceconfig";
import { signOutPreservingDevice } from "../src/main/sessionlifecycle";
import { InsecureStorageError, type Persistence, type SafeStorageLike } from "../src/main/credential";

const CONF = `[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.99.0.2/32
DNS = 10.99.0.1
MTU = 1420

[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`;

test("parseWgConf maps a .conf into a structured config", () => {
  const c = parseWgConf(CONF);
  assert.equal(c.private_key, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
  assert.equal(c.peer_public_key, "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=");
  assert.equal(c.address, "10.99.0.2/32");
  assert.deepEqual(c.addresses, ["10.99.0.2/32"]);
  assert.equal(c.endpoint, "vpn.example.com:51820");
  assert.deepEqual(c.allowed_ips, ["0.0.0.0/0", "::/0"]);
  assert.deepEqual(c.dns, ["10.99.0.1"]);
  assert.equal(c.mtu, 1420);
  assert.equal(c.persistent_keepalive, 25);
});

test("parseWgConf preserves repeated interface addresses for dual-stack", () => {
  const c = parseWgConf(CONF.replace("Address = 10.99.0.2/32", "Address = 10.99.0.2/32\nAddress = fd7a:1b2c:3d4e:33e7::a63:2/128"));
  assert.equal(c.address, "10.99.0.2/32");
  assert.deepEqual(c.addresses, ["10.99.0.2/32", "fd7a:1b2c:3d4e:33e7::a63:2/128"]);
});

test("parseWgConf rejects malformed input", () => {
  assert.throws(() => parseWgConf("PrivateKey = x\n")); // no section
  assert.throws(() => parseWgConf("[Interface]\nAddress = 10.0.0.1/32\n")); // missing PrivateKey
});

// In-memory keychain (identity "encryption") + persistence for the store tests.
function fakeSafe(available = true): SafeStorageLike {
  return {
    isEncryptionAvailable: () => available,
    encryptString: (p) => Buffer.from("enc:" + p, "utf8"),
    decryptString: (b) => b.toString("utf8").replace(/^enc:/, ""),
  };
}
function fakePersist(): Persistence {
  let buf: Buffer | null = null;
  return { read: () => buf, write: (b) => { buf = b; }, clear: () => { buf = null; } };
}

test("TunnelConfigStore is origin-keyed and refuses insecure by default", () => {
  const store = new TunnelConfigStore(fakeSafe(), fakePersist(), false);
  const sc = { origin: "https://a.example", deviceId: "dev-a", orgId: "org-1", config: { ...parseWgConf(CONF), full_tunnel: true } };
  store.put(sc);
  assert.equal(store.get("https://a.example")?.deviceId, "dev-a");
  assert.equal(store.get("https://b.example"), null); // never cross-origin
  assert.equal(store.list().length, 1);
  assert.equal(store.remove("https://a.example")?.deviceId, "dev-a");
  assert.equal(store.get("https://a.example"), null);

  // No keychain + no opt-in → refuse to write plaintext.
  const insecure = new TunnelConfigStore(fakeSafe(false), fakePersist(), false);
  assert.throws(() => insecure.put(sc), (e) => e instanceof InsecureStorageError);
});

test("imported profiles are isolated, named, and retain the legacy single-profile row", () => {
  const store = new TunnelConfigStore(fakeSafe(), fakePersist(), false);
  store.put({
    origin: "imported:local",
    deviceId: "",
    orgId: "",
    imported: true,
    config: { ...parseWgConf(CONF), full_tunnel: false },
  });
  store.put({
    origin: importedProfileOrigin("00000000-0000-4000-8000-000000000001"),
    deviceId: "",
    orgId: "",
    imported: true,
    importedName: "London gateway",
    config: { ...parseWgConf(CONF), endpoint: "uk1.example.com:51820", full_tunnel: true },
  });

  assert.deepEqual(
    store.importedProfiles().map(({ id, name, config }) => ({ id, name, endpoint: config.endpoint })),
    [
      { id: "legacy", name: "Imported profile", endpoint: "vpn.example.com:51820" },
      { id: "00000000-0000-4000-8000-000000000001", name: "London gateway", endpoint: "uk1.example.com:51820" },
    ],
  );
  assert.equal(store.importedProfile("legacy")?.config.private_key, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
  assert.equal(store.importedProfile("00000000-0000-4000-8000-000000000001")?.name, "London gateway");
  assert.equal(store.importedProfile("missing"), null);
});

// fakeApi counts creates/revokes; `exists` drives the self-heal existence check.
function fakeApi(): DeviceApi & { creates: number; modeUpdates: number; revoked: string[]; exists: boolean; pending: boolean } {
  return {
    creates: 0,
    modeUpdates: 0,
    revoked: [],
    exists: true,
    pending: false, // S7.3: when true, createDevice returns pendingApproval
    async createDevice() {
      this.creates++;
      return { deviceId: "dev-" + this.creates, confText: CONF, pendingApproval: this.pending, orgId: "org-1" };
    },
    async revokeDevice(id: string) {
      this.revoked.push(id);
    },
    async updateDeviceMode(_id: string, _org: string, fullTunnel: boolean) {
      this.modeUpdates++;
      return { fullTunnel, address: "10.99.0.2/32", endpoint: "198.51.100.1:51820", peerPublicKey: "peer", allowedIPs: fullTunnel ? ["0.0.0.0/0"] : ["10.99.0.0/24"] };
    },
    async deviceExists() {
      return this.exists;
    },
    async deviceStatus() {
      return this.pending ? "pending" : this.exists ? "active" : "gone";
    },
    async reportHealth() {
      return { state: "compliant", blocked: false, failed_checks: [] } as const;
    },
    async routedConfig() {
      return { ranges: [], forwards: [], dial: null };
    },
  };
}

test("resolveTunnelConfig: get-or-create, never re-fetch (D2)", async () => {
  const store = new TunnelConfigStore(fakeSafe(), fakePersist(), false);
  const api = fakeApi();
  const origin = "https://t.example";

  const c1 = await resolveTunnelConfig(origin, true, api, store);
  assert.equal(api.creates, 1);
  assert.equal(c1.full_tunnel, true); // intent-set, not guessed
  // Second call reuses the stored config — NO second create (never re-fetch).
  const c2 = await resolveTunnelConfig(origin, true, api, store);
  assert.equal(api.creates, 1);
  assert.equal(c2.private_key, c1.private_key);
});

test("same-user sign-out then sign-in reuses the stored UUID, IP and key", async () => {
  const store = new TunnelConfigStore(fakeSafe(), fakePersist(), false);
  const api = fakeApi();
  const origin = "https://t.example";
  const first = await resolveTunnelConfig(origin, false, api, store);

  await signOutPreservingDevice({
    stopMonitors: () => {}, clearSynthesizedState: () => {},
    downTunnel: async () => {}, emitDisconnected: () => {}, logoutSession: async () => {},
  });
  const next = await resolveTunnelConfig(origin, false, api, store);

  assert.equal(api.creates, 1);
  assert.equal(store.get(origin)?.deviceId, "dev-1");
  assert.equal(next.address, first.address);
  assert.equal(next.private_key, first.private_key);
});

test("cpEndpointFromOrigin: host:port, 443 default (WF-A / D-WFA-4)", () => {
  assert.equal(cpEndpointFromOrigin("https://api.example.com"), "api.example.com:443");
  assert.equal(cpEndpointFromOrigin("https://api.example.com:8443"), "api.example.com:8443");
  assert.equal(cpEndpointFromOrigin("http://localhost:3000"), "localhost:3000");
  assert.equal(cpEndpointFromOrigin("not a url"), ""); // unparseable → no carve-out
});

test("resolveTunnelConfig: full-tunnel ATTACHES control_plane_endpoint (D-WFA-4), split OMITS it", async () => {
  const origin = "https://api.example.com";
  // FULL: the CP endpoint rides on top, on both the fresh mint AND the reused-config path.
  const fullStore = new TunnelConfigStore(fakeSafe(), fakePersist(), false);
  const fullApi = fakeApi();
  const cf = await resolveTunnelConfig(origin, true, fullApi, fullStore);
  assert.equal(cf.control_plane_endpoint, "api.example.com:443", "full-tunnel must carry the CP endpoint");
  const cf2 = await resolveTunnelConfig(origin, true, fullApi, fullStore); // reused path
  assert.equal(cf2.control_plane_endpoint, "api.example.com:443", "reused config must ALSO re-attach the CP endpoint");
  // SPLIT: no kill-switch → no carve-out → field omitted.
  const splitStore = new TunnelConfigStore(fakeSafe(), fakePersist(), false);
  const cs = await resolveTunnelConfig(origin, false, fakeApi(), splitStore);
  assert.equal(cs.control_plane_endpoint, undefined, "split-tunnel must NOT carry a CP endpoint (no kill-switch)");
});

test("explicit device removal revokes first, then clears only the selected origin", async () => {
  const store = new TunnelConfigStore(fakeSafe(), fakePersist(), false);
  const api = fakeApi();
  await resolveTunnelConfig("https://t.example", false, api, store);

  await removeManagedTunnelConfigForOrigin("https://t.example", api, store);
  assert.deepEqual(api.revoked, ["dev-1"]);
  assert.equal(store.get("https://t.example"), null);

  // A failed revoke preserves local state so the user can retry; do not orphan a peer.
  await resolveTunnelConfig("https://u.example", false, api, store);
  const throwingApi: DeviceApi = { createDevice: api.createDevice.bind(api), revokeDevice: async () => { throw new Error("network"); }, deviceExists: async () => true, deviceStatus: async () => "active", reportHealth: api.reportHealth.bind(api), routedConfig: async () => ({ ranges: [], forwards: [], dial: null }) };
  await assert.rejects(() => removeManagedTunnelConfigForOrigin("https://u.example", throwingApi, store), /network/);
  assert.ok(store.get("https://u.example"));

  discardTunnelConfigForOrigin("https://u.example", store);
  assert.equal(store.get("https://u.example"), null);
});

test("resolveTunnelConfig: a revoked device stays terminal (no automatic re-enrollment)", async () => {
  const store = new TunnelConfigStore(fakeSafe(), fakePersist(), false);
  const api = fakeApi();
  const origin = "https://t.example";

  await resolveTunnelConfig(origin, false, api, store);
  assert.equal(api.creates, 1); // dev-1 minted + stored

  // The device is revoked server-side. A reconnect must preserve the administrator's
  // access decision rather than silently creating a replacement credential.
  api.exists = false;
  await assert.rejects(() => resolveTunnelConfig(origin, false, api, store), DeviceRevokedError);
  assert.equal(api.creates, 1);
  assert.equal(store.get(origin)?.revoked, true);

  // A terminal marker remains terminal even if a later read would be inconclusive.
  const flakyApi: DeviceApi = {
    createDevice: api.createDevice.bind(api),
    revokeDevice: api.revokeDevice.bind(api),
    deviceExists: async () => { throw new Error("network"); },
    deviceStatus: async () => { throw new Error("network"); },
    reportHealth: api.reportHealth.bind(api), routedConfig: async () => ({ ranges: [], forwards: [], dial: null }),
  };
  await assert.rejects(() => resolveTunnelConfig(origin, false, flakyApi, store), DeviceRevokedError);
  assert.equal(api.creates, 1);
});

test("resolveTunnelConfig: mode changes update the same device", async () => {
  const store = new TunnelConfigStore(fakeSafe(), fakePersist(), false);
  const api = fakeApi();
  const origin = "https://t.example";

  const split = await resolveTunnelConfig(origin, false, api, store);
  assert.equal(api.creates, 1);
  assert.equal(split.full_tunnel, false);

  const full = await resolveTunnelConfig(origin, true, api, store);
  assert.equal(api.creates, 1);
  assert.equal(api.modeUpdates, 1);
  assert.equal(full.full_tunnel, true);
  assert.deepEqual(api.revoked, []);
  assert.equal(store.get(origin)?.deviceId, "dev-1");

  // Same intent again → reuse (no churn).
  await resolveTunnelConfig(origin, true, api, store);
  assert.equal(api.creates, 1);
});

test("resolveTunnelConfig: mode change does not bypass a server-revoked cached device", async () => {
  const store = new TunnelConfigStore(fakeSafe(), fakePersist(), false);
  const api = fakeApi();
  const origin = "https://t.example";

  await resolveTunnelConfig(origin, false, api, store);
  assert.equal(store.get(origin)?.deviceId, "dev-1");

  // A split→full switch must not surface the endpoint's 404, but it also must
  // not silently mint a new credential around an administrator's revocation.
  api.exists = false;
  await assert.rejects(() => resolveTunnelConfig(origin, true, api, store), DeviceRevokedError);

  assert.equal(api.creates, 1);
  assert.equal(api.modeUpdates, 0);
  assert.equal(store.get(origin)?.deviceId, "dev-1");
  assert.equal(store.get(origin)?.revoked, true);
});

// S7.3: a pending device GATES the tunnel — resolveTunnelConfig throws PendingApprovalError
// (so tunnel.up() never arms the helper), persists the device with pending=true, and a
// re-resolve while still pending RE-THROWS instead of minting a duplicate (deviceExists
// returns false for pending and would otherwise false-heal into a second create).
test("resolveTunnelConfig: pending device gates (throws, no duplicate re-mint)", async () => {
  const store = new TunnelConfigStore(fakeSafe(), fakePersist(), false);
  const api = fakeApi();
  api.pending = true;
  const origin = "https://p.example";

  await assert.rejects(
    () => resolveTunnelConfig(origin, false, api, store),
    (e: unknown) => e instanceof PendingApprovalError && (e as PendingApprovalError).deviceId === "dev-1",
  );
  assert.equal(api.creates, 1); // device minted once
  assert.equal(store.get(origin)?.pending, true); // persisted as pending

  // Re-resolve while STILL pending → re-throws, does NOT mint a second device.
  await assert.rejects(() => resolveTunnelConfig(origin, false, api, store), PendingApprovalError);
  assert.equal(api.creates, 1); // NO duplicate create

  // Once approved (pending flag cleared, device now active) → reuse the stored config.
  const sc = store.get(origin)!;
  store.put({ ...sc, pending: false });
  api.pending = false;
  const cfg = await resolveTunnelConfig(origin, false, api, store);
  assert.ok(cfg); // returned the stored config
  assert.equal(api.creates, 1); // still no re-mint (existence check passes for active)
});

test("resolveTunnelConfig: pending device revalidates status before resuming after sign-out", async () => {
  const store = new TunnelConfigStore(fakeSafe(), fakePersist(), false);
  const api = fakeApi();
  api.pending = true;
  const origin = "https://pending.example";
  await assert.rejects(() => resolveTunnelConfig(origin, false, api, store), PendingApprovalError);
  assert.equal(api.creates, 1);

  // Approval happened while the user was signed out: reuse the same device, do not re-mint.
  api.pending = false;
  const cfg = await resolveTunnelConfig(origin, false, api, store);
  assert.equal(api.creates, 1);
  assert.equal(cfg.address, "10.99.0.2/32");
  assert.equal(store.get(origin)?.pending, false);
});

// A pending device cannot be reconfigured until approval; it remains one row and gates.
test("resolveTunnelConfig: mode change while pending keeps the same pending device", async () => {
  const store = new TunnelConfigStore(fakeSafe(), fakePersist(), false);
  const api = fakeApi();
  api.pending = true;
  const origin = "https://m.example";

  // Enroll split -> pending.
  await assert.rejects(() => resolveTunnelConfig(origin, false, api, store), PendingApprovalError);
  assert.equal(api.creates, 1);
  assert.equal(store.get(origin)?.config.full_tunnel, false);

  await assert.rejects(() => resolveTunnelConfig(origin, true, api, store), PendingApprovalError);
  assert.equal(api.creates, 1);
  assert.deepEqual(api.revoked, []);
  assert.equal(store.get(origin)?.config.full_tunnel, false);
});

// Finding #1-#5 (stamping): a LEGACY stored config (no orgId, from a pre-orgId build) is
// opportunistically STAMPED with its org on reuse — migrating onto the hardened direct path.

// REDUCTION 2 DEFENSE: connect() migrates a legacy config (clear + revoke + notice, terminal
// for that connect) BEFORE tunnel.up, so this ConfigProvider should never see a no-orgId
// config. If it does, it must NEVER query or arm it — it drops it and creates fresh (it does
// NOT revoke; connect() owns the cap-freeing revoke). This is the belt that guarantees a
// monitor never runs on a legacy config.
test("resolveTunnelConfig: a no-orgId (legacy) config is dropped + re-minted, never queried", async () => {
  const store = new TunnelConfigStore(fakeSafe(), fakePersist(), false);
  const api = fakeApi();
  let existsCalls = 0;
  let statusCalls = 0;
  const wrapped: DeviceApi = {
    createDevice: api.createDevice.bind(api),
    revokeDevice: api.revokeDevice.bind(api),
    deviceExists: async (...a) => { existsCalls++; return api.deviceExists(...a); },
    deviceStatus: async (...a) => { statusCalls++; return api.deviceStatus(...a); },
    reportHealth: api.reportHealth.bind(api), routedConfig: async () => ({ ranges: [], forwards: [], dial: null }),
  };
  const origin = "https://legacy.example";
  // A legacy stored config: NO orgId field (as an old build persisted it).
  store.put({ origin, deviceId: "dev-old", config: { ...parseWgConf(CONF), full_tunnel: false } } as never);

  const cfg = await resolveTunnelConfig(origin, false, wrapped, store);
  assert.ok(cfg);
  assert.equal(existsCalls, 0); // NEVER queried a no-orgId config (no monitor could run on it)
  assert.equal(statusCalls, 0);
  assert.equal(api.creates, 1); // dropped the legacy config + created fresh
  assert.deepEqual(api.revoked, []); // resolveTunnelConfig does NOT revoke — connect() owns that
  assert.equal(store.get(origin)?.deviceId, "dev-1"); // fresh device
  assert.ok(store.get(origin)?.orgId); // carries orgId (direct path)
});

// REDUCTION 2 harden — REVOKE-FIRST migration. The revoke frees the cap slot the next connect
// needs, so it runs BEFORE clearing and the config is cleared ONLY on revoke success.
test("migrateLegacyConfig: revoke ok -> config cleared (slot freed before next create)", async () => {
  const store = new TunnelConfigStore(fakeSafe(), fakePersist(), false);
  const origin = "https://legacy.example";
  store.put({ origin, deviceId: "dev-old", config: { ...parseWgConf(CONF), full_tunnel: false } } as never);
  const revoked: string[] = [];
  const ok = { revokeDevice: async (id: string) => { revoked.push(id); } } as unknown as DeviceApi;
  await migrateLegacyConfig(origin, "dev-old", ok, store);
  assert.deepEqual(revoked, ["dev-old"]); // slot freed
  assert.equal(store.get(origin), null); // cleared after revoke success
});

// The permanence case, now self-healing: a revoke BLIP keeps the config (throws), and the
// NEXT attempt (working revoke) succeeds — no admin-reap, no lockout.
test("migrateLegacyConfig: a revoke blip KEEPS the config; retry self-heals (no lockout)", async () => {
  const store = new TunnelConfigStore(fakeSafe(), fakePersist(), false);
  const origin = "https://legacy.example";
  store.put({ origin, deviceId: "dev-old", config: { ...parseWgConf(CONF), full_tunnel: false } } as never);

  const failing = { revokeDevice: async () => { throw new Error("network"); } } as unknown as DeviceApi;
  await assert.rejects(() => migrateLegacyConfig(origin, "dev-old", failing, store), /network/);
  assert.equal(store.get(origin)?.deviceId, "dev-old"); // config KEPT (revoke ran before remove)

  const ok = { revokeDevice: async () => {} } as unknown as DeviceApi;
  await migrateLegacyConfig(origin, "dev-old", ok, store); // retry
  assert.equal(store.get(origin), null); // now cleared — self-recovered, no admin-reap
});

// The THIRD documented state: revoke OK but store.remove throws (e.g. a storage write error).
// migrateLegacyConfig must throw (config NOT silently half-cleared) AFTER the revoke ran, so the
// caller degrades to the one soft-down outcome and the next connect re-detects + re-revokes
// (404 = idempotent). Proves the revoke-BEFORE-remove ordering for this state.
test("migrateLegacyConfig: revoke ok but remove throws -> throws, revoke already ran (ordering held)", async () => {
  const revoked: string[] = [];
  const okApi = { revokeDevice: async (id: string) => { revoked.push(id); } } as unknown as DeviceApi;
  const throwingStore = {
    remove: () => { throw new Error("insecure_storage"); },
  } as unknown as TunnelConfigStore;
  await assert.rejects(
    () => migrateLegacyConfig("https://legacy.example", "dev-old", okApi, throwingStore),
    /insecure_storage/,
  );
  assert.deepEqual(revoked, ["dev-old"]); // revoke ran BEFORE the failing remove (order proven)
});
