import { test } from "node:test";
import assert from "node:assert/strict";

import { parseWgConf } from "../src/main/wgconf";
import {
  TunnelConfigStore,
  TunnelConfigStoreCorruptError,
  importedProfileOrigin,
} from "../src/main/tunnelstore";
import {
  bindManagedDeviceOwner,
  commitManagedDeviceOwnerProof,
  resolveTunnelConfig as resolveTunnelConfigWithRecovery,
  discardTunnelConfigForOrigin,
  removeManagedTunnelConfigForOrigin,
  migrateLegacyConfig,
  proveManagedDeviceOwner,
  proveLegacyManagedDeviceOwner,
  parseImportedTunnelConfig,
  revokeAndClearManagedDevice,
  revokeAndClearLegacyManagedDevice,
  DeviceRevokedError,
  ManagedDeviceOwnerMismatchError,
  ManagedDeviceOwnerUnconfirmedError,
  PendingApprovalError,
  cpEndpointFromOrigin,
  type DeviceApi,
} from "../src/main/deviceconfig";
import { EnrollmentAnchorStore } from "../src/main/enrollmentanchor";
import { OrganizationSelectionConflictError, OrganizationSelectionRequiredError } from "../src/main/orgselection";
import { ManagedLifecycleCoordinator, type CredentialSnapshot } from "../src/main/managedlifecycle";
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
AllowedIPs = 10.99.0.0/24
PersistentKeepalive = 25
`;
const FULL_CONF = CONF.replace("10.99.0.0/24", "0.0.0.0/0, ::/0");

const USER_A = "00000000-0000-4000-8000-00000000000a";
const USER_B = "00000000-0000-4000-8000-00000000000b";
const DEVICE_A = "00000000-0000-4000-8000-00000000000c";

test("parseWgConf maps a .conf into a structured config", () => {
  const c = parseWgConf(FULL_CONF);
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

test("parseWgConf rejects unsupported, duplicate, and invalid numeric directives without echoing values", () => {
  const sentinel = "WG_IMPORT_SECRET_SENTINEL";
  const malformed = [
    CONF.replace("MTU = 1420", `Table = ${sentinel}`),
    CONF.replace("PersistentKeepalive = 25", `PresharedKey = ${sentinel}`),
    `${CONF}\n[Interface]\nAddress = 10.99.0.3/32\n`,
    `${CONF}\n[Peer]\nEndpoint = other.example:51820\n`,
    CONF.replace("Address = 10.99.0.2/32", `PrivateKey = ${sentinel}\nAddress = 10.99.0.2/32`),
    CONF.replace("AllowedIPs = 10.99.0.0/24", `Endpoint = other.example:51820\nAllowedIPs = 10.99.0.0/24`),
    CONF.replace("MTU = 1420", "MTU = nope"),
    CONF.replace("MTU = 1420", "MTU = 1279"),
    CONF.replace("MTU = 1420", "MTU = 1501"),
    CONF.replace("PersistentKeepalive = 25", "PersistentKeepalive = nope"),
    CONF.replace("PersistentKeepalive = 25", "PersistentKeepalive = -1"),
    CONF.replace("PersistentKeepalive = 25", "PersistentKeepalive = 65536"),
  ];

  for (const text of malformed) {
    assert.throws(
      () => parseWgConf(text),
      (error: unknown) => {
        assert.ok(error instanceof Error);
        assert.match(error.message, /malformed \.conf line \d+:/);
        assert.doesNotMatch(error.message, new RegExp(sentinel));
        return true;
      },
    );
  }
});

test("parseWgConf rejects malformed input", () => {
  assert.throws(() => parseWgConf("PrivateKey = x\n")); // no section
  assert.throws(() => parseWgConf("[Interface]\nAddress = 10.0.0.1/32\n")); // missing PrivateKey
});

test("parseWgConf never echoes secret-bearing malformed lines", () => {
  const secret = "PRIVATE_KEY_SENTINEL_must_never_cross_IPC_or_logs";
  for (const malformed of [
    `PrivateKey = ${secret}\n`,
    `[Interface]\nPrivateKey ${secret}\n`,
  ]) {
    assert.throws(
      () => parseWgConf(malformed),
      (error: unknown) => {
        assert.ok(error instanceof Error);
        assert.match(error.message, /malformed \.conf line \d+:/);
        assert.doesNotMatch(error.message, new RegExp(secret));
        return true;
      },
    );
  }
});

test("imported config validation is complete and secret-safe before lifecycle entry", () => {
  const valid = parseImportedTunnelConfig(FULL_CONF);
  assert.equal(valid.full_tunnel, true);
  assert.equal(valid.endpoint, "vpn.example.com:51820");
  assert.equal(parseImportedTunnelConfig(CONF).full_tunnel, false);

  const sentinel = "IMPORTED_PRIVATE_KEY_SENTINEL";
  const malformed = [
    FULL_CONF.replace("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", sentinel),
    FULL_CONF.replace("10.99.0.2/32", "10.99.0.2"),
    FULL_CONF.replace("vpn.example.com:51820", "127.0.0.1:51820"),
    FULL_CONF.replace("0.0.0.0/0, ::/0", "not-a-cidr"),
    // Import infers full-tunnel from either-family default; the helper contract
    // still requires the IPv4 default, so an IPv6-only default fails closed.
    FULL_CONF.replace("0.0.0.0/0, ::/0", "::/0"),
  ];
  for (const text of malformed) {
    assert.throws(
      () => parseImportedTunnelConfig(text),
      (error: unknown) => {
        assert.ok(error instanceof Error);
        assert.equal(error.message, "invalid_imported_config");
        assert.doesNotMatch(error.message, new RegExp(sentinel));
        return true;
      },
    );
  }
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

// Existing behavior tests use a fresh, durable-by-contract in-memory anchor.
// D14o crash-boundary tests below call the production resolver directly with a
// shared/faulting anchor store.
function resolveTunnelConfig(
  origin: string,
  fullTunnel: boolean,
  api: DeviceApi,
  store: TunnelConfigStore,
  organizationId?: string,
  ownerUserId?: string,
) {
  return resolveTunnelConfigWithRecovery(
    origin,
    fullTunnel,
    api,
    store,
    organizationId,
    ownerUserId,
    organizationId && ownerUserId
      ? {
          anchorStore: new EnrollmentAnchorStore(fakeSafe(), fakePersist(), false),
          credentialFingerprint: "fingerprint-a",
        }
      : undefined,
  );
}

function trackedPersist(): { persistence: Persistence; writes(): number; bytes(): Buffer | null } {
  let buf: Buffer | null = null;
  let writeCount = 0;
  return {
    persistence: {
      read: () => buf,
      write: (b) => { buf = b; writeCount += 1; },
      clear: () => { buf = null; },
    },
    writes: () => writeCount,
    bytes: () => buf === null ? null : Buffer.from(buf),
  };
}

function seededPersist(initial: Buffer, readError = false): {
  persistence: Persistence;
  writes(): number;
  bytes(): Buffer;
} {
  let buf = Buffer.from(initial);
  let writeCount = 0;
  return {
    persistence: {
      read: () => {
        if (readError) throw new Error("storage_read_detail_must_not_escape");
        return buf;
      },
      write: (next) => { buf = Buffer.from(next); writeCount += 1; },
      clear: () => { buf = Buffer.alloc(0); },
    },
    writes: () => writeCount,
    bytes: () => Buffer.from(buf),
  };
}

test("TunnelConfigStore is origin-keyed and refuses insecure by default", () => {
  const store = new TunnelConfigStore(fakeSafe(), fakePersist(), false);
  const sc = { origin: "https://a.example", deviceId: "00000000-0000-4000-8000-000000000101", orgId: "00000000-0000-4000-8000-000000000201", config: { ...parseWgConf(FULL_CONF), full_tunnel: true } };
  store.put(sc);
  assert.equal(store.get("https://a.example")?.deviceId, "00000000-0000-4000-8000-000000000101");
  assert.equal(store.get("https://b.example"), null); // never cross-origin
  assert.equal(store.list().length, 1);
  assert.equal(store.remove("https://a.example")?.deviceId, "00000000-0000-4000-8000-000000000101");
  assert.equal(store.get("https://a.example"), null);

  // No keychain + no opt-in → refuse to write plaintext.
  const insecure = new TunnelConfigStore(fakeSafe(false), fakePersist(), false);
  assert.throws(() => insecure.put(sc), (e) => e instanceof InsecureStorageError);
});

test("TunnelConfigStore distinguishes true absence from present-but-corrupt persistence", async () => {
  const absentPersist = trackedPersist();
  const absentStore = new TunnelConfigStore(fakeSafe(), absentPersist.persistence, false);
  const absentApi = fakeApi();
  assert.equal(absentStore.get("https://absent.example"), null);
  await resolveTunnelConfig("https://absent.example", false, absentApi, absentStore, "00000000-0000-4000-8000-000000000201", USER_A);
  assert.equal(absentApi.creates, 1, "only a true null persistence read authorizes fresh enrollment");

  const sentinel = "CORRUPT_STORE_SECRET_SENTINEL";
  const corruptCases: Array<{
    name: string;
    persisted: ReturnType<typeof seededPersist>;
    safe: SafeStorageLike;
  }> = [
    {
      name: "invalid JSON",
      persisted: seededPersist(Buffer.from(`enc:{${sentinel}`, "utf8")),
      safe: fakeSafe(),
    },
    {
      name: "root type confusion",
      persisted: seededPersist(Buffer.from("enc:[]", "utf8")),
      safe: fakeSafe(),
    },
    {
      name: "record schema corruption",
      persisted: seededPersist(Buffer.from(`enc:${JSON.stringify({
        "https://corrupt.example": {
          origin: "https://corrupt.example",
          deviceId: "00000000-0000-4000-8000-000000000104",
          orgId: "00000000-0000-4000-8000-000000000201",
          config: sentinel,
        },
      })}`, "utf8")),
      safe: fakeSafe(),
    },
    {
      name: "tampered decrypt",
      persisted: seededPersist(Buffer.from(`ciphertext-${sentinel}`, "utf8")),
      safe: {
        isEncryptionAvailable: () => true,
        encryptString: (plain) => Buffer.from(plain, "utf8"),
        decryptString: () => { throw new Error(`decrypt_failed_${sentinel}`); },
      },
    },
    {
      name: "unreadable persistence",
      persisted: seededPersist(Buffer.from(`ciphertext-${sentinel}`, "utf8"), true),
      safe: fakeSafe(),
    },
  ];

  for (const scenario of corruptCases) {
    const origin = "https://corrupt.example";
    const store = new TunnelConfigStore(scenario.safe, scenario.persisted.persistence, false);
    const bytesBefore = scenario.persisted.bytes();
    let apiCalls = 0;
    const refuseApi = async (): Promise<never> => { apiCalls += 1; throw new Error("api_must_not_run"); };
    const api: DeviceApi = {
      prepareDeviceEnrollment: refuseApi,
      devicesByPublicKey: refuseApi,
      createDevice: refuseApi,
      updateDeviceMode: refuseApi,
      revokeDevice: refuseApi,
      discoverLegacyDevice: refuseApi,
      deviceRecord: refuseApi,
      deviceStatus: refuseApi,
      deviceExists: refuseApi,
      reportHealth: refuseApi,
      routedConfig: refuseApi,
    };
    const actions: Array<{ name: string; run: () => unknown | Promise<unknown> }> = [
      { name: "get", run: () => store.get(origin) },
      { name: "resolve", run: () => resolveTunnelConfig(origin, false, api, store, "00000000-0000-4000-8000-000000000201", USER_A) },
      { name: "proof", run: () => proveManagedDeviceOwner(origin, USER_A, api, store, () => {}) },
      { name: "remove", run: () => removeManagedTunnelConfigForOrigin(origin, USER_A, api, store) },
      { name: "select", run: () => store.importedProfile("legacy") },
    ];

    for (const action of actions) {
      await assert.rejects(
        async () => action.run(),
        (error: unknown) => {
          assert.ok(error instanceof TunnelConfigStoreCorruptError, `${scenario.name}/${action.name}`);
          assert.equal(error.message, "tunnel_config_store_corrupt");
          assert.doesNotMatch(error.message, new RegExp(sentinel));
          return true;
        },
      );
    }
    assert.equal(apiCalls, 0, `${scenario.name}: no API path may interpret corruption as absence`);
    assert.equal(scenario.persisted.writes(), 0, `${scenario.name}: corrupt bytes are never overwritten`);
    assert.deepEqual(scenario.persisted.bytes(), bytesBefore, `${scenario.name}: exact recovery bytes remain untouched`);
  }
});

test("a path-shaped managed organization cannot mint a destructive owner proof", async () => {
  const origin = "https://malformed-owner.example";
  const malformed = {
    origin,
    deviceId: DEVICE_A,
    orgId: "../auth/logout?",
    ownerUserId: USER_A,
    config: { ...parseWgConf(CONF), full_tunnel: false },
  };
  let apiReads = 0;
  let writes = 0;
  let clears = 0;
  const store = {
    get: () => malformed,
    put: () => { writes += 1; },
    remove: () => { clears += 1; return malformed; },
  } as unknown as TunnelConfigStore;

  await assert.rejects(
    () => proveManagedDeviceOwner(
      origin,
      USER_A,
      { deviceRecord: async () => { apiReads += 1; return { status: "active", userId: USER_A }; } },
      store,
      () => {},
    ),
    ManagedDeviceOwnerUnconfirmedError,
  );
  assert.deepEqual({ apiReads, writes, clears }, { apiReads: 0, writes: 0, clears: 0 });
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
    config: { ...parseWgConf(FULL_CONF), endpoint: "uk1.example.com:51820", full_tunnel: true },
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
function fakeApi(): DeviceApi & {
  creates: number;
  modeUpdates: number;
  revoked: string[];
  legacyDiscovered: string[];
  selectedOrganizations: string[];
  exists: boolean;
  pending: boolean;
  ownerUserId: string;
  recordPresent: boolean;
  publicKey: string;
  enrollmentKeys: Map<string, string>;
} {
  return {
    creates: 0,
    modeUpdates: 0,
    revoked: [],
    legacyDiscovered: [],
    selectedOrganizations: [],
    exists: true,
    pending: false, // S7.3: when true, createDevice returns pendingApproval
    ownerUserId: USER_A,
    recordPresent: true,
    publicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    enrollmentKeys: new Map(),
    async prepareDeviceEnrollment() {
      return {
        nodeId: "00000000-0000-4000-8000-000000000301",
        name: "tunnex-desktop-test",
        platform: "darwin",
      };
    },
    async devicesByPublicKey(organizationId: string, publicKey: string) {
      if (this.enrollmentKeys.get(organizationId) !== publicKey) return [];
      return [{
        deviceId: "00000000-0000-4000-8000-000000000102",
        ownerUserId: this.ownerUserId,
        nodeId: "00000000-0000-4000-8000-000000000301",
        publicKey,
        status: this.pending ? "pending" as const : "active" as const,
      }];
    },
    async createDevice(intent) {
      this.creates++;
      this.selectedOrganizations.push(intent.organizationId);
      this.publicKey = intent.publicKey;
      this.enrollmentKeys.set(intent.organizationId, intent.publicKey);
      return {
        deviceId: "00000000-0000-4000-8000-000000000102",
        ownerUserId: this.ownerUserId,
        nodeId: intent.nodeId,
        publicKey: intent.publicKey,
        status: this.pending ? "pending" as const : "active" as const,
      };
    },
    async revokeDevice(id: string) {
      this.revoked.push(id);
    },
    async discoverLegacyDevice(id: string, expectedOwnerUserId: string) {
      assert.equal(expectedOwnerUserId, this.ownerUserId);
      this.legacyDiscovered.push(id);
      return "00000000-0000-4000-8000-000000000204";
    },
    async deviceRecord() {
      if (!this.recordPresent) return null;
      return { status: this.pending ? "pending" : this.exists ? "active" : "gone", userId: this.ownerUserId } as const;
    },
    async updateDeviceMode(id: string, _org: string, fullTunnel: boolean) {
      this.modeUpdates++;
      return {
        deviceId: id,
        ownerUserId: this.ownerUserId,
        nodeId: "00000000-0000-4000-8000-000000000301",
        publicKey: this.publicKey,
        status: this.pending ? "pending" as const : "active" as const,
        fullTunnel,
        address: "10.99.0.2/32",
        endpoint: "198.51.100.1:51820",
        peerPublicKey: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
        allowedIPs: fullTunnel ? ["0.0.0.0/0"] : ["10.99.0.0/24"],
      };
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

  const c1 = await resolveTunnelConfig(origin, true, api, store, "00000000-0000-4000-8000-000000000201", USER_A);
  assert.equal(api.creates, 1);
  assert.deepEqual(api.selectedOrganizations, ["00000000-0000-4000-8000-000000000201"]);
  assert.equal(store.get(origin)?.ownerUserId, USER_A);
  assert.equal(c1.full_tunnel, true); // intent-set, not guessed
  // Second call reuses the stored config — NO second create (never re-fetch).
  const c2 = await resolveTunnelConfig(origin, true, api, store, "00000000-0000-4000-8000-000000000201", USER_A);
  assert.equal(api.creates, 1);
  assert.equal(c2.private_key, c1.private_key);
});

test("resolveTunnelConfig: fresh enrollment requires and forwards an explicit organization", async () => {
  const store = new TunnelConfigStore(fakeSafe(), fakePersist(), false);
  const api = fakeApi();
  const origin = "https://selected.example";

  await assert.rejects(
    () => resolveTunnelConfig(origin, false, api, store),
    OrganizationSelectionRequiredError,
  );
  assert.equal(api.creates, 0, "no selection must make no device POST");

  await resolveTunnelConfig(origin, false, api, store, "00000000-0000-4000-8000-000000000203", USER_A);
  assert.deepEqual(api.selectedOrganizations, ["00000000-0000-4000-8000-000000000203"]);
  assert.equal(store.get(origin)?.orgId, "00000000-0000-4000-8000-000000000203");
});

test("resolveTunnelConfig: a stored org refuses a different selection until removal", async () => {
  const store = new TunnelConfigStore(fakeSafe(), fakePersist(), false);
  const api = fakeApi();
  const origin = "https://enrolled.example";
  await resolveTunnelConfig(origin, false, api, store, "00000000-0000-4000-8000-000000000202", USER_A);

  await assert.rejects(
    () => resolveTunnelConfig(origin, false, api, store, "00000000-0000-4000-8000-000000000203", USER_A),
    OrganizationSelectionConflictError,
  );
  assert.equal(api.creates, 1);
  assert.equal(store.get(origin)?.orgId, "00000000-0000-4000-8000-000000000202");
});

test("resolveTunnelConfig: fresh create verifies the returned human owner before storing", async () => {
  const store = new TunnelConfigStore(fakeSafe(), fakePersist(), false);
  const api = fakeApi();
  api.ownerUserId = USER_B;

  await assert.rejects(
    () => resolveTunnelConfig("https://foreign-create.example", false, api, store, "00000000-0000-4000-8000-000000000202", USER_A),
    ManagedDeviceOwnerMismatchError,
  );
  assert.equal(api.creates, 1, "the server mutation happened before its response could be verified");
  assert.equal(store.get("https://foreign-create.example"), null, "a foreign response is never persisted or armed");

  const missingOwnerApi: DeviceApi = {
    ...fakeApi(),
    async createDevice(intent) {
      return {
        deviceId: "00000000-0000-4000-8000-000000000107",
        ownerUserId: "",
        nodeId: intent.nodeId,
        publicKey: intent.publicKey,
        status: "active",
      };
    },
  };
  await assert.rejects(
    () => resolveTunnelConfig("https://missing-owner.example", false, missingOwnerApi, store, "00000000-0000-4000-8000-000000000202", USER_A),
    ManagedDeviceOwnerUnconfirmedError,
  );
  assert.equal(store.get("https://missing-owner.example"), null);
});

test("resolveTunnelConfig: malformed enrollment facts never persist or reach the helper-facing return", async () => {
  const sentinel = "FRESH_CONFIG_SENTINEL";
  const cases: Array<{ name: string; fullTunnel: boolean; patch: Record<string, unknown> }> = [
    { name: "peer key", fullTunnel: false, patch: { peerPublicKey: sentinel } },
    { name: "address", fullTunnel: false, patch: { address: "10.99.0.2" } },
    { name: "endpoint", fullTunnel: false, patch: { endpoint: "127.0.0.1:51820" } },
    { name: "AllowedIPs", fullTunnel: false, patch: { allowedIPs: ["not-a-cidr"] } },
    { name: "split with IPv4 default", fullTunnel: false, patch: { allowedIPs: ["0.0.0.0/0"] } },
    { name: "split with IPv6 default", fullTunnel: false, patch: { allowedIPs: ["::/0"] } },
    { name: "full without default", fullTunnel: true, patch: { allowedIPs: ["10.99.0.0/24"] } },
  ];

  for (const scenario of cases) {
    const tracked = trackedPersist();
    const store = new TunnelConfigStore(fakeSafe(), tracked.persistence, false);
    const origin = `https://fresh-${scenario.name.replace(/[^a-z]+/gi, "-").toLowerCase()}.example`;
    const api = fakeApi();
    api.updateDeviceMode = async (deviceId, _organizationId, fullTunnel) => {
      return {
        deviceId,
        ownerUserId: USER_A,
        nodeId: "00000000-0000-4000-8000-000000000301",
        publicKey: api.publicKey,
        status: "active",
        fullTunnel,
        address: "10.99.0.2/32",
        endpoint: "198.51.100.1:51820",
        peerPublicKey: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
        allowedIPs: fullTunnel ? ["0.0.0.0/0"] : ["10.99.0.0/24"],
        ...scenario.patch,
      };
    };
    let helperFacingReturns = 0;

    await assert.rejects(
      async () => {
        await resolveTunnelConfig(origin, scenario.fullTunnel, api, store, "00000000-0000-4000-8000-000000000202", USER_A);
        helperFacingReturns += 1;
      },
      (error: unknown) => {
        assert.ok(error instanceof Error, scenario.name);
        assert.equal(error.message, "create_device_failed: invalid_response", scenario.name);
        assert.doesNotMatch(error.message, new RegExp(sentinel));
        return true;
      },
    );

    assert.equal(api.creates, 1, `${scenario.name}: public identity is created before mutable facts are read`);
    assert.equal(helperFacingReturns, 0, `${scenario.name}: malformed config never leaves the provider`);
    assert.equal(tracked.writes(), 0, `${scenario.name}: malformed config is never persisted`);
    assert.equal(store.get(origin), null, `${scenario.name}: true absence remains after refusal`);
  }
});

test("bindManagedDeviceOwner: exact live ownership binds once; foreign/absent/malformed/inconclusive retain", async () => {
  const origin = "https://ownerless.example";
  const makeStore = () => {
    const store = new TunnelConfigStore(fakeSafe(), fakePersist(), false);
    store.put({ origin, deviceId: "00000000-0000-4000-8000-000000000109", orgId: "00000000-0000-4000-8000-000000000202", config: { ...parseWgConf(CONF), full_tunnel: false } } as never);
    return store;
  };

  const ownedStore = makeStore();
  const ownedApi = fakeApi();
  await bindManagedDeviceOwner(origin, USER_A, ownedApi, ownedStore);
  assert.equal(ownedStore.get(origin)?.ownerUserId, USER_A);

  const foreignStore = makeStore();
  const foreignApi = fakeApi();
  foreignApi.ownerUserId = USER_B;
  await assert.rejects(
    () => bindManagedDeviceOwner(origin, USER_A, foreignApi, foreignStore),
    ManagedDeviceOwnerMismatchError,
  );
  assert.equal(foreignStore.get(origin)?.ownerUserId, undefined);

  const absentStore = makeStore();
  const absentApi = fakeApi();
  absentApi.recordPresent = false;
  await assert.rejects(
    () => bindManagedDeviceOwner(origin, USER_A, absentApi, absentStore),
    ManagedDeviceOwnerUnconfirmedError,
  );
  assert.equal(absentStore.get(origin)?.ownerUserId, undefined);

  const malformedStore = makeStore();
  const malformedApi: DeviceApi = { ...fakeApi(), deviceRecord: async () => ({ status: "active", userId: "" }) };
  await assert.rejects(
    () => bindManagedDeviceOwner(origin, USER_A, malformedApi, malformedStore),
    ManagedDeviceOwnerUnconfirmedError,
  );
  assert.equal(malformedStore.get(origin)?.ownerUserId, undefined);

  const failedStore = makeStore();
  const failedApi: DeviceApi = { ...fakeApi(), deviceRecord: async () => { throw new Error("network"); } };
  await assert.rejects(() => bindManagedDeviceOwner(origin, USER_A, failedApi, failedStore), /network/);
  assert.equal(failedStore.get(origin)?.ownerUserId, undefined);

  const racedStore = makeStore();
  const racedApi: DeviceApi = {
    ...fakeApi(),
    deviceRecord: async () => {
      racedStore.put({
        origin,
        deviceId: "00000000-0000-4000-8000-000000000108",
        orgId: "00000000-0000-4000-8000-000000000203",
        ownerUserId: USER_B,
        config: { ...parseWgConf(CONF), full_tunnel: false },
      });
      return { status: "active", userId: USER_A };
    },
  };
  await assert.rejects(
    () => bindManagedDeviceOwner(origin, USER_A, racedApi, racedStore),
    ManagedDeviceOwnerUnconfirmedError,
  );
  assert.equal(racedStore.get(origin)?.deviceId, "00000000-0000-4000-8000-000000000108");
  assert.equal(racedStore.get(origin)?.ownerUserId, USER_B);
});

test("managed owner proof is read-only for an ownerless record and exposes only safe identity facts", async () => {
  const origin = "https://owner-proof.example";
  const tracked = trackedPersist();
  const store = new TunnelConfigStore(fakeSafe(), tracked.persistence, false);
  store.put({
    origin,
    deviceId: "00000000-0000-4000-8000-000000000109",
    orgId: "00000000-0000-4000-8000-000000000202",
    config: { ...parseWgConf(CONF), full_tunnel: false },
  });
  const writesBeforeProof = tracked.writes();

  const proof = await proveManagedDeviceOwner(origin, USER_A, fakeApi(), store, () => {});

  assert.ok(proof);
  assert.deepEqual(Object.keys(proof).sort(), ["deviceId", "organizationId"]);
  assert.equal(proof.deviceId, "00000000-0000-4000-8000-000000000109");
  assert.equal(proof.organizationId, "00000000-0000-4000-8000-000000000202");
  assert.ok(Object.isFrozen(proof));
  assert.equal(tracked.writes(), writesBeforeProof, "proof must not persist the live owner");
  assert.equal(store.get(origin)?.ownerUserId, undefined);
});

test("managed owner proof accepts a structurally valid bound record without a live read or write", async () => {
  const origin = "https://bound-proof.example";
  const tracked = trackedPersist();
  const store = new TunnelConfigStore(fakeSafe(), tracked.persistence, false);
  store.put({
    origin,
    deviceId: "00000000-0000-4000-8000-000000000103",
    orgId: "00000000-0000-4000-8000-000000000202",
    ownerUserId: USER_A,
    config: { ...parseWgConf(CONF), full_tunnel: false },
  });
  const writesBeforeProof = tracked.writes();
  let recordReads = 0;
  const api: Pick<DeviceApi, "deviceRecord"> = {
    deviceRecord: async () => { recordReads += 1; throw new Error("must not read"); },
  };

  const proof = await proveManagedDeviceOwner(origin, USER_A, api, store, () => {});
  assert.ok(proof);
  commitManagedDeviceOwnerProof(proof, () => {});

  assert.equal(recordReads, 0);
  assert.equal(tracked.writes(), writesBeforeProof, "an already-bound proof commit is a no-write success");
  assert.equal(store.get(origin)?.ownerUserId, USER_A);
});

test("managed owner proof refuses malformed, foreign, and proof-time raced records without binding", async () => {
  const config = { ...parseWgConf(CONF), full_tunnel: false };

  const malformedOrigin = "https://malformed-owner-proof.example";
  const malformedSafe = fakeSafe();
  const malformedPersist = seededPersist(malformedSafe.encryptString(JSON.stringify({
    [malformedOrigin]: {
    origin: malformedOrigin,
    deviceId: "",
    orgId: "00000000-0000-4000-8000-000000000202",
    ownerUserId: USER_A,
    config,
    },
  })));
  const malformedStore = new TunnelConfigStore(malformedSafe, malformedPersist.persistence, false);
  let malformedReads = 0;
  await assert.rejects(
    () => proveManagedDeviceOwner(malformedOrigin, USER_A, {
      deviceRecord: async () => { malformedReads += 1; return { status: "active", userId: USER_A }; },
    }, malformedStore, () => {}),
    TunnelConfigStoreCorruptError,
  );
  assert.equal(malformedReads, 0);
  assert.throws(() => malformedStore.get(malformedOrigin), TunnelConfigStoreCorruptError);

  const boundForeignOrigin = "https://bound-foreign-owner-proof.example";
  const boundForeignStore = new TunnelConfigStore(fakeSafe(), fakePersist(), false);
  boundForeignStore.put({
    origin: boundForeignOrigin,
    deviceId: "00000000-0000-4000-8000-000000000105",
    orgId: "00000000-0000-4000-8000-000000000202",
    ownerUserId: USER_B,
    config,
  });
  await assert.rejects(
    () => proveManagedDeviceOwner(boundForeignOrigin, USER_A, fakeApi(), boundForeignStore, () => {}),
    ManagedDeviceOwnerMismatchError,
  );
  assert.equal(boundForeignStore.get(boundForeignOrigin)?.ownerUserId, USER_B);

  const liveForeignOrigin = "https://live-foreign-owner-proof.example";
  const liveForeignStore = new TunnelConfigStore(fakeSafe(), fakePersist(), false);
  liveForeignStore.put({ origin: liveForeignOrigin, deviceId: "00000000-0000-4000-8000-000000000109", orgId: "00000000-0000-4000-8000-000000000202", config });
  const foreignApi = fakeApi();
  foreignApi.ownerUserId = USER_B;
  await assert.rejects(
    () => proveManagedDeviceOwner(liveForeignOrigin, USER_A, foreignApi, liveForeignStore, () => {}),
    ManagedDeviceOwnerMismatchError,
  );
  assert.equal(liveForeignStore.get(liveForeignOrigin)?.ownerUserId, undefined);

  const racedOrigin = "https://raced-owner-proof.example";
  const racedStore = new TunnelConfigStore(fakeSafe(), fakePersist(), false);
  racedStore.put({ origin: racedOrigin, deviceId: "00000000-0000-4000-8000-000000000109", orgId: "00000000-0000-4000-8000-000000000202", config });
  await assert.rejects(
    () => proveManagedDeviceOwner(racedOrigin, USER_A, {
      deviceRecord: async () => {
        racedStore.put({
          origin: racedOrigin,
          deviceId: "00000000-0000-4000-8000-000000000108",
          orgId: "00000000-0000-4000-8000-000000000203",
          ownerUserId: USER_B,
          config,
        });
        return { status: "active", userId: USER_A };
      },
    }, racedStore, () => {}),
    ManagedDeviceOwnerUnconfirmedError,
  );
  assert.equal(racedStore.get(racedOrigin)?.deviceId, "00000000-0000-4000-8000-000000000108");
  assert.equal(racedStore.get(racedOrigin)?.ownerUserId, USER_B);
});

test("managed owner proof stale consume is zero-write, burns the proof, and cannot replay", async () => {
  const origin = "https://stale-owner-proof.example";
  const tracked = trackedPersist();
  const store = new TunnelConfigStore(fakeSafe(), tracked.persistence, false);
  store.put({
    origin,
    deviceId: "00000000-0000-4000-8000-000000000109",
    orgId: "00000000-0000-4000-8000-000000000202",
    config: { ...parseWgConf(CONF), full_tunnel: false },
  });
  const proof = await proveManagedDeviceOwner(origin, USER_A, fakeApi(), store, () => {});
  assert.ok(proof);
  const writesBeforeCommit = tracked.writes();

  assert.throws(
    () => commitManagedDeviceOwnerProof(proof, () => { throw new Error("stale lease"); }),
    /stale lease/,
  );
  assert.equal(tracked.writes(), writesBeforeCommit);
  assert.equal(store.get(origin)?.ownerUserId, undefined);

  assert.throws(
    () => commitManagedDeviceOwnerProof(proof, () => {}),
    ManagedDeviceOwnerUnconfirmedError,
  );
  assert.equal(tracked.writes(), writesBeforeCommit);
});

test("managed owner proof commit rechecks the exact record before its single owner write", async () => {
  const config = { ...parseWgConf(CONF), full_tunnel: false };
  const racedOrigin = "https://consume-raced-owner-proof.example";
  const racedTracked = trackedPersist();
  const racedStore = new TunnelConfigStore(fakeSafe(), racedTracked.persistence, false);
  racedStore.put({ origin: racedOrigin, deviceId: "00000000-0000-4000-8000-000000000109", orgId: "00000000-0000-4000-8000-000000000202", config });
  const racedProof = await proveManagedDeviceOwner(racedOrigin, USER_A, fakeApi(), racedStore, () => {});
  assert.ok(racedProof);
  racedStore.put({ origin: racedOrigin, deviceId: "00000000-0000-4000-8000-000000000109", orgId: "00000000-0000-4000-8000-000000000202", pending: true, config });
  const writesAfterRace = racedTracked.writes();

  assert.throws(
    () => commitManagedDeviceOwnerProof(racedProof, () => {}),
    ManagedDeviceOwnerUnconfirmedError,
  );
  assert.equal(racedTracked.writes(), writesAfterRace, "a changed record must not receive the proved owner");
  assert.equal(racedStore.get(racedOrigin)?.ownerUserId, undefined);
  assert.equal(racedStore.get(racedOrigin)?.pending, true);

  const successOrigin = "https://committed-owner-proof.example";
  const successTracked = trackedPersist();
  const successStore = new TunnelConfigStore(fakeSafe(), successTracked.persistence, false);
  successStore.put({ origin: successOrigin, deviceId: "00000000-0000-4000-8000-000000000109", orgId: "00000000-0000-4000-8000-000000000202", config });
  const successProof = await proveManagedDeviceOwner(successOrigin, USER_A, fakeApi(), successStore, () => {});
  assert.ok(successProof);
  const writesBeforeCommit = successTracked.writes();

  commitManagedDeviceOwnerProof(successProof, () => {});
  assert.equal(successTracked.writes(), writesBeforeCommit + 1);
  assert.equal(successStore.get(successOrigin)?.ownerUserId, USER_A);

  assert.throws(
    () => commitManagedDeviceOwnerProof(successProof, () => {}),
    ManagedDeviceOwnerUnconfirmedError,
  );
  assert.equal(successTracked.writes(), writesBeforeCommit + 1, "a consumed proof cannot repeat the owner write");
});

test("managed owner removal consumes the pre-quiesce proof and clears only after guarded revoke", async () => {
  const origin = "https://remove-owner-proof.example";
  const tracked = trackedPersist();
  const store = new TunnelConfigStore(fakeSafe(), tracked.persistence, false);
  store.put({
    origin,
    deviceId: "00000000-0000-4000-8000-000000000109",
    orgId: "00000000-0000-4000-8000-000000000202",
    config: { ...parseWgConf(CONF), full_tunnel: false },
  });
  const events: string[] = [];
  const removalApi = fakeApi();
  removalApi.revokeDevice = async (deviceId, organizationId) => {
    events.push(`revoke:${deviceId}:${organizationId}`);
    assert.equal(store.get(origin)?.ownerUserId, USER_A, "binding commits only in the post-quiesce consumer");
  };
  const proof = await proveManagedDeviceOwner(origin, USER_A, removalApi, store, () => {});
  assert.ok(proof);

  await revokeAndClearManagedDevice(proof, removalApi, () => events.push("lease"));

  assert.deepEqual(events, [
    "lease",
    "lease",
    "revoke:00000000-0000-4000-8000-000000000109:00000000-0000-4000-8000-000000000202",
    "lease",
  ]);
  assert.equal(store.get(origin), null);
  await assert.rejects(
    () => revokeAndClearManagedDevice(proof, removalApi, () => {}),
    ManagedDeviceOwnerUnconfirmedError,
  );
});

test("managed owner removal proof cannot be consumed through a different API identity", async () => {
  const origin = "https://remove-owner-api-identity.example";
  const store = new TunnelConfigStore(fakeSafe(), fakePersist(), false);
  store.put({
    origin,
    deviceId: "00000000-0000-4000-8000-000000000109",
    orgId: "00000000-0000-4000-8000-000000000202",
    config: { ...parseWgConf(CONF), full_tunnel: false },
  });
  const provedApi = fakeApi();
  const substitutedApi = fakeApi();
  let substitutedPosts = 0;
  substitutedApi.revokeDevice = async () => { substitutedPosts += 1; };
  const proof = await proveManagedDeviceOwner(origin, USER_A, provedApi, store, () => {});
  assert.ok(proof);
  let leaseChecks = 0;

  await assert.rejects(
    () => revokeAndClearManagedDevice(proof, substitutedApi, () => { leaseChecks += 1; }),
    ManagedDeviceOwnerUnconfirmedError,
  );

  assert.equal(substitutedPosts, 0, "a substituted credential adapter must perform zero POSTs");
  assert.equal(leaseChecks, 0, "API identity refuses before consuming or advancing the proved lease");
  assert.equal(store.get(origin)?.ownerUserId, undefined);
  assert.ok(store.get(origin), "the exact recovery record remains available to the proved API");

  await revokeAndClearManagedDevice(proof, provedApi, () => { leaseChecks += 1; });
  assert.equal(leaseChecks, 3, "the proved API is guarded before binding, before POST, and before clear");
  assert.deepEqual(provedApi.revoked, ["00000000-0000-4000-8000-000000000109"]);
  assert.equal(store.get(origin), null);
});

test("managed owner removal retains exact recovery state on stale lease or post-POST drift", async () => {
  const staleOrigin = "https://remove-owner-stale.example";
  const staleTracked = trackedPersist();
  const staleStore = new TunnelConfigStore(fakeSafe(), staleTracked.persistence, false);
  staleStore.put({
    origin: staleOrigin,
    deviceId: "00000000-0000-4000-8000-000000000109",
    orgId: "00000000-0000-4000-8000-000000000202",
    config: { ...parseWgConf(CONF), full_tunnel: false },
  });
  const writesBeforeStale = staleTracked.writes();
  let stalePosts = 0;
  const staleApi = fakeApi();
  staleApi.revokeDevice = async () => { stalePosts += 1; };
  const staleProof = await proveManagedDeviceOwner(staleOrigin, USER_A, staleApi, staleStore, () => {});
  assert.ok(staleProof);

  await assert.rejects(
    () => revokeAndClearManagedDevice(staleProof, staleApi, () => { throw new Error("stale lease"); }),
    /stale lease/,
  );
  assert.equal(stalePosts, 0);
  assert.equal(staleTracked.writes(), writesBeforeStale, "pre-consume lease refusal performs zero binding write");
  assert.equal(staleStore.get(staleOrigin)?.ownerUserId, undefined);

  const racedOrigin = "https://remove-owner-raced.example";
  const racedStore = new TunnelConfigStore(fakeSafe(), fakePersist(), false);
  const config = { ...parseWgConf(CONF), full_tunnel: false };
  racedStore.put({ origin: racedOrigin, deviceId: "00000000-0000-4000-8000-000000000109", orgId: "00000000-0000-4000-8000-000000000202", config });
  let racedPosts = 0;
  const racedApi = fakeApi();
  racedApi.revokeDevice = async () => {
    racedPosts += 1;
    racedStore.put({
      origin: racedOrigin,
      deviceId: "00000000-0000-4000-8000-000000000108",
      orgId: "00000000-0000-4000-8000-000000000203",
      ownerUserId: USER_B,
      config,
    });
  };
  const racedProof = await proveManagedDeviceOwner(racedOrigin, USER_A, racedApi, racedStore, () => {});
  assert.ok(racedProof);

  await assert.rejects(
    () => revokeAndClearManagedDevice(racedProof, racedApi, () => {}),
    ManagedDeviceOwnerUnconfirmedError,
  );
  assert.equal(racedPosts, 1);
  assert.equal(racedStore.get(racedOrigin)?.deviceId, "00000000-0000-4000-8000-000000000108");
  assert.equal(racedStore.get(racedOrigin)?.ownerUserId, USER_B);
});

test("resolveTunnelConfig: local owner mismatch refuses before status/mode; same owner keeps fail-static reuse", async () => {
  const store = new TunnelConfigStore(fakeSafe(), fakePersist(), false);
  const api = fakeApi();
  const origin = "https://shared-mac.example";
  const first = await resolveTunnelConfig(origin, false, api, store, "00000000-0000-4000-8000-000000000202", USER_A);

  let statusReads = 0;
  const unreadable: DeviceApi = {
    ...api,
    deviceExists: async () => { statusReads++; throw new Error("network"); },
  };
  await assert.rejects(
    () => resolveTunnelConfig(origin, false, unreadable, store, "00000000-0000-4000-8000-000000000202", USER_B),
    ManagedDeviceOwnerMismatchError,
  );
  assert.equal(statusReads, 0, "foreign user is refused before a fail-open status read");
  assert.equal(store.get(origin)?.revoked, undefined);
  assert.equal(api.modeUpdates, 1, "fresh enrollment performs one idempotent config read-through");

  const reused = await resolveTunnelConfig(origin, false, unreadable, store, "00000000-0000-4000-8000-000000000202", USER_A);
  assert.equal(statusReads, 1);
  assert.equal(reused.private_key, first.private_key, "same bound owner retains existing fail-static behavior");
});

test("connect preflight refuses a bound record with a malformed device identity before any API read", async () => {
  const origin = "https://malformed-bound-connect.example";
  const safe = fakeSafe();
  const persisted = seededPersist(safe.encryptString(JSON.stringify({
    [origin]: {
      origin,
      deviceId: "",
      orgId: "00000000-0000-4000-8000-000000000202",
      ownerUserId: USER_A,
      config: { ...parseWgConf(CONF), full_tunnel: false },
    },
  })));
  const store = new TunnelConfigStore(safe, persisted.persistence, false);
  const baseApi = fakeApi();
  let recordReads = 0;
  let statusReads = 0;
  const api: DeviceApi = {
    ...baseApi,
    deviceRecord: async () => { recordReads += 1; return { status: "active", userId: USER_A }; },
    deviceExists: async () => { statusReads += 1; return true; },
  };

  await assert.rejects(async () => {
    await bindManagedDeviceOwner(origin, USER_A, api, store);
    await resolveTunnelConfig(origin, false, api, store, "00000000-0000-4000-8000-000000000202", USER_A);
  }, TunnelConfigStoreCorruptError);

  assert.equal(recordReads, 0, "a bound record must not use the ownerless live-binding path");
  assert.equal(statusReads, 0, "malformed identity must not reach fail-static status reuse");
  assert.equal(baseApi.creates, 0);
  assert.throws(() => store.get(origin), TunnelConfigStoreCorruptError, "refusal retains the corrupt encrypted recovery record");
});

test("stored managed config is fully validated before any API read or helper handoff", async () => {
  const valid = { ...parseWgConf(CONF), full_tunnel: false };
  const malformed: Array<{ label: string; config: unknown }> = [
    { label: "missing config", config: null },
    { label: "private key", config: { ...valid, private_key: "not-a-wireguard-key" } },
    { label: "peer key", config: { ...valid, peer_public_key: "" } },
    { label: "address", config: { ...valid, address: "10.99.0.2" } },
    { label: "endpoint", config: { ...valid, endpoint: "vpn.example.com" } },
    { label: "AllowedIPs", config: { ...valid, allowed_ips: [] } },
    { label: "full-tunnel intent", config: { ...valid, full_tunnel: "false" } },
    { label: "split default route", config: { ...valid, allowed_ips: ["0.0.0.0/0"] } },
    { label: "split IPv6 default route", config: { ...valid, allowed_ips: ["::/0"] } },
    { label: "extra config key", config: { ...valid, token: "EXTRA_CONFIG_SECRET_SENTINEL" } },
    { label: "extra DNS forward key", config: { ...valid, dns_forwards: [{ domain: "corp.example", resolver_ip: "10.0.0.53", token: "EXTRA_FORWARD_SECRET_SENTINEL" }] } },
  ];

  for (const { label, config: malformedConfig } of malformed) {
    const origin = `https://malformed-${label.replace(/[^a-z]+/gi, "-").toLowerCase()}.example`;
    const tracked = trackedPersist();
    const safe = fakeSafe();
    const stored = {
      origin,
      deviceId: "00000000-0000-4000-8000-000000000103",
      orgId: "00000000-0000-4000-8000-000000000202",
      ownerUserId: USER_A,
      config: malformedConfig,
    };
    if (malformedConfig === null) {
      tracked.persistence.write(safe.encryptString(JSON.stringify({ [origin]: stored })));
    }
    const store = new TunnelConfigStore(safe, tracked.persistence, false);
    if (malformedConfig !== null) store.put(stored as never);
    const writesBefore = tracked.writes();
    const bytesBefore = tracked.bytes();
    let recordReads = 0;
    let statusReads = 0;
    let modeUpdates = 0;
    let revokes = 0;
    const baseApi = fakeApi();
    const api: DeviceApi = {
      ...baseApi,
      deviceRecord: async () => { recordReads += 1; return { status: "active", userId: USER_A }; },
      deviceExists: async () => { statusReads += 1; return true; },
      updateDeviceMode: async (deviceId, _orgId, fullTunnel) => {
        modeUpdates += 1;
        return {
          deviceId,
          ownerUserId: USER_A,
          nodeId: "00000000-0000-4000-8000-000000000301",
          publicKey: baseApi.publicKey,
          status: "active",
          fullTunnel,
          address: valid.address,
          endpoint: valid.endpoint,
          peerPublicKey: valid.peer_public_key,
          allowedIPs: valid.allowed_ips,
        };
      },
      revokeDevice: async () => { revokes += 1; },
    };

    const expectedError = label === "missing config"
      ? TunnelConfigStoreCorruptError
      : ManagedDeviceOwnerUnconfirmedError;
    await assert.rejects(
      () => proveManagedDeviceOwner(origin, USER_A, api, store, () => {}),
      expectedError,
      label,
    );
    await assert.rejects(
      () => resolveTunnelConfig(origin, false, api, store, "00000000-0000-4000-8000-000000000202", USER_A),
      expectedError,
      label,
    );

    assert.deepEqual({ recordReads, statusReads, modeUpdates, revokes }, {
      recordReads: 0,
      statusReads: 0,
      modeUpdates: 0,
      revokes: 0,
    }, `${label}: refusal precedes all live/destructive API work`);
    assert.equal(tracked.writes(), writesBefore, `${label}: refusal performs no store mutation`);
    assert.deepEqual(tracked.bytes(), bytesBefore, `${label}: encrypted recovery record is retained byte-for-byte`);
  }
});

test("stored managed config preserves the valid historical optional-field shape", async () => {
  const origin = "https://historical-managed-config.example";
  const store = new TunnelConfigStore(fakeSafe(), fakePersist(), false);
  store.put({
    origin,
    deviceId: "00000000-0000-4000-8000-000000000103",
    orgId: "00000000-0000-4000-8000-000000000202",
    ownerUserId: USER_A,
    config: parseWgConf(CONF),
  });
  let recordReads = 0;
  const api = fakeApi();
  api.deviceRecord = async () => { recordReads += 1; throw new Error("bound history must not need a live owner read"); };

  const proof = await proveManagedDeviceOwner(origin, USER_A, api, store, () => {});

  assert.ok(proof);
  assert.equal(recordReads, 0);
  commitManagedDeviceOwnerProof(proof, () => {});
  assert.equal(store.get(origin)?.ownerUserId, USER_A);
});

test("same-user sign-out then sign-in reuses the stored UUID, IP and key", async () => {
  const store = new TunnelConfigStore(fakeSafe(), fakePersist(), false);
  const api = fakeApi();
  const origin = "https://t.example";
  const first = await resolveTunnelConfig(origin, false, api, store, "00000000-0000-4000-8000-000000000201", USER_A);

  await signOutPreservingDevice({
    retireLifecycle: () => {},
    stopMonitors: () => {}, clearSynthesizedState: () => {},
    downTunnel: async () => {}, emitDisconnected: () => {}, logoutSession: async () => {},
  });
  const next = await resolveTunnelConfig(origin, false, api, store, "00000000-0000-4000-8000-000000000201", USER_A);

  assert.equal(api.creates, 1);
  assert.equal(store.get(origin)?.deviceId, "00000000-0000-4000-8000-000000000102");
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
  const cf = await resolveTunnelConfig(origin, true, fullApi, fullStore, "00000000-0000-4000-8000-000000000201", USER_A);
  assert.equal(cf.control_plane_endpoint, "api.example.com:443", "full-tunnel must carry the CP endpoint");
  const cf2 = await resolveTunnelConfig(origin, true, fullApi, fullStore, "00000000-0000-4000-8000-000000000201", USER_A); // reused path
  assert.equal(cf2.control_plane_endpoint, "api.example.com:443", "reused config must ALSO re-attach the CP endpoint");
  // SPLIT: no kill-switch → no carve-out → field omitted.
  const splitStore = new TunnelConfigStore(fakeSafe(), fakePersist(), false);
  const cs = await resolveTunnelConfig(origin, false, fakeApi(), splitStore, "00000000-0000-4000-8000-000000000201", USER_A);
  assert.equal(cs.control_plane_endpoint, undefined, "split-tunnel must NOT carry a CP endpoint (no kill-switch)");
});

test("explicit device removal revokes first, then clears only the selected origin", async () => {
  const store = new TunnelConfigStore(fakeSafe(), fakePersist(), false);
  const api = fakeApi();
  await resolveTunnelConfig("https://t.example", false, api, store, "00000000-0000-4000-8000-000000000201", USER_A);

  await removeManagedTunnelConfigForOrigin("https://t.example", USER_A, api, store);
  assert.deepEqual(api.revoked, ["00000000-0000-4000-8000-000000000102"]);
  assert.equal(store.get("https://t.example"), null);

  // A failed revoke preserves local state so the user can retry; do not orphan a peer.
  await resolveTunnelConfig("https://u.example", false, api, store, "00000000-0000-4000-8000-000000000201", USER_A);
  const throwingApi: DeviceApi = { ...api, revokeDevice: async () => { throw new Error("network"); } };
  await assert.rejects(() => removeManagedTunnelConfigForOrigin("https://u.example", USER_A, throwingApi, store), /network/);
  assert.ok(store.get("https://u.example"));

  discardTunnelConfigForOrigin("https://u.example", USER_A, store);
  assert.equal(store.get("https://u.example"), null);
});

test("explicit device removal refuses foreign or unconfirmed ownership without revoke or clear", async () => {
  const origin = "https://remove-owner.example";
  const store = new TunnelConfigStore(fakeSafe(), fakePersist(), false);
  const api = fakeApi();
  await resolveTunnelConfig(origin, false, api, store, "00000000-0000-4000-8000-000000000202", USER_A);

  await assert.rejects(
    () => removeManagedTunnelConfigForOrigin(origin, USER_B, api, store),
    ManagedDeviceOwnerMismatchError,
  );
  assert.deepEqual(api.revoked, []);
  assert.equal(store.get(origin)?.ownerUserId, USER_A);
  assert.throws(
    () => discardTunnelConfigForOrigin(origin, USER_B, store),
    ManagedDeviceOwnerMismatchError,
  );
  assert.ok(store.get(origin));

  const legacyOrigin = "https://remove-ownerless.example";
  store.put({
    origin: legacyOrigin,
    deviceId: "00000000-0000-4000-8000-00000000010a",
    orgId: "00000000-0000-4000-8000-000000000202",
    config: { ...parseWgConf(CONF), full_tunnel: false },
  } as never);
  const absentApi = fakeApi();
  absentApi.recordPresent = false;
  await assert.rejects(
    () => removeManagedTunnelConfigForOrigin(legacyOrigin, USER_A, absentApi, store),
    ManagedDeviceOwnerUnconfirmedError,
  );
  assert.deepEqual(absentApi.revoked, []);
  assert.equal(store.get(legacyOrigin)?.ownerUserId, undefined);
});

test("explicit removal refuses a bound record with a malformed device identity before revoke or clear", async () => {
  const origin = "https://malformed-bound-remove.example";
  const safe = fakeSafe();
  const persisted = seededPersist(safe.encryptString(JSON.stringify({
    [origin]: {
      origin,
      deviceId: "",
      orgId: "00000000-0000-4000-8000-000000000202",
      ownerUserId: USER_A,
      config: { ...parseWgConf(CONF), full_tunnel: false },
    },
  })));
  const store = new TunnelConfigStore(safe, persisted.persistence, false);
  const api = fakeApi();

  await assert.rejects(
    () => removeManagedTunnelConfigForOrigin(origin, USER_A, api, store),
    TunnelConfigStoreCorruptError,
  );

  assert.deepEqual(api.revoked, []);
  assert.throws(() => store.get(origin), TunnelConfigStoreCorruptError, "refusal retains the corrupt encrypted recovery record");
});

test("resolveTunnelConfig: a revoked device stays terminal (no automatic re-enrollment)", async () => {
  const store = new TunnelConfigStore(fakeSafe(), fakePersist(), false);
  const api = fakeApi();
  const origin = "https://t.example";

  await resolveTunnelConfig(origin, false, api, store, "00000000-0000-4000-8000-000000000201", USER_A);
  assert.equal(api.creates, 1); // dev-1 minted + stored

  // The device is revoked server-side. A reconnect must preserve the administrator's
  // access decision rather than silently creating a replacement credential.
  api.exists = false;
  await assert.rejects(() => resolveTunnelConfig(origin, false, api, store, "00000000-0000-4000-8000-000000000201", USER_A), DeviceRevokedError);
  assert.equal(api.creates, 1);
  assert.equal(store.get(origin)?.revoked, true);

  // A terminal marker remains terminal even if a later read would be inconclusive.
  const flakyApi: DeviceApi = {
    ...api,
    deviceExists: async () => { throw new Error("network"); },
    deviceStatus: async () => { throw new Error("network"); },
  };
  await assert.rejects(() => resolveTunnelConfig(origin, false, flakyApi, store, "00000000-0000-4000-8000-000000000201", USER_A), DeviceRevokedError);
  assert.equal(api.creates, 1);
});

test("resolveTunnelConfig: mode changes update the same device", async () => {
  const store = new TunnelConfigStore(fakeSafe(), fakePersist(), false);
  const api = fakeApi();
  const origin = "https://t.example";

  const split = await resolveTunnelConfig(origin, false, api, store, "00000000-0000-4000-8000-000000000201", USER_A);
  assert.equal(api.creates, 1);
  assert.equal(split.full_tunnel, false);

  const full = await resolveTunnelConfig(origin, true, api, store, "00000000-0000-4000-8000-000000000201", USER_A);
  assert.equal(api.creates, 1);
  assert.equal(api.modeUpdates, 2, "one enrollment read-through plus one real mode change");
  assert.equal(full.full_tunnel, true);
  assert.deepEqual(api.revoked, []);
  assert.equal(store.get(origin)?.deviceId, "00000000-0000-4000-8000-000000000102");

  // Same intent again → reuse (no churn).
  await resolveTunnelConfig(origin, true, api, store, "00000000-0000-4000-8000-000000000201", USER_A);
  assert.equal(api.creates, 1);
});

test("resolveTunnelConfig: malformed mode results never persist or reach the helper-facing return", async () => {
  const validMode = {
    fullTunnel: true,
    address: "10.99.0.2/32",
    endpoint: "198.51.100.1:51820",
    peerPublicKey: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
    allowedIPs: ["0.0.0.0/0"],
  };
  const cases: Array<{ name: string; mode: unknown }> = [
    { name: "mode mismatch", mode: { ...validMode, fullTunnel: false } },
    { name: "bad peer key", mode: { ...validMode, peerPublicKey: "peer" } },
    { name: "bad address", mode: { ...validMode, address: "10.99.0.2" } },
    { name: "unsafe endpoint", mode: { ...validMode, endpoint: "127.0.0.1:51820" } },
    { name: "empty AllowedIPs", mode: { ...validMode, allowedIPs: [] } },
  ];

  for (const scenario of cases) {
    const tracked = trackedPersist();
    const store = new TunnelConfigStore(fakeSafe(), tracked.persistence, false);
    const origin = `https://mode-${scenario.name.replace(/[^a-z]+/gi, "-").toLowerCase()}.example`;
    const api = fakeApi();
    await resolveTunnelConfig(origin, false, api, store, "00000000-0000-4000-8000-000000000201", USER_A);
    const recordBefore = JSON.stringify(store.get(origin));
    const writesBefore = tracked.writes();
    let helperFacingReturns = 0;
    api.updateDeviceMode = async () => scenario.mode as never;

    await assert.rejects(async () => {
      await resolveTunnelConfig(origin, true, api, store, "00000000-0000-4000-8000-000000000201", USER_A);
      helperFacingReturns += 1;
    }, /update_device_mode_failed: invalid_response/, scenario.name);

    assert.equal(helperFacingReturns, 0, `${scenario.name}: malformed config never leaves the provider`);
    assert.equal(tracked.writes(), writesBefore, `${scenario.name}: encrypted store is unchanged`);
    assert.equal(JSON.stringify(store.get(origin)), recordBefore, `${scenario.name}: recovery record is retained byte-for-byte`);
  }
});

test("resolveTunnelConfig: mode change does not bypass a server-revoked cached device", async () => {
  const store = new TunnelConfigStore(fakeSafe(), fakePersist(), false);
  const api = fakeApi();
  const origin = "https://t.example";

  await resolveTunnelConfig(origin, false, api, store, "00000000-0000-4000-8000-000000000201", USER_A);
  assert.equal(store.get(origin)?.deviceId, "00000000-0000-4000-8000-000000000102");

  // A split→full switch must not surface the endpoint's 404, but it also must
  // not silently mint a new credential around an administrator's revocation.
  api.exists = false;
  await assert.rejects(() => resolveTunnelConfig(origin, true, api, store, "00000000-0000-4000-8000-000000000201", USER_A), DeviceRevokedError);

  assert.equal(api.creates, 1);
  assert.equal(api.modeUpdates, 1, "revocation blocks the toggle after the enrollment read-through");
  assert.equal(store.get(origin)?.deviceId, "00000000-0000-4000-8000-000000000102");
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
    () => resolveTunnelConfig(origin, false, api, store, "00000000-0000-4000-8000-000000000201", USER_A),
    (e: unknown) => e instanceof PendingApprovalError && (e as PendingApprovalError).deviceId === "00000000-0000-4000-8000-000000000102",
  );
  assert.equal(api.creates, 1); // device minted once
  assert.equal(store.get(origin)?.pending, true); // persisted as pending

  // Re-resolve while STILL pending → re-throws, does NOT mint a second device.
  await assert.rejects(() => resolveTunnelConfig(origin, false, api, store, "00000000-0000-4000-8000-000000000201", USER_A), PendingApprovalError);
  assert.equal(api.creates, 1); // NO duplicate create

  // Once approved (pending flag cleared, device now active) → reuse the stored config.
  const sc = store.get(origin)!;
  store.put({ ...sc, pending: false });
  api.pending = false;
  const cfg = await resolveTunnelConfig(origin, false, api, store, "00000000-0000-4000-8000-000000000201", USER_A);
  assert.ok(cfg); // returned the stored config
  assert.equal(api.creates, 1); // still no re-mint (existence check passes for active)
});

test("resolveTunnelConfig: pending device revalidates status before resuming after sign-out", async () => {
  const store = new TunnelConfigStore(fakeSafe(), fakePersist(), false);
  const api = fakeApi();
  api.pending = true;
  const origin = "https://pending.example";
  await assert.rejects(() => resolveTunnelConfig(origin, false, api, store, "00000000-0000-4000-8000-000000000201", USER_A), PendingApprovalError);
  assert.equal(api.creates, 1);

  // Approval happened while the user was signed out: reuse the same device, do not re-mint.
  api.pending = false;
  const cfg = await resolveTunnelConfig(origin, false, api, store, "00000000-0000-4000-8000-000000000201", USER_A);
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
  await assert.rejects(() => resolveTunnelConfig(origin, false, api, store, "00000000-0000-4000-8000-000000000201", USER_A), PendingApprovalError);
  assert.equal(api.creates, 1);
  assert.equal(store.get(origin)?.config.full_tunnel, false);

  await assert.rejects(() => resolveTunnelConfig(origin, true, api, store, "00000000-0000-4000-8000-000000000201", USER_A), PendingApprovalError);
  assert.equal(api.creates, 1);
  assert.deepEqual(api.revoked, []);
  assert.equal(store.get(origin)?.config.full_tunnel, false);
});

// Finding #1-#5 (stamping): a LEGACY stored config (no orgId, from a pre-orgId build) is
// opportunistically STAMPED with its org on reuse — migrating onto the hardened direct path.

// D14 belt: connect() owns the exact current-user scan + revoke-first migration.
// If ConfigProvider sees a no-orgId record directly, it retains and refuses it;
// it never clears, queries status, arms, or silently creates around the proof.
test("resolveTunnelConfig: a no-orgId legacy config is retained and refused, never queried", async () => {
  const store = new TunnelConfigStore(fakeSafe(), fakePersist(), false);
  const api = fakeApi();
  let existsCalls = 0;
  let statusCalls = 0;
  const wrapped: DeviceApi = {
    ...api,
    deviceExists: async (...a) => { existsCalls++; return api.deviceExists(...a); },
    deviceStatus: async (...a) => { statusCalls++; return api.deviceStatus(...a); },
  };
  const origin = "https://legacy.example";
  // A legacy stored config: NO orgId field (as an old build persisted it).
  store.put({ origin, deviceId: "00000000-0000-4000-8000-000000000109", config: { ...parseWgConf(CONF), full_tunnel: false } } as never);

  await assert.rejects(
    () => resolveTunnelConfig(origin, false, wrapped, store, "00000000-0000-4000-8000-000000000201", USER_A),
    ManagedDeviceOwnerUnconfirmedError,
  );
  assert.equal(existsCalls, 0); // NEVER queried a no-orgId config (no monitor could run on it)
  assert.equal(statusCalls, 0);
  assert.equal(api.creates, 0);
  assert.deepEqual(api.revoked, []);
  assert.equal(store.get(origin)?.deviceId, "00000000-0000-4000-8000-000000000109");
});

// REDUCTION 2 harden — REVOKE-FIRST migration. The revoke frees the cap slot the next connect
// needs, so it runs BEFORE clearing and the config is cleared ONLY on revoke success.
test("legacy no-org proof is opaque and revoke+clear rechecks lease and record around the POST", async () => {
  const store = new TunnelConfigStore(fakeSafe(), fakePersist(), false);
  const origin = "https://legacy-proof.example";
  store.put({ origin, deviceId: "00000000-0000-4000-8000-000000000109", config: { ...parseWgConf(CONF), full_tunnel: false } } as never);
  const events: string[] = [];
  const api = {
    discoverLegacyDevice: async (deviceId: string, ownerUserId: string) => {
      assert.equal(deviceId, "00000000-0000-4000-8000-000000000109");
      assert.equal(ownerUserId, USER_A);
      events.push("discover");
      return "00000000-0000-4000-8000-000000000205";
    },
    revokeDevice: async (deviceId: string, organizationId: string) => {
      assert.equal(deviceId, "00000000-0000-4000-8000-000000000109");
      assert.equal(organizationId, "00000000-0000-4000-8000-000000000205");
      events.push("revoke");
    },
  };
  const assertLeaseCurrent = () => { events.push("lease"); };

  const proof = await proveLegacyManagedDeviceOwner(
    origin,
    "00000000-0000-4000-8000-000000000109",
    USER_A,
    api,
    store,
    assertLeaseCurrent,
  );
  assert.deepEqual(Object.keys(proof), [], "the destructive identity is not exposed on the proof handle");
  assert.ok(store.get(origin), "read-only proof does not clear the record");

  await revokeAndClearLegacyManagedDevice(proof, assertLeaseCurrent);
  assert.deepEqual(events, ["discover", "lease", "lease", "revoke", "lease"]);
  assert.equal(store.get(origin), null);
});

test("legacy no-org proof refuses foreign, ambiguous, inconclusive, or malformed discovery without revoke or clear", async () => {
  const scenarios: Array<{
    name: string;
    discover: () => Promise<string>;
    error: RegExp;
  }> = [
    {
      name: "foreign",
      discover: async () => { throw new ManagedDeviceOwnerMismatchError(); },
      error: /managed_device_owner_mismatch/,
    },
    {
      name: "ambiguous",
      discover: async () => { throw new Error("legacy_device_organization_ambiguous"); },
      error: /legacy_device_organization_ambiguous/,
    },
    {
      name: "inconclusive",
      discover: async () => { throw new Error("network"); },
      error: /network/,
    },
    {
      name: "malformed",
      discover: async () => "",
      error: /managed_device_owner_unconfirmed/,
    },
  ];

  for (const scenario of scenarios) {
    const store = new TunnelConfigStore(fakeSafe(), fakePersist(), false);
    const origin = `https://legacy-${scenario.name}.example`;
    store.put({ origin, deviceId: "00000000-0000-4000-8000-000000000109", config: { ...parseWgConf(CONF), full_tunnel: false } } as never);
    let revokeCalls = 0;

    await assert.rejects(
      () => proveLegacyManagedDeviceOwner(origin, "00000000-0000-4000-8000-000000000109", USER_A, {
        discoverLegacyDevice: scenario.discover,
        revokeDevice: async () => { revokeCalls += 1; },
      }, store, () => {}),
      scenario.error,
      scenario.name,
    );

    assert.equal(revokeCalls, 0, `${scenario.name}: proof must stay read-only`);
    assert.equal(store.get(origin)?.deviceId, "00000000-0000-4000-8000-000000000109", `${scenario.name}: record must be retained`);
  }
});

test("legacy no-org proof refuses a raced stored record without revoke or clear", async () => {
  const store = new TunnelConfigStore(fakeSafe(), fakePersist(), false);
  const origin = "https://legacy-proof-race.example";
  const config = { ...parseWgConf(CONF), full_tunnel: false };
  store.put({ origin, deviceId: "00000000-0000-4000-8000-000000000109", config } as never);
  let revokeCalls = 0;

  await assert.rejects(
    () => proveLegacyManagedDeviceOwner(origin, "00000000-0000-4000-8000-000000000109", USER_A, {
      discoverLegacyDevice: async () => {
        store.put({ origin, deviceId: "00000000-0000-4000-8000-000000000108", config } as never);
        return "00000000-0000-4000-8000-000000000205";
      },
      revokeDevice: async () => { revokeCalls += 1; },
    }, store, () => {}),
    ManagedDeviceOwnerUnconfirmedError,
  );

  assert.equal(revokeCalls, 0);
  assert.equal(store.get(origin)?.deviceId, "00000000-0000-4000-8000-000000000108", "the replacement record is retained");
});

test("legacy no-org consumer rechecks token and exact record before revoke", async () => {
  const tokenStore = new TunnelConfigStore(fakeSafe(), fakePersist(), false);
  const tokenOrigin = "https://legacy-consume-token.example";
  tokenStore.put({ origin: tokenOrigin, deviceId: "00000000-0000-4000-8000-000000000109", config: { ...parseWgConf(CONF), full_tunnel: false } } as never);
  let credential: CredentialSnapshot = {
    server: tokenOrigin,
    token: "token-a",
    fingerprint: "fingerprint-a",
    expiresAt: "2999-01-01T00:00:00Z",
  };
  const lifecycle = new ManagedLifecycleCoordinator(() => credential);
  const lease = await lifecycle.capture(async () => USER_A);
  let tokenRevokeCalls = 0;
  const tokenProof = await proveLegacyManagedDeviceOwner(tokenOrigin, "00000000-0000-4000-8000-000000000109", USER_A, {
    discoverLegacyDevice: async () => "00000000-0000-4000-8000-000000000205",
    revokeDevice: async () => { tokenRevokeCalls += 1; },
  }, tokenStore, () => lifecycle.assertCurrent(lease));

  credential = { ...credential, token: "token-b" };
  await assert.rejects(
    () => revokeAndClearLegacyManagedDevice(tokenProof, () => lifecycle.assertCurrent(lease)),
    /managed lifecycle lease is stale/,
  );
  assert.equal(tokenRevokeCalls, 0);
  assert.ok(tokenStore.get(tokenOrigin));

  const recordStore = new TunnelConfigStore(fakeSafe(), fakePersist(), false);
  const recordOrigin = "https://legacy-consume-record.example";
  recordStore.put({ origin: recordOrigin, deviceId: "00000000-0000-4000-8000-000000000109", config: { ...parseWgConf(CONF), full_tunnel: false } } as never);
  let recordRevokeCalls = 0;
  const recordProof = await proveLegacyManagedDeviceOwner(recordOrigin, "00000000-0000-4000-8000-000000000109", USER_A, {
    discoverLegacyDevice: async () => "00000000-0000-4000-8000-000000000205",
    revokeDevice: async () => { recordRevokeCalls += 1; },
  }, recordStore, () => {});
  const raced = recordStore.get(recordOrigin)!;
  recordStore.put({ ...raced, pending: true });

  await assert.rejects(
    () => revokeAndClearLegacyManagedDevice(recordProof, () => {}),
    ManagedDeviceOwnerUnconfirmedError,
  );
  assert.equal(recordRevokeCalls, 0);
  assert.equal(recordStore.get(recordOrigin)?.pending, true);
});

test("legacy no-org consumer rechecks token and exact record before clear", async () => {
  const tokenStore = new TunnelConfigStore(fakeSafe(), fakePersist(), false);
  const tokenOrigin = "https://legacy-post-token.example";
  tokenStore.put({ origin: tokenOrigin, deviceId: "00000000-0000-4000-8000-000000000109", config: { ...parseWgConf(CONF), full_tunnel: false } } as never);
  let credential: CredentialSnapshot = {
    server: tokenOrigin,
    token: "token-a",
    fingerprint: "fingerprint-a",
    expiresAt: "2999-01-01T00:00:00Z",
  };
  const lifecycle = new ManagedLifecycleCoordinator(() => credential);
  const lease = await lifecycle.capture(async () => USER_A);
  let tokenRevokeCalls = 0;
  const tokenProof = await proveLegacyManagedDeviceOwner(tokenOrigin, "00000000-0000-4000-8000-000000000109", USER_A, {
    discoverLegacyDevice: async () => "00000000-0000-4000-8000-000000000205",
    revokeDevice: async () => {
      tokenRevokeCalls += 1;
      credential = { ...credential, token: "token-b" };
    },
  }, tokenStore, () => lifecycle.assertCurrent(lease));

  await assert.rejects(
    () => revokeAndClearLegacyManagedDevice(tokenProof, () => lifecycle.assertCurrent(lease)),
    /managed lifecycle lease is stale/,
  );
  assert.equal(tokenRevokeCalls, 1, "the POST completed before the token drift was observed");
  assert.ok(tokenStore.get(tokenOrigin), "token drift prevents local clear");

  const recordStore = new TunnelConfigStore(fakeSafe(), fakePersist(), false);
  const recordOrigin = "https://legacy-post-record.example";
  const config = { ...parseWgConf(CONF), full_tunnel: false };
  recordStore.put({ origin: recordOrigin, deviceId: "00000000-0000-4000-8000-000000000109", config } as never);
  let recordRevokeCalls = 0;
  const recordProof = await proveLegacyManagedDeviceOwner(recordOrigin, "00000000-0000-4000-8000-000000000109", USER_A, {
    discoverLegacyDevice: async () => "00000000-0000-4000-8000-000000000205",
    revokeDevice: async () => {
      recordRevokeCalls += 1;
      recordStore.put({ origin: recordOrigin, deviceId: "00000000-0000-4000-8000-000000000108", config } as never);
    },
  }, recordStore, () => {});

  await assert.rejects(
    () => revokeAndClearLegacyManagedDevice(recordProof, () => {}),
    ManagedDeviceOwnerUnconfirmedError,
  );
  assert.equal(recordRevokeCalls, 1);
  assert.equal(recordStore.get(recordOrigin)?.deviceId, "00000000-0000-4000-8000-000000000108", "post-revoke race retains replacement");
});

test("legacy no-org proof is single-use and replay performs zero POST or clear", async () => {
  const refusedStore = new TunnelConfigStore(fakeSafe(), fakePersist(), false);
  const refusedOrigin = "https://legacy-refused-replay.example";
  refusedStore.put({ origin: refusedOrigin, deviceId: "00000000-0000-4000-8000-000000000109", config: { ...parseWgConf(CONF), full_tunnel: false } } as never);
  let refusedRevokeCalls = 0;
  const refusedProof = await proveLegacyManagedDeviceOwner(refusedOrigin, "00000000-0000-4000-8000-000000000109", USER_A, {
    discoverLegacyDevice: async () => "00000000-0000-4000-8000-000000000205",
    revokeDevice: async () => { refusedRevokeCalls += 1; },
  }, refusedStore, () => {});

  await assert.rejects(
    () => revokeAndClearLegacyManagedDevice(refusedProof, () => { throw new Error("stale"); }),
    /stale/,
  );
  await assert.rejects(
    () => revokeAndClearLegacyManagedDevice(refusedProof, () => {}),
    ManagedDeviceOwnerUnconfirmedError,
  );
  assert.equal(refusedRevokeCalls, 0, "a pre-POST refusal still burns the proof");
  assert.ok(refusedStore.get(refusedOrigin));

  const replayStore = new TunnelConfigStore(fakeSafe(), fakePersist(), false);
  const replayOrigin = "https://legacy-success-replay.example";
  const exactRecord = {
    origin: replayOrigin,
    deviceId: "00000000-0000-4000-8000-000000000109",
    config: { ...parseWgConf(CONF), full_tunnel: false },
  } as never;
  replayStore.put(exactRecord);
  let replayRevokeCalls = 0;
  const consumedProof = await proveLegacyManagedDeviceOwner(replayOrigin, "00000000-0000-4000-8000-000000000109", USER_A, {
    discoverLegacyDevice: async () => "00000000-0000-4000-8000-000000000205",
    revokeDevice: async () => { replayRevokeCalls += 1; },
  }, replayStore, () => {});
  await revokeAndClearLegacyManagedDevice(consumedProof, () => {});
  assert.equal(replayRevokeCalls, 1);
  assert.equal(replayStore.get(replayOrigin), null);

  replayStore.put(exactRecord);
  await assert.rejects(
    () => revokeAndClearLegacyManagedDevice(consumedProof, () => {}),
    ManagedDeviceOwnerUnconfirmedError,
  );
  assert.equal(replayRevokeCalls, 1, "recreated byte-identical state cannot replay the POST");
  assert.ok(replayStore.get(replayOrigin), "replay cannot clear the recreated record");
});

test("migrateLegacyConfig: revoke ok -> config cleared (slot freed before next create)", async () => {
  const store = new TunnelConfigStore(fakeSafe(), fakePersist(), false);
  const origin = "https://legacy.example";
  store.put({ origin, deviceId: "00000000-0000-4000-8000-000000000109", config: { ...parseWgConf(CONF), full_tunnel: false } } as never);
  const events: string[] = [];
  const ok = {
    discoverLegacyDevice: async (id: string, owner: string) => {
      assert.equal(id, "00000000-0000-4000-8000-000000000109");
      assert.equal(owner, USER_A);
      events.push("discover");
      return "00000000-0000-4000-8000-000000000205";
    },
    revokeDevice: async (id: string, orgId: string) => {
      assert.equal(id, "00000000-0000-4000-8000-000000000109");
      assert.equal(orgId, "00000000-0000-4000-8000-000000000205");
      events.push("revoke");
    },
  };
  await migrateLegacyConfig(origin, "00000000-0000-4000-8000-000000000109", USER_A, ok, store, () => events.push("assert-current"));
  assert.deepEqual(events, [
    "discover",
    "assert-current",
    "assert-current",
    "revoke",
    "assert-current",
  ]); // proof, pre-POST, and pre-clear lease fences all ran
  assert.equal(store.get(origin), null); // cleared after revoke success
});

// The permanence case, now self-healing: a revoke BLIP keeps the config (throws), and the
// NEXT attempt (working revoke) succeeds — no admin-reap, no lockout.
test("migrateLegacyConfig: a revoke blip KEEPS the config; retry self-heals (no lockout)", async () => {
  const store = new TunnelConfigStore(fakeSafe(), fakePersist(), false);
  const origin = "https://legacy.example";
  store.put({ origin, deviceId: "00000000-0000-4000-8000-000000000109", config: { ...parseWgConf(CONF), full_tunnel: false } } as never);

  const failing = {
    discoverLegacyDevice: async () => { throw new Error("network"); },
    revokeDevice: async () => { throw new Error("must not revoke"); },
  };
  await assert.rejects(() => migrateLegacyConfig(origin, "00000000-0000-4000-8000-000000000109", USER_A, failing, store, () => {}), /network/);
  assert.equal(store.get(origin)?.deviceId, "00000000-0000-4000-8000-000000000109"); // config KEPT (revoke ran before remove)

  const ok = { discoverLegacyDevice: async () => "00000000-0000-4000-8000-000000000205", revokeDevice: async () => {} };
  await migrateLegacyConfig(origin, "00000000-0000-4000-8000-000000000109", USER_A, ok, store, () => {}); // retry
  assert.equal(store.get(origin), null); // now cleared — self-recovered, no admin-reap
});

test("migrateLegacyConfig: an in-flight replacement is retained without revoke", async () => {
  const store = new TunnelConfigStore(fakeSafe(), fakePersist(), false);
  const origin = "https://legacy.example";
  const config = { ...parseWgConf(CONF), full_tunnel: false };
  store.put({ origin, deviceId: "00000000-0000-4000-8000-000000000109", config } as never);

  let revokeCalls = 0;
  await assert.rejects(
    () => migrateLegacyConfig(origin, "00000000-0000-4000-8000-000000000109", USER_A, {
      discoverLegacyDevice: async () => {
        store.put({ origin, deviceId: "00000000-0000-4000-8000-000000000109", orgId: "", ownerUserId: USER_B, config });
        return "00000000-0000-4000-8000-000000000205";
      },
      revokeDevice: async () => { revokeCalls += 1; },
    }, store, () => {}),
    ManagedDeviceOwnerUnconfirmedError,
  );
  assert.equal(revokeCalls, 0);
  assert.equal(store.get(origin)?.ownerUserId, USER_B);
});

test("migrateLegacyConfig: token drift during discovery performs zero revoke or clear", async () => {
  const store = new TunnelConfigStore(fakeSafe(), fakePersist(), false);
  const origin = "https://legacy-token-drift.example";
  store.put({ origin, deviceId: "00000000-0000-4000-8000-000000000109", config: { ...parseWgConf(CONF), full_tunnel: false } } as never);
  let credential: CredentialSnapshot = {
    server: origin,
    token: "token-a",
    fingerprint: "fingerprint-a",
    expiresAt: "2999-01-01T00:00:00Z",
  };
  const lifecycle = new ManagedLifecycleCoordinator(() => credential);
  let revokeCalls = 0;

  await lifecycle.serial(async () => {
    const lease = await lifecycle.capture(async () => USER_A);
    await assert.rejects(
      () => migrateLegacyConfig(origin, "00000000-0000-4000-8000-000000000109", USER_A, {
        discoverLegacyDevice: async () => {
          credential = { ...credential, token: "token-b" };
          return "00000000-0000-4000-8000-000000000205";
        },
        revokeDevice: async () => { revokeCalls += 1; },
      }, store, () => lifecycle.assertCurrent(lease)),
      /managed lifecycle lease is stale/,
    );
  });
  assert.equal(revokeCalls, 0);
  assert.equal(store.get(origin)?.deviceId, "00000000-0000-4000-8000-000000000109");
});

// The THIRD documented state: revoke OK but store.remove throws (e.g. a storage write error).
// migrateLegacyConfig must throw (config NOT silently half-cleared) AFTER the revoke ran, so the
// caller degrades to the one soft-down outcome and the next connect re-detects + re-revokes
// (404 = idempotent). Proves the revoke-BEFORE-remove ordering for this state.
test("migrateLegacyConfig: revoke ok but remove throws -> throws, revoke already ran (ordering held)", async () => {
  const revoked: string[] = [];
  const okApi = {
    discoverLegacyDevice: async () => "00000000-0000-4000-8000-000000000205",
    revokeDevice: async (id: string) => { revoked.push(id); },
  };
  const existing = {
    origin: "https://legacy.example",
    deviceId: "00000000-0000-4000-8000-000000000109",
    config: { ...parseWgConf(CONF), full_tunnel: false },
  } as never;
  const throwingStore = {
    get: () => existing,
    remove: () => { throw new Error("insecure_storage"); },
  } as unknown as TunnelConfigStore;
  await assert.rejects(
    () => migrateLegacyConfig("https://legacy.example", "00000000-0000-4000-8000-000000000109", USER_A, okApi, throwingStore, () => {}),
    /insecure_storage/,
  );
  assert.deepEqual(revoked, ["00000000-0000-4000-8000-000000000109"]); // revoke ran BEFORE the failing remove (order proven)
});
