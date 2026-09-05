import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import type { Persistence, SafeStorageLike } from "../src/main/credential";
import {
  deriveWireGuardPublicKey,
  EnrollmentAnchorStore,
  EnrollmentAnchorStoreCorruptError,
  generateWireGuardKeyPair,
  type EnrollmentAnchor,
} from "../src/main/enrollmentanchor";
import {
  buildDurableFilePersistence,
} from "../src/main/durablefile";
import {
  assertManagedEnrollmentOwner,
  enrollmentAnchorBlocksUser,
  ManagedEnrollmentOwnerMismatchError,
  PendingApprovalError,
  consumeManagedEnrollmentAbandonProof,
  enrollmentAnchorOrganizationForUser,
  proveManagedEnrollmentAbandonment,
  resolveTunnelConfig,
  type DeviceApi,
  type ManagedEnrollmentCreate,
  type ManagedEnrollmentDevice,
} from "../src/main/deviceconfig";
import {
  ManagedOrganizationSelector,
  OrganizationSelectionConflictError,
} from "../src/main/orgselection";
import { TunnelConfigStore } from "../src/main/tunnelstore";
import { ManagedLifecycleCoordinator } from "../src/main/managedlifecycle";
import { runManagedConnectFlow, runManagedRemoveFlow } from "../src/main/managedlifecycleflows";

const ORIGIN = "https://recovery.example";
const ORGANIZATION_ID = "00000000-0000-4000-8000-000000000201";
const OWNER_ID = "00000000-0000-4000-8000-000000000101";
const DEVICE_ID = "00000000-0000-4000-8000-000000000301";
const NODE_A = "00000000-0000-4000-8000-000000000401";
const NODE_B = "00000000-0000-4000-8000-000000000402";
const GATEWAY_PUBLIC_KEY = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=";

function safeStorage(available = true): SafeStorageLike {
  return {
    isEncryptionAvailable: () => available,
    encryptString: (plain) => Buffer.from(plain, "utf8").reverse(),
    decryptString: (encrypted) => Buffer.from(encrypted).reverse().toString("utf8"),
  };
}

function memoryPersistence(): Persistence & { bytes: () => Buffer | null } {
  let value: Buffer | null = null;
  return {
    read: () => value === null ? null : Buffer.from(value),
    write: (next) => { value = Buffer.from(next); },
    clear: () => { value = null; },
    bytes: () => value === null ? null : Buffer.from(value),
  };
}

function stores(anchorPersistence: Persistence = memoryPersistence(), finalPersistence: Persistence = memoryPersistence()) {
  return {
    anchors: new EnrollmentAnchorStore(safeStorage(), anchorPersistence, false),
    final: new TunnelConfigStore(safeStorage(), finalPersistence, false),
  };
}

interface ApiState {
  prepareCalls: number;
  listCalls: number;
  createCalls: number;
  modeCalls: number;
  existsCalls: number;
  rows: ManagedEnrollmentDevice[];
  loseCreateResponse: boolean;
  pending: boolean;
  rehomeOnCreate: boolean;
  beforeList?: (publicKey: string) => void;
}

function apiHarness(overrides: Partial<ApiState> = {}): { api: DeviceApi; state: ApiState } {
  const state: ApiState = {
    prepareCalls: 0,
    listCalls: 0,
    createCalls: 0,
    modeCalls: 0,
    existsCalls: 0,
    rows: [],
    loseCreateResponse: false,
    pending: false,
    rehomeOnCreate: false,
    ...overrides,
  };
  const api: DeviceApi = {
    async prepareDeviceEnrollment() {
      state.prepareCalls += 1;
      return { nodeId: NODE_A, name: "tunnex-desktop-test", platform: "darwin" };
    },
    async devicesByPublicKey(_organizationId, publicKey) {
      state.listCalls += 1;
      state.beforeList?.(publicKey);
      return state.rows.filter((row) => row.publicKey === publicKey);
    },
    async createDevice(intent: ManagedEnrollmentCreate) {
      state.createCalls += 1;
      const row: ManagedEnrollmentDevice = {
        deviceId: DEVICE_ID,
        ownerUserId: OWNER_ID,
        nodeId: state.rehomeOnCreate ? NODE_B : intent.nodeId,
        publicKey: intent.publicKey,
        status: state.pending ? "pending" : "active",
      };
      state.rows = [row];
      if (state.loseCreateResponse) {
        state.loseCreateResponse = false;
        throw new Error("control_plane_request_timeout");
      }
      return row;
    },
    async updateDeviceMode(deviceId, _organizationId, fullTunnel) {
      state.modeCalls += 1;
      const row = state.rows.find((candidate) => candidate.deviceId === deviceId);
      if (!row || row.status === "gone") throw new Error("update_device_mode_failed: 409");
      return {
        deviceId: row.deviceId,
        ownerUserId: row.ownerUserId,
        nodeId: row.nodeId,
        publicKey: row.publicKey,
        status: row.status,
        fullTunnel,
        address: "10.99.0.2/32",
        endpoint: "198.51.100.1:51820",
        peerPublicKey: GATEWAY_PUBLIC_KEY,
        allowedIPs: fullTunnel ? ["0.0.0.0/0"] : ["10.99.0.0/24"],
      };
    },
    async revokeDevice() {},
    async discoverLegacyDevice() { return ORGANIZATION_ID; },
    async deviceRecord() { return { status: "active", userId: OWNER_ID }; },
    async deviceStatus() { return "active"; },
    async deviceExists() { state.existsCalls += 1; return true; },
    async reportHealth() { return { state: "compliant", blocked: false, failed_checks: [] }; },
    async routedConfig() { return { ranges: [], forwards: [], dial: null }; },
  };
  return { api, state };
}

function recovery(anchors: EnrollmentAnchorStore, fingerprint = "fingerprint-a") {
  return { anchorStore: anchors, credentialFingerprint: fingerprint };
}

function seedEnrollmentAnchor(
  anchorStore: EnrollmentAnchorStore,
  deviceId?: string,
): EnrollmentAnchor {
  const pair = generateWireGuardKeyPair();
  const anchor: EnrollmentAnchor = {
    version: 1,
    origin: ORIGIN,
    organizationId: ORGANIZATION_ID,
    ownerUserId: OWNER_ID,
    credentialFingerprint: "fingerprint-a",
    nodeId: NODE_A,
    name: "desktop",
    platform: "darwin",
    fullTunnel: false,
    publicKey: pair.publicKey,
    privateKey: pair.privateKey,
    ...(deviceId ? { deviceId } : {}),
  };
  anchorStore.put(anchor);
  return anchor;
}

function abandonmentApi(initialRows: ManagedEnrollmentDevice[]) {
  let rows = initialRows.map((row) => ({ ...row }));
  const state = { rosterCalls: 0, revokeCalls: 0 };
  const api: Pick<DeviceApi, "devicesByPublicKey" | "revokeDevice"> = {
    async devicesByPublicKey(organizationId, publicKey) {
      assert.equal(organizationId, ORGANIZATION_ID);
      state.rosterCalls += 1;
      return rows
        .filter((row) => row.publicKey === publicKey)
        .map((row) => ({ ...row }));
    },
    async revokeDevice(deviceId, organizationId) {
      assert.equal(organizationId, ORGANIZATION_ID);
      state.revokeCalls += 1;
      rows = rows.map((row) => row.deviceId === deviceId ? { ...row, status: "gone" } : row);
    },
  };
  return { api, state };
}

test("X25519 raw-key derivation matches RFC 7748 and generated pairs", () => {
  const privateKey = Buffer.from(
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    "hex",
  ).toString("base64");
  const expectedPublic = Buffer.from(
    "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
    "hex",
  ).toString("base64");
  assert.equal(deriveWireGuardPublicKey(privateKey), expectedPublic);

  for (let i = 0; i < 8; i += 1) {
    const pair = generateWireGuardKeyPair();
    assert.equal(Buffer.from(pair.privateKey, "base64").length, 32);
    assert.equal(Buffer.from(pair.publicKey, "base64").length, 32);
    assert.equal(deriveWireGuardPublicKey(pair.privateKey), pair.publicKey);
  }
});

test("anchor store encrypts, validates key derivation, and never downgrades corruption to absence", () => {
  const persistence = memoryPersistence();
  const anchorStore = new EnrollmentAnchorStore(safeStorage(), persistence, false);
  const pair = generateWireGuardKeyPair();
  const anchor: EnrollmentAnchor = {
    version: 1,
    origin: ORIGIN,
    organizationId: ORGANIZATION_ID,
    ownerUserId: OWNER_ID,
    credentialFingerprint: "fingerprint-a",
    nodeId: NODE_A,
    name: "desktop",
    platform: "darwin",
    fullTunnel: false,
    publicKey: pair.publicKey,
    privateKey: pair.privateKey,
  };
  anchorStore.put(anchor);
  const bytes = persistence.bytes();
  assert.ok(bytes);
  assert.equal(bytes.includes(Buffer.from(pair.privateKey)), false, "private key must not be plaintext at rest");
  assert.deepEqual(anchorStore.get(ORIGIN), anchor);

  const tampered = { ...anchor, publicKey: generateWireGuardKeyPair().publicKey };
  assert.throws(() => anchorStore.put(tampered), EnrollmentAnchorStoreCorruptError);
  assert.deepEqual(anchorStore.get(ORIGIN), anchor, "invalid replacement cannot overwrite the last good anchor");

  persistence.write(Buffer.from("corrupt", "utf8"));
  assert.throws(() => anchorStore.get(ORIGIN), EnrollmentAnchorStoreCorruptError);
});

test("durable file persistence atomically publishes 0600 bytes and proves clear", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "tunnex-enrollment-"));
  try {
    const file = path.join(directory, "anchor.bin");
    const persistence = buildDurableFilePersistence(file);
    const expected = Buffer.from("durable-anchor");
    persistence.write(expected);
    assert.deepEqual(persistence.read(), expected);
    if (process.platform !== "win32") {
      assert.equal(fs.statSync(file).mode & 0o777, 0o600);
    }
    assert.deepEqual(fs.readdirSync(directory), ["anchor.bin"], "no temporary publication file remains");
    persistence.clear();
    assert.equal(persistence.read(), null);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

function directorySyncError(code: string, syscall: string, detail: string): NodeJS.ErrnoException {
  const error = new Error(detail) as NodeJS.ErrnoException;
  error.code = code;
  error.syscall = syscall;
  return error;
}

test("win32 accepts only its classified unsupported directory fsync after final-file sync", () => {
  for (const code of ["EPERM", "EINVAL"]) {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "tunnex-enrollment-win32-"));
    try {
      const file = path.join(directory, "anchor.bin");
      let namespaceSyncs = 0;
      const persistence = buildDurableFilePersistence(file, {
        platform: "win32",
        syncDirectory() {
          namespaceSyncs += 1;
          throw directorySyncError(code, "fsync", "unsupported directory flush");
        },
      });
      const expected = Buffer.from(`portable-${code}`);
      persistence.write(expected);
      assert.deepEqual(persistence.read(), expected);
      persistence.clear();
      assert.equal(persistence.read(), null);
      assert.equal(
        namespaceSyncs,
        4,
        "publication, trusted read, unlink, and trusted absence each attempt namespace durability",
      );
    } finally {
      fs.rmSync(directory, { recursive: true, force: true });
    }
  }
});

test("directory durability fallback is platform/error exact and never leaks anchor details", () => {
  const pair = generateWireGuardKeyPair();
  const cases: Array<{ platform: NodeJS.Platform; code: string; syscall: string }> = [
    { platform: "win32", code: "EACCES", syscall: "fsync" },
    { platform: "win32", code: "EPERM", syscall: "open" },
    { platform: "darwin", code: "EPERM", syscall: "fsync" },
  ];
  for (const scenario of cases) {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "tunnex-enrollment-refuse-"));
    const file = path.join(directory, "anchor.bin");
    try {
      const persistence = buildDurableFilePersistence(file, {
        platform: scenario.platform,
        syncDirectory() {
          throw directorySyncError(
            scenario.code,
            scenario.syscall,
            `secret=${pair.privateKey} path=${file}`,
          );
        },
      });
      const anchorStore = new EnrollmentAnchorStore(safeStorage(), persistence, false);
      let surfaced: unknown;
      try {
        anchorStore.put({
          version: 1,
          origin: ORIGIN,
          organizationId: ORGANIZATION_ID,
          ownerUserId: OWNER_ID,
          credentialFingerprint: "fingerprint-a",
          nodeId: NODE_A,
          name: "desktop",
          platform: scenario.platform,
          fullTunnel: false,
          publicKey: pair.publicKey,
          privateKey: pair.privateKey,
        });
      } catch (error) {
        surfaced = error;
      }
      assert.ok(surfaced instanceof EnrollmentAnchorStoreCorruptError);
      assert.equal((surfaced as Error).message, "managed_enrollment_anchor_corrupt");
      assert.equal((surfaced as Error).message.includes(pair.privateKey), false);
      assert.equal((surfaced as Error).message.includes(file), false);
    } finally {
      fs.rmSync(directory, { recursive: true, force: true });
    }
  }
});

test("a visible anchor from rename-before-sync is re-proved before recovery API", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "tunnex-visible-anchor-"));
  try {
    const file = path.join(directory, "anchor.bin");
    let namespaceSyncs = 0;
    let failPublication = true;
    const persistence = buildDurableFilePersistence(file, {
      platform: "darwin",
      syncDirectory() {
        namespaceSyncs += 1;
        if (failPublication && namespaceSyncs === 4) {
          throw directorySyncError("EIO", "fsync", "visible anchor not yet durable");
        }
      },
    });
    const { anchors, final } = stores(persistence);
    const { api, state } = apiHarness();

    await assert.rejects(
      resolveTunnelConfig(ORIGIN, false, api, final, ORGANIZATION_ID, OWNER_ID, recovery(anchors)),
      EnrollmentAnchorStoreCorruptError,
    );
    assert.equal(fs.existsSync(file), true, "rename crossed before namespace sync failed");
    assert.deepEqual(
      { prepare: state.prepareCalls, list: state.listCalls, create: state.createCalls, mode: state.modeCalls },
      { prepare: 1, list: 0, create: 0, mode: 0 },
    );

    failPublication = false;
    const config = await resolveTunnelConfig(
      ORIGIN,
      false,
      api,
      final,
      ORGANIZATION_ID,
      OWNER_ID,
      recovery(anchors),
    );
    assert.equal(deriveWireGuardPublicKey(config.private_key), state.rows[0]?.publicKey);
    assert.equal(state.createCalls, 1);
    assert.equal(anchors.get(ORIGIN), null);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("persistent visible-anchor reproof failure performs zero API, publish, helper handoff, or clear", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "tunnex-visible-anchor-refuse-"));
  try {
    const file = path.join(directory, "anchor.bin");
    let namespaceSyncs = 0;
    let refuseReproof = true;
    let clearCalls = 0;
    const durable = buildDurableFilePersistence(file, {
      platform: "darwin",
      syncDirectory() {
        namespaceSyncs += 1;
        if (namespaceSyncs >= 4 && refuseReproof) {
          throw directorySyncError("EIO", "fsync", `secret=storage-sentinel path=${file}`);
        }
      },
    });
    const counted: Persistence = {
      read: () => durable.read(),
      write: (bytes) => durable.write(bytes),
      clear: () => { clearCalls += 1; durable.clear(); },
    };
    const { anchors, final } = stores(counted);
    const { api, state } = apiHarness();

    await assert.rejects(
      resolveTunnelConfig(ORIGIN, false, api, final, ORGANIZATION_ID, OWNER_ID, recovery(anchors)),
      EnrollmentAnchorStoreCorruptError,
    );
    const visible = fs.readFileSync(file);
    const decoded = JSON.parse(safeStorage().decryptString(visible)) as Record<string, EnrollmentAnchor>;
    const privateKey = decoded[ORIGIN]?.privateKey;
    assert.ok(privateKey);

    let surfaced: unknown;
    try {
      await resolveTunnelConfig(ORIGIN, false, api, final, ORGANIZATION_ID, OWNER_ID, recovery(anchors));
    } catch (error) {
      surfaced = error;
    }
    assert.ok(surfaced instanceof EnrollmentAnchorStoreCorruptError);
    assert.equal((surfaced as Error).message, "managed_enrollment_anchor_corrupt");
    assert.equal((surfaced as Error).message.includes(privateKey), false);
    assert.equal((surfaced as Error).message.includes(file), false);
    assert.equal((surfaced as Error).message.includes("storage-sentinel"), false);
    assert.deepEqual(
      { list: state.listCalls, create: state.createCalls, mode: state.modeCalls, clear: clearCalls },
      { list: 0, create: 0, mode: 0, clear: 0 },
    );
    assert.equal(final.get(ORIGIN), null, "no helper-facing config can be returned");

    refuseReproof = false;
    assert.equal(anchors.get(ORIGIN)?.publicKey, decoded[ORIGIN]?.publicKey);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("a visible final record is re-proved before it can clear the recovery anchor", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "tunnex-visible-final-"));
  try {
    const file = path.join(directory, "tunnel.bin");
    let namespaceSyncs = 0;
    let failPublication = true;
    const finalPersistence = buildDurableFilePersistence(file, {
      platform: "darwin",
      syncDirectory() {
        namespaceSyncs += 1;
        if (failPublication && namespaceSyncs === 3) {
          throw directorySyncError("EIO", "fsync", "visible final not yet durable");
        }
      },
    });
    const { anchors, final } = stores(memoryPersistence(), finalPersistence);
    const { api, state } = apiHarness();

    await assert.rejects(
      resolveTunnelConfig(ORIGIN, false, api, final, ORGANIZATION_ID, OWNER_ID, recovery(anchors)),
      /tunnel_config_store_corrupt/,
    );
    const anchored = anchors.get(ORIGIN);
    assert.ok(anchored?.deviceId);
    assert.equal(fs.existsSync(file), true);
    const calls = { list: state.listCalls, create: state.createCalls, mode: state.modeCalls };

    failPublication = false;
    const config = await resolveTunnelConfig(
      ORIGIN,
      false,
      api,
      final,
      ORGANIZATION_ID,
      OWNER_ID,
      recovery(anchors),
    );
    assert.equal(config.private_key, anchored.privateKey);
    assert.equal(anchors.get(ORIGIN), null);
    assert.deepEqual(
      { list: state.listCalls, create: state.createCalls, mode: state.modeCalls },
      calls,
      "visible final is trusted only after reproof, without re-enrollment",
    );
    assert.equal(state.existsCalls, 1);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("lost create response resumes the same key, accepts current node drift, and changes mode without a second POST", async () => {
  const { anchors, final } = stores();
  const { api, state } = apiHarness({ loseCreateResponse: true, rehomeOnCreate: true });

  await assert.rejects(
    resolveTunnelConfig(ORIGIN, false, api, final, ORGANIZATION_ID, OWNER_ID, recovery(anchors)),
    /control_plane_request_timeout/,
  );
  const anchored = anchors.get(ORIGIN);
  assert.ok(anchored);
  assert.equal(anchored.deviceId, undefined);
  assert.equal(final.get(ORIGIN), null);
  assert.equal(state.createCalls, 1);
  assert.equal(state.modeCalls, 0);

  state.beforeList = () => {
    assert.equal(anchors.get(ORIGIN)?.credentialFingerprint, "fingerprint-b");
  };
  const config = await resolveTunnelConfig(
    ORIGIN,
    true,
    api,
    final,
    ORGANIZATION_ID,
    OWNER_ID,
    recovery(anchors, "fingerprint-b"),
  );
  assert.equal(state.prepareCalls, 1, "restart reuses anchored gateway selection");
  assert.equal(state.createCalls, 1, "sole public-key match recovers without another POST");
  assert.equal(state.modeCalls, 1);
  assert.equal(config.full_tunnel, true);
  assert.equal(final.get(ORIGIN)?.deviceId, DEVICE_ID);
  assert.equal(final.get(ORIGIN)?.config.private_key, anchored.privateKey);
  assert.equal(deriveWireGuardPublicKey(config.private_key), anchored.publicKey);
  assert.equal(anchors.get(ORIGIN), null);
});

test("pending enrollment publishes the recovery record before gating the helper", async () => {
  const { anchors, final } = stores();
  const { api, state } = apiHarness({ pending: true });
  await assert.rejects(
    resolveTunnelConfig(ORIGIN, false, api, final, ORGANIZATION_ID, OWNER_ID, recovery(anchors)),
    PendingApprovalError,
  );
  assert.equal(state.createCalls, 1);
  assert.equal(state.modeCalls, 1);
  assert.equal(final.get(ORIGIN)?.pending, true);
  assert.equal(final.get(ORIGIN)?.deviceId, DEVICE_ID);
  assert.equal(anchors.get(ORIGIN), null);
});

test("foreign, retired, and duplicate public-key matches retain the anchor and perform no create", async () => {
  const scenarios: Array<{ name: string; rows: (publicKey: string) => ManagedEnrollmentDevice[] }> = [
    {
      name: "foreign",
      rows: (publicKey) => [{ deviceId: DEVICE_ID, ownerUserId: "00000000-0000-4000-8000-000000000102", nodeId: NODE_A, publicKey, status: "active" }],
    },
    {
      name: "retired",
      rows: (publicKey) => [{ deviceId: DEVICE_ID, ownerUserId: OWNER_ID, nodeId: NODE_A, publicKey, status: "gone" }],
    },
    {
      name: "duplicate",
      rows: (publicKey) => [
        { deviceId: DEVICE_ID, ownerUserId: OWNER_ID, nodeId: NODE_A, publicKey, status: "active" },
        { deviceId: "00000000-0000-4000-8000-000000000302", ownerUserId: OWNER_ID, nodeId: NODE_B, publicKey, status: "pending" },
      ],
    },
  ];
  for (const scenario of scenarios) {
    const { anchors, final } = stores();
    const { api, state } = apiHarness();
    state.beforeList = (publicKey) => { state.rows = scenario.rows(publicKey); };
    await assert.rejects(
      resolveTunnelConfig(ORIGIN, false, api, final, ORGANIZATION_ID, OWNER_ID, recovery(anchors)),
      /device_key_recovery_conflict|managed_device_owner_mismatch/,
      scenario.name,
    );
    assert.equal(state.createCalls, 0, scenario.name);
    assert.equal(state.modeCalls, 0, scenario.name);
    assert.ok(anchors.get(ORIGIN), `${scenario.name}: unresolved identity retained`);
    assert.equal(final.get(ORIGIN), null, scenario.name);
  }
});

test("anchor publication ambiguity performs no list, create, mode, or final write", async () => {
  let anchorBytes: Buffer | null = null;
  const ambiguousPersistence: Persistence = {
    read: () => anchorBytes,
    write: (bytes) => {
      anchorBytes = Buffer.from(bytes);
      throw new Error("namespace_sync_failed");
    },
    clear: () => { anchorBytes = null; },
  };
  const { anchors, final } = stores(ambiguousPersistence);
  const { api, state } = apiHarness();
  await assert.rejects(
    resolveTunnelConfig(ORIGIN, false, api, final, ORGANIZATION_ID, OWNER_ID, recovery(anchors)),
    EnrollmentAnchorStoreCorruptError,
  );
  assert.equal(state.prepareCalls, 1);
  assert.equal(state.listCalls, 0);
  assert.equal(state.createCalls, 0);
  assert.equal(state.modeCalls, 0);
  assert.equal(final.get(ORIGIN), null);
});

test("ambiguous final publication retains the bound anchor for exact recovery", async () => {
  const finalPersistence: Persistence = {
    read: () => null,
    write: () => { throw new Error("final_namespace_sync_failed"); },
    clear: () => {},
  };
  const { anchors, final } = stores(memoryPersistence(), finalPersistence);
  const { api, state } = apiHarness();
  await assert.rejects(
    resolveTunnelConfig(ORIGIN, false, api, final, ORGANIZATION_ID, OWNER_ID, recovery(anchors)),
    /tunnel_config_store_corrupt/,
  );
  assert.equal(state.createCalls, 1);
  assert.equal(state.modeCalls, 1);
  assert.equal(anchors.get(ORIGIN)?.deviceId, DEVICE_ID);
});

test("final publish before anchor-clear failure is recognized exactly on retry", async () => {
  let bytes: Buffer | null = null;
  let failClear = true;
  const anchorPersistence: Persistence = {
    read: () => bytes === null ? null : Buffer.from(bytes),
    write: (next) => { bytes = Buffer.from(next); },
    clear: () => {
      if (failClear) throw new Error("anchor_clear_sync_failed");
      bytes = null;
    },
  };
  const { anchors, final } = stores(anchorPersistence);
  const { api, state } = apiHarness();
  await assert.rejects(
    resolveTunnelConfig(ORIGIN, false, api, final, ORGANIZATION_ID, OWNER_ID, recovery(anchors)),
    EnrollmentAnchorStoreCorruptError,
  );
  assert.ok(final.get(ORIGIN), "final record was already durably published");
  assert.ok(anchors.get(ORIGIN), "failed clear retains the exact anchor");
  const creates = state.createCalls;
  const modes = state.modeCalls;
  const lists = state.listCalls;

  failClear = false;
  await resolveTunnelConfig(ORIGIN, false, api, final, ORGANIZATION_ID, OWNER_ID, recovery(anchors));
  assert.equal(anchors.get(ORIGIN), null);
  assert.equal(state.createCalls, creates);
  assert.equal(state.modeCalls, modes);
  assert.equal(state.listCalls, lists);
  assert.equal(state.existsCalls, 1, "normal final-record liveness resumes only after exact anchor clear");
});

test("final/anchor key mismatch refuses before API and preserves both recovery records", async () => {
  const { anchors, final } = stores();
  const anchorPair = generateWireGuardKeyPair();
  const otherPair = generateWireGuardKeyPair();
  anchors.put({
    version: 1,
    origin: ORIGIN,
    organizationId: ORGANIZATION_ID,
    ownerUserId: OWNER_ID,
    credentialFingerprint: "fingerprint-a",
    nodeId: NODE_A,
    name: "desktop",
    platform: "darwin",
    fullTunnel: false,
    publicKey: anchorPair.publicKey,
    privateKey: anchorPair.privateKey,
    deviceId: DEVICE_ID,
  });
  final.put({
    origin: ORIGIN,
    orgId: ORGANIZATION_ID,
    ownerUserId: OWNER_ID,
    deviceId: DEVICE_ID,
    config: {
      private_key: otherPair.privateKey,
      peer_public_key: GATEWAY_PUBLIC_KEY,
      endpoint: "198.51.100.1:51820",
      address: "10.99.0.2/32",
      allowed_ips: ["10.99.0.0/24"],
      full_tunnel: false,
    },
  });
  const { api, state } = apiHarness();
  await assert.rejects(
    resolveTunnelConfig(ORIGIN, false, api, final, ORGANIZATION_ID, OWNER_ID, recovery(anchors)),
    /device_key_recovery_conflict/,
  );
  assert.equal(state.prepareCalls + state.listCalls + state.createCalls + state.modeCalls + state.existsCalls, 0);
  assert.equal(anchors.get(ORIGIN)?.publicKey, anchorPair.publicKey);
  assert.equal(final.get(ORIGIN)?.config.private_key, otherPair.privateKey);
});

test("explicit abandon revokes the sole same-owner live row, proves it terminal, and next connect uses a new key", async () => {
  const { anchors, final } = stores();
  const oldAnchor = seedEnrollmentAnchor(anchors, DEVICE_ID);
  const { api, state } = abandonmentApi([{
    deviceId: DEVICE_ID,
    ownerUserId: OWNER_ID,
    nodeId: NODE_A,
    publicKey: oldAnchor.publicKey,
    status: "active",
  }]);
  let leaseChecks = 0;
  const proof = await proveManagedEnrollmentAbandonment(
    ORIGIN,
    OWNER_ID,
    ORGANIZATION_ID,
    "fingerprint-a",
    [ORGANIZATION_ID],
    api,
    anchors,
    () => { leaseChecks += 1; },
  );
  assert.ok(proof);
  await consumeManagedEnrollmentAbandonProof(proof, api, () => { leaseChecks += 1; });
  assert.deepEqual({ roster: state.rosterCalls, revoke: state.revokeCalls }, { roster: 3, revoke: 1 });
  assert.ok(leaseChecks >= 5);
  assert.equal(anchors.get(ORIGIN), null);

  const fresh = apiHarness({ loseCreateResponse: true });
  await assert.rejects(
    resolveTunnelConfig(ORIGIN, false, fresh.api, final, ORGANIZATION_ID, OWNER_ID, recovery(anchors)),
    /control_plane_request_timeout/,
  );
  const replacement = anchors.get(ORIGIN);
  assert.ok(replacement);
  assert.notEqual(replacement.publicKey, oldAnchor.publicKey);
  assert.equal(fresh.state.createCalls, 1);
});

test("explicit abandon may clear bounded zero, foreign, multiple, or terminal visible evidence without guessed revocation", async () => {
  const foreignOwner = "00000000-0000-4000-8000-000000000102";
  const secondDevice = "00000000-0000-4000-8000-000000000302";
  const scenarios: Array<{
    name: string;
    rows: (anchor: EnrollmentAnchor) => ManagedEnrollmentDevice[];
  }> = [
    { name: "zero", rows: () => [] },
    {
      name: "foreign",
      rows: (anchor) => [{ deviceId: DEVICE_ID, ownerUserId: foreignOwner, nodeId: NODE_A, publicKey: anchor.publicKey, status: "active" }],
    },
    {
      name: "multiple",
      rows: (anchor) => [
        { deviceId: DEVICE_ID, ownerUserId: OWNER_ID, nodeId: NODE_A, publicKey: anchor.publicKey, status: "active" },
        { deviceId: secondDevice, ownerUserId: OWNER_ID, nodeId: NODE_B, publicKey: anchor.publicKey, status: "pending" },
      ],
    },
    {
      name: "terminal",
      rows: (anchor) => [{ deviceId: DEVICE_ID, ownerUserId: OWNER_ID, nodeId: NODE_A, publicKey: anchor.publicKey, status: "gone" }],
    },
  ];

  for (const scenario of scenarios) {
    const { anchors } = stores();
    const anchor = seedEnrollmentAnchor(anchors);
    const { api, state } = abandonmentApi(scenario.rows(anchor));
    const proof = await proveManagedEnrollmentAbandonment(
      ORIGIN,
      OWNER_ID,
      ORGANIZATION_ID,
      "fingerprint-a",
      [ORGANIZATION_ID],
      api,
      anchors,
      () => {},
    );
    assert.ok(proof, scenario.name);
    await consumeManagedEnrollmentAbandonProof(proof, api, () => {});
    assert.equal(anchors.get(ORIGIN), null, scenario.name);
    assert.deepEqual(
      { roster: state.rosterCalls, revoke: state.revokeCalls },
      { roster: 2, revoke: 0 },
      scenario.name,
    );
  }
});

test("explicit abandon completes only after re-proving a real unlink whose first parent sync failed", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "tunnex-abandon-unlink-"));
  const file = path.join(directory, "anchor.bin");
  try {
    let injectUnlinkedFailure = false;
    let failUnlinkedNamespaceOnce = true;
    let unlinkSyncFailures = 0;
    let trustedAbsenceSyncs = 0;
    const persistence = buildDurableFilePersistence(file, {
      platform: process.platform,
      syncDirectory(parent) {
        if (injectUnlinkedFailure && !fs.existsSync(file)) {
          if (failUnlinkedNamespaceOnce) {
            failUnlinkedNamespaceOnce = false;
            unlinkSyncFailures += 1;
            throw directorySyncError(
              "EIO",
              "fsync",
              `secret=${generateWireGuardKeyPair().privateKey} path=${file}`,
            );
          }
          trustedAbsenceSyncs += 1;
        }
        const descriptor = fs.openSync(parent, fs.constants.O_RDONLY);
        try { fs.fsyncSync(descriptor); } finally { fs.closeSync(descriptor); }
      },
    });
    const { anchors } = stores(persistence);
    seedEnrollmentAnchor(anchors);
    const { api, state } = abandonmentApi([]);
    let leaseChecks = 0;
    const proof = await proveManagedEnrollmentAbandonment(
      ORIGIN,
      OWNER_ID,
      ORGANIZATION_ID,
      "fingerprint-a",
      [ORGANIZATION_ID],
      api,
      anchors,
      () => { leaseChecks += 1; },
    );
    assert.ok(proof);
    injectUnlinkedFailure = true;

    await consumeManagedEnrollmentAbandonProof(proof, api, () => { leaseChecks += 1; });

    assert.equal(fs.existsSync(file), false, "the real final pathname crossed unlink before refusal");
    assert.equal(unlinkSyncFailures, 1);
    assert.equal(
      trustedAbsenceSyncs,
      2,
      "the one-shot clear capability and the trusted store read both synced the absent namespace",
    );
    assert.deepEqual({ roster: state.rosterCalls, revoke: state.revokeCalls }, { roster: 2, revoke: 0 });
    assert.ok(leaseChecks >= 4, "the fixed lifecycle lease was rechecked before absence recovery");
    assert.equal(anchors.get(ORIGIN), null);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("explicit abandon refuses when unlink visibility cannot be durably re-proved", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "tunnex-abandon-unlink-refuse-"));
  const file = path.join(directory, "anchor.bin");
  const secret = generateWireGuardKeyPair().privateKey;
  try {
    let injectUnlinkedFailure = false;
    let absentNamespaceSyncs = 0;
    const persistence = buildDurableFilePersistence(file, {
      platform: process.platform,
      syncDirectory(parent) {
        if (injectUnlinkedFailure && !fs.existsSync(file)) {
          absentNamespaceSyncs += 1;
          throw directorySyncError("EIO", "fsync", `secret=${secret} path=${file}`);
        }
        const descriptor = fs.openSync(parent, fs.constants.O_RDONLY);
        try { fs.fsyncSync(descriptor); } finally { fs.closeSync(descriptor); }
      },
    });
    const { anchors } = stores(persistence);
    seedEnrollmentAnchor(anchors);
    const { api, state } = abandonmentApi([]);
    const proof = await proveManagedEnrollmentAbandonment(
      ORIGIN,
      OWNER_ID,
      ORGANIZATION_ID,
      "fingerprint-a",
      [ORGANIZATION_ID],
      api,
      anchors,
      () => {},
    );
    assert.ok(proof);
    injectUnlinkedFailure = true;

    let surfaced: unknown;
    try {
      await consumeManagedEnrollmentAbandonProof(proof, api, () => {});
    } catch (error) {
      surfaced = error;
    }
    assert.ok(surfaced instanceof EnrollmentAnchorStoreCorruptError);
    assert.equal((surfaced as Error).message, "managed_enrollment_anchor_corrupt");
    assert.equal((surfaced as Error).message.includes(secret), false);
    assert.equal((surfaced as Error).message.includes(file), false);
    assert.equal(fs.existsSync(file), false, "the refused first sync still crossed the real unlink");
    assert.equal(absentNamespaceSyncs, 2, "clear and trusted absence read both refused namespace proof");
    assert.deepEqual({ roster: state.rosterCalls, revoke: state.revokeCalls }, { roster: 2, revoke: 0 });
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("explicit abandon never treats a missing post-unlink parent as ordinary first-run absence", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "tunnex-abandon-parent-missing-"));
  const file = path.join(directory, "anchor.bin");
  try {
    let removeParentAfterUnlink = false;
    const persistence = buildDurableFilePersistence(file, {
      platform: process.platform,
      syncDirectory(parent) {
        if (removeParentAfterUnlink && !fs.existsSync(file)) {
          fs.rmdirSync(parent);
          throw directorySyncError("ENOENT", "fsync", `missing parent path=${parent}`);
        }
        const descriptor = fs.openSync(parent, fs.constants.O_RDONLY);
        try { fs.fsyncSync(descriptor); } finally { fs.closeSync(descriptor); }
      },
    });
    const { anchors } = stores(persistence);
    seedEnrollmentAnchor(anchors);
    const { api, state } = abandonmentApi([]);
    const proof = await proveManagedEnrollmentAbandonment(
      ORIGIN,
      OWNER_ID,
      ORGANIZATION_ID,
      "fingerprint-a",
      [ORGANIZATION_ID],
      api,
      anchors,
      () => {},
    );
    assert.ok(proof);
    removeParentAfterUnlink = true;

    let surfaced: unknown;
    try {
      await consumeManagedEnrollmentAbandonProof(proof, api, () => {});
    } catch (error) {
      surfaced = error;
    }
    assert.ok(surfaced instanceof EnrollmentAnchorStoreCorruptError);
    assert.equal((surfaced as Error).message, "managed_enrollment_anchor_corrupt");
    assert.equal((surfaced as Error).message.includes(directory), false);
    assert.equal(fs.existsSync(directory), false);
    assert.deepEqual({ roster: state.rosterCalls, revoke: state.revokeCalls }, { roster: 2, revoke: 0 });
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("explicit abandon reports retained enrollment when an after-unlink classification still reads the exact anchor", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "tunnex-abandon-retained-"));
  const file = path.join(directory, "anchor.bin");
  try {
    let restoreAfterUnlink = false;
    let restored = false;
    let encryptedAnchor: Buffer | null = null;
    const persistence = buildDurableFilePersistence(file, {
      platform: process.platform,
      syncDirectory(parent) {
        if (restoreAfterUnlink && !restored && !fs.existsSync(file)) {
          if (!encryptedAnchor) throw new Error("test anchor was not captured");
          fs.writeFileSync(file, encryptedAnchor, { mode: 0o600 });
          restored = true;
          throw directorySyncError("EIO", "fsync", "unlink namespace rolled back");
        }
        const descriptor = fs.openSync(parent, fs.constants.O_RDONLY);
        try { fs.fsyncSync(descriptor); } finally { fs.closeSync(descriptor); }
      },
    });
    const { anchors } = stores(persistence);
    const anchor = seedEnrollmentAnchor(anchors);
    encryptedAnchor = fs.readFileSync(file);
    const { api, state } = abandonmentApi([]);
    const proof = await proveManagedEnrollmentAbandonment(
      ORIGIN,
      OWNER_ID,
      ORGANIZATION_ID,
      "fingerprint-a",
      [ORGANIZATION_ID],
      api,
      anchors,
      () => {},
    );
    assert.ok(proof);
    restoreAfterUnlink = true;

    await assert.rejects(
      consumeManagedEnrollmentAbandonProof(proof, api, () => {}),
      /managed_enrollment_abandon_refused/,
    );
    assert.equal(restored, true);
    assert.equal(anchors.get(ORIGIN)?.publicKey, anchor.publicKey);
    assert.deepEqual({ roster: state.rosterCalls, revoke: state.revokeCalls }, { roster: 2, revoke: 0 });
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("explicit abandon refuses an encrypted other-origin map after unlink ambiguity", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "tunnex-abandon-other-origin-"));
  const file = path.join(directory, "anchor.bin");
  const otherOrigin = "https://other-recovery.example";
  const otherPair = generateWireGuardKeyPair();
  const otherAnchor: EnrollmentAnchor = {
    version: 1,
    origin: otherOrigin,
    organizationId: ORGANIZATION_ID,
    ownerUserId: OWNER_ID,
    credentialFingerprint: "fingerprint-other",
    nodeId: NODE_B,
    name: "other-desktop",
    platform: "darwin",
    fullTunnel: false,
    publicKey: otherPair.publicKey,
    privateKey: otherPair.privateKey,
  };
  const encryptedReplacement = safeStorage().encryptString(JSON.stringify({
    [otherOrigin]: otherAnchor,
  }));
  try {
    let replaceAfterUnlink = false;
    let replaced = false;
    const persistence = buildDurableFilePersistence(file, {
      platform: process.platform,
      syncDirectory(parent) {
        if (replaceAfterUnlink && !replaced && !fs.existsSync(file)) {
          fs.writeFileSync(file, encryptedReplacement, { mode: 0o600 });
          replaced = true;
          throw directorySyncError(
            "EIO",
            "fsync",
            `secret=${otherPair.privateKey} path=${file}`,
          );
        }
        const descriptor = fs.openSync(parent, fs.constants.O_RDONLY);
        try { fs.fsyncSync(descriptor); } finally { fs.closeSync(descriptor); }
      },
    });
    const { anchors } = stores(persistence);
    seedEnrollmentAnchor(anchors);
    const { api, state } = abandonmentApi([]);
    const proof = await proveManagedEnrollmentAbandonment(
      ORIGIN,
      OWNER_ID,
      ORGANIZATION_ID,
      "fingerprint-a",
      [ORGANIZATION_ID],
      api,
      anchors,
      () => {},
    );
    assert.ok(proof);
    replaceAfterUnlink = true;

    let surfaced: unknown;
    try {
      await consumeManagedEnrollmentAbandonProof(proof, api, () => {});
    } catch (error) {
      surfaced = error;
    }
    assert.ok(surfaced instanceof EnrollmentAnchorStoreCorruptError);
    assert.equal((surfaced as Error).message, "managed_enrollment_anchor_corrupt");
    assert.equal((surfaced as Error).message.includes(otherPair.privateKey), false);
    assert.equal((surfaced as Error).message.includes(file), false);
    assert.equal(replaced, true);
    assert.equal(anchors.get(otherOrigin)?.publicKey, otherPair.publicKey);
    assert.deepEqual({ roster: state.rosterCalls, revoke: state.revokeCalls }, { roster: 2, revoke: 0 });
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("abandon rechecks the exact revoked row but does not mistake foreign visible evidence for its survival", async () => {
  const foreignDevice = "00000000-0000-4000-8000-000000000302";
  const foreignOwner = "00000000-0000-4000-8000-000000000102";
  const { anchors } = stores();
  const anchor = seedEnrollmentAnchor(anchors, DEVICE_ID);
  const { api, state } = abandonmentApi([
    { deviceId: DEVICE_ID, ownerUserId: OWNER_ID, nodeId: NODE_A, publicKey: anchor.publicKey, status: "pending" },
    { deviceId: foreignDevice, ownerUserId: foreignOwner, nodeId: NODE_B, publicKey: anchor.publicKey, status: "active" },
  ]);
  const proof = await proveManagedEnrollmentAbandonment(
    ORIGIN,
    OWNER_ID,
    ORGANIZATION_ID,
    "fingerprint-a",
    [ORGANIZATION_ID],
    api,
    anchors,
    () => {},
  );
  assert.ok(proof);
  await consumeManagedEnrollmentAbandonProof(proof, api, () => {});
  assert.equal(anchors.get(ORIGIN), null);
  assert.deepEqual({ roster: state.rosterCalls, revoke: state.revokeCalls }, { roster: 3, revoke: 1 });
});

test("abandon refusal retains the anchor on identity, membership, roster, lease, and clear ambiguity", async () => {
  const cases: Array<{
    name: string;
    fingerprint: string;
    memberships: string[];
    apiFailure?: boolean;
    staleLease?: boolean;
  }> = [
    { name: "fingerprint", fingerprint: "fingerprint-b", memberships: [ORGANIZATION_ID] },
    { name: "membership", fingerprint: "fingerprint-a", memberships: [] },
    { name: "roster", fingerprint: "fingerprint-a", memberships: [ORGANIZATION_ID], apiFailure: true },
    { name: "lease", fingerprint: "fingerprint-a", memberships: [ORGANIZATION_ID], staleLease: true },
  ];
  for (const scenario of cases) {
    const { anchors } = stores();
    const anchor = seedEnrollmentAnchor(anchors);
    let rosterCalls = 0;
    const api: Pick<DeviceApi, "devicesByPublicKey" | "revokeDevice"> = {
      async devicesByPublicKey() {
        rosterCalls += 1;
        if (scenario.apiFailure) throw new Error("roster unavailable");
        return [];
      },
      async revokeDevice() { throw new Error("must not revoke"); },
    };
    await assert.rejects(
      proveManagedEnrollmentAbandonment(
        ORIGIN,
        OWNER_ID,
        ORGANIZATION_ID,
        scenario.fingerprint,
        scenario.memberships,
        api,
        anchors,
        () => { if (scenario.staleLease) throw new Error("stale lease"); },
      ),
      /managed_enrollment_abandon_refused|roster unavailable|stale lease/,
      scenario.name,
    );
    assert.equal(anchors.get(ORIGIN)?.publicKey, anchor.publicKey, scenario.name);
    assert.equal(rosterCalls, scenario.apiFailure || scenario.staleLease ? 1 : 0, scenario.name);
  }

  let bytes: Buffer | null = null;
  let clearCalls = 0;
  const ambiguousClear: Persistence = {
    read: () => bytes === null ? null : Buffer.from(bytes),
    write: (next) => { bytes = Buffer.from(next); },
    clear: () => { clearCalls += 1; throw new Error("anchor clear not durable"); },
  };
  const { anchors } = stores(ambiguousClear);
  const anchor = seedEnrollmentAnchor(anchors);
  const { api, state } = abandonmentApi([]);
  const proof = await proveManagedEnrollmentAbandonment(
    ORIGIN,
    OWNER_ID,
    ORGANIZATION_ID,
    "fingerprint-a",
    [ORGANIZATION_ID],
    api,
    anchors,
    () => {},
  );
  assert.ok(proof);
  await assert.rejects(
    consumeManagedEnrollmentAbandonProof(proof, api, () => {}),
    EnrollmentAnchorStoreCorruptError,
  );
  assert.equal(clearCalls, 1);
  assert.equal(state.revokeCalls, 0);
  assert.equal(anchors.get(ORIGIN)?.publicKey, anchor.publicKey);
});

test("an unresolved anchor projects and locks only for its exact current user", () => {
  const { anchors } = stores();
  const anchor = seedEnrollmentAnchor(anchors);
  const currentProjection = enrollmentAnchorOrganizationForUser(anchor, ORIGIN, OWNER_ID);
  assert.equal(currentProjection, ORGANIZATION_ID);
  const values = new Map<string, string>();
  const selector = new ManagedOrganizationSelector({
    get: (key) => values.get(key) ?? "",
    set: (key, organizationId) => { values.set(key, organizationId); },
  });
  const live = [
    { id: ORGANIZATION_ID, name: "Recovery org", slug: "recovery" },
    { id: "00000000-0000-4000-8000-000000000202", name: "Other org", slug: "other" },
  ];
  assert.equal(selector.organizations(ORIGIN, OWNER_ID, live, currentProjection, true).enrollmentLocked, true);
  assert.throws(
    () => selector.select(ORIGIN, OWNER_ID, live, live[1].id, currentProjection, true),
    OrganizationSelectionConflictError,
  );

  const foreignOwner = "00000000-0000-4000-8000-000000000102";
  const foreignProjection = enrollmentAnchorOrganizationForUser(anchor, ORIGIN, foreignOwner);
  assert.equal(foreignProjection, null);
  assert.equal(selector.organizations(ORIGIN, foreignOwner, live, foreignProjection, false).enrollmentLocked, false);
  assert.equal(enrollmentAnchorOrganizationForUser(anchor, "https://other.example", OWNER_ID), null);
});

test("foreign enrollment refuses connect and removal proof without lifecycle, API, or encrypted-byte effects", async () => {
  const persistence = memoryPersistence();
  const { anchors } = stores(persistence);
  const anchor = seedEnrollmentAnchor(anchors);
  const before = persistence.bytes();
  const otherUser = "00000000-0000-4000-8000-000000000102";
  const credential = {
    server: ORIGIN, token: "other-user-token", fingerprint: "other-user-fingerprint", expiresAt: "2999-01-01T00:00:00Z",
  };
  const coordinator = new ManagedLifecycleCoordinator(() => credential);
  const lease = await coordinator.capture(async () => otherUser);
  const effects: string[] = [];
  const proveOwner = () => {
    assertManagedEnrollmentOwner(anchors.get(ORIGIN), ORIGIN, lease.userId);
    effects.push("API owner and organization reads");
    throw new Error("foreign proof must refuse first");
  };
  const expectStaticRefusal = (error: unknown): boolean => {
    assert.ok(error instanceof ManagedEnrollmentOwnerMismatchError);
    assert.equal(error.message, "managed_enrollment_owner_mismatch");
    for (const hidden of Object.values(anchor)) {
      if (typeof hidden === "string") assert.ok(!error.message.includes(hidden));
    }
    return true;
  };
  await assert.rejects(coordinator.serial((owner) =>
    runManagedConnectFlow(owner, {
      proveAndPrepare: async () => proveOwner(),
      quiesceExisting: () => { effects.push("helper Down"); },
      publishQuiesced: () => { effects.push("publish Down"); },
      prepareRuntime: () => { effects.push("stop monitors"); },
      installHelper: () => { effects.push("install helper"); },
      up: async () => { effects.push("config/create/helper Up"); },
      onUpError: () => { effects.push("runtime error"); },
      publish: () => { effects.push("publish"); },
    })), expectStaticRefusal);
  coordinator.assertCurrent(lease);
  await assert.rejects(coordinator.serial((owner) =>
    runManagedRemoveFlow(owner, {
      proveOwner: async () => proveOwner(),
      quiesceExisting: () => { effects.push("helper Down"); },
      stopMonitors: () => { effects.push("stop monitors"); },
      revokeAndClear: () => { effects.push("revoke and clear"); return true; },
    })), expectStaticRefusal);
  coordinator.assertCurrent(lease);
  assert.deepEqual(effects, []);
  assert.deepEqual(persistence.bytes(), before);
  assert.deepEqual(anchors.get(ORIGIN), anchor);
});

test("foreign enrollment exposes only a boolean and leaves the original owner able to resume its lost response", async () => {
  const persistence = memoryPersistence();
  const { anchors, final } = stores(persistence);
  const { api, state } = apiHarness({ loseCreateResponse: true });
  await assert.rejects(
    resolveTunnelConfig(ORIGIN, false, api, final, ORGANIZATION_ID, OWNER_ID, recovery(anchors)),
    /control_plane_request_timeout/,
  );
  const anchor = anchors.get(ORIGIN)!;
  const before = persistence.bytes();
  const otherUser = "00000000-0000-4000-8000-000000000102";
  assert.equal(enrollmentAnchorBlocksUser(anchor, ORIGIN, otherUser), true);
  assert.equal(enrollmentAnchorOrganizationForUser(anchor, ORIGIN, otherUser), null);
  assert.throws(() => assertManagedEnrollmentOwner(anchor, ORIGIN, otherUser), ManagedEnrollmentOwnerMismatchError);
  // The config-provider check remains a second guard if the context drifts
  // after preflight; it must retain the very same locally generated key.
  await assert.rejects(
    resolveTunnelConfig(ORIGIN, false, api, final, ORGANIZATION_ID, otherUser, recovery(anchors, "other-user-fingerprint")),
    /device_key_recovery_conflict/,
  );
  assert.deepEqual(persistence.bytes(), before);
  assert.equal(state.createCalls, 1);
  assert.equal(state.listCalls, 1);

  assert.equal(enrollmentAnchorBlocksUser(anchor, ORIGIN, OWNER_ID), false);
  assert.doesNotThrow(() => assertManagedEnrollmentOwner(anchor, ORIGIN, OWNER_ID));
  assert.doesNotThrow(() => assertManagedEnrollmentOwner(null, ORIGIN, otherUser));
  assert.equal(enrollmentAnchorBlocksUser(null, ORIGIN, otherUser), false);
  assert.equal(enrollmentAnchorBlocksUser(anchor, "https://other.example", otherUser), false);
  const config = await resolveTunnelConfig(
    ORIGIN, false, api, final, ORGANIZATION_ID, OWNER_ID, recovery(anchors, "returning-owner-fingerprint"),
  );
  assert.equal(config.private_key, anchor.privateKey);
  assert.equal(final.get(ORIGIN)?.deviceId, DEVICE_ID);
  assert.equal(final.get(ORIGIN)?.ownerUserId, OWNER_ID);
  assert.equal(state.createCalls, 1, "original account recovers the sole server identity without a new create");
  assert.equal(anchors.get(ORIGIN), null);
});
