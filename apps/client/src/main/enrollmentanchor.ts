import { createPrivateKey, createPublicKey, randomBytes } from "node:crypto";
import { InsecureStorageError, type Persistence, type SafeStorageLike } from "./credential";
import {
  DurableFileClearAfterUnlinkError,
  reproveDurableFileClearNamespace,
} from "./durablefile";
import { normalizeServerUrl } from "./serverurl";
import { isCanonicalUuid } from "./uuid";

const X25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");
const X25519_SPKI_PREFIX = Buffer.from("302a300506032b656e032100", "hex");

export interface WireGuardKeyPair {
  privateKey: string;
  publicKey: string;
}

function rawWireGuardKey(value: unknown): Buffer | null {
  if (typeof value !== "string") return null;
  const decoded = Buffer.from(value, "base64");
  return decoded.length === 32 && decoded.toString("base64") === value ? decoded : null;
}

// deriveWireGuardPublicKey uses Node's X25519 implementation over the raw
// 32-byte WireGuard private value. The fixed DER wrappers are key-format
// envelopes only; neither wrapper nor the derived public value changes the raw
// private bytes persisted by WireGuard clients.
export function deriveWireGuardPublicKey(privateKey: string): string {
  const raw = rawWireGuardKey(privateKey);
  if (!raw) throw new Error("managed_enrollment_key_invalid");
  let publicDer: Buffer;
  try {
    const key = createPrivateKey({
      key: Buffer.concat([X25519_PKCS8_PREFIX, raw]),
      format: "der",
      type: "pkcs8",
    });
    publicDer = createPublicKey(key).export({ format: "der", type: "spki" }) as Buffer;
  } catch {
    throw new Error("managed_enrollment_key_invalid");
  }
  if (
    publicDer.length !== X25519_SPKI_PREFIX.length + 32
    || !publicDer.subarray(0, X25519_SPKI_PREFIX.length).equals(X25519_SPKI_PREFIX)
  ) {
    throw new Error("managed_enrollment_key_invalid");
  }
  return publicDer.subarray(X25519_SPKI_PREFIX.length).toString("base64");
}

export function generateWireGuardKeyPair(): WireGuardKeyPair {
  const privateKey = randomBytes(32).toString("base64");
  return { privateKey, publicKey: deriveWireGuardPublicKey(privateKey) };
}

export interface EnrollmentAnchor {
  version: 1;
  origin: string;
  organizationId: string;
  ownerUserId: string;
  credentialFingerprint: string;
  nodeId: string;
  name: string;
  platform: string;
  fullTunnel: boolean;
  publicKey: string;
  privateKey: string;
  deviceId?: string;
}

type AnchorMap = Record<string, EnrollmentAnchor>;

export class EnrollmentAnchorStoreCorruptError extends Error {
  constructor() {
    super("managed_enrollment_anchor_corrupt");
    this.name = "EnrollmentAnchorStoreCorruptError";
  }
}

// Same static customer-facing error as every corrupt/unproved anchor read, but
// with an internal type that lets the already-confirmed abandonment operation
// perform one exact trusted-absence reproof. Generic callers must not infer
// absence from an arbitrary clear failure.
export class EnrollmentAnchorClearAfterUnlinkError extends EnrollmentAnchorStoreCorruptError {}

interface EnrollmentAnchorClearRecovery {
  store: EnrollmentAnchorStore;
  origin: string;
  durableError: DurableFileClearAfterUnlinkError;
}

const enrollmentAnchorClearRecoveries = new WeakMap<
  EnrollmentAnchorClearAfterUnlinkError,
  EnrollmentAnchorClearRecovery
>();

function exactKeys(value: Record<string, unknown>, required: readonly string[], optional: readonly string[]): boolean {
  const allowed = new Set([...required, ...optional]);
  return required.every((key) => Object.hasOwn(value, key))
    && Object.keys(value).every((key) => allowed.has(key));
}

function validOrigin(value: unknown): value is string {
  if (typeof value !== "string") return false;
  try {
    return normalizeServerUrl(value) === value;
  } catch {
    return false;
  }
}

function validAnchor(key: string, value: unknown): value is EnrollmentAnchor {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const anchor = value as Record<string, unknown>;
  if (!exactKeys(anchor, [
    "version", "origin", "organizationId", "ownerUserId", "credentialFingerprint",
    "nodeId", "name", "platform", "fullTunnel", "publicKey", "privateKey",
  ], ["deviceId"])) return false;
  if (
    anchor.version !== 1
    || !validOrigin(anchor.origin)
    || anchor.origin !== key
    || !isCanonicalUuid(anchor.organizationId)
    || !isCanonicalUuid(anchor.ownerUserId)
    || !isCanonicalUuid(anchor.nodeId)
    || (anchor.deviceId !== undefined && !isCanonicalUuid(anchor.deviceId))
    || typeof anchor.credentialFingerprint !== "string"
    || anchor.credentialFingerprint.length === 0
    || typeof anchor.name !== "string"
    || anchor.name.length === 0
    || typeof anchor.platform !== "string"
    || anchor.platform.length === 0
    || typeof anchor.fullTunnel !== "boolean"
    || rawWireGuardKey(anchor.privateKey) === null
    || rawWireGuardKey(anchor.publicKey) === null
  ) return false;
  try {
    return deriveWireGuardPublicKey(anchor.privateKey as string) === anchor.publicKey;
  } catch {
    return false;
  }
}

function parseAnchorMap(json: string): AnchorMap {
  let value: unknown;
  try {
    value = JSON.parse(json);
  } catch {
    throw new EnrollmentAnchorStoreCorruptError();
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new EnrollmentAnchorStoreCorruptError();
  }
  for (const [key, anchor] of Object.entries(value)) {
    if (!validAnchor(key, anchor)) throw new EnrollmentAnchorStoreCorruptError();
  }
  return value as AnchorMap;
}

export class EnrollmentAnchorStore {
  constructor(
    private readonly safe: SafeStorageLike,
    private readonly persistence: Persistence,
    private readonly allowInsecure: boolean,
  ) {}

  private readMap(): AnchorMap {
    let raw: Buffer | null;
    try {
      raw = this.persistence.read();
    } catch {
      throw new EnrollmentAnchorStoreCorruptError();
    }
    if (raw === null) return {};
    let json: string;
    try {
      json = this.safe.isEncryptionAvailable() ? this.safe.decryptString(raw) : raw.toString("utf8");
    } catch {
      throw new EnrollmentAnchorStoreCorruptError();
    }
    return parseAnchorMap(json);
  }

  private writeMap(anchors: AnchorMap): void {
    const json = JSON.stringify(anchors);
    let bytes: Buffer;
    if (this.safe.isEncryptionAvailable()) {
      try {
        bytes = this.safe.encryptString(json);
      } catch {
        throw new EnrollmentAnchorStoreCorruptError();
      }
    } else {
      if (!this.allowInsecure) throw new InsecureStorageError();
      bytes = Buffer.from(json, "utf8");
    }
    try {
      this.persistence.write(bytes);
      if (JSON.stringify(this.readMap()) !== json) throw new EnrollmentAnchorStoreCorruptError();
    } catch (error) {
      if (error instanceof InsecureStorageError || error instanceof EnrollmentAnchorStoreCorruptError) throw error;
      throw new EnrollmentAnchorStoreCorruptError();
    }
  }

  get(origin: string): EnrollmentAnchor | null {
    return this.readMap()[origin] ?? null;
  }

  put(anchor: EnrollmentAnchor): void {
    if (!validAnchor(anchor.origin, anchor)) throw new EnrollmentAnchorStoreCorruptError();
    const anchors = this.readMap();
    anchors[anchor.origin] = anchor;
    this.writeMap(anchors);
  }

  bind(origin: string, deviceId: string): EnrollmentAnchor {
    if (!isCanonicalUuid(deviceId)) throw new EnrollmentAnchorStoreCorruptError();
    const anchors = this.readMap();
    const anchor = anchors[origin];
    if (!anchor || (anchor.deviceId !== undefined && anchor.deviceId !== deviceId)) {
      throw new EnrollmentAnchorStoreCorruptError();
    }
    const bound: EnrollmentAnchor = { ...anchor, deviceId };
    anchors[origin] = bound;
    this.writeMap(anchors);
    return bound;
  }

  rebindCredential(origin: string, credentialFingerprint: string): EnrollmentAnchor {
    if (!credentialFingerprint) throw new EnrollmentAnchorStoreCorruptError();
    const anchors = this.readMap();
    const anchor = anchors[origin];
    if (!anchor) throw new EnrollmentAnchorStoreCorruptError();
    const rebound: EnrollmentAnchor = { ...anchor, credentialFingerprint };
    anchors[origin] = rebound;
    this.writeMap(anchors);
    return rebound;
  }

  // Consume only the exact one-shot clear classification emitted by this store
  // for this origin. It first requires the known parent namespace to exist and
  // synchronize, then performs the ordinary trusted encrypted/shape/key read.
  // The returned anchor never leaves MAIN.
  reproveClearAfterUnlink(
    error: EnrollmentAnchorClearAfterUnlinkError,
    origin: string,
  ): EnrollmentAnchor | null {
    const recovery = enrollmentAnchorClearRecoveries.get(error);
    enrollmentAnchorClearRecoveries.delete(error);
    if (!recovery || recovery.store !== this || recovery.origin !== origin) {
      throw new EnrollmentAnchorStoreCorruptError();
    }
    try {
      reproveDurableFileClearNamespace(recovery.durableError);
      const anchors = this.readMap();
      const keys = Object.keys(anchors);
      if (keys.length === 0) return null;
      if (keys.length === 1 && keys[0] === origin) return anchors[origin];
      throw new EnrollmentAnchorStoreCorruptError();
    } catch {
      throw new EnrollmentAnchorStoreCorruptError();
    }
  }

  remove(origin: string): EnrollmentAnchor | null {
    const anchors = this.readMap();
    const existing = anchors[origin] ?? null;
    if (!existing) return null;
    delete anchors[origin];
    try {
      if (Object.keys(anchors).length === 0) {
        this.persistence.clear();
        if (this.persistence.read() !== null) throw new EnrollmentAnchorStoreCorruptError();
      } else {
        this.writeMap(anchors);
      }
    } catch (error) {
      if (error instanceof DurableFileClearAfterUnlinkError) {
        const classified = new EnrollmentAnchorClearAfterUnlinkError();
        enrollmentAnchorClearRecoveries.set(classified, {
          store: this,
          origin,
          durableError: error,
        });
        throw classified;
      }
      if (error instanceof EnrollmentAnchorStoreCorruptError) throw error;
      throw new EnrollmentAnchorStoreCorruptError();
    }
    return existing;
  }
}
