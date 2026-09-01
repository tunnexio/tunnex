import { InsecureStorageError, type Persistence, type SafeStorageLike } from "./credential";
import type { TunnelConfig } from "./helperclient";
import { isCanonicalUuid } from "./uuid";

// A device's config is ORIGIN-KEYED (like the bearer) and NEVER used cross-origin:
// a stored config belongs to exactly the server it was minted against. The map is
// encrypted at rest via the OS keychain — the WG private key lives here + in the
// helper only, never in the renderer.
export interface StoredTunnelConfig {
  origin: string; // the server origin this config/device belongs to
  deviceId: string; // for best-effort revoke (against THIS origin only)
  orgId: string; // the device's OWN org — the monitors query it directly (S7.3 finding #4)
  // D14: the authenticated human who owns this managed device. Optional only so
  // encrypted records written by older clients remain readable long enough for
  // the live owner-binding migration. Every newly minted managed record sets it;
  // imported profiles intentionally do not have a control-plane owner.
  ownerUserId?: string;
  config: TunnelConfig;
  // pending (S7.3) = the device is AWAITING admin approval: the config is valid but the
  // gateway won't serve the peer yet, so resolveTunnelConfig refuses to arm the helper and
  // re-signals PendingApprovalError. Cleared by the ApprovalMonitor on approval.
  pending?: boolean;
  // revoked is a locally persisted terminal marker set only after the control plane
  // definitively reports this device gone. It prevents a normal reconnect or a
  // split/full toggle from silently re-enrolling a device an administrator revoked.
  // An explicit remove/re-enrollment workflow is required to replace it.
  revoked?: boolean;
  // ⛔ IMPORTED = A CONFIG THIS CLIENT DID NOT MINT, AND IT IS A DEGRADED MODE ON PURPOSE.
  //
  // Founder-directed: a user who downloaded a `.conf` from the control plane at device creation
  // must be able to connect with it. It works — the helper only needs keys and routes — but it
  // arrives with NO device identity, and everything the client does to keep a tunnel honest is
  // keyed on one:
  //
  //   · `RevocationMonitor` polls `deviceExists(deviceId, orgId)`. Without them there is no poll,
  //     so an admin revoking this device sees it STAY UP on the client until the peer is dropped
  //     server-side. The tunnel stops working; the app does not know why.
  //   · `ApprovalMonitor` and `HealthMonitor` are keyed the same way — no posture reporting, no
  //     pending-approval transition.
  //   · The split↔full re-mint cannot run: an imported profile's AllowedIPs are fixed at whatever
  //     the file says, so the routing toggle has nothing to re-issue.
  //
  // > **THE FLAG EXISTS SO THE DEGRADATION IS A FACT IN THE DATA, NOT A COMMENT.** Every surface
  // > that shows an imported tunnel reads this and says so; a mode that is only degraded in the
  // > documentation is a mode that looks identical to the safe one.
  imported?: boolean;
  // Human-readable label from the selected filename. It contains no key material and
  // lets the profile picker distinguish multiple imported devices/gateways.
  importedName?: string;
}

/**
 * The store key for an imported profile.
 *
 * ⚠ NOT AN HTTP ORIGIN, AND DELIBERATELY UNSPELLABLE AS ONE. Every other key in this map is a
 * server origin, and the whole point of origin-keying is that a config is never used against a
 * server it was not minted for. An imported profile has no minting server, so it gets a key that
 * cannot collide with a real one rather than borrowing whichever origin happens to be configured.
 */
export const IMPORTED_ORIGIN = "imported:local";
export const IMPORTED_PROFILE_PREFIX = "imported:profile:";

export interface ImportedTunnelProfile {
  id: string;
  name: string;
  config: TunnelConfig;
}

export function importedProfileOrigin(id: string): string {
  return id === "legacy" ? IMPORTED_ORIGIN : `${IMPORTED_PROFILE_PREFIX}${id}`;
}

export function importedProfileId(origin: string): string | null {
  if (origin === IMPORTED_ORIGIN) return "legacy";
  return origin.startsWith(IMPORTED_PROFILE_PREFIX)
    ? origin.slice(IMPORTED_PROFILE_PREFIX.length)
    : null;
}

type ConfigMap = Record<string, StoredTunnelConfig>;

export class TunnelConfigStoreCorruptError extends Error {
  constructor() {
    super("tunnel_config_store_corrupt");
    this.name = "TunnelConfigStoreCorruptError";
  }
}

function validStoredRecordEnvelope(key: string, value: unknown): value is StoredTunnelConfig {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  const imported = record.imported === true;
  const validControlPlaneIdentities = imported
    ? record.deviceId === ""
      && (record.orgId === undefined || record.orgId === "")
      && record.ownerUserId === undefined
    : isCanonicalUuid(record.deviceId)
      // Compatibility records written before org/owner binding remain readable
      // only while those fields are absent/empty. Any present identity is UUID.
      && (record.orgId === undefined || record.orgId === "" || isCanonicalUuid(record.orgId))
      && (record.ownerUserId === undefined || isCanonicalUuid(record.ownerUserId));
  return typeof record.origin === "string"
    && record.origin === key
    && validControlPlaneIdentities
    && record.config !== null
    && typeof record.config === "object"
    && !Array.isArray(record.config)
    && (record.pending === undefined || typeof record.pending === "boolean")
    && (record.revoked === undefined || typeof record.revoked === "boolean")
    && (record.imported === undefined || typeof record.imported === "boolean")
    && (record.importedName === undefined || typeof record.importedName === "string");
}

function parseConfigMap(json: string): ConfigMap {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    throw new TunnelConfigStoreCorruptError();
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new TunnelConfigStoreCorruptError();
  }
  for (const [key, value] of Object.entries(parsed)) {
    if (!validStoredRecordEnvelope(key, value)) throw new TunnelConfigStoreCorruptError();
  }
  return parsed as ConfigMap;
}

// TunnelConfigStore refuses-by-default when there is no keychain (same posture as
// CredentialStore) — a plaintext WG private key on disk is exactly the mistake D2
// called out about the browser flow.
export class TunnelConfigStore {
  constructor(
    private safe: SafeStorageLike,
    private persist: Persistence,
    private allowInsecure: boolean,
  ) {}

  available(): boolean {
    return this.safe.isEncryptionAvailable() || this.allowInsecure;
  }

  private readMap(): ConfigMap {
    let raw: Buffer | null;
    try {
      raw = this.persist.read();
    } catch {
      throw new TunnelConfigStoreCorruptError();
    }
    if (!raw) return {};
    let json: string;
    try {
      json = this.safe.isEncryptionAvailable() ? this.safe.decryptString(raw) : raw.toString("utf8");
    } catch {
      // Never expose ciphertext, decrypted bytes, or the storage provider's
      // exception. Presence plus unreadability is corruption, not absence.
      throw new TunnelConfigStoreCorruptError();
    }
    return parseConfigMap(json);
  }

  private writeMap(m: ConfigMap): void {
    const json = JSON.stringify(m);
    let bytes: Buffer;
    try {
      if (this.safe.isEncryptionAvailable()) {
        bytes = this.safe.encryptString(json);
      } else {
        if (!this.allowInsecure) throw new InsecureStorageError();
        bytes = Buffer.from(json, "utf8");
      }
      this.persist.write(bytes);
      // A managed private key becomes helper-authoritative only after an exact
      // decrypted readback of the atomically published record. Storage
      // ambiguity remains corruption, never permission to enroll again.
      if (JSON.stringify(this.readMap()) !== json) throw new TunnelConfigStoreCorruptError();
    } catch (error) {
      if (error instanceof InsecureStorageError || error instanceof TunnelConfigStoreCorruptError) throw error;
      throw new TunnelConfigStoreCorruptError();
    }
  }

  get(origin: string): StoredTunnelConfig | null {
    return this.readMap()[origin] ?? null;
  }

  put(sc: StoredTunnelConfig): void {
    if (!validStoredRecordEnvelope(sc.origin, sc)) throw new TunnelConfigStoreCorruptError();
    const m = this.readMap();
    m[sc.origin] = sc;
    this.writeMap(m);
  }

  // remove drops the entry for origin and returns it (so the caller can revoke the
  // device against THAT origin). No-op returns null.
  remove(origin: string): StoredTunnelConfig | null {
    const m = this.readMap();
    const existing = m[origin] ?? null;
    if (existing) {
      delete m[origin];
      this.writeMap(m);
    }
    return existing;
  }

  // list is for the UI to surface orphaned (non-current-origin) devices with a
  // remove-or-switch-back affordance.
  list(): StoredTunnelConfig[] {
    return Object.values(this.readMap());
  }

  // Imported profiles remain encrypted in this store. This projection is main-process
  // only; IPC deliberately returns only public connection facts, never `config`.
  importedProfiles(): ImportedTunnelProfile[] {
    return this.list()
      .filter((sc) => sc.imported)
      .flatMap((sc) => {
        const id = importedProfileId(sc.origin);
        return id ? [{ id, name: sc.importedName || (id === "legacy" ? "Imported profile" : "Unnamed profile"), config: sc.config }] : [];
      })
      .sort((a, b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id));
  }

  importedProfile(id: string): ImportedTunnelProfile | null {
    const sc = this.get(importedProfileOrigin(id));
    return sc?.imported
      ? { id, name: sc.importedName || (id === "legacy" ? "Imported profile" : "Unnamed profile"), config: sc.config }
      : null;
  }
}
