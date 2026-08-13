// Credential store — the tnx_ bearer lives ONLY here (encrypted at rest via the
// OS keychain) and in the webRequest injector; it never crosses into the
// renderer. The safeStorage + persistence dependencies are injected so the whole
// store is unit-testable without Electron.

export interface SafeStorageLike {
  isEncryptionAvailable(): boolean;
  encryptString(plain: string): Buffer;
  decryptString(enc: Buffer): string;
}

export interface Persistence {
  read(): Buffer | null;
  write(b: Buffer): void;
  clear(): void;
}

export interface StoredCredential {
  server: string;
  token: string;
  fingerprint: string;
  expiresAt: string; // ISO
}

// InsecureStorageError is thrown when the OS has no keychain (common on a
// headless Linux with no keyring) and the operator has NOT opted in. We REFUSE
// rather than silently write a plaintext token — a plaintext tnx_ on disk is
// strictly worse than making the choice deliberate. The desktop offers an
// explicit --allow-insecure-credential-storage opt-out, or in-memory
// device-code sessions.
export class InsecureStorageError extends Error {
  constructor() {
    super("no OS keychain available — refusing to store the credential in plaintext");
    this.name = "InsecureStorageError";
  }
}

export class CredentialStore {
  constructor(
    private safe: SafeStorageLike,
    private persist: Persistence,
    private allowInsecure: boolean,
  ) {}

  // available reports whether persistence is permitted right now.
  available(): boolean {
    return this.safe.isEncryptionAvailable() || this.allowInsecure;
  }

  // save encrypts + persists. Refuses (InsecureStorageError) when there is no
  // keychain and no explicit opt-out.
  save(cred: StoredCredential): void {
    const json = JSON.stringify(cred);
    if (this.safe.isEncryptionAvailable()) {
      this.persist.write(this.safe.encryptString(json));
      return;
    }
    if (!this.allowInsecure) {
      throw new InsecureStorageError();
    }
    // Opt-in plaintext (flagged, visible). Marked so load knows not to decrypt.
    this.persist.write(Buffer.from("PLAINTEXT:" + json, "utf8"));
  }

  load(): StoredCredential | null {
    const raw = this.persist.read();
    if (!raw) return null;
    // Both branches degrade to null on a corrupt/truncated file (never throw) —
    // a damaged credential must read as "logged out", not crash startup.
    if (raw.length >= 10 && raw.subarray(0, 10).toString("utf8") === "PLAINTEXT:") {
      try {
        return JSON.parse(raw.subarray(10).toString("utf8")) as StoredCredential;
      } catch {
        return null;
      }
    }
    if (!this.safe.isEncryptionAvailable()) return null; // can't decrypt now
    try {
      return JSON.parse(this.safe.decryptString(raw)) as StoredCredential;
    } catch {
      return null;
    }
  }

  clear(): void {
    this.persist.clear();
  }

  // isExpired checks the LOCAL expiry (the server gives no expiry oracle — S5.1).
  static isExpired(cred: StoredCredential, now: Date): boolean {
    const exp = new Date(cred.expiresAt);
    return !Number.isNaN(exp.getTime()) && exp.getTime() <= now.getTime();
  }
}
