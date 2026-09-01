export interface CredentialSnapshot {
  readonly server: string;
  readonly token: string;
  readonly fingerprint: string;
  readonly expiresAt: string;
}

export interface ManagedLease {
  readonly epoch: number;
  readonly credential: Readonly<CredentialSnapshot>;
  readonly userId: string;
}

type MaybePromise<T> = T | Promise<T>;

// Epoch mutations are available only while one serial() callback owns the FIFO
// turn. The runtime expiry check keeps an escaped capability from becoming a
// back door around the lifecycle mutex after that callback returns.
export interface ManagedLifecycleOperation {
  advance(lease: ManagedLease): ManagedLease;
  invalidate(): number;
}

export interface LoginReplacementEffects<T> {
  resolveServer(): string;
  sessionIsValid(credential: Readonly<CredentialSnapshot>): Promise<boolean>;
  stopMonitors(): MaybePromise<void>;
  downTunnel(): Promise<void>;
  publishDown(): MaybePromise<void>;
  saveCredential(server: string): MaybePromise<T>;
}

export class StaleManagedLeaseError extends Error {
  constructor() {
    super("managed lifecycle lease is stale");
    this.name = "StaleManagedLeaseError";
  }
}

function snapshotCredential(credential: CredentialSnapshot): Readonly<CredentialSnapshot> {
  return Object.freeze({
    server: credential.server,
    token: credential.token,
    fingerprint: credential.fingerprint,
    expiresAt: credential.expiresAt,
  });
}

function credentialsEqual(
  left: Readonly<CredentialSnapshot>,
  right: Readonly<CredentialSnapshot>,
): boolean {
  return left.server === right.server
    && left.token === right.token
    && left.fingerprint === right.fingerprint
    && left.expiresAt === right.expiresAt;
}

// One instance lives for the lifetime of the main process. serial() is the only
// lifecycle mutation lane; monitor effects enter it through guarded().
export class ManagedLifecycleCoordinator {
  private tail: Promise<void> = Promise.resolve();
  private epoch = 0;

  constructor(private readonly readCredential: () => CredentialSnapshot | null) {}

  serial<T>(operation: (owner: ManagedLifecycleOperation) => MaybePromise<T>): Promise<T> {
    const previous = this.tail;
    let release!: () => void;
    this.tail = new Promise<void>((resolve) => {
      release = resolve;
    });

    return (async () => {
      await previous;
      let active = true;
      const requireActive = (): void => {
        if (!active) throw new Error("managed lifecycle operation is no longer active");
      };
      const owner = Object.freeze({
        advance: (lease: ManagedLease): ManagedLease => {
          requireActive();
          return this.advanceLocked(lease);
        },
        invalidate: (): number => {
          requireActive();
          return this.nextEpoch();
        },
      });
      try {
        return await operation(owner);
      } finally {
        active = false;
        release();
      }
    })();
  }

  // The resolver must use only the supplied fixed snapshot. A second exact
  // store read closes the A-to-B replacement window while identity is in flight.
  async capture(
    resolveUser: (credential: Readonly<CredentialSnapshot>) => Promise<string>,
  ): Promise<ManagedLease> {
    const epoch = this.epoch;
    const stored = this.readCredential();
    if (!stored) throw new Error("managed credential is missing");

    const credential = snapshotCredential(stored);
    const userId = await resolveUser(credential);
    if (!userId) throw new Error("authenticated user id is missing");

    this.assertSnapshotCurrent(epoch, credential);
    return Object.freeze({ epoch, credential, userId });
  }

  // A proven operation advances ownership before handing its lease to monitors.
  // Advancing invalidates the pre-proof lease without changing its credential.
  private advanceLocked(lease: ManagedLease): ManagedLease {
    this.assertCurrent(lease);
    const epoch = this.nextEpoch();
    return Object.freeze({
      epoch,
      credential: lease.credential,
      userId: lease.userId,
    });
  }

  assertCurrent(lease: ManagedLease): void {
    this.assertSnapshotCurrent(lease.epoch, lease.credential);
  }

  // Stale monitor work is deliberately a no-op, not an exception that could
  // create an unhandled callback rejection. Current effects remain serialized.
  guarded<T>(lease: ManagedLease, effect: () => MaybePromise<T>): Promise<T | undefined> {
    return this.serial(async () => {
      if (!this.isSnapshotCurrent(lease.epoch, lease.credential)) return undefined;
      return await effect();
    });
  }

  // A terminal callback (revocation, helper owner loss) must fence every
  // already-queued callback for the same lease before it mutates helper, store,
  // renderer, tray, or notification state. The check and epoch advance share
  // the FIFO turn, so a stale terminal callback is a zero-effect no-op and a
  // current one makes every later callback stale before its first effect.
  terminal<T>(lease: ManagedLease, effect: () => MaybePromise<T>): Promise<T | undefined> {
    return this.serial(async (owner) => {
      if (!this.isSnapshotCurrent(lease.epoch, lease.credential)) return undefined;
      owner.invalidate();
      return await effect();
    });
  }

  // runLogin persists internally, so replacement must fence the old lifecycle
  // before invoking it. A credential proven still valid is never overwritten.
  replaceLogin<T>(effects: LoginReplacementEffects<T>): Promise<T> {
    return this.serial(async (owner) => {
      // Resolve inside this FIFO turn. A server change queued ahead of login
      // must commit before login pins the origin used by the entire PKCE flow.
      const server = effects.resolveServer();
      const stored = this.readCredential();
      if (stored) {
        const epoch = this.epoch;
        const credential = snapshotCredential(stored);
        const valid = await effects.sessionIsValid(credential);
        this.assertSnapshotCurrent(epoch, credential);
        if (valid) throw new Error("managed session is already active");
      }

      await effects.downTunnel();
      // Login may be cancelled or fail after the old helper is already down.
      // Publish that confirmed network truth before invalidating the old lease
      // or starting the fallible PKCE/save flow.
      await effects.publishDown();
      owner.invalidate();
      await effects.stopMonitors();
      return await effects.saveCredential(server);
    });
  }

  private nextEpoch(): number {
    if (this.epoch === Number.MAX_SAFE_INTEGER) {
      throw new Error("managed lifecycle epoch exhausted");
    }
    this.epoch += 1;
    return this.epoch;
  }

  private assertSnapshotCurrent(
    epoch: number,
    credential: Readonly<CredentialSnapshot>,
  ): void {
    if (!this.isSnapshotCurrent(epoch, credential)) throw new StaleManagedLeaseError();
  }

  private isSnapshotCurrent(
    epoch: number,
    credential: Readonly<CredentialSnapshot>,
  ): boolean {
    if (epoch !== this.epoch) return false;
    const stored = this.readCredential();
    return stored !== null && credentialsEqual(stored, credential);
  }
}
