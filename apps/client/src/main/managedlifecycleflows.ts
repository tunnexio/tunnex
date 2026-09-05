import type {
  ManagedLease,
  ManagedLifecycleOperation,
} from "./managedlifecycle";

type MaybePromise<T> = T | Promise<T>;

export type ManagedConfigProvider<TConfig> = () => Promise<TConfig>;

export interface ManagedConnectPreparation<TContext, TConfig> {
  readonly lease: ManagedLease;
  readonly organizationId: string;
  readonly fullTunnel: boolean;
  readonly configProvider: ManagedConfigProvider<TConfig>;
  readonly context: TContext;
}

export interface FixedManagedConnectContext<TApi> {
  readonly origin: string;
  readonly api: TApi;
}

export interface ManagedConnectProviderArguments<TApi> {
  readonly lease: ManagedLease;
  readonly credential: ManagedLease["credential"];
  readonly userId: string;
  readonly organizationId: string;
  readonly fullTunnel: boolean;
  readonly origin: string;
  readonly api: TApi;
}

export interface ManagedConnectPreparationInput<TApi, TConfig> {
  readonly lease: ManagedLease;
  readonly organizationId: string;
  readonly fullTunnel: boolean;
  readonly origin: string;
  readonly api: TApi;
  readonly resolveConfig: (arguments_: ManagedConnectProviderArguments<TApi>) => Promise<TConfig>;
}

// Build the production connect tuple once, at proof time. Every request-varying
// identity value is copied into a frozen object before the provider exists, so
// later mutation/reassignment of IPC caller variables cannot mix user, token,
// organization, mode, origin, or API context inside helper configuration.
export function buildManagedConnectPreparation<TApi, TConfig>(
  input: ManagedConnectPreparationInput<TApi, TConfig>,
): ManagedConnectPreparation<FixedManagedConnectContext<TApi>, TConfig> {
  const credential = Object.freeze({
    server: input.lease.credential.server,
    token: input.lease.credential.token,
    fingerprint: input.lease.credential.fingerprint,
    expiresAt: input.lease.credential.expiresAt,
  });
  if (input.origin !== credential.server) {
    throw new Error("managed connect origin does not match credential");
  }

  const lease: ManagedLease = Object.freeze({
    epoch: input.lease.epoch,
    credential,
    userId: input.lease.userId,
  });
  const context: FixedManagedConnectContext<TApi> = Object.freeze({
    origin: input.origin,
    api: input.api,
  });
  const providerArguments: ManagedConnectProviderArguments<TApi> = Object.freeze({
    lease,
    credential,
    userId: lease.userId,
    organizationId: input.organizationId,
    fullTunnel: input.fullTunnel,
    origin: context.origin,
    api: context.api,
  });
  const resolveConfig = input.resolveConfig;

  return Object.freeze({
    lease,
    organizationId: providerArguments.organizationId,
    fullTunnel: providerArguments.fullTunnel,
    context,
    configProvider: () => resolveConfig(providerArguments),
  });
}

export type ActiveManagedConnect<TContext, TConfig> = Omit<
  ManagedConnectPreparation<TContext, TConfig>,
  "lease"
> & { readonly lease: ManagedLease };

export interface ManagedConnectFlowEffects<TContext, TConfig, TStatus, TResult> {
  proveAndPrepare(): Promise<ManagedConnectPreparation<TContext, TConfig>>;
  quiesceExisting(connection: ManagedConnectPreparation<TContext, TConfig>): MaybePromise<void>;
  publishQuiesced(connection: ManagedConnectPreparation<TContext, TConfig>): MaybePromise<void>;
  prepareRuntime(connection: ActiveManagedConnect<TContext, TConfig>): MaybePromise<void>;
  installHelper(connection: ActiveManagedConnect<TContext, TConfig>): MaybePromise<void>;
  up(
    configProvider: ManagedConfigProvider<TConfig>,
    connection: ActiveManagedConnect<TContext, TConfig>,
  ): Promise<TStatus>;
  onUpError(
    error: unknown,
    connection: ActiveManagedConnect<TContext, TConfig>,
  ): MaybePromise<TResult>;
  publish(
    connection: ActiveManagedConnect<TContext, TConfig>,
    status: TStatus,
  ): MaybePromise<TResult>;
}

// Production-owned managed connect ordering. Identity, organization, owner,
// mode, API context, and the config provider are captured together before the
// lifecycle epoch advances; no later request-global state participates.
export async function runManagedConnectFlow<TContext, TConfig, TStatus, TResult>(
  owner: ManagedLifecycleOperation,
  effects: ManagedConnectFlowEffects<TContext, TConfig, TStatus, TResult>,
): Promise<TResult> {
  const prepared = await effects.proveAndPrepare();
  // Keep the prior lease and its monitors current until its helper ownership is
  // safely quiesced. If down refuses, the old session remains fully owned and
  // monitored; no lifecycle epoch has moved. Once down succeeds, advancing the
  // epoch makes queued old-session callbacks stale before new-session effects.
  await effects.quiesceExisting(prepared);
  // Quiescence is already true even if any later owner-binding, helper install,
  // config resolution, or tunnel-up step fails. Publish that truth before those
  // fallible effects so the renderer and tray cannot retain stale Connected.
  await effects.publishQuiesced(prepared);
  const connection: ActiveManagedConnect<TContext, TConfig> = Object.freeze({
    ...prepared,
    lease: owner.advance(prepared.lease),
  });

  let status: TStatus;
  try {
    await effects.prepareRuntime(connection);
    await effects.installHelper(connection);
    status = await effects.up(connection.configProvider, connection);
  } catch (error) {
    return await effects.onUpError(error, connection);
  }
  return await effects.publish(connection, status);
}

export interface ManagedRemovePreparation<TContext> {
  readonly lease: ManagedLease;
  readonly context: TContext;
}

export type ActiveManagedRemove<TContext> = Omit<
  ManagedRemovePreparation<TContext>,
  "lease"
> & { readonly lease: ManagedLease };

export interface ManagedRemoveFlowEffects<TContext, TResult> {
  proveOwner(): Promise<ManagedRemovePreparation<TContext> | null>;
  quiesceExisting(removal: ManagedRemovePreparation<TContext>): MaybePromise<void>;
  stopMonitors(removal: ActiveManagedRemove<TContext>): MaybePromise<void>;
  revokeAndClear(removal: ActiveManagedRemove<TContext>): MaybePromise<TResult>;
}

// Removal proves the fixed owner before invalidating the old lifecycle. Only a
// successful proof may stop monitors/the helper or reach revoke-and-clear.
export async function runManagedRemoveFlow<TContext, TResult>(
  owner: ManagedLifecycleOperation,
  effects: ManagedRemoveFlowEffects<TContext, TResult>,
): Promise<TResult | false> {
  const prepared = await effects.proveOwner();
  if (prepared === null) return false;
  // Direction A: helper teardown refusal aborts the destructive action while
  // the proven lease and its monitors are still current. Only a successful
  // quiesce may fence callbacks and proceed to revoke-and-clear.
  await effects.quiesceExisting(prepared);
  const removal: ActiveManagedRemove<TContext> = Object.freeze({
    ...prepared,
    lease: owner.advance(prepared.lease),
  });

  await effects.stopMonitors(removal);
  return await effects.revokeAndClear(removal);
}

export interface ManagedDisconnectFlowEffects {
  quiesceExisting(): Promise<void>;
  stopMonitors(): MaybePromise<void>;
  publishDown(): MaybePromise<void>;
  notifyDisconnected(): MaybePromise<void>;
}

// A user disconnect retains the current lifecycle, monitors, and visible state
// until helper teardown is confirmed. Once confirmed, every later effect is a
// publication of that already-established down state.
export async function runManagedDisconnectFlow(
  owner: ManagedLifecycleOperation,
  effects: ManagedDisconnectFlowEffects,
): Promise<void> {
  await effects.quiesceExisting();
  owner.invalidate();
  await effects.stopMonitors();
  await effects.publishDown();
  await effects.notifyDisconnected();
}

export type TerminalRevocationOutcome = "revoked" | "failed";

export interface TerminalRevocationProblems {
  readonly monitorStopError?: unknown;
  readonly cleanupError?: unknown;
  readonly forceCloseError?: unknown;
  readonly retentionError?: unknown;
  readonly publicationError?: unknown;
}

export interface TerminalRevocationResult {
  readonly outcome: TerminalRevocationOutcome;
  readonly problems: TerminalRevocationProblems;
}

export interface TerminalRevocationFlowEffects {
  stopMonitors(): MaybePromise<void>;
  downTunnel(): Promise<void>;
  forceFailClosed(): MaybePromise<void>;
  retainTerminalRecord(): MaybePromise<void>;
  publishRevoked(): MaybePromise<void>;
  publishFailed(): MaybePromise<void>;
  reportProblems(problems: TerminalRevocationProblems): MaybePromise<void>;
}

// The server's terminal verdict has already fenced the managed lease before
// this runs. A local teardown refusal must not be relabelled as a clean revoked
// disconnect: force the owner socket closed, surface the existing actionable
// failed state, then retain the encrypted terminal record for recovery.
export async function runTerminalRevocationFlow(
  effects: TerminalRevocationFlowEffects,
): Promise<TerminalRevocationResult> {
  const problems: {
    monitorStopError?: unknown;
    cleanupError?: unknown;
    forceCloseError?: unknown;
    retentionError?: unknown;
    publicationError?: unknown;
  } = {};

  try {
    await effects.stopMonitors();
  } catch (error) {
    problems.monitorStopError = error;
  }

  try {
    await effects.downTunnel();
  } catch (error) {
    problems.cleanupError = error;
    try {
      await effects.forceFailClosed();
    } catch (forceCloseError) {
      problems.forceCloseError = forceCloseError;
    }
  }

  // JavaScript permits throwing any value, including undefined. Presence of the
  // captured key—not its truthiness—is the teardown verdict.
  const cleanupFailed = Object.prototype.hasOwnProperty.call(problems, "cleanupError");
  const outcome: TerminalRevocationOutcome = cleanupFailed ? "failed" : "revoked";
  try {
    if (outcome === "failed") {
      await effects.publishFailed();
    } else {
      await effects.publishRevoked();
    }
  } catch (error) {
    problems.publicationError = error;
  }

  // Recovery persistence is important but fallible. It deliberately follows
  // transport publication so a slow/throwing encrypted store cannot hold the
  // renderer and tray on stale Connected/Posture truth.
  try {
    await effects.retainTerminalRecord();
  } catch (error) {
    problems.retentionError = error;
  }

  const problemSnapshot: TerminalRevocationProblems = Object.freeze({ ...problems });
  if (Object.keys(problemSnapshot).length > 0) {
    try {
      await effects.reportProblems(problemSnapshot);
    } catch {
      // Reporting is diagnostic only. It must never turn an already-published
      // terminal transport truth into a rejected monitor callback.
    }
  }

  return Object.freeze({
    outcome,
    problems: problemSnapshot,
  });
}
