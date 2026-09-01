// The authenticated desktop session and the managed WireGuard device have different
// lifecycles. Signing out must never revoke a device: the next sign-in on the same
// installation re-validates and reuses its encrypted device configuration.
export interface SignOutActions {
  retireLifecycle(): void;
  stopMonitors(): void;
  clearSynthesizedState(): void;
  downTunnel(): Promise<void>;
  emitDisconnected(): void;
  logoutSession(): Promise<void>;
}

export async function signOutPreservingDevice(actions: SignOutActions): Promise<void> {
  // Keep the current session and its monitors authoritative until helper
  // ownership is safely quiesced. A teardown refusal aborts sign-out without
  // stranding an active tunnel under a stale lifecycle lease.
  await actions.downTunnel();
  actions.retireLifecycle();
  actions.stopMonitors();
  actions.clearSynthesizedState();
  actions.emitDisconnected();
  await actions.logoutSession();
}
