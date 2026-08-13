// The authenticated desktop session and the managed WireGuard device have different
// lifecycles. Signing out must never revoke a device: the next sign-in on the same
// installation re-validates and reuses its encrypted device configuration.
export interface SignOutActions {
  stopMonitors(): void;
  clearSynthesizedState(): void;
  downTunnel(): Promise<void>;
  emitDisconnected(): void;
  logoutSession(): Promise<void>;
}

export async function signOutPreservingDevice(actions: SignOutActions): Promise<void> {
  actions.stopMonitors();
  actions.clearSynthesizedState();
  await actions.downTunnel().catch(() => {});
  actions.emitDisconnected();
  await actions.logoutSession();
}
