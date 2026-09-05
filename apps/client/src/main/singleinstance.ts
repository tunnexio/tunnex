export interface SingleInstanceApp {
  requestSingleInstanceLock(): boolean;
  quit(): void;
  on(event: "second-instance", listener: () => void): unknown;
}

// The callback boundary is intentional: a losing process cannot even schedule
// whenReady, so it cannot construct stores, register IPC, touch the helper/API,
// or create a window before quit.
export function startSingleInstance(
  app: SingleInstanceApp,
  initializePrimary: () => void,
  focusPrimary: () => void,
): boolean {
  if (!app.requestSingleInstanceLock()) {
    app.quit();
    return false;
  }
  app.on("second-instance", focusPrimary);
  initializePrimary();
  return true;
}
