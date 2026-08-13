// Build-time feature flags, in a dependency-free module so they can be asserted
// in unit tests without importing the Electron-coupled updater.
//
// AUTOUPDATE_ENABLED gates the auto-updater. It stays FALSE until S6.5 signing:
// macOS auto-update (Squirrel.Mac) cannot function unsigned, and shipping an
// unsigned auto-updater is a security anti-pattern. A test pins this false.
export const AUTOUPDATE_ENABLED = false;
