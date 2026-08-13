/**
 * Manual desktop-release discovery.
 *
 * This is deliberately separate from electron-updater: the result may tell a user that a
 * newer build exists and offer the official download page, but it never downloads or installs
 * code. That remains unavailable until macOS signing/notarization and Windows signing exist.
 */
export const DESKTOP_RELEASE_ENDPOINT = "https://tunnex.io/api/desktop-release";
export const DESKTOP_DOWNLOAD_PAGE = "https://tunnex.io/download";

export type ReleaseCheck =
  | { kind: "available"; version: string }
  | { kind: "current"; version: string }
  | { kind: "unavailable"; reason: string };

type ParsedVersion = {
  major: number;
  minor: number;
  patch: number;
  prerelease: string[];
};

function parseVersion(raw: string): ParsedVersion | null {
  const match = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$/.exec(raw);
  if (!match) return null;
  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3]),
    prerelease: match[4]?.split(".") ?? [],
  };
}

function compareIdentifier(a: string, b: string): number {
  const aNumeric = /^\d+$/.test(a);
  const bNumeric = /^\d+$/.test(b);
  if (aNumeric && bNumeric) return Number(a) - Number(b);
  if (aNumeric) return -1;
  if (bNumeric) return 1;
  return a.localeCompare(b);
}

/** Compare SemVer release precedence; positive means `a` is newer than `b`. */
export function compareVersions(a: string, b: string): number | null {
  const left = parseVersion(a);
  const right = parseVersion(b);
  if (!left || !right) return null;
  for (const key of ["major", "minor", "patch"] as const) {
    if (left[key] !== right[key]) return left[key] - right[key];
  }
  if (!left.prerelease.length && !right.prerelease.length) return 0;
  if (!left.prerelease.length) return 1;
  if (!right.prerelease.length) return -1;
  const count = Math.max(left.prerelease.length, right.prerelease.length);
  for (let index = 0; index < count; index += 1) {
    const aPart = left.prerelease[index];
    const bPart = right.prerelease[index];
    if (aPart === undefined) return -1;
    if (bPart === undefined) return 1;
    const comparison = compareIdentifier(aPart, bPart);
    if (comparison !== 0) return comparison;
  }
  return 0;
}

/**
 * Convert the public website's deliberately tiny release response into an honest UI state.
 * Unknown/malformed version data is unavailable; we never guess a release or present a download.
 */
export function releaseCheckFor(currentVersion: string, payload: unknown): ReleaseCheck {
  if (typeof payload !== "object" || payload === null || !("version" in payload) || typeof payload.version !== "string") {
    return { kind: "unavailable", reason: "Tunnex could not verify the latest desktop release." };
  }
  const comparison = compareVersions(payload.version, currentVersion);
  if (comparison === null) {
    return { kind: "unavailable", reason: "Tunnex received an invalid desktop release version." };
  }
  return comparison > 0
    ? { kind: "available", version: payload.version }
    : { kind: "current", version: currentVersion };
}
