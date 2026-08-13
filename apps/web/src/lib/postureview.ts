import type { Device, HealthCheck } from "./api";
import { badgeClass, type BadgeTone } from "./healthview";

// postureview — PURE projections for the S7.5.3 device-posture surfaces
// (config section + devices-list badge). No fetches, no JSX: unit-tested like
// healthview/policyview.

// ── the verbatim honesty line (docs + config UI, D6 — locked) ────────────────────────
// This exact copy ships wherever an admin configures posture checks. Client-reported
// posture is NOT attestation; selling it as attestation is the dishonest failure mode
// the paper forbids.
export const POSTURE_HONESTY_LINE =
  "Posture checks deter honest non-compliance and give you an audit trail. They are " +
  "client-reported, not hardware-attested — a compromised device can misreport. " +
  "Treat posture as defense-in-depth, not a guarantee.";

// The client platforms that actually REPORT posture (the desktop apps). The coverage
// indicator enumerates exactly these — a min set for only one of them leaves the other
// unconstrained, and that gap must be VISIBLE (fail-open by design is fine; fail-open
// invisibly is the reassuring-green class).
export const REPORTING_PLATFORMS = ["macos", "windows"] as const;
export type ReportingPlatform = (typeof REPORTING_PLATFORMS)[number];

export const PLATFORM_LABELS: Record<ReportingPlatform, string> = {
  macos: "macOS",
  windows: "Windows",
};

// ── device badge (devices list + approval queue) ─────────────────────────────────────
// The three-way surface, sharpened per the slice-3 rider:
//   blocked      → danger  (excluded from every gateway right now)
//   noncompliant → warn    (warn-mode failure: surfaced, access continues)
//   unknown      → unknown ("not reported" — an admin must NOT read this as a pass)
//   compliant    → subtle ok
// Returns null when the API sent no health fields (org has no checks configured /
// open edition) — no posture noise on a feature the org doesn't use.
export interface PostureBadge {
  label: string;
  tone: BadgeTone;
}

/** The facts a report carries. Their PRESENCE is what separates a stale report from an incomplete one. */
type PostureFacts = Pick<
  Device,
  "health_reported_at" | "health_os_version" | "health_disk_encrypted"
>;

/**
 * Which of the **TWO** reachable `unknown` causes this is.
 *
 * ⛔ THIS WAS BRIEFLY THREE, AND THE THIRD WAS UNREACHABLE. The spec says
 * `unknown = no report, stale report, or the fact was reported absent`, and that third disjunct cannot occur.
 * MEASURED, on the live schema and in the evaluator:
 *
 *   device_health.evaluated_state   NOT NULL, CHECK (evaluated_state IN ('compliant','noncompliant'))
 *   healthInfoFor                   falls to `unknown` ONLY when evaluatedState is nil, reportedAt is nil,
 *                                   or the report is past HealthStaleTTL
 *   the evaluator                   `if f.DiskEncrypted == nil { continue }` — "absence never blocks"
 *
 * So a device that reports and CANNOT determine the disk fact is evaluated **compliant** (the check is skipped)
 * and stored as `compliant`. It never becomes `unknown`. With a row present, `evaluatedState` is never nil, so
 * `unknown` means exactly: NO ROW, or a STALE row.
 *
 * ⛔ THE SPEC IS A WRONG SOURCE OF TRUTH HERE — same class as the `listSiteSubnets` summary and the
 * `policy_degraded_kind` paragraph, and it cost a full build-and-revert. Registered as a spec defect; the
 * correction belongs in `openapi.yaml`, in place.
 *
 * HOW IT WAS CAUGHT: a reachability check on the RENDERED PAGE returned 0 matches for the new label. The unit
 * tests passed, the payload looked right, and five reds were green against a state production cannot produce.
 *
 *   A TEST CAN PIN A LABEL THAT PRODUCTION CAN NEVER PRODUCE. ONLY THE SCREEN SAYS OTHERWISE.
 */
export function unknownPostureLabel(d: PostureFacts): string {
  return d.health_reported_at ? "posture stale" : "posture not reported";
}

export function postureBadge(
  d: Pick<
    Device,
    | "health_state"
    | "health_blocked"
    | "health_reported_at"
    | "health_os_version"
    | "health_disk_encrypted"
  >,
): PostureBadge | null {
  if (d.health_state === undefined) return null; // surface inactive — no badge, no noise
  if (d.health_blocked) {
    // The enforcement fact wins the label even when the report has gone stale
    // (state unknown): the device IS excluded until the sweep clears it.
    return { label: "posture blocked", tone: "danger" };
  }
  switch (d.health_state) {
    case "noncompliant":
      return { label: "posture warning", tone: "warn" };
    case "compliant":
      return { label: "posture ok", tone: "ok" };
    default:
      // ⛔ THREE CAUSES, THREE LABELS. This arm used to emit TWO on a presence check of
      // `health_reported_at`, and the comment above it named all three — a reassuring comment
      // sitting on top of the defect it described.
      //
      // THE MISLABEL IT FIXES, and it is the reassuring-INVERSE: a device that reported 30
      // seconds ago but could not determine disk encryption (the tri-state `health_disk_encrypted`
      // case) has a present, fresh `health_reported_at`, so it rendered "posture stale". It is not
      // stale. It is CURRENT AND INCOMPLETE, and the old label told an operator the device was
      // silent while it was talking.
      //
      // THE DERIVATION, and it uses TWO SERVER-EMITTED FIELDS AND NO CLIENT CLOCK — the same
      // standard the two-label version was correctly defended on:
      //
      //   `healthInfoFor` sets state to the evaluated value ONLY when the report exists AND is
      //   within HealthStaleTTL. So `unknown` WITH facts present can only mean the server judged
      //   the report past that TTL — a fresh report carrying facts would have evaluated to
      //   compliant or noncompliant and never reached this arm.
      //
      //   reported_at absent            -> never reported
      //   present, facts present        -> STALE (the server judged it past the TTL)
      //   present, facts absent         -> reported, and the fact was not
      //
      // ⚠ REGISTERED, NOT SOLVED: this RECONSTRUCTS a decision the server already made.
      // `HealthStaleTTL` is server-side and neither it nor a staleness flag is served, so one-truth
      // says the server should SAY it. A `health_stale` discriminator is the clean fix
      // (docs/DEFERRAL-REGISTER.md).
      return {
        label: unknownPostureLabel(d),
        tone: "unknown",
      };
  }
}

// postureBadgeClass extends healthview's tone vocabulary with the compliant-ok tone
// (subtle, not celebratory — compliance is the expected steady state). warn/danger/
// unknown DELEGATE to healthview.badgeClass so a palette restyle can't drift the
// posture and gateway-health badges out of sync; only "ok" is new here.
export function postureBadgeClass(tone: PostureBadge["tone"]): string {
  return tone === "ok" ? "text-emerald-400" : badgeClass(tone);
}

// ── per-fact tri-state rendering (admin detail) ──────────────────────────────────────
// A fact the client reported ABSENT renders "not reported" — never a dash that reads
// as n/a-fine, never a guessed value.
export function diskFactLabel(diskEncrypted: boolean | undefined): string {
  if (diskEncrypted === undefined) return "not reported";
  return diskEncrypted ? "encrypted" : "not encrypted";
}

/** Admin-visible explanation of the latest posture evaluation. */
export function postureFailureSummary(
  checks: Array<{ kind: string; mode: string }> | undefined,
): string | null {
  if (!checks?.length) return null;
  const labels = [...new Set(checks.map((c) => {
    switch (c.kind) {
      case "disk_encryption":
        return "disk encryption not enabled or not verified";
      case "os_version":
        return "operating system below the configured minimum";
      default:
        return `failed check: ${c.kind}`;
    }
  }))];
  return labels.join("; ");
}

// ── config rows + the coverage indicator ─────────────────────────────────────────────
export interface OsVersionMins {
  macos: string;
  windows: string;
}

// osVersionMins extracts the per-platform min map from a HealthCheck's param
// ("" = not set = that platform is NOT constrained).
export function osVersionMins(
  check: Pick<HealthCheck, "param"> | undefined,
): OsVersionMins {
  const min =
    (check?.param as { min?: Record<string, string> } | undefined | null)
      ?.min ?? {};
  return { macos: min.macos ?? "", windows: min.windows ?? "" };
}

// osVersionCoverage is THE coverage indicator (the ratified rider): one line per
// reporting platform, constrained platforms with their floor, unconstrained ones
// NAMED as unconstrained — never silently omitted.
export interface CoverageLine {
  platform: ReportingPlatform;
  label: string; // e.g. "macOS: 14.0 or newer required" / "Windows: not constrained by this check"
  covered: boolean;
}

export function osVersionCoverage(mins: OsVersionMins): CoverageLine[] {
  return REPORTING_PLATFORMS.map((p) => {
    const min = mins[p].trim();
    if (!min) {
      return {
        platform: p,
        label: `${PLATFORM_LABELS[p]}: not constrained by this check`,
        covered: false,
      };
    }
    return {
      platform: p,
      label: `${PLATFORM_LABELS[p]}: ${min} or newer required`,
      covered: true,
    };
  });
}

// buildOsVersionParam builds the PUT param from the two inputs; empty inputs are
// OMITTED (platform-absent = not enforced). Returns null when NO platform is set —
// the caller must refuse the save (an os_version check constraining nothing is a
// config lie, and the server rejects an empty min anyway).
export function buildOsVersionParam(
  mins: OsVersionMins,
): { min: Record<string, string> } | null {
  const min: Record<string, string> = {};
  if (mins.macos.trim()) min.macos = mins.macos.trim();
  if (mins.windows.trim()) min.windows = mins.windows.trim();
  return Object.keys(min).length > 0 ? { min } : null;
}

// ── save-result copy (the would_fail blast radius) ───────────────────────────────────
// After a PUT, the server returns the best-effort count of devices whose LAST report
// would fail the check. require-mode failing devices get BLOCKED at their next report
// (~one report cycle); warn-mode ones surface a warning. The config write itself
// blocks nothing (D4 grandfather) — the copy says when the effect lands, honestly.
export function wouldFailCopy(
  mode: "warn" | "require",
  wouldFail: number | undefined,
): string | null {
  if (wouldFail === undefined || wouldFail === 0) return null;
  const n = `${wouldFail} device${wouldFail === 1 ? "" : "s"}`;
  if (mode === "require") {
    return `${n} last reported non-compliant for this check — they will be BLOCKED at their next report (within ~10 minutes). Devices that never report stay unaffected (unknown, not blocked).`;
  }
  return `${n} last reported non-compliant for this check — they will show a warning; access continues.`;
}

// ── section state helpers ────────────────────────────────────────────────────────────
export type CheckMode = "off" | "warn" | "require";

// checkModeOf maps the config list (no row = off) to the 3-state control.
export function checkModeOf(
  checks: HealthCheck[] | null,
  kind: HealthCheck["kind"],
): CheckMode {
  const row = checks?.find((c) => c.kind === kind);
  return row ? row.mode : "off";
}

// ── S14.10 ITEM 2 — THE ADDRESS CELL ────────────────────────────────────────────────────────────────────
//
// ⛔ THE EM-DASH SWEEP DELETED A PLACEHOLDER INSTEAD OF REPLACING IT. `d.assigned_ip ?? "—"` became
// `?? ""`, so a device with no address rendered a BLANK CELL — and "this device has no address" became
// pixel-identical to "this cell failed to render". That is the reassuring-empty class the `loadOne` law
// exists for, applied one level down at cell scale.
//
// The em-dash obligation is about PUNCTUATION IN PROSE COPY. A placeholder glyph standing in for a null is
// not prose, and removing it removed information.
//
// ⛔ AND `assigned_ip` IS ABSENT ON MORE THAN REVOKED DEVICES — it is not in Device's `required` list, so
// the placeholder has to read correctly for EVERY absent case, not just the one in the fixture:
//
//   revoked   -> the pool IP was released on revoke (a full sweep)
//   rejected  -> `RejectDevice` sets assigned_ip = NULL, freeing the held IP
//   pending   -> holds one in the normal path, but the field is optional, so absence is representable
//   any       -> a device the pool never assigned
//
// So the text says WHAT IS TRUE OF ALL OF THEM — no address is assigned — and never guesses the cause.
// "released" would be wrong for a device that never had one; "revoked" would be wrong for three of four.
export const NO_ADDRESS = "none assigned";

/** The address cell's text. A string, never an empty one — absence is stated, not left as blank pixels. */
export function addressLabel(assignedIp: string | undefined | null): string {
  return assignedIp && assignedIp.length > 0 ? assignedIp : NO_ADDRESS;
}

// ── S14.10 ITEM 4 — THREE COLUMNS, EACH FROM A SERVED FIELD ─────────────────────────────────────────────

/**
 * PROTOCOL. An OpenVPN device is minted with NO WireGuard key ("Creates an OpenVPN-transport device (no
 * WireGuard key)"), so an empty `public_key` IS the discriminator.
 *
 * ⛔ THERE IS NO `protocol` FIELD ON `Device` — measured. This is a derivation from a REQUIRED field, which is
 * why it is safe: `public_key` cannot go absent without the schema changing.
 */
export function deviceProtocol(
  publicKey: string | undefined,
): "WireGuard" | "OpenVPN" {
  return publicKey && publicKey.length > 0 ? "WireGuard" : "OpenVPN";
}

/**
 * POSTURE N/A — the platforms that CANNOT report posture, as opposed to devices that simply have not.
 *
 * ⛔ THE DISTINCTION IS THE WHOLE POINT: "not reported" is a device that could report and did not; "N/A" is a
 * platform with no reporting client at all. Rendering an iPad as "posture not reported" invites an admin to
 * chase a report that will never exist.
 *
 * ⚠ AND `darwin` IS macOS. The API serves both spellings — the seeded fixture has `darwin` AND `macos` — while
 * `REPORTING_PLATFORMS` lists only `macos`. Treating `darwin` as non-reporting would mark real macOS desktops
 * N/A, and `blocked-device` (platform `darwin`) is exactly such a device: it DOES report. Both spellings map.
 */
const REPORTING_ALIASES: Record<string, true> = {
  macos: true,
  darwin: true, // the API serves BOTH spellings; `blocked-device` is `darwin` and reports
  windows: true,
};

// ⛔ KNOWN NON-REPORTING, LISTED EXPLICITLY — three-way, not two. My first version was two-way with
// "unknown ⇒ can report", which made `ios`/`android`/`linux` report as capable and would have rendered
// "posture not reported" on an iPad: an invitation to chase a report that will never exist.
//
// The distinction between "we know this platform has no client" and "we have never seen this platform" is
// real, and they need OPPOSITE defaults.
const NON_REPORTING: Record<string, true> = {
  ios: true,
  android: true,
  linux: true, // the CLI and the node agent run here; no posture-reporting desktop client does
};

export function posturePlatformSupported(
  platform: string | undefined,
): boolean {
  if (!platform) return true;
  const p = platform.toLowerCase();
  if (REPORTING_ALIASES[p]) return true;
  if (NON_REPORTING[p]) return false;
  // ⛔ AN UNRECOGNISED PLATFORM IS ASSUMED TO REPORT. Marking it N/A would excuse a real gap behind a shrug —
  // fail towards SHOWING the absence, not towards explaining it away.
  return true;
}

// ── S14.10 ITEM 5 — THE FILTER CHIPS ────────────────────────────────────────────────────────────────────
//
// ⛔ CLIENT-SIDE, OVER ROWS ALREADY LOADED. No new endpoint and no round-trip: `listDevices` returns the whole
// set, so a server filter would be a request to re-fetch data the browser is holding. The Gateways precedent.
//
// ⛔ AND THE COUNTS COME FROM THE SAME FUNCTION THE TABLE FILTERS WITH, so a chip and its table can never
// disagree. Two separate derivations of "how many need attention" is how a badge starts lying.

export type DeviceFilter = "all" | "attention" | "revoked";

/**
 * NEEDS ATTENTION — the union of every state an operator must act on:
 *   · posture-blocked (excluded from every gateway right now)
 *   · noncompliant (a warn-mode failure that access survives, but someone should look)
 *   · pending approval
 *   · needs_reexport (a static profile whose baked routes are stale)
 *
 * ⛔ REVOKED IS NOT ATTENTION. A revoked device is DONE — surfacing it as actionable is an instruction to act
 * on a device that cannot come back, which is the same defect as showing it a re-export badge.
 */
export function needsAttention(
  d: Pick<
    Device,
    "status" | "health_blocked" | "health_state" | "needs_reexport"
  >,
): boolean {
  if (d.status === "revoked") return false;
  return (
    d.status === "pending" ||
    d.health_blocked === true ||
    d.health_state === "noncompliant" ||
    d.needs_reexport === true
  );
}

export function applyDeviceFilter<
  T extends Pick<
    Device,
    "status" | "health_blocked" | "health_state" | "needs_reexport"
  >,
>(devices: T[], f: DeviceFilter): T[] {
  if (f === "attention") return devices.filter(needsAttention);
  if (f === "revoked") return devices.filter((d) => d.status === "revoked");
  return devices;
}

/**
 * The chip counts. `all` INCLUDES revoked while the other two do not, so
 * `attention + revoked < all` — arithmetic that reads as a bug unless the screen says why.
 */
export function deviceFilterCounts<
  T extends Pick<
    Device,
    "status" | "health_blocked" | "health_state" | "needs_reexport"
  >,
>(devices: T[]): { all: number; attention: number; revoked: number } {
  return {
    all: devices.length,
    attention: applyDeviceFilter(devices, "attention").length,
    revoked: applyDeviceFilter(devices, "revoked").length,
  };
}
