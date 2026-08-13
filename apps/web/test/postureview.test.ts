import { describe, expect, it } from "vitest";
import {
  POSTURE_HONESTY_LINE,
  buildOsVersionParam,
  checkModeOf,
  diskFactLabel,
  osVersionCoverage,
  osVersionMins,
  postureBadge,
  postureFailureSummary,
  postureBadgeClass,
  wouldFailCopy,
  addressLabel,
  applyDeviceFilter,
  deviceFilterCounts,
  deviceProtocol,
  needsAttention,
  posturePlatformSupported,
  NO_ADDRESS,
  unknownPostureLabel,
} from "../src/lib/postureview";
import type { HealthCheck } from "../src/lib/api";

describe("postureBadge — the three-way legibility rider", () => {
  it("renders NOTHING when the surface is inactive (no health fields = org has no checks)", () => {
    expect(postureBadge({})).toBeNull();
  });

  it("unknown is FIRST-CLASS and distinct — never a pass", () => {
    const never = postureBadge({
      health_state: "unknown",
      health_blocked: false,
    });
    expect(never).toEqual({ label: "posture not reported", tone: "unknown" });
    // ⛔ THIS ASSERTION ENCODED THE DEFECT (corrected S14.10). It gave a device with a present
    // `health_reported_at` and NO FACTS AT ALL the label "posture stale" — the tri-state case, where the
    // device reported and simply could not determine the fact. It is current and incomplete, not silent.
    //
    // A test can pin a defect as firmly as it pins a behaviour, and this one did: it is why the mislabel
    // survived a green suite. FACTS ARE NOW PRESENT, which is what actually makes a report stale.
    // STALE is marked by the NULLABLE fact being present — os_version is NOT NULL and so cannot discriminate.
    const stale = postureBadge({
      health_state: "unknown",
      health_blocked: false,
      health_reported_at: "2026-07-16T00:00:00Z",
    });
    expect(stale).toEqual({ label: "posture stale", tone: "unknown" });

    // The load-bearing distinction: unknown must never share compliant's tone/label.
    const ok = postureBadge({
      health_state: "compliant",
      health_blocked: false,
    });
    expect(never!.tone).not.toBe(ok!.tone);
    expect(stale!.tone).not.toBe(ok!.tone);
  });

  it("blocked wins the label even when the report went stale (the device IS still excluded)", () => {
    expect(
      postureBadge({
        health_state: "unknown",
        health_blocked: true,
        health_reported_at: "2026-07-16T00:00:00Z",
      }),
    ).toEqual({
      label: "posture blocked",
      tone: "danger",
    });
  });

  it("warn-mode noncompliance is a warning, not a block", () => {
    expect(
      postureBadge({ health_state: "noncompliant", health_blocked: false }),
    ).toEqual({
      label: "posture warning",
      tone: "warn",
    });
  });

  it("tones map to distinct classes (incl. the ok tone)", () => {
    const tones = ["ok", "warn", "danger", "unknown"] as const;
    const classes = tones.map(postureBadgeClass);
    expect(new Set(classes).size).toBe(tones.length);
  });
});

describe("postureFailureSummary", () => {
  it("names the checks an administrator must remediate", () => {
    expect(postureFailureSummary([
      { kind: "disk_encryption", mode: "require" },
      { kind: "os_version", mode: "warn" },
    ])).toMatch(/disk encryption.*operating system/i);
  });
});

describe("diskFactLabel — per-fact tri-state", () => {
  it("an absent fact reads 'not reported', never a guessed value", () => {
    expect(diskFactLabel(undefined)).toBe("not reported");
    expect(diskFactLabel(true)).toBe("encrypted");
    expect(diskFactLabel(false)).toBe("not encrypted");
  });
});

describe("osVersionCoverage — the ratified coverage indicator", () => {
  it("names an unconstrained platform explicitly — never a silent gap", () => {
    const lines = osVersionCoverage({ macos: "14.0", windows: "" });
    expect(lines).toHaveLength(2); // every reporting platform enumerated
    expect(lines.find((l) => l.platform === "macos")).toEqual({
      platform: "macos",
      label: "macOS: 14.0 or newer required",
      covered: true,
    });
    expect(lines.find((l) => l.platform === "windows")).toEqual({
      platform: "windows",
      label: "Windows: not constrained by this check",
      covered: false,
    });
  });

  it("both platforms empty → both named unconstrained", () => {
    expect(
      osVersionCoverage({ macos: "", windows: "" }).every((l) => !l.covered),
    ).toBe(true);
  });
});

describe("buildOsVersionParam", () => {
  it("omits empty platforms (platform-absent = not enforced)", () => {
    expect(buildOsVersionParam({ macos: "14.0", windows: "" })).toEqual({
      min: { macos: "14.0" },
    });
    expect(buildOsVersionParam({ macos: " 14.0 ", windows: "10.0" })).toEqual({
      min: { macos: "14.0", windows: "10.0" },
    });
  });
  it("refuses an all-empty min (a check constraining nothing is a config lie)", () => {
    expect(buildOsVersionParam({ macos: "", windows: "  " })).toBeNull();
  });
});

describe("osVersionMins / checkModeOf — config round-trip", () => {
  const checks: HealthCheck[] = [
    {
      kind: "os_version",
      mode: "require",
      param: { min: { macos: "14.0" } } as never,
    },
    { kind: "disk_encryption", mode: "warn" },
  ];
  it("extracts per-platform mins ('' = unset)", () => {
    expect(osVersionMins(checks[0])).toEqual({ macos: "14.0", windows: "" });
    expect(osVersionMins(undefined)).toEqual({ macos: "", windows: "" });
  });
  it("no row = off (opt-in by absence)", () => {
    expect(checkModeOf(checks, "os_version")).toBe("require");
    expect(checkModeOf(checks, "disk_encryption")).toBe("warn");
    expect(checkModeOf([], "disk_encryption")).toBe("off");
    expect(checkModeOf(null, "os_version")).toBe("off");
  });
});

describe("wouldFailCopy — honest blast-radius copy", () => {
  it("require says WHEN blocking lands and that non-reporters stay unaffected", () => {
    const c = wouldFailCopy("require", 3)!;
    expect(c).toContain("3 devices");
    expect(c).toContain("BLOCKED at their next report");
    expect(c).toContain("never report stay unaffected");
  });
  it("warn says access continues", () => {
    expect(wouldFailCopy("warn", 1)).toContain("access continues");
  });
  it("zero / unknown count → no banner", () => {
    expect(wouldFailCopy("require", 0)).toBeNull();
    expect(wouldFailCopy("require", undefined)).toBeNull();
  });
});

describe("the verbatim honesty line (D6 — locked copy)", () => {
  it("carries the three load-bearing claims verbatim", () => {
    expect(POSTURE_HONESTY_LINE).toContain("deter honest non-compliance");
    expect(POSTURE_HONESTY_LINE).toContain(
      "client-reported, not hardware-attested",
    );
    expect(POSTURE_HONESTY_LINE).toContain("defense-in-depth, not a guarantee");
  });
});

// ── S14.10 ITEM 1 — THREE CAUSES, THREE LABELS ──────────────────────────────────────────────────────────
//
// The old arm emitted TWO labels on a presence check of `health_reported_at`, so the tri-state case — a
// device that reported seconds ago but could not determine a fact — rendered "posture stale". THE
// REASSURING-INVERSE: it told an operator the device was silent while it was talking.
describe("unknownPostureLabel — TWO reachable causes, and the third is unreachable BY SCHEMA", () => {
  const base = {
    health_reported_at: undefined,
    health_os_version: undefined,
    health_disk_encrypted: undefined,
  };

  it("⛔ CAUSE 1 — never reported", () => {
    expect(unknownPostureLabel(base)).toBe("posture not reported");
  });

  it("⛔ CAUSE 2 — reported: the server judged it past the TTL", () => {
    // With a row present, `evaluated_state` is NOT NULL and CHECK-constrained to compliant|noncompliant, so
    // `healthInfoFor` can only reach `unknown` via staleness. No client clock is used or needed.
    expect(
      unknownPostureLabel({
        ...base,
        health_reported_at: "2026-08-02T09:00:00Z",
      }),
    ).toBe("posture stale");
  });

  it("⛔ THE THIRD CAUSE THE SPEC CLAIMS IS UNREACHABLE — a fact-absent report is COMPLIANT, not unknown", () => {
    // The spec says unknown = "no report, stale report, or the fact was reported absent". Measured: the
    // evaluator does `if f.DiskEncrypted == nil { continue }` — "absence never blocks" — so the check is
    // SKIPPED and the device evaluates COMPLIANT. It never becomes unknown.
    //
    // This test exists so the next reader does not rebuild the third label from the spec's prose, as I did.
    // A device with a report and no disk answer still lands on the STALE arm, and that arm is correct because
    // the only way it reaches `unknown` at all is staleness.
    expect(
      unknownPostureLabel({
        ...base,
        health_reported_at: "2026-08-02T09:00:00Z",
        health_os_version: "6.8.0",
      }),
    ).toBe("posture stale");
  });

  it("the two causes produce TWO DISTINCT labels", () => {
    expect(
      new Set([
        unknownPostureLabel(base),
        unknownPostureLabel({ ...base, health_reported_at: "x" }),
      ]).size,
    ).toBe(2);
  });
});

// ── S14.10 ITEM 2 — THE ADDRESS PLACEHOLDER ─────────────────────────────────────────────────────────────
describe("addressLabel", () => {
  it("⛔ NEVER returns an empty string — blank pixels cannot say 'no address'", () => {
    // The regression this pins: `?? ""` made "has no address" and "the cell failed to render" identical.
    for (const absent of [undefined, null, ""])
      expect(addressLabel(absent).length).toBeGreaterThan(0);
  });

  it("returns the address verbatim when there is one", () => {
    // Both sides in one test: a function returning the placeholder unconditionally passes the assertion above.
    expect(addressLabel("10.99.0.7")).toBe("10.99.0.7");
    expect(addressLabel(undefined)).toBe(NO_ADDRESS);
  });

  it("names the STATE, not a CAUSE — it is absent on four different paths", () => {
    // revoked (swept) · rejected (RejectDevice NULLs it) · pending · never assigned. "released" would be
    // wrong for a device that never had one; "revoked" would be wrong for three of the four.
    expect(NO_ADDRESS).not.toMatch(/revoked|released|freed|expired/i);
  });
});

// ── S14.10 ITEMS 4 & 5 ──────────────────────────────────────────────────────────────────────────────────
describe("deviceProtocol", () => {
  it("⛔ derives OpenVPN from an ABSENT WireGuard key — there is no protocol field on Device", () => {
    // An OpenVPN device is minted with "no WireGuard key". `public_key` is REQUIRED, so it cannot go absent
    // without a schema change — which is what makes this derivation safe rather than a guess.
    expect(deviceProtocol("Zm9vYmFy")).toBe("WireGuard");
    expect(deviceProtocol("")).toBe("OpenVPN");
    expect(deviceProtocol(undefined)).toBe("OpenVPN");
  });
});

describe("posturePlatformSupported", () => {
  it("⛔ darwin AND macos both report — the API serves both spellings", () => {
    // REPORTING_PLATFORMS lists only `macos`, and the seeded `blocked-device` is `darwin` and DOES report.
    // Treating darwin as non-reporting would mark real macOS desktops "n/a" and hide a live posture state.
    expect(posturePlatformSupported("darwin")).toBe(true);
    expect(posturePlatformSupported("macos")).toBe(true);
    expect(posturePlatformSupported("windows")).toBe(true);
  });

  it("platforms with no reporting client are N/A", () => {
    for (const p of ["ios", "android", "linux"])
      expect(posturePlatformSupported(p), p).toBe(false);
  });

  it("an UNKNOWN platform is assumed to report — fail towards showing the absence", () => {
    // Marking an unrecognised platform N/A would excuse a real gap instead of surfacing it.
    expect(posturePlatformSupported("freebsd")).toBe(true);
    expect(posturePlatformSupported(undefined)).toBe(true);
  });
});

describe("needsAttention / applyDeviceFilter", () => {
  const d = (o: Record<string, unknown> = {}) =>
    ({ status: "active", ...o }) as Parameters<typeof needsAttention>[0];

  it("⛔ REVOKED IS NOT ATTENTION, even carrying every other trigger", () => {
    // A revoked device is DONE. Surfacing it as actionable is an instruction to act on a device that cannot
    // come back — the same defect as showing it a re-export badge.
    expect(
      needsAttention(
        d({
          status: "revoked",
          health_blocked: true,
          health_state: "noncompliant",
          needs_reexport: true,
        }),
      ),
    ).toBe(false);
  });

  it("each trigger alone is enough, and a clean device is not attention", () => {
    // Both sides: a function returning true unconditionally passes the four positives.
    expect(needsAttention(d({ status: "pending" }))).toBe(true);
    expect(needsAttention(d({ health_blocked: true }))).toBe(true);
    expect(needsAttention(d({ health_state: "noncompliant" }))).toBe(true);
    expect(needsAttention(d({ needs_reexport: true }))).toBe(true);
    expect(needsAttention(d({ health_state: "compliant" }))).toBe(false);
    expect(needsAttention(d({ health_state: "unknown" }))).toBe(false);
  });

  it("⛔ the counts come from the SAME function the table filters with", () => {
    // Two separate derivations of "how many need attention" is how a badge starts lying. This asserts the
    // identity, not two numbers that happen to agree today.
    const rows = [
      d({ health_blocked: true }),
      d({ status: "revoked" }),
      d({ health_state: "compliant" }),
      d({ status: "pending" }),
    ];
    const c = deviceFilterCounts(rows);
    expect(c.attention).toBe(applyDeviceFilter(rows, "attention").length);
    expect(c.revoked).toBe(applyDeviceFilter(rows, "revoked").length);
    expect(c.all).toBe(rows.length);
    // `all` INCLUDES revoked while the others do not, so the three never sum to `all` — which is why the
    // screen states it rather than leaving a reader to arithmetic.
    expect(c.attention + c.revoked).not.toBe(c.all);
  });

  it("`all` is the identity, not a filter", () => {
    const rows = [d(), d({ status: "revoked" })];
    expect(applyDeviceFilter(rows, "all")).toHaveLength(2);
  });
});
