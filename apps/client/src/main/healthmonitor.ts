import type { DeviceApi, HealthFacts, HealthReportResult } from "./deviceconfig";

// HealthMonitor (S7.5.3) is the client side of device posture: it periodically
// collects facts (OS version in main; disk encryption via the privileged helper's
// read-only posture verb) and self-reports them to the tenant, which evaluates
// server-side. PERIODIC, not terminal — unlike the Approval/Revocation monitors
// there is no fire-once transition; it reports for as long as it runs.
//
// Cadence: 10 minutes (the S7.5.2 poll cadence class) + a FIXED per-instance
// jitter offset (0..2min, mirroring the server poller's convention) so a fleet
// doesn't thundering-herd the report endpoint. First report is EARLY (15s after
// start): a device would otherwise sit "posture unknown" on the dashboard for a
// full interval after every connect.
//
// Honesty rule (the taxonomy): a fact the collector cannot determine is reported
// ABSENT, never guessed — collectFacts omits it; a collector THROW skips the
// whole report (nothing to say beats saying something wrong). The server treats
// absence as posture_unknown, which never blocks.
//
// Poll discipline (inherited from Approval/RevocationMonitor): app-level
// singleton, self-scheduling recursive setTimeout (no overlap, no wake-from-sleep
// backlog), throw → inconclusive → keep + capped backoff, origin-lifecycle stop.
// TERMINAL server answers stop it cleanly: "unsupported" (403 — open edition:
// reporting is pointless until the org's edition changes; restarts on the next
// connect) and "gone" (404 — the device teardown paths own that transition).
export const HEALTH_REPORT_BASE_MS = 10 * 60_000;
export const HEALTH_REPORT_JITTER_MAX_MS = 2 * 60_000;
export const HEALTH_FIRST_REPORT_MS = 15_000;
export const HEALTH_BACKOFF_MAX_MS = 30 * 60_000;

// HealthOutcome is what a single cycle decided — surfaced for the unit tests
// (the decision carries the safety properties, like the sibling monitors).
export type HealthOutcome = "reported" | "unsupported" | "gone" | "inconclusive" | "skipped";

export class HealthMonitor {
  private timer: ReturnType<typeof setTimeout> | null = null;
  private stopped = false;
  private running = false;
  private inFlight = false;
  private terminal = false;
  private backoff = 0;
  // hasReported gates the EARLY phase ([4]): until the FIRST successful report, an
  // inconclusive result retries at the short first-report delay, NOT the 10-min
  // base — a first-report blip must not leave the device "unknown" for a full
  // interval, which is the exact outcome the early first report exists to avoid.
  private hasReported = false;
  private readonly jitter: number;

  constructor(
    private readonly deviceId: string,
    private readonly orgId: string,
    private readonly api: Pick<DeviceApi, "reportHealth">,
    // collectFacts gathers platform/os_version/disk_encrypted. Injected so this
    // module stays electron-free (the wiring passes process.getSystemVersion +
    // the helper posture call). It OMITS any fact it cannot determine; it may
    // throw, which skips this cycle entirely.
    private readonly collectFacts: () => Promise<HealthFacts>,
    // onResult surfaces the server's evaluation (warn banner / blocked state).
    private readonly onResult?: (r: HealthReportResult) => void,
    private readonly baseMs: number = HEALTH_REPORT_BASE_MS,
    private readonly maxMs: number = HEALTH_BACKOFF_MAX_MS,
    jitterMaxMs: number = HEALTH_REPORT_JITTER_MAX_MS,
    private readonly firstMs: number = HEALTH_FIRST_REPORT_MS,
    private readonly setTimer: (cb: () => void, ms: number) => ReturnType<typeof setTimeout> = (cb, ms) => {
      const t = setTimeout(cb, ms);
      t.unref?.();
      return t;
    },
    private readonly clearTimer: (t: ReturnType<typeof setTimeout>) => void = (t) => clearTimeout(t),
  ) {
    // Fixed per-instance phase offset (the server poller's jitter convention),
    // not per-tick randomness.
    this.jitter = jitterMaxMs > 0 ? Math.floor(Math.random() * jitterMaxMs) : 0;
  }

  start(): void {
    if (this.running) return; // idempotent, even mid-report (timer is transiently null)
    this.running = true;
    this.stopped = false;
    this.terminal = false;
    this.backoff = 0;
    this.schedule(this.firstMs);
  }

  stop(): void {
    this.stopped = true;
    this.running = false;
    if (this.timer) {
      this.clearTimer(this.timer);
      this.timer = null;
    }
  }

  // reportOnce runs a single collect+report cycle. Exposed for the tests.
  async reportOnce(): Promise<HealthOutcome> {
    if (this.stopped || this.terminal || this.inFlight) return "skipped";
    this.inFlight = true;
    try {
      let facts: HealthFacts;
      try {
        facts = await this.collectFacts();
      } catch {
        // Collector failure: nothing honest to send this cycle. Skip (steady
        // cadence, no backoff — the collector is local, not a server signal).
        return "skipped";
      }
      if (!facts.os_version) return "skipped"; // nothing useful to report
      const res = await this.api.reportHealth(this.deviceId, this.orgId, facts);
      if (this.stopped) return "skipped"; // stopped during the await — abandon
      if (res === "unsupported" || res === "gone") {
        // Terminal: stop reporting (edition off / device gone). No error loop —
        // the monitor restarts on the next connect if circumstances changed.
        this.terminal = true;
        return res;
      }
      this.backoff = 0;
      this.hasReported = true;
      this.onResult?.(res);
      return "reported";
    } catch {
      // Inconclusive (network blip / 5xx): keep reporting, lengthen the next try —
      // EXCEPT in the early phase (no successful report yet), where we retry at the
      // short first-report delay so a first-report blip doesn't drop the device to
      // 10-min "unknown" ([4]).
      if (!this.hasReported) {
        this.backoff = this.firstMs;
      } else {
        this.backoff = this.backoff === 0 ? this.baseMs : Math.min(this.backoff * 2, this.maxMs);
      }
      return "inconclusive";
    } finally {
      this.inFlight = false;
    }
  }

  private nextDelay(): number {
    return this.backoff === 0 ? this.baseMs + this.jitter : this.backoff;
  }

  private schedule(ms: number): void {
    if (this.stopped || this.terminal) return;
    this.timer = this.setTimer(() => {
      this.timer = null;
      void this.loop();
    }, ms);
  }

  private async loop(): Promise<void> {
    await this.reportOnce();
    if (!this.stopped && !this.terminal) this.schedule(this.nextDelay());
  }
}
