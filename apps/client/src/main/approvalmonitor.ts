import type { DeviceApi } from "./deviceconfig";

// APPROVAL_POLL_MS is the steady cadence while a device is AWAITING admin approval
// (S7.3). Calmer than the revocation poll: approval is a human action (seconds to
// hours), so a 30s check is responsive without being a wakeup cost. Backoff caps the
// exponential slow-down applied after inconclusive (throwing) probes.
export const APPROVAL_POLL_MS = 30_000;
export const APPROVAL_BACKOFF_MAX_MS = 5 * 60_000;

// ApprovalStatus is the definitive server answer for the awaited device. A read error
// is NOT one of these — it throws (inconclusive) so a network blip never reads as a
// transition (the deviceExists empty-orgs lesson, applied to this new component).
export type ApprovalStatus = "pending" | "active" | "gone";

// ApprovalOutcome is what a single probe decided — surfaced for the unit tests (the
// DECISION carries the safety properties, like RevocationMonitor / the S6.3 supervisor).
export type ApprovalOutcome = "waiting" | "approved" | "rejected" | "inconclusive" | "skipped";

// ApprovalMonitor is the CLIENT-side awaiting-approval poll (S7.3), the sibling of the
// RevocationMonitor. It runs ONLY while a device is PENDING for the current origin and
// polls the tenant for its status. It is a DETECTOR, not an executor:
//   * pending      -> keep waiting (calm, stable — never an error loop).
//   * active       -> the admin APPROVED: fire onApproved ONCE, then stop. It does NOT
//                     auto-connect — surfacing + becoming connectable is all; the human
//                     clicks connect (a background poll must never arm the kill-switch or
//                     trigger the helper's privilege flow as a side effect).
//   * gone         -> REJECTED (or deleted): fire onRejected ONCE, then stop. onRejected
//                     routes through the EXISTING S6.4 teardown path (config clear + sweep
//                     + loud notification) — one revocation-execution path, two detectors.
//   * a throw      -> INCONCLUSIVE: KEEP waiting (never transition on a blip) and BACK OFF.
//
// Poll discipline (inherited from RevocationMonitor S6.4, verbatim): app-level SINGLETON
// (never per-window), runs only between start()/stop(), SELF-SCHEDULING (recursive
// setTimeout — no overlap, no wake-from-sleep backlog), fire-ONCE on a terminal transition
// (approved/rejected), and ORIGIN-LIFECYCLE STOP: it is stopped when its origin context
// dies (a server-URL change / logout — finding #5), not just on connect/disconnect, so an
// old-origin poll never lingers against a stale bearer.
export class ApprovalMonitor {
  private timer: ReturnType<typeof setTimeout> | null = null;
  private stopped = false;
  private running = false;
  private inFlight = false;
  private fired = false;
  private backoff = 0;

  constructor(
    private readonly deviceId: string,
    private readonly orgId: string, // the device's own org — queried directly (S7.3 #4)
    private readonly api: Pick<DeviceApi, "deviceStatus">,
    private readonly onApproved: () => void | Promise<void>,
    private readonly onRejected: () => void | Promise<void>,
    private readonly baseMs: number = APPROVAL_POLL_MS,
    private readonly maxMs: number = APPROVAL_BACKOFF_MAX_MS,
    private readonly setTimer: (cb: () => void, ms: number) => ReturnType<typeof setTimeout> = (cb, ms) => {
      const t = setTimeout(cb, ms);
      t.unref?.();
      return t;
    },
    private readonly clearTimer: (t: ReturnType<typeof setTimeout>) => void = (t) => clearTimeout(t),
  ) {}

  start(): void {
    if (this.running) return; // idempotent, even mid-probe (timer is transiently null)
    this.running = true;
    this.stopped = false;
    this.fired = false;
    this.backoff = 0;
    this.schedule(this.baseMs);
  }

  stop(): void {
    this.stopped = true;
    this.running = false;
    if (this.timer) {
      this.clearTimer(this.timer);
      this.timer = null;
    }
  }

  // checkOnce runs a single probe and applies the decision. Exposed for the tests.
  async checkOnce(): Promise<ApprovalOutcome> {
    if (this.stopped || this.fired || this.inFlight) return "skipped";
    this.inFlight = true;
    try {
      const status = await this.api.deviceStatus(this.deviceId, this.orgId);
      // A stop() during the await means the awaiting UI is already dismissed — abandon.
      if (this.stopped) return "skipped";
      if (status === "pending") {
        this.backoff = 0; // a healthy probe returns to steady cadence
        return "waiting";
      }
      // A DEFINITIVE not-pending answer is the only thing that transitions (fire-once).
      this.fired = true;
      if (status === "active") {
        await this.onApproved();
        return "approved";
      }
      await this.onRejected(); // "gone" — rejected or deleted
      return "rejected";
    } catch {
      // Inconclusive: deviceStatus throws on ANY read error (its fail-safe). KEEP waiting
      // (a blip must NEVER read as rejected) and lengthen the next probe.
      this.backoff = this.backoff === 0 ? this.baseMs : Math.min(this.backoff * 2, this.maxMs);
      return "inconclusive";
    } finally {
      this.inFlight = false;
    }
  }

  private nextDelay(): number {
    return this.backoff === 0 ? this.baseMs : this.backoff;
  }

  private schedule(ms: number): void {
    if (this.stopped || this.fired) return;
    this.timer = this.setTimer(() => {
      this.timer = null;
      void this.loop();
    }, ms);
  }

  private async loop(): Promise<void> {
    await this.checkOnce();
    if (!this.stopped && !this.fired) this.schedule(this.nextDelay());
  }
}
