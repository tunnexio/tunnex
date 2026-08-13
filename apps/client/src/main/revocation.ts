import type { DeviceApi } from "./deviceconfig";
import { PollMonitor } from "./pollmonitor";

// REVOKE_POLL_MS is the steady-state cadence: while a tunnel is UP the client asks
// the tenant "does THIS device still exist+active?" every 30s. That is frequent
// enough that a revoked device disconnects within a rekey window, and rare enough
// that it is not a battery/wakeup cost. REVOKE_BACKOFF_MAX_MS caps the exponential
// back-off applied after inconclusive (throwing) probes so a flapping server is
// probed ever more slowly, not hammered.
export const REVOKE_POLL_MS = 30_000;
export const REVOKE_BACKOFF_MAX_MS = 5 * 60_000;

// ProbeOutcome is what a single check decided — surfaced for the unit tests (the
// scheduler around checkOnce is thin; the DECISION is what carries the safety
// properties, so that is what the tests drive directly, like the S6.3 supervisor).
export type ProbeOutcome = "torn-down" | "kept" | "inconclusive" | "skipped";

// RevocationMonitor is the CLIENT-side proactive revocation detector (S6.4). It is
// the counterpart to the helper's kernel-side dead-man: while the tunnel is up it
// polls the tenant and, on a DEFINITIVE "device gone", tears the tunnel down + clears
// the dead config + notifies loudly — instead of the user staring at a stuck
// "Connecting…" until the helper's 90s dead-man eventually fires.
//
// Poll discipline (S6.4 watch-item #1 — the poll must not become its own bug):
//   * runs ONLY between start() and stop() — i.e. only while a tunnel is up. A
//     disconnected client polls nothing.
//   * SELF-SCHEDULING (recursive setTimeout, not setInterval): the next probe is
//     armed only after the current one resolves, so probes can NEVER overlap and a
//     wake-from-sleep can NEVER release a backlog of catch-up fires (the #9 concern).
//   * a throw from deviceExists is INCONCLUSIVE → KEEP the tunnel (never disconnect a
//     working tunnel on a transient blip) and BACK OFF the next probe exponentially.
//   * a definitive gone fires onRevoked EXACTLY ONCE, then the monitor stops itself
//     (no re-fire storm while the teardown is in flight).
export class RevocationMonitor extends PollMonitor {
  // fired = the terminal fire-once latch: after a definitive "device gone" fires onRevoked exactly once,
  // the monitor halts (no re-fire storm while teardown is in flight). Reset by onStart() so the same
  // instance can be reused across reconnects.
  private fired = false;

  constructor(
    private readonly deviceId: string,
    private readonly orgId: string, // the device's own org — queried directly (S7.3 #4)
    private readonly api: Pick<DeviceApi, "deviceExists">,
    private readonly onRevoked: () => void | Promise<void>,
    baseMs: number = REVOKE_POLL_MS,
    maxMs: number = REVOKE_BACKOFF_MAX_MS,
    setTimer?: (cb: () => void, ms: number) => ReturnType<typeof setTimeout>,
    clearTimer?: (t: ReturnType<typeof setTimeout>) => void,
  ) {
    super(baseMs, maxMs, setTimer, clearTimer);
  }

  protected override onStart(): void {
    this.fired = false;
  }
  protected override halted(): boolean {
    return this.fired;
  }

  // checkOnce runs a single probe and applies the decision. Exposed for the tests.
  async checkOnce(): Promise<ProbeOutcome> {
    if (this.stopped || this.fired || this.inFlight) return "skipped";
    this.inFlight = true;
    try {
      const exists = await this.api.deviceExists(this.deviceId, this.orgId);
      // A stop() during the await means the user is already disconnecting — abandon
      // the result rather than tearing down (or resetting backoff) behind their back.
      if (this.stopped) return "skipped";
      if (exists) {
        this.resetBackoff(); // a healthy probe returns to steady cadence
        return "kept";
      }
      this.fired = true; // fire-once: block any concurrent/next probe from re-firing
      await this.onRevoked();
      return "torn-down";
    } catch {
      // Inconclusive: deviceExists throws on ANY read error (its fail-safe). KEEP the
      // tunnel and lengthen the next probe so a flapping server is not hammered.
      this.bumpBackoff();
      return "inconclusive";
    } finally {
      this.inFlight = false;
    }
  }
}
