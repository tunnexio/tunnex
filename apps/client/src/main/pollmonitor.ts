// PollMonitor is the shared self-scheduling poll scheduler (S8.5 #7) behind RevocationMonitor and
// RoutedRangesMonitor — one copy of the discipline both depend on, so a fix to it (the wake-storm guard,
// the start-idempotency-by-intent guard) can never land in only one:
//   * SELF-SCHEDULING (recursive setTimeout, NEVER setInterval): the next probe is armed only after the
//     current one resolves, so probes can NEVER overlap and a wake-from-sleep can NEVER release a backlog
//     of catch-up fires.
//   * runs ONLY between start() and stop(); start() is idempotent BY INTENT (the `running` flag, not the
//     timer — during an in-flight probe the timer is transiently null).
//   * exponential backoff on inconclusive probes, driven by the subclass from checkOnce().
// The scheduler is thin; the DECISION that carries the safety properties lives in the subclass's
// checkOnce(), which the unit tests drive directly.
export abstract class PollMonitor {
  private timer: ReturnType<typeof setTimeout> | null = null;
  // stopped=false means "not explicitly stopped" — checkOnce is callable on its own (tests drive it). The
  // scheduling loop only runs between start() and stop(); stop() sets this so an in-flight probe abandons.
  protected stopped = false;
  // running guards start() idempotency BY INTENT, not by timer presence (mid-probe the timer is null).
  private running = false;
  protected inFlight = false;
  private backoff = 0; // 0 = steady state (baseMs); >0 = current backed-off delay

  constructor(
    protected readonly baseMs: number,
    protected readonly maxMs: number,
    // Injectable timer for tests; defaults to the real ones. unref so a pending probe never keeps the app
    // alive on quit.
    private readonly setTimer: (cb: () => void, ms: number) => ReturnType<typeof setTimeout> = (cb, ms) => {
      const t = setTimeout(cb, ms);
      t.unref?.();
      return t;
    },
    private readonly clearTimer: (t: ReturnType<typeof setTimeout>) => void = (t) => clearTimeout(t),
  ) {}

  // checkOnce runs a single probe and applies its decision. Exposed for the tests.
  abstract checkOnce(): Promise<unknown>;

  // firstTick schedules the FIRST poll. Default: after baseMs (RevocationMonitor). Override for an
  // immediate first poll (RoutedRangesMonitor — a new device gets ranges within seconds).
  protected firstTick(): void {
    this.schedule(this.baseMs);
  }

  // halted is a TERMINAL stop beyond stop() (RevocationMonitor's fire-once). Default: never.
  protected halted(): boolean {
    return false;
  }

  // onStart resets subclass fire/latch state on a fresh start (the instance is reused across reconnects).
  protected onStart(): void {}

  // resetBackoff / bumpBackoff — the subclass drives backoff from checkOnce (reset on a healthy probe,
  // bump on an inconclusive one).
  protected resetBackoff(): void {
    this.backoff = 0;
  }
  protected bumpBackoff(): void {
    this.backoff = this.backoff === 0 ? this.baseMs : Math.min(this.backoff * 2, this.maxMs);
  }

  start(): void {
    if (this.running) return; // already running — idempotent (even mid-probe, when timer is null)
    this.running = true;
    this.stopped = false;
    this.backoff = 0;
    this.onStart();
    this.firstTick();
  }

  stop(): void {
    this.stopped = true;
    this.running = false;
    if (this.timer) {
      this.clearTimer(this.timer);
      this.timer = null;
    }
  }

  // loop runs one probe then reschedules — AFTER checkOnce resolves, which is what guarantees no overlap
  // and no wake-storm. Protected so firstTick() overrides can trigger an immediate first iteration.
  protected async loop(): Promise<void> {
    await this.checkOnce();
    if (!this.stopped && !this.halted()) this.schedule(this.nextDelay());
  }

  private nextDelay(): number {
    return this.backoff === 0 ? this.baseMs : this.backoff;
  }

  private schedule(ms: number): void {
    if (this.stopped || this.halted()) return;
    this.timer = this.setTimer(() => {
      this.timer = null;
      void this.loop();
    }, ms);
  }
}
