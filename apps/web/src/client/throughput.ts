// The throughput plot — REAL bytes, and only real bytes.
//
// ⛔ WHAT THIS FILE REPLACED, AND WHY IT IS A CORRECTION RATHER THAN A DELETION.
//
// `hyperdrive.ts` carried the design's mesh animation AND a graph fed by `pushSample`, which
// invented its samples: a 14% chance of a burst, otherwise a low idle band, all from `Math.random`.
// So the client drew a lively traffic plot while every number beside it read `n/a`.
//
// > **A PLOT OF INVENTED DATA NEXT TO AN HONEST `n/a` IS WORSE THAN EITHER ALONE.** The `n/a` says
// > "we did not measure this"; the plot says "we measured this". One of them is lying, and it is
// > the one that looks like evidence. This repo's own rule — a zero nobody measured is a claim —
// > applies with more force to a curve than to a zero.
//
// The mesh went at the founder's direction. The plot stayed and now draws deltas of `rx_bytes` +
// `tx_bytes` as reported by the helper via `wg show`, which are real counters.
//
// ⚠ NORMALISED TO THE SESSION PEAK, NOT TO AN ABSOLUTE SCALE. There is no meaningful ceiling for a
// tunnel's throughput, so the curve is relative and the peak is printed beside it — the number is
// what carries the magnitude, the shape carries the pattern.

/** The design's own window: 64 samples, so the plot SCROLLS rather than rescaling horizontally. */
export const THROUGHPUT_WINDOW = 64;

/** Append one rate sample (bytes/sec), keeping the newest `THROUGHPUT_WINDOW`. */
export function pushRate(history: readonly number[], bytesPerSec: number): number[] {
  const next = [...history, Math.max(0, bytesPerSec)];
  return next.length > THROUGHPUT_WINDOW
    ? next.slice(next.length - THROUGHPUT_WINDOW)
    : next;
}

/**
 * Bytes/sec between two counter readings.
 *
 * ⛔ A COUNTER THAT WENT BACKWARDS IS A NEW INTERFACE, NOT NEGATIVE TRAFFIC. `wg show` counters
 * reset when the tunnel is torn down and rebuilt, so a naive delta would render a large negative
 * spike at exactly the moment a reconnect happens. Treated as a restart: report 0 and let the next
 * sample establish a new baseline.
 */
export function rateBetween(
  prev: { bytes: number; at: number } | null,
  now: { bytes: number; at: number },
): number {
  if (!prev) return 0;
  const dt = (now.at - prev.at) / 1000;
  if (dt <= 0) return 0;
  const db = now.bytes - prev.bytes;
  if (db < 0) return 0;
  return db / dt;
}

/**
 * The plot: a filled area under a 1.6px line over a fixed 64-sample window.
 *
 * The geometry is the designer's, unchanged. Only the SOURCE of the samples changed.
 */
export function drawGraph(
  ctx: CanvasRenderingContext2D,
  w: number,
  h: number,
  samples: readonly number[],
): void {
  ctx.clearRect(0, 0, w, h);
  ctx.strokeStyle = "rgba(255,255,255,0.12)";
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(0, h * 0.5);
  ctx.lineTo(w, h * 0.5);
  ctx.stroke();

  const n = samples.length;
  if (n <= 1) return;
  // 63, not n-1: the window is fixed so the plot scrolls rather than rescaling.
  const step = w / (THROUGHPUT_WINDOW - 1);
  const base = h - 6;
  // Floor of 1 keeps an all-idle session flat on the baseline instead of dividing by zero.
  const max = Math.max(...samples, 1);

  const grad = ctx.createLinearGradient(0, 0, 0, h);
  grad.addColorStop(0, "rgba(255,255,255,0.14)");
  grad.addColorStop(1, "rgba(255,255,255,0)");
  ctx.beginPath();
  ctx.moveTo(0, base);
  samples.forEach((v, i) => ctx.lineTo(i * step, base - (v / max) * (h - 12)));
  ctx.lineTo((n - 1) * step, base);
  ctx.closePath();
  ctx.fillStyle = grad;
  ctx.fill();

  ctx.beginPath();
  samples.forEach((v, i) => {
    const x = i * step;
    const y = base - (v / max) * (h - 12);
    if (i) ctx.lineTo(x, y);
    else ctx.moveTo(x, y);
  });
  ctx.strokeStyle = "#D6D6D2";
  ctx.lineWidth = 1.6;
  ctx.stroke();
}
