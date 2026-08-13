import * as fs from "node:fs";
import log from "electron-log";

// ⛔ THE CLIENT HAD A LOG FILE AND NO LOGGING.
//
// `~/Library/Logs/@tunnex/client/main.log` existed, was writable, and rotated correctly. It also
// contained **thirty lines accumulated over weeks, every one of them the auto-updater announcing
// itself as inert.** The one failure anybody actually hit —
//
//     Error occurred in handler for 'tunnel:up': Error: not_authenticated
//
// appears in it ZERO times. `electron-log` was imported by `updater.ts` alone, so the only code
// that logged was the code that had nothing to say.
//
// > **A LOG FILE THAT EXISTS IS NOT LOGGING.** It is worse than no log file: "check the logs" reads
// > as a real instruction, the file opens, it has content and timestamps, and the incident is
// > simply absent. The absence looks like "nothing went wrong" rather than "nothing was recorded" —
// > the same false-green shape as a census that matches its own prose.
//
// Everything below is about making the file contain the incident.

/**
 * Route the process's own output into the log file.
 *
 * ⛔ `console` IS THE IMPORTANT PART, NOT OUR OWN CALLS. Electron writes "Error occurred in handler
 * for X" to `console.error` itself, which is exactly the line that was missing — so capturing
 * console captures failures nobody remembered to instrument, including future ones.
 */
export function initLogging(): void {
  log.transports.file.level = "info";
  log.transports.console.level = "info";
  // electron-log's documented console capture: replaces console.* with its own functions, so both
  // our logging and Electron's internal reporting land in the same file, in order.
  Object.assign(console, log.functions);

  // ⚠ A CRASH IS THE ONE EVENT MOST WORTH HAVING AND LEAST LIKELY TO BE WRITTEN. Both handlers are
  // registered before any window exists, because a failure during startup is the case where the
  // user has the least else to go on.
  process.on("uncaughtException", (err) => {
    log.error("uncaughtException", err);
  });
  process.on("unhandledRejection", (reason) => {
    log.error("unhandledRejection", reason);
  });

  log.info("--- tunnex client started ---");
}

/**
 * Where the log actually is.
 *
 * ⛔ ASKED, NEVER GUESSED. The path is platform-specific and uses the npm SCOPE (`@tunnex/client`),
 * not the product name — a directory a user has already been sent to the wrong version of once.
 * `electron-log` knows it; hardcoding a second copy of that knowledge is how the two drift.
 */
export function logFilePath(): string {
  return log.transports.file.getFile().path;
}

/**
 * The tail of the log, as text, for display INSIDE the client.
 *
 * ⛔ THIS DELIBERATELY WEAKENS A POSTURE I ARGUED FOR ONE REVISION AGO, AND THE TRADE IS WORTH
 * NAMING RATHER THAN QUIETLY MAKING. `openLogs` reveals the file in the OS file manager precisely
 * so the log never enters the renderer, where a compromised page could read it out. Showing it
 * in-app removes that property.
 *
 * It is still the right call: a log a user cannot see is a log they will not read, and "reveal in
 * Finder" is not troubleshooting on a machine where the problem is that the app will not start. The
 * mitigations are that the renderer is `app://` with a strict CSP and no remote script, and that
 * the log carries no key material by construction — the client never writes credentials or WG keys
 * to it.
 *
 * ⚠ TAIL, NOT WHOLE FILE. An unbounded read would hand a multi-megabyte string to a React state on
 * a machine that is already misbehaving.
 */
export function readLogTail(maxBytes = 256 * 1024): string {
  const path = logFilePath();
  try {
    const size = fs.statSync(path).size;
    const start = Math.max(0, size - maxBytes);
    const fd = fs.openSync(path, "r");
    try {
      const len = size - start;
      const buf = Buffer.alloc(len);
      fs.readSync(fd, buf, 0, len, start);
      const text = buf.toString("utf8");
      // A byte-offset read can land mid-line; drop the partial head rather than show a fragment.
      return start > 0 ? text.slice(text.indexOf("\n") + 1) : text;
    } finally {
      fs.closeSync(fd);
    }
  } catch (e) {
    // ⛔ AN UNREADABLE LOG IS A REPORTABLE FACT, NOT AN EMPTY ONE. Returning "" would render as a
    // clean log — the false-green shape again — so the failure is the content.
    return `Could not read the log at ${path}: ${e instanceof Error ? e.message : String(e)}`;
  }
}

export { log };
