// The desktop client's state model.
//
// ⛔ TEN STATES, TRANSCRIBED FROM THE BLOCK — and one of ours the design omits.
//
// The wireframe lists: CONNECTED · CONNECTING · DISCONNECTED · REVOKED (loud) · POSTURE_BLOCKED ·
// MIGRATE_FAILED ("reconnect to retry") · AWAITING ADMIN APPROVAL · HELPER OUTDATED ·
// KILL-SWITCH ENGAGED · EXPIRED CREDS (re-login).
//
// `failed` is OURS and stays: a generic connect failure is a real thing the design does not draw,
// and this epic's own law says a design's missing state is usually the FAILURE state — a designer
// drawing a healthy product has nothing to look at when drawing it.
//
// ⛔ THE ONE RULE THE BLOCK STATES OUTRIGHT: "Status is derived from handshake liveness — the icon
// is never green while the tunnel is dead." So `connected` is not "the helper said up"; it is "the
// helper said up AND a handshake happened recently". `apps/client/src/main/trayview.ts` already
// implements exactly this and this module must not disagree with it.

export type ClientState =
  | "signed_out"
  | "connected"
  | "connecting"
  | "disconnected"
  | "failed"
  | "revoked"
  | "posture_warning"
  | "posture_blocked"
  | "migrate_failed"
  | "pending_approval"
  | "helper_outdated"
  | "kill_switch"
  | "expired_creds";

/** Every state, in the block's order, with ours appended. Drives the preview and the tests. */
export const CLIENT_STATES: readonly ClientState[] = [
  "signed_out",
  "connected",
  "connecting",
  "disconnected",
  "revoked",
  "posture_warning",
  "posture_blocked",
  "migrate_failed",
  "pending_approval",
  "helper_outdated",
  "kill_switch",
  "expired_creds",
  "failed",
] as const;

export type Severity = "ok" | "busy" | "idle" | "warn" | "loud";

// ⛔ THE VERB IS ONE WORD — founder-directed, and it removes a real ambiguity as well as noise.
//
// The labels used to be "Connect · link the mesh" / "Disconnect · tear down the mesh". The suffix
// read as a SECOND clause of the action, so "Disconnect · restore normal routing" on the
// kill-switch state looked like a button that does two things — and on a 440px column it wrapped.
// The explanation belongs in `detail`, which every state already has; a button says what it does.

export type StateView = {
  /** The big status word. */
  label: string;
  /** One line of what it MEANS — not a restatement of the label. */
  detail: string;
  severity: Severity;
  /** The primary verb's label, or null when there is nothing useful to press. */
  action: string | null;
  /**
   * ⛔ Whether an OS notification fires. The block says notifications fire for REVOKED and
   * KILL-SWITCH — the two states where access changed WITHOUT the user asking. A notification on
   * every transition trains people to dismiss them, which costs exactly the two that matter.
   */
  notify: boolean;
};

/** Exact, server-evaluated reasons for a posture warning or block. */
export function postureCheckSummary(checks: Array<{ kind: string; mode: string }> = []): string | null {
  const labels = [...new Set(checks.map((c) => {
    switch (c.kind) {
      case "disk_encryption":
        return "Disk encryption is not enabled or could not be verified.";
      case "os_version":
        return "Your operating system is below your organization's minimum version.";
      default:
        return `A device-health check failed: ${c.kind}.`;
    }
  }))];
  return labels.length ? labels.join(" ") : null;
}

export function stateView(s: ClientState): StateView {
  switch (s) {
    // ⛔ OURS, AND THE DESIGN HAS NO EQUIVALENT — which is exactly the gap this epic keeps finding.
    //
    // The block draws EXPIRED CREDS (a credential that WAS valid) and never the state before any
    // credential exists. So a fresh install landed on "Disconnected" with a Connect button, and
    // pressing it threw `not_authenticated` out of the main process into a log nobody reads. The
    // button was not broken; it was offered in a state where it cannot work.
    //
    // > **A DESIGNER DRAWING A HEALTHY PRODUCT HAS NOTHING TO LOOK AT WHEN DRAWING THE EMPTY ONE.**
    // > Same reason `failed` is ours: the states a design omits are the ones nobody was in while
    // > designing it.
    case "signed_out":
      return {
        label: "Not signed in",
        detail:
          "This device has no credential for the configured server. Sign in with your browser — the app never collects a password itself.",
        severity: "idle",
        action: "Sign in with your browser",
        notify: false,
      };
    case "connected":
      return {
        label: "Connected",
        detail: "Handshake fresh — traffic is flowing through the mesh.",
        severity: "ok",
        action: "Disconnect",
        notify: false,
      };
    case "connecting":
      return {
        label: "Connecting",
        detail: "Linking peers — the icon stays amber until a handshake lands.",
        severity: "busy",
        action: "Cancel",
        notify: false,
      };
    case "disconnected":
      return {
        label: "Disconnected",
        detail: "No tunnel. Your traffic is taking its normal route.",
        severity: "idle",
        action: "Connect",
        notify: false,
      };
    case "failed":
      return {
        label: "Connection failed",
        detail:
          "The tunnel could not be established. Retrying will re-request a config.",
        severity: "warn",
        action: "Connect",
        notify: false,
      };
    // ── the two the block marks LOUD ────────────────────────────────────────────────────────────
    case "revoked":
      return {
        label: "Revoked",
        detail:
          "An administrator revoked this device. The tunnel is down; contact an administrator to approve or enroll a replacement device.",
        severity: "loud",
        action: null, // ⛔ nothing to press — offering Connect here would be a button that cannot work
        notify: true,
      };
    case "kill_switch":
      return {
        label: "Kill-switch engaged",
        detail:
          "The tunnel dropped while full-tunnel was on, so all traffic is BLOCKED rather than leaking to your normal route. This is the safe state, not a fault. Disconnect to restore normal routing.",
        severity: "loud",
        action: "Disconnect",
        notify: true,
      };
    // ── states that need someone or something else ──────────────────────────────────────────────
    case "posture_warning":
      return {
        label: "Device posture warning",
        detail:
          "This device misses a recommended health check. Access still works, but fix it before your organization makes the check required.",
        severity: "warn",
        action: "Disconnect",
        notify: true,
      };
    case "posture_blocked":
      return {
        label: "Blocked by device posture",
        detail:
          "This device fails a required health check. Fix the check on the device — an administrator cannot grant an exception from here.",
        severity: "warn",
        action: null,
        notify: true,
      };
    case "pending_approval":
      return {
        label: "Awaiting admin approval",
        detail:
          "This device is enrolled but not yet approved. Nothing to do here until it is.",
        severity: "warn",
        action: null,
        notify: false,
      };
    case "migrate_failed":
      return {
        label: "Migration failed",
        detail: "The replacement config did not complete. Reconnect to retry.",
        severity: "warn",
        action: "Connect",
        notify: false,
      };
    case "helper_outdated":
      return {
        label: "Helper out of date",
        detail:
          "The privileged helper is older than this app expects. Reinstall Tunnex — the tunnel will not start against a mismatched helper.",
        severity: "warn",
        action: null,
        notify: false,
      };
    case "expired_creds":
      return {
        label: "Session expired",
        detail: "Sign in with your browser to continue.",
        severity: "warn",
        // ⛔ BROWSER RE-AUTH ONLY. The block: "MFA touches the client only via browser re-auth …
        // NEVER an in-app password field." So the verb opens the loopback flow; it never collects
        // a credential here.
        action: "Sign in with your browser",
        notify: false,
      };
  }
}

/**
 * The tray's four appearances, from the block:
 *   solid — connected (handshake fresh) · pulsing — connecting / re-keying ·
 *   grey — disconnected · red badge — revoked / kill-switch
 *
 * ⛔ EVERYTHING THAT IS NOT LIVE IS GREY OR RED. A state like `posture_blocked` is NOT green: the
 * tunnel is down, and the block's rule is that the icon is never green while the tunnel is dead.
 */
export type TrayAppearance = "solid" | "pulsing" | "warning" | "grey" | "red";

export function trayAppearance(s: ClientState): TrayAppearance {
  if (s === "connected") return "solid";
  if (s === "connecting") return "pulsing";
  if (s === "posture_warning") return "warning";
  if (s === "revoked" || s === "kill_switch") return "red";
  return "grey";
}

/** Formatting for the stats block — bytes and duration, both of which read badly raw. */
export function formatBytes(n: number | null | undefined): string {
  if (n == null) return "n/a";
  // ⛔ THIS WAS THE HOLE. Raw bytes returned the NUMBER verbatim — fine for an integer counter,
  // ruinous for a rate, which is a division and therefore almost never integral.
  if (n < 1024) return `${n.toFixed(2)} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  // ⛔ TWO DECIMALS, ALWAYS — founder-directed, and the magnitude-scaled rule that preceded it was
  // still leaving one hole: values UNDER 1024 never reached this branch at all, so a rate of
  // 256.2562562562563 B/s printed in full, sixteen significant figures wide, and pushed the row off
  // the card. A rule with an exception is a rule that will be broken by whichever value takes the
  // exception.
  return `${v.toFixed(2)} ${units[i]}`;
}

export function formatRate(bytesPerSec: number | null | undefined): string {
  return bytesPerSec == null ? "n/a" : `${formatBytes(bytesPerSec)}/s`;
}

export function formatDuration(sec: number | null | undefined): string {
  if (sec == null || sec < 0) return "n/a";
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = Math.floor(sec % 60);
  const pad = (n: number) => String(n).padStart(2, "0");
  return h > 0 ? `${h}:${pad(m)}:${pad(s)}` : `${m}:${pad(s)}`;
}

/**
 * ⛔ THE PREVIEW IS A RENDER PROOF, NEVER A TRANSITION PROOF — and it must say so on screen.
 *
 * Six of the ten states are reachable on a local stack; four (migrate_failed, helper_outdated,
 * kill_switch, expired_creds) need contrivance. The preview lets a reviewer SEE all eleven renders
 * without pretending they were arrived at.
 */
export const PREVIEW_DISCLAIMER =
  "State preview — these are rendered directly, not reached by a real transition. Six of the ten states occur on a local stack; the rest need a contrived condition.";

export function parsePreviewState(search: string): ClientState | null {
  const v = new URLSearchParams(search).get("state");
  return v && (CLIENT_STATES as readonly string[]).includes(v)
    ? (v as ClientState)
    : null;
}
