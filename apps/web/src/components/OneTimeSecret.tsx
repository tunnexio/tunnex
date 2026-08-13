import { createPortal } from "react-dom";
import { useState, type ReactNode } from "react";
import { Button, StatusDot } from "./ui";

/**
 * OneTimeSecretModal is the shared "shown once" ceremony for the app's most
 * security-sensitive moments — a device config (with its private key) and a
 * gateway join token. The secret exists only in the caller's page state, is never
 * re-fetched (the server serves it exactly once), and must be explicitly
 * acknowledged to dismiss; navigating away discards it.
 *
 * Kept as ONE component so both ceremonies can't drift — a hardening of the reveal
 * (e.g. copy-confirmation, redaction) lands in a single place. `leadingActions`
 * lets a caller add extra buttons (e.g. Download) beside the built-in Copy.
 */
// legacyCopy copies via a throwaway <textarea> + document.execCommand("copy") —
// the only clipboard path available in an insecure (plain-HTTP) context, where
// the async Clipboard API is undefined. Returns whether the copy succeeded.
function legacyCopy(text: string): boolean {
  try {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    const ok = document.execCommand("copy");
    document.body.removeChild(ta);
    return ok;
  } catch {
    return false;
  }
}

// downloadText saves the secret as a file. Uses a Blob object-URL — works in an
// INSECURE (plain-HTTP) context too (no secure-context requirement), matching the
// self-host POC case where the async Clipboard API is unavailable.
function downloadText(filename: string, text: string) {
  const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

export function OneTimeSecretModal({
  title,
  caption,
  secret,
  copyLabel = "Copy",
  downloadFilename,
  leadingActions,
  children,
  onDismiss,
  requireAck,
}: {
  title: string;
  caption: ReactNode;
  secret: string;
  copyLabel?: string;
  // When set, a Download button is shown that saves the secret to this filename —
  // the offline fallback to Copy for the codes a user must keep (recovery codes).
  downloadFilename?: string;
  leadingActions?: ReactNode;
  // Extra one-time content rendered inside the modal (e.g. a QR of the secret). Lives and dies with
  // the modal — dismissing clears it, so a QR here inherits the one-time discipline (never re-rendered
  // after close, since the secret it encodes is only in the caller's state and never re-fetched).
  children?: ReactNode;
  onDismiss: () => void;
  /**
   * ⛔ REQUIRE AN EXPLICIT ACKNOWLEDGEMENT BEFORE THE MODAL CAN CLOSE.
   *
   * The wireframe's forced-enrollment ceremony specifies it: *"Modal cannot be dismissed by
   * click-away or Esc — only by the 'I've saved them' checkbox + button."* Two of those three were
   * already true HERE BY ABSENCE — there is no backdrop `onClick` and no key handler, so neither
   * gesture closes it. **But absence is not a guarantee**: nothing stopped a later edit adding
   * either, and nothing tested it. The checkbox was genuinely missing.
   *
   * Recovery codes are shown ONCE. A dismiss that takes one stray click is the difference between
   * a user who has their codes and a user who needs an administrator.
   */
  requireAck?: string;
}) {
  const [copied, setCopied] = useState(false);
  const [copyFailed, setCopyFailed] = useState(false);
  // ⛔ THE ACKNOWLEDGEMENT GATE. Undefined `requireAck` keeps every existing caller unchanged; a
  // caller that opts in cannot be dismissed until the box is ticked.
  const [acked, setAcked] = useState(false);

  async function copy() {
    try {
      // The async Clipboard API only exists in a SECURE context (HTTPS or
      // localhost). A plain-HTTP self-host (e.g. http://<ip>) — exactly the POC
      // case — leaves navigator.clipboard UNDEFINED, so fall back to the legacy
      // execCommand path, which works off-HTTPS.
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(secret);
      } else if (!legacyCopy(secret)) {
        throw new Error("clipboard unavailable");
      }
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // Never fail silently — tell the user to select + copy by hand.
      setCopyFailed(true);
      setTimeout(() => setCopyFailed(false), 4000);
    }
  }

  return createPortal(
    <div className="fixed inset-0 z-50 grid place-items-center bg-ink-950/80 p-4">
      <div className="w-full max-w-lg rounded-xl border-2 border-warn/60 bg-ink-800 p-5 shadow-2xl">
        <div className="flex items-center gap-2">
          <StatusDot tone="warn" />
          <span className="text-sm font-semibold text-warn">{title}</span>
        </div>
        <p className="mt-2 text-xs text-slate-400">{caption}</p>
        {children}
        <pre className="mt-3 max-h-64 overflow-auto rounded-md bg-ink-950 p-3 font-mono text-xs text-slate-300">
          {secret}
        </pre>
        {requireAck && (
          <label className="mt-3 flex items-start gap-2 text-xs text-slate-300">
            <input
              type="checkbox"
              data-testid="ots-ack"
              checked={acked}
              onChange={(e) => setAcked(e.target.checked)}
              className="mt-0.5"
            />
            {requireAck}
          </label>
        )}
        <div className="mt-4 flex items-center justify-between">
          <div className="flex gap-2">
            {downloadFilename && (
              <Button
                variant="ghost"
                onClick={() => downloadText(downloadFilename, secret)}
              >
                Download
              </Button>
            )}
            {leadingActions}
            <Button variant="ghost" onClick={copy}>
              {copied
                ? "Copied"
                : copyFailed
                  ? "Select + ⌘C to copy"
                  : copyLabel}
            </Button>
          </div>
          <Button
            variant="ghost"
            onClick={onDismiss}
            disabled={Boolean(requireAck) && !acked}
          >
            I&rsquo;ve saved it
          </Button>
        </div>
      </div>
    </div>,
    document.body,
  );
}
