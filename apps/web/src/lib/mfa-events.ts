import { useEffect, useRef } from "react";

// LS-UX-4: a successful MFA step-up anywhere in the console (or in another tab of it) lets panels that
// were waiting for one re-check by themselves. The message carries no data: the server decides again.
const EVENT = "tnx-mfa-verified";
const CHANNEL = "tnx-mfa";
let channel: BroadcastChannel | null | undefined;
function tabs(): BroadcastChannel | null {
  if (channel !== undefined) return channel;
  try {
    channel = typeof BroadcastChannel === "undefined" ? null : new BroadcastChannel(CHANNEL);
    if (channel) {
      channel.onmessage = () => window.dispatchEvent(new Event(EVENT));
      (channel as unknown as { unref?: () => void }).unref?.();
    }
  } catch { channel = null; }
  return channel;
}
/** Call after the server confirmed a step-up. */
export function announceMfaVerified() {
  window.dispatchEvent(new Event(EVENT));
  try { tabs()?.postMessage("verified"); } catch { /* another tab will re-check on focus */ }
}
export function onMfaVerified(listener: () => void): () => void {
  tabs();
  window.addEventListener(EVENT, listener);
  return () => window.removeEventListener(EVENT, listener);
}
/**
 * While `active` (a panel is showing an MFA prompt), run `recheck` after a step-up anywhere in the
 * console, and, unless `focus` is false, when the window regains focus or the tab becomes visible.
 * Inactive panels add no listeners and make no requests.
 */
export function useMfaRecheck(active: boolean, recheck: () => void, { focus = true }: { focus?: boolean } = {}) {
  const latest = useRef(recheck);
  latest.current = recheck;
  useEffect(() => {
    if (!active) return;
    const run = () => latest.current();
    const visible = () => { if (document.visibilityState !== "hidden") run(); };
    const stop = onMfaVerified(run);
    if (focus) { window.addEventListener("focus", run); document.addEventListener("visibilitychange", visible); }
    return () => { stop(); window.removeEventListener("focus", run); document.removeEventListener("visibilitychange", visible); };
  }, [active, focus]);
}
