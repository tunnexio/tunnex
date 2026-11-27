/**
 * Copy text to the clipboard. The async Clipboard API exists only in a secure context (HTTPS or localhost);
 * a plain-HTTP self-hosted console falls back to the selection command. Returns whether the copy worked, so
 * the caller can tell the person to select and copy by hand instead of failing silently.
 */
export async function copyText(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard?.writeText) { await navigator.clipboard.writeText(text); return true; }
    const area = document.createElement("textarea");
    area.value = text; area.style.position = "fixed"; area.style.opacity = "0";
    document.body.appendChild(area); area.focus(); area.select();
    const ok = document.execCommand("copy");
    document.body.removeChild(area);
    return ok;
  } catch { return false; }
}
