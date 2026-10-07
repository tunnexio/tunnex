import { useRef, useState } from "react";

// Use the CP's clock, then elapsed monotonic time. Changing the workstation
// clock must not prolong access or make a current share look expired.
export function useBeamClock() {
  const anchor = useRef({ instant: Date.now(), elapsed: performance.now() });
  const [, refresh] = useState(0);
  function synchronize(serverTime?: string) {
    if (!serverTime || !Number.isFinite(Date.parse(serverTime))) return;
    anchor.current = { instant: Date.parse(serverTime), elapsed: performance.now() };
    refresh(n => n + 1);
  }
  return { synchronize, now: () => anchor.current.instant + Math.max(0, performance.now() - anchor.current.elapsed) };
}
export function beamCountdown(expiresAt: string, now: number) {
  const seconds = Math.max(0, Math.ceil((Date.parse(expiresAt) - now) / 1000));
  if (!Number.isFinite(seconds)) return "Expiry unavailable";
  if (!seconds) return "Expired";
  const hours = Math.floor(seconds / 3600), minutes = Math.floor(seconds % 3600 / 60), remainder = seconds % 60;
  return `${hours ? `${hours}h ` : ""}${minutes}m ${remainder}s remaining`;
}
