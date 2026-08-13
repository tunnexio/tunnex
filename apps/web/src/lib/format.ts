// relativeAge renders a compact "42s ago" / "3m ago" / "2h ago" / "5d ago" from
// an ISO timestamp. Shared by the dashboard activity feed and the device list so
// the two surfaces format recency identically (WireGuard has no live state — the
// UI only ever shows honest last-seen recency, never a fabricated live claim).
export function relativeAge(iso: string): string {
  const s = Math.max(
    0,
    Math.floor((Date.now() - new Date(iso).getTime()) / 1000),
  );
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

// endSentence terminates a message with a full stop unless it already ends in punctuation.
//
// ⛔ THE CALLER CANNOT KNOW WHETHER THE STRING IS PUNCTUATED, WHICH IS WHY THIS EXISTS. An error
// message reaching the UI comes from two places with different conventions: the client's own
// fallbacks are written as sentences ("Could not reach the API."), while `apiErrorMessage` returns
// the SERVER's `error.message`, whose punctuation is not the client's to assume. Appending "." to
// both produced "Could not reach the API.." in shipping copy; appending to neither leaves server
// messages unterminated mid-sentence.
//
// ⚠ Trailing whitespace is trimmed first — " already ends." with a space would otherwise be read as
// unpunctuated and get a second stop.
export function endSentence(message: string): string {
  const m = message.trim();
  if (m === "") return m;
  return /[.!?:;…]$/.test(m) ? m : `${m}.`;
}
