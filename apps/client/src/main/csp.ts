// cspFor builds the Content-Security-Policy for the app:// SPA. 'self' is the
// app:// origin (its own bundled assets); the API lives at the configured server
// origin, so connect-src includes it (only when set). Deliberately strict:
// default-src 'none', scripts only from the bundle (no remote/eval), styles
// self + inline (the built CSS + any inlined styles), images/fonts self + data:.
// This is the primary hardening control against an XSS/supply-chain injection in
// the bundled SPA — without it, injected JS could pull remote code and drive the
// auto-attached bearer against the API.
export function cspFor(serverOrigin: string): string {
  const connect = ["'self'"];
  if (serverOrigin) connect.push(serverOrigin);
  return [
    "default-src 'none'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self' data:",
    `connect-src ${connect.join(" ")}`,
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
  ].join("; ");
}
