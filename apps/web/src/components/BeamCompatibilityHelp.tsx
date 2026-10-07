import type { BeamShare } from "../lib/beam";

export function BeamCompatibilityHelp({ share }: { share?: BeamShare }) {
  const hostname = share?.hostname ?? "your-allocated-beam-hostname";
  const configuration = `server: {\n  host: "127.0.0.1",\n  port: 5173,\n  strictPort: true,\n  allowedHosts: [${JSON.stringify(hostname)}],\n  hmr: { protocol: "wss", host: ${JSON.stringify(hostname)}, clientPort: 443 }\n}`;
  return <details className="rounded-md border border-line p-4 text-sm space-y-3">
    <summary className="cursor-pointer font-medium">Web app compatibility help</summary>
    <div className="space-y-3 pt-3 text-ink-secondary">
      <p>Publish one HTTP or verified HTTPS app on a numeric loopback address. Keep the desktop client and local app running. Reviewers use the shared HTTPS hostname, so their localhost points to their own computer.</p>
      <p>Use relative asset URLs and the shared hostname for absolute redirects or WebSocket URLs. The app receives its shared hostname as Host and HTTPS forwarding headers. App content is forwarded without rewriting HTML or JavaScript.</p>
      <h3 className="font-medium text-ink-heading">Vite and hot reload</h3>
      <p>Use this server configuration in vite.config.ts, then restart Vite on the same port selected in the desktop share. Update the exact hostname for each new share.</p>
      <pre className="overflow-x-auto rounded border border-line p-3 text-xs" tabIndex={0} aria-label="Vite configuration"><code>{configuration}</code></pre>
      <p>Keep Vite's host restrictions enabled. HMR must use wss on the shared hostname and port 443, on the same local server as the app.</p>
      <h3 className="font-medium text-ink-heading">Forms, cookies and streams</h3>
      <p>HTTP requests, relative redirects, host-scoped app cookies, SSE and WebSockets use the same share access checks. Use Secure app cookies on the public HTTPS link. Wider cookie domains and external redirects are refused. Tunnex sign-in cookies and connector credentials are never passed to your app.</p>
      <p>Apps that depend on another origin, an absolute localhost URL, a separate HMR port, or rewriting their content need app configuration changes. Pause, expiry, lost permission or unavailable authority closes review access, including streams. Restarting the app does not extend expiry.</p>
    </div>
  </details>;
}
