import type { BeamShare } from "../lib/beam";

export function BeamCompatibilityHelp({ share }: { share?: BeamShare }) {
  const hostname = share?.hostname ?? "your-allocated-sharing-hostname";
  const configuration = `server: {\n  host: "127.0.0.1",\n  port: 5173,\n  strictPort: true,\n  allowedHosts: [${JSON.stringify(hostname)}],\n  hmr: { protocol: "wss", host: ${JSON.stringify(hostname)}, clientPort: 443 }\n}`;
  return <details className="rounded-md border border-line p-4 text-sm space-y-3">
    <summary className="cursor-pointer font-medium">If your app doesn&apos;t load for reviewers</summary>
    <div className="space-y-3 pt-3 text-ink-secondary">
      <p>Share an app running on this computer at 127.0.0.1 or ::1, over HTTP or HTTPS with a trusted certificate. Keep the CLI or desktop client and your app running. Reviewers use the shared HTTPS hostname, so their localhost points to their own computer.</p>
      <p>Use relative asset URLs and the shared hostname for absolute redirects or WebSocket URLs. The app receives its shared hostname as Host and HTTPS forwarding headers. App content is forwarded without rewriting HTML or JavaScript.</p>
      <h3 className="font-medium text-ink-heading">Vite and hot reload</h3>
      <p>Use this server configuration in vite.config.ts, then restart Vite on the port you shared. Update the hostname for each new share.</p>
      <pre className="overflow-x-auto rounded border border-line p-3 text-xs" tabIndex={0} aria-label="Vite configuration"><code>{configuration}</code></pre>
      <p>Keep Vite's host restrictions enabled. HMR must use wss on the shared hostname and port 443, on the same local server as the app.</p>
      <h3 className="font-medium text-ink-heading">Forms, cookies and streams</h3>
      <p>HTTP requests, relative redirects, host-scoped app cookies, SSE and WebSockets use the same share access checks. Use Secure app cookies on the public HTTPS link. Wider cookie domains and external redirects are refused. Tunnex sign-in cookies and publisher credentials are never passed to your app.</p>
      <p>Apps that depend on another origin, an absolute localhost URL, a separate HMR port, or rewriting their content need app configuration changes. Pausing, expiry or a lost permission ends reviewers' access, including open streams. Restarting the app does not extend expiry.</p>
    </div>
  </details>;
}
