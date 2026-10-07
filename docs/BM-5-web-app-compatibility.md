# Beam web app and Vite HMR compatibility

Status: **Local native transport qualification passed. Full authenticated browser qualification remains pending.**
Story: BM-5. Prepared: 2026-10-06.
Core worktree: `/private/tmp/tunnex-beam-plan`, baseline `7ed12a91`, uncommitted Beam development.
Client worktree: `/private/tmp/tunnex-client-beam`, baseline `9b71d19`, uncommitted Beam development.

## Supported local app shape

Beam serves one fixed HTTP or verified HTTPS app on numeric loopback. The developer keeps the Tunnex desktop client and the local app running. Reviewers use the app's shared HTTPS hostname after sign-in and a current reviewer grant. The URL remains the same during pause/resume, reconnect and local app restart; these operations do not extend its expiry.

The connector forwards the published hostname as `Host`, supplies its own `X-Forwarded-Host` and `X-Forwarded-Proto: https`, and strips Tunnex credentials and spoofed identity/forwarding headers. Apps with hostname checks must explicitly accept their allocated Beam hostname. Apps that generate absolute asset, redirect or WebSocket URLs must use that HTTPS hostname.

| Traffic | Current local evidence | Qualification boundary |
| --- | --- | --- |
| HTML and JavaScript modules | Real Vite HTML, transformed client and app module reached the native proxy | No content-body rewriting is provided |
| Static assets | A real SVG asset reached the native proxy while streams stayed open | Relative assets and one fixed origin are covered |
| Forms, app cookies and relative redirects | Existing native integration proves request body, permitted app cookie and safe redirect | External redirects and wider cookie domains are refused |
| SSE | Real Vite middleware SSE continued while HMR and short HTTP requests were active | Expiry/withdrawal still closes the shared authority lease |
| Vite HMR | A real file edit emitted Vite's `js-update` through its actual WebSocket; a timestamped module refetch contained the new version | This test does not execute a browser DOM update or prove the production login/grant exchange |
| Concurrent traffic | HMR and SSE remained open while HTML, modules and assets were fetched | Production pool has at most 32 active and two idle/opening reservations |
| Authority withdrawal | HMR and SSE both closed within the five-second acceptance bound after fixture revocation | The fixture injects authority; the complete production withdrawal matrix needs the combined CP/proxy/client qualification |

## Configure Vite for a Beam link

Use the exact hostname shown in the desktop share. For a link such as `https://p-<random>.beam.example.net`, the hostname is `p-<random>.beam.example.net`.

```ts
import { defineConfig } from "vite";

const beamHostname = process.env.TUNNEX_BEAM_HOST;

export default defineConfig({
  server: {
    host: "127.0.0.1",
    port: 5173,
    strictPort: true,
    allowedHosts: beamHostname ? [beamHostname] : [],
    hmr: beamHostname
      ? { protocol: "wss", host: beamHostname, clientPort: 443 }
      : undefined,
  },
});
```

Set `TUNNEX_BEAM_HOST` for this app's Vite process to the hostname allocated to the share, then start or restart Vite. Select the same loopback port in the desktop share. Restarting the local app does not create another share or reset its TTL. A new share receives another hostname, so update this app configuration for the new link.

`TUNNEX_BEAM_HOST` here is an app-specific Vite environment variable consumed by this example; the control plane does not configure it automatically. Retain normal Vite host restrictions. Do not use `allowedHosts: true` or a globally insecure TLS setting. Keep HMR on the same local server and public HTTPS hostname as the app; a separate HMR port or a socket URL targeting the reviewer's localhost is outside this qualified configuration.

The fixture uses canonical filesystem paths and Vite's real polling watcher to make file-change observation deterministic on the local macOS temporary filesystem. That polling choice is test setup. A developer app can use its normal watcher when file changes are detected reliably.

## Reproduce the native proof

Use the task's pinned Node 24.21.0 and pnpm 10.34.5. Build the development-only Go fixture from the isolated core worktree:

```sh
cd /private/tmp/tunnex-beam-plan/packages/apptransport
go build -o /private/tmp/tunnex-beam-spike ./cmd/beam-spike

cd /private/tmp/tunnex-client-beam
BEAM_SPIKE_BIN=/private/tmp/tunnex-beam-spike \
  pnpm --filter @tunnex/client exec node --require ts-node/register \
  --test dev/beam-vite.integration.test.ts
```

The test fails if `BEAM_SPIKE_BIN` is missing; it is never silently skipped. It launches a private Go fixture, creates a private Vite app, uses the actual production `runBeamChannelPool`, obtains Vite's current WebSocket token through the proxied client, edits an owned module file and observes Vite's native HMR frame. It does not call `ws.send()` or manually emit watcher events to manufacture an update. Cleanup aborts the connector pool and closes its app/stream sockets before stopping the fixture.

Test source: client `apps/client/dev/beam-vite.integration.test.ts`.
Runtime dependencies: actual Vite 6.4.3, native Node TLS/HTTP and the existing Go Beam transport fixture. The local proof ran on macOS with Node 24.21.0; this is not packaged macOS/Windows release qualification.

## Recorded local result

The final local run passed **1 test, 0 failures and 0 skipped tests**. The actual Vite update was observed 28 milliseconds after the file edit. Maximum connector reservations were 5, below the 34-reservation cap. Fixture revocation closed both HMR and SSE in 1,906 milliseconds. These measurements describe this local run and are not production latency guarantees.

Local evidence log: `/private/tmp/tunnex-beam-vite-proof.log`. Client typecheck passed with the new development test included. The desktop agent added the convenience command `test:beam:vite`, which runs the same test and still requires the real `BEAM_SPIKE_BIN`.

## Remaining acceptance

Complete the production CP authentication and reviewer grant journey, render an actual browser edit through the served HTTPS hostname, and run the production withdrawal/outage matrix. Qualify supported HTTPS origins, slow/large uploads and downloads, browser cookie/CSRF/service-worker boundaries and documented app limitations. BM-5 and the full epic are not closed by this native fixture alone.
