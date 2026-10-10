# Owned private Azure control-plane UI

`deploy/nginx/azure-private-ui.conf` serves the production SPA from `/srv/azure-private-ui` on peer-host loopback port 48084. Its same-origin API proxy targets that host's owned control plane at `127.0.0.1:48083`. This does not use the Mac's local qualification API or Vite 45173. Preserve browser Host including its port, Origin, session cookies and the shared client's CSRF header. No CORS, authentication or licence enforcement override is provided. Port 48084 must remain loopback-only and accessed through the lead's private SSH forwarding path.

Rebuild from the lead's final integrated source using the repository's required Node 24.21.x and frozen lockfile:

```sh
pnpm install --frozen-lockfile
pnpm --filter @tunnex/web build
```

Copy only `apps/web/dist` static files (exclude `*.map`) and this nginx configuration into the owned deployment directory. Inspect ownership before replacing any files. Run `nginx -t -c /absolute/owned/nginx.conf` on the peer host, then run the isolated nginx process with that exact config and an owned PID/process handle. Do not replace a system nginx config or restart an existing server. The prepared local tarball contains only `html/` and `nginx.conf`; it has no accounts, licence keys, PSKs or runtime fixtures. Its existing build passed host Node 24.19.0 qualification; the exact-engine limitation is recorded in `AZ-S2S-UI.md`.

Before user handoff, verify the actual forwarded URL serves the SPA, `/healthz` reaches the intended cloud control plane, normal sign-in/session refresh works and an unsafe authenticated request passes normal CSRF validation. If that CP requires Secure cookies or HTTPS origin, use its existing HTTPS path instead of weakening its cookie/security settings. A loopback HTTP tunnel alone does not prove compatibility with those settings.

Normal licence installation is deployment-wide: `LicenceCard` reads and posts `/api/v1/license`. Settings permits management only to an owner. Open Settings → Plan → Manage, enter the legitimate issued key, and select Install licence. The UI confirms successful installation before clearing the key and closing the dialog. It applies immediately without restart. The existing licence acquisition link in `CeilingUpgrade` points to `https://tunnex.io/trial`; `LicenceCard` itself has no issuer/trial link. Obtaining a key and any issuer account, agreement or payment steps remain the user's normal flow. Do not mint a key, expose issuer signing material or override entitlement checks.
