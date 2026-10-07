# Disposable Beam local stack

This fixture uses the `tunnex-beam-local` Compose project and loopback-only host
ports. It is separate from the default installer and production Beam override.
`prepare.sh` builds local API, node, operator and proxy binaries; it generates
private ignored credentials and a two-day local TLS root. No system trust root
is installed. Keep `.runtime` private and out of Git/build contexts.

The console is `http://127.0.0.1:18283` (HTTPS on `18443`); API is `18284`,
gateway readiness is `19293`, browser Beam TLS is `443`, connector TLS is `19444`,
and proxy operations are `19445`. The desktop development application uses the
console address and an isolated encrypted profile. VPN enrollment is independent.

The API and Beam proxy share only this fixture's network namespace: wildcard
`*.beam.127.0.0.1.sslip.io` resolves to loopback, so real readiness probes can reach
the actual proxy. The API's explicit development flag and fixed public CA file
allow strict verification of this private fixture; production rejects these
development flags and retains system-root verification and public-address checks.
The API agent listener on `8443` stays separate from Beam's browser listener.
The proxy runs as UID 10001. Every published port binds `127.0.0.1`.

After updating artifacts, sync the Docker-managed binaries and console volumes.
Start or recreate API first and wait for its health check, then recreate
`beam-proxy` so it joins the current API namespace. Do not restart these two
containers concurrently: the proxy can otherwise retain an obsolete namespace.
Refresh the console after API recreation so its upstream address is resolved.
The API trusts only the owned `console` service to report its observed TLS
transport. HTTPS console sign-in uses a separate Secure host-only cookie from
HTTP development sign-in. After enabling this proxy configuration, sign in
normally again on each console transport; an old development cookie cannot
authenticate the HTTPS launch. Keep the exact-origin CSRF check enabled.

Applying migration 211 leaves installation serving and organization policy off.
The environment domain values only prefill the operator form. Actual admission
requires an explicitly saved installation configuration, a current real DNS/TLS
measurement, organization opt-in, an authorized publisher and a current reviewer
grant. Never force readiness through SQL or an environment assertion.

The fixture proposal in private `.runtime/web-fixture-proposed.json` is pending
approval until authorized. It restricts publishing/reviewing to the local test
admin; it does not establish anonymous access. The password handoff remains a
normal first-login action. Do not print passwords, tokens or private key material
in shell output, screenshots, reports or test logs.

`/livez` shows process liveness. `/readyz` remains unavailable while installation
serving is disabled or measured authority is absent; this is expected default-off
behavior. A running container alone is not evidence that a share can be reviewed.

Private local certificates, HTTP development cookies and artifact-content checks
do not qualify production browser trust, production cookie topology or Windows
runtime. The epic's acceptance record tracks these remaining qualifications.
