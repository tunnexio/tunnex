# AA-EN-1: first-class App Access enablement

Status: decision paper only. Local branch `story/app-access-enablement-papers`, base
`origin/main` 4d693d12 (v0.1.45). Nothing is implemented, pushed or run on a host. It
builds on UPG-1 (`story/app-access-one-click-upgrade`, founder rulings D1–D6 of
2026-11-24, not yet merged) and follows the pattern of SA-UI-1
(`story/server-access-ui-enable`, not yet merged). It answers UPG-1 D5.

Binding principles (founder, 2026-11-24): no user confusion; security unchanged; upgrades
work in one click; no dependency between App Access and Server Access, and no feature
blocks upgrades.

## 1. Summary

Turning App Access on for an existing installation took an operator with SSH six manual
stages on the demo (2026-11-24). Some of them, such as certificate renewal and gateway
host mappings, have to be repeated by hand later. This paper proposes one product-owned
path that ends in the same composition UPG-1 already knows how to upgrade.

**Recommendation:**

- A single host-side command, `tunnex-app-access` (`enable | status | renew | disable`),
  is shipped as signed release content. Both the installer flag `--app-access` and, later,
  the dashboard (through the existing fixed-purpose root runner) drive it. It does
  everything after the customer creates DNS records:
  - signed proxy image selection
  - issuing the proxy credential and the gateway listener certificate into a managed
    private directory
  - obtaining the public certificate and renewing it automatically
  - sharing port 443 with the console through SNI passthrough, so the console's TLS
    stays exactly as it is
  - writing the managed overlay
  - readiness checks
- Gateways learn the proxy endpoint over their existing mTLS agent channel. No gateway
  environment variable and no `/etc/hosts` entry is needed.

**First slice (Phase 1a):**

- Gateways get the proxy endpoint over the agent channel, with a supervisor.
- The managed overlay publishes the gateway port, and UPG-1 admission accepts it.
- `adopt` moves the demo layout into the managed composition.
- A stop-gap `renew` installs a renewed certificate pair with a controlled proxy restart.
  It adds no new dependency.

This removes the per-gateway work and makes the demo upgradable. It also meets the demo
certificate's expiry around **2027-02-22**.

**Later phases:**

- **Phase 1b:** automatic DNS-01 renewal (`app-certs`), proxy hot reload of the public
  leaf, and a readiness panel.
- **Phase 2:** the enable command.
- **Phase 3:** the dashboard flow.

## 2. What happened on the demo, and what each step really needs

| # | Manual step (demo, 2026-11-24) | Why it was manual | What the product must own |
|---|---|---|---|
| 1 | Wildcard DNS `*.cp.tunnex.app`, Let's Encrypt wildcard via certbot DNS-01 with a Cloudflare token | Nothing in the product obtains public certificates for the proxy. Caddy's ACME serves only the console. | DNS guidance and checks, ACME issuance, **automatic renewal** |
| 2 | `backupctl app-proxy-certificate` and `app-proxy-issue` through `docker compose run`, with a writable marker volume; secrets assembled by hand into a uid-10001 directory with mode 0400 | Both commands need DB, master key and the stable restore lock (F4 in UPG-1). The serving API mounts the marker read-only. | Issuance through a one-off helper, files written straight into a managed private directory, never displayed |
| 3 | Base overlay plus a hand-written demo overlay: app-proxy on public 443 forwarding the console to Caddy, 8444 published on the VPC address, GCP firewall rule | Base `tunnex.yml` publishes Caddy on `443:443`. The signed overlay binds the proxy to `127.0.0.1:443` and does not publish 8444. Compose merges `ports` additively, so an overlay cannot take 443 away from Caddy. | 443 ownership in **signed managed files**, a gateway port, and a firewall check |
| 4 | `.env`: base domain, signed proxy digest, secrets directory | No writer exists | The command writes these keys from verified inputs |
| 5 | Every VM gateway recreated with `TUNNEX_APP_PROXY_URL=https://tunnex-app-proxy:8444` and `--add-host tunnex-app-proxy:<CP VPC IP>` | The gateway reads `TUNNEX_APP_PROXY_URL` once at start (`apps/node/cmd/agent/main.go`) | Delivery over the agent channel and a supervisor that starts and stops the browser pool without a restart |
| 6 | Organization feature toggle; allowed private ranges per app | Already in the product | Unchanged |

Facts found while reading the code. Each one shapes the design.

| # | Fact | Consequence |
|---|---|---|
| G1 | `NewBrowserPool` pins `ServerName = "tunnex-app-proxy"` whatever the URL host is (`apps/node/internal/appaccess/browser.go`). Trust is the enrollment CA through the rotating agent identity (`control.AppAccessTLSConfig`). | The `--add-host` mapping on the demo was a naming convention, not a TLS requirement. A gateway can dial `https://<CP address>:8444` directly. This needs a test (section 11), because it has not been run. |
| G2 | `DenyControlEndpoint` adds the proxy URL host to the control-host list, so origins on that host are refused. | An endpoint delivered as the CP host or IP also makes origins on the CP machine unreachable as apps. That is desirable, and it stays. |
| G3 | The proxy loads the public and gateway pairs once at start with `tls.LoadX509KeyPair` (`apps/app-proxy/cmd/app-proxy/main.go`). CERTIFICATES.md: no hot reload. | Automatic renewal needs either a controlled restart (which closes streams) or a new reload path. Decision E4. |
| G4 | The gateway listener leaf comes from `agentca.ServerTLSCertificate` and is valid for 365 days. | A second renewal that nobody currently does. It must be automated too. |
| G5 | UPG-1 admission (by reading its `upgrade.sh`) requires `tunnex.yml` plus **exactly one** overlay. It also requires the proxy's port bindings to equal exactly `8443/tcp=<bind>:<port>;`. | The demo composition (two overlay files, 8444 also published) is **refused** by UPG-1. If it were adopted, the signed overlay would drop the 8444 publication and collide with Caddy's 443. The demo is therefore not one-click upgradable even after UPG-1. This must be verified on the host and fixed in Phase 1 (decision E12). |
| G6 | Caddy's public-IP mode uses TLS-ALPN only (`disable_http_challenge`). Hostname mode uses Caddy defaults (HTTP-01 and TLS-ALPN). | If anything other than Caddy terminates TLS on 443, Caddy's console ACME breaks in IP mode. A design that keeps Caddy as the console's TLS terminator avoids this. |
| G7 | The README rule for domains: the portal is either exactly the app base hostname, or on an independent known ICANN registrable domain. An HTTPS IP portal is allowed. Other same-site layouts are refused. | Domain validation is binary, and the existing checks are reused unchanged. |
| G8 | `app-access/compose.yml` has the proxy's gateway listener on the private Compose network only. The bundled `node-agent` uses `https://app-proxy:8444`. | The bundled gateway already works. Only remote gateways need a published port. |

## 3. Requirements

1. One flow, one place to look. The customer enters a domain, creates the DNS records
   the product prints, picks a certificate option and confirms. Every later check is
   shown as a named readiness item with a fix.
2. Security unchanged:
   - Same AA-0/AA-7 authority contract, restore barrier, dedicated proxy credential,
     gateway CA trust and SAN.
   - No secret is displayed, logged or stored in a new place readable by the API
     process.
   - The console's public TLS is unchanged.
3. The end state of enablement is exactly the composition that UPG-1 admits. Later
   upgrades are one click.
4. No dependency on Server Access, in either direction. That covers configuration, code
   paths that gate each other, and runner request kinds.
5. Reversible: disable returns the host to its pre-enable shape, except for the retained
   restore volume (which must never be deleted).
6. Non-App Access installations are unaffected. Their rendered Compose configuration is
   byte-for-byte the same as today.

## 4. Design areas and options

### 4.1 Domain choice and validation

The options are fixed by G7:

- **D-a.** Portal equals the app base, for example portal `cp.tunnex.app` with apps
  `*.cp.tunnex.app`. This is the demo layout. One DNS zone, one wildcard record.
- **D-b.** A separate registrable domain for apps, for example portal `vpn.acme.com` with
  apps `*.acme-apps.com`.
- **D-c.** An IP portal (HTTPS on a public IP) with a DNS app base. Apps still need DNS
  names.

The flow pre-selects D-a when the portal is a hostname, because it needs the fewest DNS
changes. It offers D-b as "use a different domain for applications". Validation reuses
the existing domain-settings validator (the same code as Settings → App Access domains).
It refuses any other same-site layout with the existing message.

### 4.2 DNS guidance and checks

The product prints the exact records, for example `*.cp.tunnex.app A 203.0.113.10`,
which is the public address the portal already resolves to. It then checks:

- **Wildcard resolves:** a random label `<nonce>.base` resolves to the expected
  addresses, using the host's resolver.
- **Portal unchanged:** the portal host still resolves as before.
- **Split horizon:** when the CP sees a private address, the check reports "resolves
  to a private address from this host", rather than failing.

No third-party resolver is queried by default, because that would leak the domain.

DNS records are never created by the product (decision E11). Only ACME challenge records
are written, and only in DNS-01 mode.

### 4.3 Public certificates

| Option | How it works | Pros | Cons |
|---|---|---|---|
| **C1. DNS-01 wildcard, provider token** | ACME DNS-01 for `*.base` (plus `base` in D-a only if the proxy must serve it, which it does not with SNI passthrough, see 4.5) | One certificate, no per-app issuance, app hostnames never appear in Certificate Transparency logs, works behind firewalls with no inbound 80 | Needs a DNS API credential, which is the most sensitive input in the flow |
| **C2. HTTP-01 / TLS-ALPN-01 per host** | One certificate per published hostname, issued at publish/readiness time, never on demand from arbitrary SNI | No DNS credential | Every app name is published in public CT logs (an internal-name disclosure); Let's Encrypt rate limits; inbound 80/443 from the internet must be open; a publish depends on ACME being up |
| **C3. Operator-supplied** | The operator places `public-cert.pem`/`public-key.pem` into a host import directory; the product validates and installs them | Works with any CA, including corporate PKI | No automatic renewal. The product can only warn about expiry, and says so plainly. |

**Recommendation:** C1 is the default and C3 is always available. C2 comes later (Phase 4)
with a CT-disclosure warning in the UI. Cloudflare is the first DNS provider. Route 53 and
Google Cloud DNS follow in Phase 4.

**ACME component:** a new fixed-purpose subcommand in the signed app-proxy image,
`tunnex-app-proxy certs`, run as a separate `app-certs` service in the managed overlay.
- It is the only process that holds the ACME account key and the DNS credential.
- It writes the issued pair atomically (write to a new name, fsync, rename) into a
  dedicated volume `<project>_app_public_tls`. The proxy mounts that volume read-only.
- The proxy itself gains no internet egress and no DNS credential.
- Library: `lego` (or `x/crypto/acme` for C2). This is a reviewed dependency addition.

**DNS credential storage (E9):**
- The credential is a host file `<install>/app-access/dns-credential`, owned by root and
  mounted read-only into `app-certs` only, mode 0400 for uid 10001.
- It is **never** in PostgreSQL, so it is never in a database backup. It is never in
  `.env`, never in API memory and never displayed.
- The UI shows only "configured, last used, last result".
- Guidance strongly prefers least privilege:
  1. A Cloudflare token scoped to `Zone:DNS:Edit` on one zone.
  2. Better, a CNAME from `_acme-challenge.<base>` to a dedicated challenge-only zone,
     so the token cannot change the portal's records.

**Automatic renewal:**
- `app-certs` checks every 12 hours. It renews when less than one third of the lifetime
  remains (about 30 days for a 90-day certificate). Let's Encrypt is shortening
  lifetimes, so nothing may assume 90 days.
- It validates the new pair before installing it: chain, key match, SAN covers `*.base`,
  validity window.
- The proxy reloads the public leaf without a restart (decision E4, recommended). It
  watches the volume, validates the pair again, and swaps it atomically through
  `tls.Config.GetCertificate`. A failed validation keeps the old leaf and raises a
  readiness error.
- Failures retry with backoff. They show as readiness items at 21, 14 and 7 days before
  expiry and are audited as `app_access.certificate_renewal_failed`.

**Gateway listener leaf (G4):**
- The leaf is renewed by the host command's `renew` action through the same one-off
  `backupctl app-proxy-certificate` helper. It is triggered by a host systemd timer when
  the leaf is within 30 days of expiry.
- Renewal needs a controlled proxy restart, which happens once a year. Reload is optional
  later.
- The timer runs only the fixed action. It takes no inputs.

### 4.4 Proxy credential and gateway listener certificate without a manual shell

Issuance must run with the DB, the master key and a **writable** marker lock (UPG-1 F4).
The serving API keeps the marker read-only, so issuance cannot happen inside the API
process.

**Vehicle:** the host command, which root runs, either on its own or through the runner.
It uses the same derived one-off override that UPG-1 uses for `app-preflight`. Only the
marker mount is writable; serving mounts stay read-only.
- It runs `backupctl app-proxy-issue --name app-proxy-<host> --output <tmp>` and
  `backupctl app-proxy-certificate --output-dir <tmp>`.
- It moves the files into the managed directory `<install>/app-access/secrets`: owner
  uid 10001, directory mode 0700, files mode 0400.
- It records only fingerprints, serial and expiry in the command's status output.

The existing refusals stay in force: a pending restore, a dirty schema, incomplete
authority, or a missing CA or master key.

**Later (Phase 4, optional):** the proxy enrolls itself like a gateway, generating its
key locally and sending a CSR to the CA. That would remove host-side key files
altogether, but it changes the credential model, so it needs its own paper.

### 4.5 Port 443 sharing, done by the product

**Precondition:** S1 and S2 assume that Caddy terminates the console's public TLS on this
host's 443, which is `TUNNEX_TLS_MODE=direct` with a hostname or public IP.

- **`terminated` installs:** an external load balancer terminates TLS, and Caddy listens
  on `:80`.
- **`http` installs:** there is no public TLS at all.

In those modes, enable refuses sharing. It offers S5, a dedicated address or port for the
proxy, or for `terminated` the load balancer dispatching app hostnames to the proxy with
re-encryption, per the README. The readiness list shows the reason.

| Option | Description | Assessment |
|---|---|---|
| **S1. Proxy owns 443; SNI passthrough for everything that is not an app** | The proxy reads the ClientHello SNI. For `*.base` (excluding the portal host in D-a) it terminates TLS as today. For any other SNI, or none (IP clients), it splices raw TCP to Caddy's TLS listener on an internal port and prepends a PROXY protocol v2 header. Caddy accepts PROXY only from the proxy container's address. | **Recommended.** The console's TLS, certificates and ACME stay in Caddy unchanged, including TLS-ALPN challenges in IP mode (G6), which pass through. The proxy never sees console plaintext or cookies, and needs only the app wildcard. New proxy code, but well bounded: ClientHello parse, splice, PROXY header, a connection cap. |
| S2. Proxy owns 443 and terminates everything; the portal is forwarded to Caddy (existing `CONSOLE_UPSTREAM` dispatcher, used on the demo) | Shipped already | The console's public TLS moves to the proxy certificate, which must then cover the portal (and, in D-b, two zones). Caddy's public ACME is disabled and IP mode breaks. Console cookies are decrypted in the proxy. Kept only to **adopt** existing installations such as the demo. |
| S3. Caddy keeps 443 with layer-4 SNI routing | Needs a custom Caddy build (the `caddy-l4` plugin) | Rejected: a new third-party build in the supply chain. |
| S4. Caddy terminates app TLS and reverse-proxies to the proxy | The README's load-balancer pattern | Rejected: it moves app TLS termination, browser HTTP/2 to the proxy's HTTP/1.1 surface creates chunked bodies the proxy refuses, and the client address is lost. |
| S5. A separate public IP or port for apps | No sharing needed | Supported as an operator-only advanced setting (`TUNNEX_APP_PROXY_BIND_IP`). Not the default, because most VMs have one address. |

**Mechanics (S1):**
- `tunnex.yml` gains `.env`-parameterized Caddy HTTPS publishing,
  `${TUNNEX_EDGE_HTTPS_BIND:-0.0.0.0}:${TUNNEX_EDGE_HTTPS_PORT:-443}:443`. The defaults
  render exactly today's binding.
- On enable, the command sets Caddy to an internal port that is not published (loopback
  publish, or none), and the managed overlay publishes the proxy on public 443.
- On disable, it restores the defaults.
- Port 80 stays with Caddy, which keeps HTTP-01 working for the console in hostname mode
  and the HTTP-to-HTTPS redirect.
- No change for installations without App Access.

### 4.6 Gateways learn the proxy endpoint over the agent channel

This follows SA-UI-1's capability endpoint. A new mTLS agent endpoint,
`GET /agent/app-access/proxy-endpoint`, returns
`{"enabled": bool, "port": 8444, "host": "<optional override>"}`.

- **`enabled`** is true only when all of these hold:
  - the installation has App Access enabled,
  - the operator lock is not set,
  - the gateway's organization has the feature on.
- **`host`** is empty by default. The gateway then dials **the same host it already
  uses for its agent channel**, at the delivered port. No address needs to be entered,
  because gateways already reach the CP. A CP setting can override it for split
  networks; the demo used the VPC IP. The override is validated as a bare hostname or
  IP, with no path or credentials.
- **The gateway** keeps `ServerName` pinned to `tunnex-app-proxy` and trusts only the
  enrollment CA (G1). A wrong or hostile `host` can cause unavailability, but not
  impersonation: an impostor needs a leaf from the agent CA, which the CP already holds.
- **A gateway supervisor** polls every 5 seconds. It starts or stops `ObserveBrowser`
  under a child context without a restart, and applies `DenyControlEndpoint` (G2) to the
  dialled host.
- **Gateway environment is tri-state, as in SA-UI-1:**
  - `TUNNEX_APP_PROXY_URL` set to a URL is a local override and wins.
  - `TUNNEX_APP_PROXY_URL=off` is a gateway-local lock.
  - Unset follows the control plane.
  - Old control planes answer 404, which means "keep the current state". Upgrade the
    control plane first.
- **Reachability as a firewall check:** the supervisor reports
  `proxy_reachable | tls_failed | unreachable` with a timestamp. It uses the existing app
  access result path, or a new small result endpoint. The readiness panel shows it per
  gateway as "Gateway X cannot reach the proxy at <host>:8444. Allow TCP 8444 from this
  gateway to the control plane." No inbound port is opened on any gateway.

### 4.7 Gateway listener exposure

The managed overlay publishes `8444` on `${TUNNEX_APP_PROXY_GATEWAY_BIND_IP:-0.0.0.0}`.

The listener requires a client certificate from the agent CA, with the gateway feature
and assignment checks. That is the same exposure class as the agent channel `8443`, which
is already public. The bind IP narrows it (the demo used the VPC address).

The alternative is to multiplex the gateway listener onto public 443 by SNI
`tunnex-app-proxy` inside the proxy. That removes the extra firewall rule, but mixes
browser and gateway admission limits on one socket. It is deferred to Phase 4 as an option
(E6).

### 4.8 Readiness checks (UI and `status`)

Each check is shown as a named item with its state and a one-line fix. It is computed by
the API from authority, settings, gateway reports and proxy reports, or by the host
command where noted.

1. **Signed proxy available.** The installed release has a signed `app-proxy` digest
   (`releaseverify -require-app-proxy`). Checked by the host.
2. **Restore barrier clear and authority completed.** Uses `app-preflight`.
3. **Domain valid.** Uses the existing validator.
4. **DNS.** The wildcard resolves, and the portal resolves (4.2).
5. **Public certificate.** It is present, covers `*.base`, and is not expired. Shows days
   left, the mode (DNS-01, files) and the last renewal result.
6. **Gateway listener certificate.** Shows days left.
7. **Proxy ready.** `/readyz`, which means a recent authority claim.
8. **Port 443 shared.** The TLS mode is `direct`, or S5 is configured. The proxy owns
   public 443, and the console is reachable through passthrough. Checked by the host
   with a loopback SNI probe.
9. **Per gateway.** Endpoint delivered; reachable (4.6).
10. **Organization feature on.** Then, per app, the existing readiness and publish checks.

A green list does not claim that a specific app is published. That stays with the
existing app readiness and publication checks (README: "a settings save is not readiness
proof").

### 4.9 Vehicle: installer flag, host command, dashboard

The host side has to change for enablement: compose files, a privileged port, a root-owned
secrets directory, and a systemd timer. So the dashboard cannot enable App Access by
writing a database row, as SA-UI-1 does.

- **Host command.** `tunnex-app-access enable --domain <base> --cert dns01-cloudflare|files [--gateway-host H]`.
  - It is shipped in the signed release and installed next to `upgrade.sh`. With UPG-2
    it is taken from the signed API image, not from raw GitHub.
  - It is idempotent and resumable. Each step checks before it acts.
  - It prints DNS records and readiness at the end. `status`, `renew` and `disable`
    share the same code.
- **Installer flag.** `install.sh --app-access --app-domain <base> ...` calls the same
  command after the base install is healthy. D4 (reinstall over App Access is refused)
  is unchanged.
- **Dashboard (Phase 3).** Settings → App Access → "Turn on".
  - The API validates the input and writes a bounded request file. The new request kind
    is `action=app_access_enable|app_access_disable|app_access_renew`, with
    enumerated or validated fields only: domain, certificate mode, gateway host. It
    carries no secrets and no free text.
  - The existing root runner (`upgrade-runner.sh` pattern: snapshot, validate, fixed
    helper) executes the host command.
  - Progress and the readiness list come back through the status file.
  - The DNS credential is not entered in the browser (E9). The UI tells the operator
    which one host command places it, or offers C3.

### 4.10 Who can enable: threat notes

**Authorization:**
- Server administrators only (`users.cp_admin`), with a human browser session. Machine,
  agent and bearer principals are refused.
- Recent re-authentication with SA-UI-1's rules: a password with its own failure budget,
  fresh MFA within 5 minutes, or a fresh `sso_mfa`.
- CSRF and an `expected_version`.
- Each change is audited as `app_access.installation_enable_requested`, `…_completed`,
  `…_failed` or `…_disabled`. The metadata covers domain, certificate mode, gateway host
  and the result, never material.
- Org owners cannot enable. They keep the per-organization toggle.

**Operator hard-off:** `TUNNEX_APP_ACCESS_LOCKED=true` in `.env`. The dashboard shows
"locked by server environment", the runner refuses enable requests, and the agent
endpoint returns `enabled:false`.

**Step-up code:** reuse SA-UI-1's re-authentication **pattern**, not its branch. If a
shared helper is extracted, it lives in a neutral package (`internal/stepup`), so neither
feature's merge blocks the other.

**Secrets:**
- The proxy credential and the gateway key never leave the host's managed directory and
  never appear in stdout, the status file, logs or audit.
- The DNS credential is a host-only file read by one process (4.3).
- The ACME account key lives in the `app-certs` volume.

**Threats considered:**
- **Hijacked admin session.** Step-up re-authentication and audit apply. Enabling
  publishes nothing by itself: apps still need org opt-in, grants and readiness.
- **Hostile request file.** The runner accepts only enumerated keys and validated
  values, as with upgrades.
- **Compromised CP.** It can already mint gateway-CA certificates. A delivered endpoint
  adds nothing beyond availability. The gateway-local lock remains the mitigation.
- **DNS credential theft.** Least-privilege guidance and challenge-zone delegation apply.
  The file stays out of backups, and rotation means replacing the file.
- **Passthrough abuse.** Passthrough only splices to the fixed internal Caddy address,
  never to a destination derived from SNI. Passthrough connections have their own cap.
  PROXY headers are accepted by Caddy only from the proxy's container address.

### 4.11 Disable and rollback

`disable` (from the host command or the dashboard):

1. Stop and remove `app-proxy` and `app-certs`.
2. Restore Caddy's public 443 (defaults in `.env`) and recreate Caddy. The console is
   briefly unavailable (seconds).
3. Revoke the dedicated proxy credential (`app-proxy-revoke`). A later enable issues a
   new one.
4. The agent endpoint returns `enabled:false`, and gateways stop their browser pools
   within about 5 seconds.
5. Remove `app-access` from `COMPOSE_PROFILES`. Keep `app-access.yml` and the
   `<project>_app_restore` volume, because the API keeps the marker mount. Removing the
   overlay entirely is operator-only and documented, because it changes the API's
   restore-barrier wiring.

Kept: app definitions, publications (they become unreachable), grants, events,
certificates and the DNS credential. A later enable reuses them, subject to fresh
readiness.

If enable fails partway, the command undoes its own completed steps in reverse order
(stop the proxy, restore Caddy's 443). It leaves issued files in the private directory for
the next attempt, except a credential, which is revoked. The console is never left without
a 443 listener: the command restores Caddy's binding before it reports failure.

### 4.12 Upgrade compatibility (UPG-1) and independence

**Invariant: the enabled end state is exactly UPG-1's admission predicate:**
- managed `app-access.yml` with its hash in `.env`
- `<project>_app_restore`
- the secrets directory from `.env`
- base domain in `.env`
- `app-access` in `COMPOSE_PROFILES`

UPG-1's admission changes so that the proxy's port set is the managed form: public
`8443/tcp` and gateway `8444/tcp`, each from `.env`. It also accepts the new `app-certs`
service and `app_public_tls` volume.

Named tests:
- enable, then UPG-1 upgrade passes
- enable, disable, then upgrade passes
- the demo's adopted layout, then upgrade passes

**Independence:**
- No Server Access setting is read, required or changed by any App Access step, and the
  reverse also holds.
- The runner request kinds are distinct.
- The readiness lists are separate.
- Each feature's lock is its own.

**Upgrade ordering:** control plane before gateways, as in SA-UI-1. Gateways on an old
agent keep using their environment variable.

### 4.13 What stays operator-only

- Creating DNS records.
- Cloud firewall and security-group rules: the product checks and explains them, but
  cannot change them.
- Placing the DNS credential file, or certificate files in C3.
- `TUNNEX_APP_ACCESS_LOCKED` and the gateway-local `off` lock.
- Restore and recovery (`app-access-restore.py`, AA-7: never automatic).
- Removing the App Access overlay and restore volume entirely.
- Kubernetes/Helm and HA control planes (UPG-1 D6). The Helm chart keeps its explicit
  values.
- Dedicated IP or port layouts (S5).

## 5. Recommendation

Adopt **S1 + C1/C3 + agent-channel endpoint delivery + one host command driven by
installer, CLI and (later) dashboard**. Phase 1a delivers endpoint delivery, `adopt`
and a validated `renew`. Phase 1b adds automatic DNS-01 renewal and hot reload of the
public leaf.

This removes every manual step except DNS records, the cloud firewall rule and (for C1)
placing a scoped DNS credential once. It leaves the security model unchanged, and its end
state is upgradable by UPG-1.

## 6. Phased delivery

**Phase 1a: the smallest valuable slice (deadline before 2027-02-01, ahead of the demo
certificate expiry).**

Control-plane and gateway release:
- the agent `proxy-endpoint` endpoint, CP setting and gateway supervisor (tri-state
  environment, `off` lock, reachability report)

Managed files:
- the overlay publishes the gateway port from `.env`
- `tunnex.yml` gets parameterized Caddy HTTPS publishing (defaults unchanged). This is
  needed so the S2 layout no longer needs a second overlay.
- UPG-1 admission accepts the managed port set. This is a cross-story change to UPG-1.

Host:
- `tunnex-app-access adopt` for the demo's S2 layout: it checks the identity of the
  barrier volume, secrets and project, then rewrites the composition to the managed
  overlay and keeps S2
- a stop-gap `tunnex-app-access renew`: it takes a renewed pair (the operator's certbot
  output or files), validates chain, key, SAN and validity, installs it into the managed
  directory, and does a controlled proxy restart. It does the same for the gateway leaf
  through `backupctl app-proxy-certificate`. There is no new dependency, and a host
  timer can run it.

Outcome: the demo gateways drop their environment variables and host mappings, renewal
is one command, and the demo becomes one-click upgradable.

**Phase 1b: automatic renewal.**
- the `app-certs` service (DNS-01 Cloudflare and file import), with renewal at one third
  of the lifetime remaining
- proxy hot reload of the public leaf
- the read-only readiness panel (items 1–10)

**Phase 2: one-command enable.**
- `tunnex-app-access enable|status|disable`: issuance into the managed directory, S1
  passthrough (proxy SNI splice, Caddy PROXY protocol listener), DNS checks.
- Installer flag `--app-access`.
- Release notes.

**Phase 3: dashboard enable.**
- The runner request kinds.
- Settings → App Access turn on/off, with step-up, audit and the lock.
- Progress through the status file.

**Phase 4: breadth.**
- C2 per-host ACME with the CT warning.
- More DNS providers.
- SNI multiplexing of the gateway listener onto 443 (E6).
- Folding App Access into `tunnex.yml` (UPG-1 Option C).
- Proxy self-enrollment.

## 7. Test plan

- **Unit:**
  - Domain validation reuses the existing tests, adding D-a, D-b and IP portal cases.
  - The endpoint `enabled` truth table: installation × lock × organization.
  - The gateway tri-state decision function.
  - Supervisor start and stop with a fake poller.
  - The SNI router: app SNI is terminated; portal, unknown, missing and IP-literal SNI
    pass through; malformed ClientHello closes; the PROXY v2 header is correct; the
    passthrough cap applies.
  - Certificate validation before swap: wrong key, SAN miss, expired, future NotBefore,
    broken chain. Each keeps the old leaf.
- **Agent channel:** the endpoint requires a gateway identity; old-CP 404 handling.
- **Gateway with a real TLS listener (G1):** a pool dialling `https://127.0.0.1:<port>`
  with pinned `ServerName` succeeds against a `tunnex-app-proxy` leaf and fails against
  any other SAN or CA. This proves `--add-host` is unnecessary.
- **Proxy:** hot reload under live traffic. An existing stream survives, and new
  handshakes present the new leaf. A failed reload keeps serving the old leaf and raises
  readiness.
- **`app-certs`** against Pebble (a local ACME test server) with a fake DNS provider:
  issue, renew at one third of the lifetime, retry, and file permissions.
- **Host command** (contract tests under `sh`/`dash` with a Docker fake, like
  `upgrade_apply_contract_test.sh`):
  - enable is idempotent and resumes after each failure point
  - failure rollback restores Caddy's 443
  - secrets have mode 0400 and uid 10001, and nothing secret reaches stdout or status
  - a pending marker refuses
  - an unsigned proxy refuses
  - `adopt` on the demo layout refuses on identity mismatch
- **Compose:** `docker compose config` shows a non-App Access installation renders
  byte-identically before and after the `tunnex.yml` change. The managed overlay merges
  with S1 ports.
- **UPG-1 interplay:** enable then upgrade; enable, disable, upgrade; adopt (demo) then
  upgrade.
- **Independence:** App Access enable and disable with Server Access on, off and locked,
  and the reverse.
- **Local walk** (owned harness, loopback): fresh install, enable with C3 files, a
  gateway with an empty environment picks up the endpoint, an app publishes, the console
  still works through passthrough, disable, re-enable.
- **Must verify before building:**
  - The pinned Caddy digest includes the `proxy_protocol` listener wrapper. If it does
    not, console client addresses collapse to the proxy's address, and S1 needs a
    fallback.
  - An IP URL with a pinned `ServerName` works from a real gateway (G1).
  - On the demo host: the UPG-1 refusal of its composition (G5).
- **Isolated test CP before release:** DNS-01 with a scoped Cloudflare token on a test
  zone, a real renewal (short-lived profile), a remote gateway behind a firewall (the
  reachability item turns red, then green after the rule).

## 8. Founder decisions (with recommendation)

- **E1. Vehicle.**
  - **Recommendation:** one signed host command, driven by the installer flag and the
    CLI (Phase 2), and by the dashboard through the existing root runner with new
    bounded request kinds (Phase 3).
  - The dashboard cannot be a pure database toggle, because enablement mutates the host.
- **E2. Sharing port 443.**
  - **Recommendation:** S1 SNI passthrough, so the console's TLS and ACME stay in Caddy.
  - S2 (the demo's terminate-and-forward) is supported only for adopted installations.
- **E3. Certificate options and default.**
  - **Recommendation:** default to C1, DNS-01 wildcard (one certificate, no
    app-hostname disclosure in CT logs), with Cloudflare first and automated by
    `app-certs` in Phase 1b. C3 operator files are always available.
  - Phase 1a ships only the validated `renew` install step with a restart.
  - C2 per-host comes in Phase 4, with a CT-disclosure warning.
- **E4. Renewal without interruption.**
  - **Recommendation:** add hot reload of the public leaf to the proxy (validate, then
    swap atomically) in Phase 1b. Phase 1a renews with a controlled restart.
  - The gateway listener leaf is renewed yearly with a controlled restart.
- **E5. Gateway endpoint delivery.**
  - **Recommendation:** deliver it over the mTLS agent channel. By default it uses the
    gateway's own agent host and port 8444, with an optional CP override.
  - Gateway environment is tri-state (URL overrides, `off` locks, unset follows).
  - Control plane first, then gateways.
- **E6. Gateway port exposure.**
  - **Recommendation:** publish 8444 on all addresses by default (mutual TLS, the same
    class as agent 8443), narrowed by `TUNNEX_APP_PROXY_GATEWAY_BIND_IP`.
  - SNI multiplexing onto 443 waits until Phase 4.
- **E7. Who can enable.**
  - **Recommendation:** server administrators with a human session, SA-UI-1 step-up
    rules and audit, plus a `TUNNEX_APP_ACCESS_LOCKED` operator hard-off.
  - Org owners keep only the per-organization toggle.
- **E8. Disable semantics.**
  - **Recommendation:** stop the proxy, return 443 to Caddy and revoke the proxy
    credential. Keep apps, publications (unreachable), events, certificates and the
    restore volume.
  - Full removal is operator-only.
- **E9. DNS credential storage.**
  - **Recommendation:** a host-only file, mode 0400, read only by `app-certs`. Never in
    the database, `.env`, the API, backups or the UI.
  - It is placed by one host command. Prefer a zone-scoped token, or `_acme-challenge`
    CNAME delegation to a challenge-only zone.
  - Browser entry is not offered (revisit after Phase 3).
- **E10. Fold App Access into `tunnex.yml` (UPG-1 Option C).**
  - **Recommendation:** not now. Keep the managed overlay and revisit in Phase 4.
- **E11. Should the product create DNS records with the token?**
  - **Recommendation:** no. Only ACME challenge TXT records. The customer creates the
    wildcard A record.
- **E12. The demo's current composition.**
  - **Recommendation:** treat it as **not one-click upgradable today**.
  - By reading UPG-1's admission, two overlay files and the extra 8444 port binding
    refuse it. Adoption by the signed overlay would also collide with Caddy's 443 and
    drop the 8444 publication.
  - Verify on the host. Ship `adopt` in Phase 1, and until then upgrade the demo only
    through a reviewed manual procedure.

## Founder rulings, 2026-11-24

The founder accepted every recommendation ("do recommended"), under the standing
principles: no user confusion, security unchanged, one-click upgrades, no dependency
between App Access and Server Access.

- **E1, vehicle:** accepted. One signed host command, `tunnex-app-access`, driven by the
  installer flag and the CLI first, and by the dashboard through the root runner with
  bounded request kinds in Phase 3.
- **E2, sharing port 443:** accepted. SNI passthrough (S1), so the console's TLS and ACME
  stay in Caddy. Terminate-and-forward (S2) is kept only for adopted installations.
- **E3, certificates:** accepted.
  - Default is a DNS-01 wildcard, Cloudflare first, automated by `app-certs` in Phase 1b.
  - Operator-supplied files are always available.
  - Phase 1a ships the validated `renew` step with a restart.
  - Per-host ACME comes in Phase 4, with a CT-disclosure warning.
- **E4, renewal:** accepted. Hot reload of the public leaf in Phase 1b, a controlled
  restart in Phase 1a, and the gateway listener leaf renewed yearly with a restart.
- **E5, gateway endpoint:** accepted. Delivered over the mTLS agent channel, by default
  the gateway's agent host on port 8444, with an optional CP override. The gateway
  setting is tri-state, and the control plane is upgraded first.
- **E6, gateway port exposure:** accepted. 8444 is published on all addresses by default,
  narrowed by `TUNNEX_APP_PROXY_GATEWAY_BIND_IP`. SNI multiplexing onto 443 waits for
  Phase 4.
- **E7, who can enable:** accepted. Server administrators with a human session, SA-UI-1
  step-up rules and audit, plus the `TUNNEX_APP_ACCESS_LOCKED` operator hard-off.
- **E8, disable:** accepted. Stop the proxy, return 443 to Caddy and revoke the proxy
  credential. Keep apps, publications, events, certificates and the restore volume.
- **E9, DNS credential:** accepted. A host-only 0400 file read only by `app-certs`, never
  in the database, `.env`, the API, backups or the UI. A zone-scoped token or
  `_acme-challenge` delegation is preferred.
- **E10, folding into `tunnex.yml`:** accepted. Not now; revisit in Phase 4.
- **E11, DNS records:** accepted. The product writes only ACME challenge records.
- **E12, the demo's composition:** accepted. Treat it as not one-click upgradable until it
  is verified on the host, and ship `adopt` in Phase 1a.

### Added to Phase 1a by founder ruling (2026-11-24)
- **Dashboard forward-fix re-run.** UPG-1 D2 makes re-running the upgrade the default response to a failed upgrade, and UPG-2 U4 allows a same-SHA re-run. The API currently refuses any dashboard upgrade target whose sequence is not newer than the installed one, so a forward fix is only possible from the command line. Phase 1a lets a server administrator re-run the same verified release from the dashboard after a failed upgrade (same sequence AND same source SHA only; never older), with the same step-up and audit as other host actions. Verify the current refusal on a host first.
