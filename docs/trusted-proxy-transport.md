# Trusted proxy transport and browser sessions

AI transport policy uses the request's observed HTTP or HTTPS connection. It
never treats `APP_BASE_URL=https://...` as evidence that a request arrived over
TLS. `APP_BASE_URL` remains the canonical origin for links and IdP callbacks.

## Hosted Docker deployment

The canonical deployment sets `TUNNEX_TRUSTED_PROXIES=nginx`. The API accepts one
`X-Forwarded-Proto: http` or `https` value only from that immediate peer, resolving
its current container address. Caller-controlled forwarded IP headers do not
select a trusted peer. Missing, malformed, or untrusted forwarding information
cannot grant HTTPS access. A TLS-encrypted internal proxy connection also uses
the trusted proxy's original client scheme.

Caddy is the public edge and replaces client-supplied forwarding headers. nginx
preserves Caddy's observed scheme across the internal HTTP hop. Keep nginx and
the API unexposed: publish only Caddy's ports. If another TLS terminator precedes
Caddy, configure that complete proxy chain explicitly; changing the canonical
URL does not supply transport evidence.

## Docker with an external TLS load balancer

For `TUNNEX_TLS_MODE=terminated`, add `TUNNEX_EDGE_TRUSTED_PROXIES` to the
installation `.env` before upgrading to a release with transport controls.
Use space-separated IPv4/IPv6 addresses or CIDRs of the immediate load-balancer
peers as Caddy actually sees them, accounting for source NAT. For example:

```dotenv
TUNNEX_TLS_MODE=terminated
TUNNEX_EDGE_TRUSTED_PROXIES=192.0.2.10/32 2001:db8::10/128
```

These are documentation addresses; replace them with your verified peers. The
list accepts numeric IPs/CIDRs only. Hostnames, comma-separated lists, embedded dotted IPv4
notation in IPv6, shell syntax, and all-address `/0` ranges are rejected. Use narrow dedicated
ranges; do not trust an entire shared private network. Restrict VM port 80 to the
same peers and configure the load balancer to **replace** incoming
`X-Forwarded-Proto` with its actual client scheme.

Caddy accepts requests only from those peers, preserves their reported `http`
or `https` scheme, and rejects missing or invalid scheme headers. `/healthz`
permits a trusted peer's health check without that header. HTTPS therefore keeps
secure cookies and AI access; real HTTP still requires the saved server-admin
opt-in. An arbitrary caller cannot gain HTTPS privileges by forging a header.

Fresh installs can supply the same variable to `install.sh`; interactive
terminated installs ask for it. The updated upgrade helper refuses missing
or invalid peers before replacing `.env`, Compose, or the running deployment.
For installations still using an older upgrade helper, set and verify this list
before starting the upgrade; an old helper cannot perform the new preflight.
Set the list and retry. The check applies only to target releases that support
edge proxy trust; selecting an older signed release retains its existing
behavior. Direct HTTPS and direct public-IP HTTPS require no proxy list.

## Kubernetes ingress: configure before upgrading

The chart creates an internal headless Service selecting only this release's
edge pods. The API trusts those current pod addresses, not the edge ClusterIP
or every address in the cluster. Edge pods accept the original client scheme
only from `edge.trustedIngressCIDRs`.

Set that list to the ingress-controller source IPs or dedicated CIDRs actually
observed by the edge pods. Account for any source NAT in your network. Do not
copy an entire pod/private network just because the controller lives there.
Configure the ingress controller to replace client-supplied
`X-Forwarded-Proto` with its observed client scheme. TLS termination upstream
of the ingress needs the same explicit trust configuration at that hop.

```yaml
edge:
  trustedIngressCIDRs:
    - 192.0.2.10/32 # Example only: replace with your verified ingress peer.
```

The list defaults to empty. Requests from other peers retain the edge's actual
HTTP scheme, regardless of forged forwarding headers, and the server's HTTP AI
policy applies. With chart-managed TLS ingress enabled, Helm rejects an empty
list before deployment. For an externally managed ingress, supply the same list
before upgrading; its TLS configuration cannot be inferred from this chart.

Verify both HTTPS and HTTP behavior, including requests with a forged
`X-Forwarded-Proto: https`, before directing users to the upgraded console.
Updating the peer list changes the edge configuration checksum and rolls its
pods. The headless peer service publishes not-ready pod addresses so the edge's
API-backed readiness probe does not create a DNS/readiness cycle.

## Validate a Docker proxy change

Run `python3 deploy/edge-ip-tls_test.py` for startup and input validation. With
Docker available, `TUNNEX_TEST_CADDY_RUNTIME=1 python3 deploy/edge-ip-tls_test.py`
also checks the generated configuration using the pinned Caddy image and tests
trusted HTTPS/HTTP, forged or duplicate scheme headers, and health probes in
network-isolated disposable containers.

## Session migration

Configured proxy deployments use separate HTTP and HTTPS session cookies.
HTTPS sessions use a `__Host-` cookie with `Secure`, `HttpOnly`, `Path=/`, and no
Domain; HTTP cannot overwrite that browser cookie. HTTP uses its own HttpOnly
cookie. Both retain SameSite=Lax and the existing CSRF header requirement.

Existing sessions require a new login when enabling this mode. Legacy cookie
names are not accepted as a migration fallback because an HTTP response could
plant them into a subsequent HTTPS login. Deployments without proxy
configuration retain the existing `TUNNEX_COOKIE_SECURE` cookie behavior;
forwarded headers remain untrusted for AI transport policy.

Password and MFA login work independently on each origin. When SSO callbacks
are registered against an HTTPS canonical URL, start SSO, connection tests, and
account linking from that HTTPS console. HTTP receives an instruction to open
HTTPS, preserving the browser binding across the IdP callback.
