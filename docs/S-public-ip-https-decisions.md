# Public-IP HTTPS for hosted AI access

Status: implementation on `codex/public-ip-https`.

## Problem

The original AWS control plane upgraded successfully to v0.1.36, but the
Models page remains unavailable because its public HTTP origin cannot safely
accept provider credentials. Container health did not prove usable AI access.

## Decisions

- Locked: retain the HTTPS requirement for public AI credential entry. Do not
  turn on the private-HTTP exception for an Internet-facing endpoint.
- Locked: support direct HTTPS for public IPv4 addresses using the existing
  pinned Caddy 2.11.4 edge and Let's Encrypt's short-lived certificate profile.
  Explicit ACME configuration and default SNI are required for IP certificates;
  Caddy's normal IP default uses a local CA. Validate using TLS-ALPN on port 443.
- Locked: derive a `TUNNEX_EDGE_PUBLIC_IP` value from the validated public URL
  for direct public-IPv4 deployments. Generate the Caddyfile within the canonical
  Compose service, retaining Caddy's certificate volumes and automatic renewal.
  DNS-based direct TLS and externally terminated TLS retain their behavior.
- Locked: installation and upgrade preserve the same URL contract. A patched
  upgrade helper refuses a target Compose file lacking the IP-TLS capability
  before replacing a working deployment. No review-only override is required.
- Locked: preserve provider encryption keys, database and engine volumes,
  egress rules, and the original gateway. Add the public IP to egress protected
  hosts before enabling AI. Back up deployment configuration before changes.
- Locked: prove a trusted certificate, safe API availability, and the actual
  Models page on the existing CP; capture only non-secret evidence.
- Rejected: allowing public HTTP for provider credentials or restoring the
  old review-only deployment overlay; both evade the persistent deployment fix.
- Deferred: direct IPv6 certificate support and automatic handling of an EC2
  public-IP change. Operators must update the origin when the address changes;
  this change does not allocate a new AWS resource.

## Validation

Run the public URL, edge TLS, installer bootstrap, and upgrade contract tests.
Verify the rendered Caddy configuration with the pinned image. On the existing
CP, verify normal trust-chain validation, AI settings availability, Models UI,
key/volume/gateway preservation, and certificate persistence. Record wire
results under `walk-artifacts/` during the work. Publish a reviewable PR; merging
and tagging a release remain separate user actions.

## Review dispositions

- Accepted: validate the complete direct-IPv4 authority, including port syntax,
  before installing; reject empty or repeated colon suffixes consistently.
- Accepted: add public-URL and edge-startup contracts to CI's installer step.
- Accepted: installer reruns must check the preserved installed origin as well
  as newly supplied input before replacing a public-IP-capable deployment.
