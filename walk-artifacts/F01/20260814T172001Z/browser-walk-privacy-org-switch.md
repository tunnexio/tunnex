# F01 affected-path authenticated wire walk

Date: 2026-08-14 UTC
Environment: isolated `f01-browser` compose project through the reversible Colima SSH forward
Redaction: emails, cookies, request IDs, and credentials are omitted; only field presence/counts are retained.

## List wire shaping

The authenticated fixture accounts queried `GET /api/v1/organizations/<demo-org>/agents` through the local tunnel. The response body was parsed locally and reduced to the following redacted shape:

```json
{
  "owner": {
    "rows": 2,
    "owner_email_keys": 2,
    "sample_owner_email": "<redacted>",
    "keys": ["address", "config_issued", "device_id", "gateway_name", "gateway_reporting", "last_handshake_at", "name", "node_id", "online", "owner_email", "rx_bytes", "status", "tx_bytes", "unattributable"]
  },
  "manager": {
    "rows": 2,
    "owner_email_keys": 2,
    "sample_owner_email": "<redacted>",
    "keys": ["address", "config_issued", "device_id", "gateway_name", "gateway_reporting", "last_handshake_at", "name", "node_id", "online", "owner_email", "rx_bytes", "status", "tx_bytes", "unattributable"]
  },
  "plain_member": {
    "rows": 2,
    "owner_email_keys": 0,
    "keys": ["address", "config_issued", "device_id", "gateway_name", "gateway_reporting", "last_handshake_at", "name", "node_id", "online", "rx_bytes", "status", "tx_bytes", "unattributable"]
  }
}
```

The member `/agents` DOM had no `Authorised by`, owner email, `Actions`, or `Remove`; the manager/owner DOM included attribution and actions. No CSS-only hiding was used.

## Org switch

The released route test held the target `/nodes` and `/agents` responses in flight. Immediately after switching orgs, the old gateway option and old roster/profile/runtime facts were absent and the page showed `Loading…`. Releasing the target response produced only the target gateway/options and target data. This is also covered by `apps/web/test/agentsruntimewiring.test.tsx`.

## Boundary and cleanup

- API and web images were rebuilt only for `f01-browser`; retained named volumes were not removed.
- The SSH forward was terminated after capture.
- This artifact is live route/wire evidence for list privacy and org-switch clearing. Unit tests and the PostgreSQL lifecycle/rollback/data-plane proofs remain SUBSTITUTES, never SATISFIES.
