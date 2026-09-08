# Test Connect response diagnostics — 2026-09-08

User request: replace the generic failed-test toaster with the actual response
code and an appropriate explanation, including privately deployed Foundry
endpoints that cannot be reached.

## Locked decisions

- Extend the existing optional Test Connect result with a bounded failure object:
  `kind`, `source` and optional numeric `http_status`. The existing `status` and
  `duration_ms` contract remains compatible. HTTP 200 on this operation is its
  envelope, not evidence that the provider succeeded.
- Record an HTTP status only when an HTTP response was observed, distinguishing
  a provider response from a CONNECT proxy response. Connection/DNS/TLS failures
  and timeouts have no invented provider status. API transport errors retain
  their actual Tunnex HTTP status in the UI.
- Capture sanitized categories at the existing locked transport before SDK
  exception wrapping loses the cause. Never forward arbitrary exception text,
  upstream bodies, headers, URLs, keys, stack traces or cloud error payloads.
- Carry the same result through draft and saved-credential tests, including the
  private engine operation. Existing authorization, revision checks, timeouts,
  retry limits and serving/model scope remain unchanged. Older engines/bridges
  without diagnostic fields continue to produce the existing safe fallback.
- Display the same explanation in the toaster and inline form error. HTTP 403
  means access was rejected; it does not prove a network route is absent.
  Network explanations point to private routing, firewall/proxy and DNS access.
- No cloud network changes or actual credential tests are required to implement
  the error display. Verify synthetic provider 401/403/404/429/5xx responses,
  proxy rejection, socket failure, timeout and secret-redaction boundaries.

No schema migration, new dependency or new service. This is the user's requested
diagnostic behavior, not authorization to change private endpoint access.
