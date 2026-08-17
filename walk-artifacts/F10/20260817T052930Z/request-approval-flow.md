# Request and approval flow

- Organization F10 opt-in started Off. Enabling returned persisted `enabled=true`
  with zero live requests and created no grant.
- A uniquely named disposable requester group and destination were created. A
  uniquely named managed agent was enrolled through the supported one-time
  bootstrap API, approved, assigned to that group, and connected through the
  existing healthy gateway.
- Runtime proof before the request: service active/enabled, restart count zero,
  WireGuard handshake nonzero, control-plane health `ready`, freshness true,
  and desired/attempted/applied revisions `1/1/1`.
- Scoped-member Test Access began `denied` with `no_matching_grant`.
- Create returned 201/pending with no expiry and no policy rule. Exact create
  replay returned 200 with the same request id. A changed payload using that
  idempotency key returned 409 `agent_access_request_conflict`.
- Deleting the destination while pending and approved returned 409
  `agent_access_destination_in_use` with an explicit live-request count.
- Approval returned 200 and materialized exactly one ordinary policy rule. Its
  expiry was exactly five minutes after the server approval timestamp; exact
  approval replay returned the same request/rule.
- After the normal gateway reconcile, F08 Test Access changed from `denied` to
  `allowed`: agent lifecycle, runtime, gateway reporting, destination route,
  matching policy and applied-policy revision all passed.
