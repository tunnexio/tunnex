# F11 AWS DEV walk record — 2026-08-20

## Provenance and health

- Control plane: `54.79.53.95`.
- Managed-agent host: `3.26.228.109`.
- Deployed API image: `tunnex-f11-api:onecommand-20260820`.
- Deployed web image: `tunnex-f11-web:onecommand-20260820`.
- PostgreSQL schema: version `100`, `dirty=false`.
- API, web, nginx, PostgreSQL, Redis and node-agent containers reported up;
  health-checked services reported healthy.
- After restart, `tunnex-agent-runtime.service` reported
  `ActiveState=active`, `SubState=running`, `NRestarts=0`,
  `ExecMainStatus=0`, with active-enter timestamp
  `2026-08-20 12:03:15 UTC`.

The deployed walk image predates the final review-fold commits `ba3fc3c` and
`8bd4046`. Those narrow retry-state, error-sanitization and UI truth folds are
covered by exact-head local generation, Go and web gates; they are not claimed
as post-fold live deployment evidence.

## Secret-free destination evidence

The live destination query deliberately selected only kind, name, display
host, keyed fingerprint and archive state:

| Kind | Name | Display host | Fingerprint | Active |
| --- | --- | --- | --- | --- |
| webhook | F11 dev receiver | `f11-alert-receiver:18080` | `8bf3bd7a7439` | yes |
| slack | slack-test | `hooks.slack.com` | `09a46280e3b3` | no |
| slack | slack | `hooks.slack.com` | `09a46280e3b3` | yes |

No endpoint URL, sealed endpoint, payload or reusable credential was selected
or recorded.

## Offline transition and delivery

1. The managed runtime was stopped and remained inactive beyond the fixed
   one-minute heartbeat boundary.
2. The UI initially exposed the stale-connected defect; the F11 fold changes
   the unknown initial state to checking and withdraws connected state after a
   failed poll.
3. The producer emitted `agent.offline` to both active subscribed destinations.
4. PostgreSQL recorded sent deliveries with exactly one attempt each. Slack
   attempts returned HTTP 200; the generic receiver attempts returned HTTP 204.
5. The user confirmed that Slack alerts arrived.
6. The managed runtime was started again. The server-backed UI status returned
   to connected, and the final read-only service check showed it running with
   zero restarts.

The final secret-free query contained 24 historical `agent.offline` attempt
rows from repeated walk checks: 12 Slack HTTP-200 outcomes and 12 generic
webhook HTTP-204 outcomes. Every row was `state=sent`, `attempts=1`,
`outcome=sent`.

## PagerDuty substitute

No PagerDuty routing key was available. The real-provider leg was not invented
and is not marked satisfied. Tests cover Events v2 shaping, trigger-only
lifecycle, stable deduplication, sealed routing-key handling, bounded retry and
safe failure reporting. Named live trigger: the first PagerDuty routing key
configured for Tunnex.

## Final state

- Shared AWS DEV services remained healthy.
- The managed runtime remained active and enabled.
- Live destinations and delivery history were retained intentionally; this
  record performs no production cleanup or mutation.
