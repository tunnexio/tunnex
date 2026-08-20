# F11 — Alerts, webhooks and SIEM box-walk

Status: **SATISFIES the Slack and generic-webhook wire path; PagerDuty is a
NAMED SUBSTITUTE, not a satisfied wire leg.**

The AWS DEV walk used control plane `54.79.53.95`, managed-agent host
`3.26.228.109`, schema 100, and the deployed images recorded in
`walk-artifacts/F11/20260820/walk-record.md`. No reusable endpoint credential,
sealed value, payload, cookie, or token is committed.

## Acceptance

- [x] Alerting is organization opt-in and owner-configured.
- [x] Active Slack and generic webhook destinations expose only their host and
      keyed fingerprint in the recorded evidence.
- [x] Stopping the managed runtime past the fixed one-minute threshold emitted
      `agent.offline`; Slack returned HTTP 200 and the generic receiver HTTP 204.
- [x] Delivery rows and append-only attempt rows both record one successful
      attempt; the user independently confirmed the Slack message arrived.
- [x] Restarting the runtime restored the server-backed connected state. A
      fresh UI load no longer assumes connected while the runtime check is in
      flight; failed checks withdraw stale connected truth.
- [x] The control-plane services, node agent and managed runtime were healthy
      after the walk; schema 100 was clean.
- [ ] Send through a real PagerDuty Events v2 routing key. No key was available
      in this environment. Formatter, trigger-only lifecycle, stable dedup key,
      secret handling and failure reporting are covered by tests, which
      **SUBSTITUTE for but do not SATISFY** this wire leg. Named trigger: the
      first PagerDuty routing key configured for Tunnex, before calling F11
      fully wire-satisfied.

## Scope notes

The generic webhook is F11's typed alert/SIEM path; broad audit-stream export
remains S7.5.1. PagerDuty and Opsgenie auto-resolve remain F11.1. The producer
threshold is one minute, not three minutes.

## Evidence

- `walk-artifacts/F11/20260820/walk-record.md`
