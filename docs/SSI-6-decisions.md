# SSI-6 — site changes reach gateways promptly; the hub is stable and audited

Epic: [EPIC-site-to-site-improvements.md](EPIC-site-to-site-improvements.md). Findings F6 and F7.

## What was wrong

- **F7.** Explicit bind and unbind reconciled the persisted hub set. The one-screen route and site
  deletion did not. An organization set up only through the wizard therefore had no persisted hub
  set, and its hub was re-elected from live health on every compile, with no hysteresis and no
  audit row.
- **F6.** No site handler told gateways to re-fetch. An approved range, a removed range and a
  deleted site reached each gateway only on that gateway's own poll.

## Decisions

| Item | Decision |
| --- | --- |
| One seam | `siteTopologyChanged` is called after every committed site mutation that changes what gateways carry: one-screen route, bind, unbind, approve, remove, delete. |
| What it does | Reconcile and persist the hub set, then push to every active gateway in the organization. |
| Reconcile failure | Logged, not returned, as before. The push still happens: the hub set heals on the failover tick, a removed range must leave the gateways now. |
| Refused one-screen route | Converges when a site exists after the call. An overlap refusal leaves the gateway bound, which is a membership change like an explicit bind. An inadmissible range (SSI-1) creates nothing and converges nothing. |
| Not included | Creating a site and advertising a pending range change nothing a gateway carries, so they do not converge. |
| Guard against omission | A census test over `site_handlers.go` names the six handlers and fails if one stops calling the seam. The original defect was an omission; a test of the handlers that already had the call could not see it. |

## Tests

| Test | Proves |
| --- | --- |
| `TestConvergeSiteTopologyReconcilesThenPushes` | One reconcile and one push per mutation; a failed reconcile does not swallow the push. |
| `TestEverySiteTopologyMutationConverges` | Every topology-changing site handler calls the seam. |

These are substitutes. The wire proof is SSI-10: a removed range leaves a real gateway without
waiting for its poll, and the hub of a two-gateway organization does not change on one stale report.
