# F08 blocker matrix

The same released route and disposable identity produced these live, ordered outcomes:

| Condition | First blocker | Result |
| --- | --- | --- |
| Active agent, no grant | `no_matching_grant` | denied |
| Hostname without agent DNS observation | `agent_dns_not_observed` | inconclusive; route and policy destination also unresolved |
| Literal IP outside managed AllowedIPs | `route_not_configured` | denied |
| Disposable rule expired | `no_matching_grant` | denied; compiled hash changed and applied-policy convergence remained explicit |
| Runtime report aged four minutes | `runtime_not_ready` | denied; health `last_good`, desired/applied still `1/1` |
| Disposable agent's gateway-status observation aged four minutes | `gateway_not_reporting` | denied; shared gateway process was not stopped |
| Agent suspended through released lifecycle UI | `agent_not_active` | denied with lifecycle `suspended` |

The expired timestamp and stale clocks were bounded to the disposable rule/agent and restored. The suspension was followed by supported resume and service recovery. The shared node and unrelated identities were not stopped or edited.

Uniform unrelated-member `403 forbidden`, missing-agent no-oracle equivalence and released DOM absence remain proven by the exact-current PostgreSQL/HTTP and web route suites. A fresh live member browser session was not available during this operator session; that leg is recorded as a SUBSTITUTE pending the named trigger `next staffed AWS DEV member-session walk` and is not claimed as live evidence.
