# Explicit GCP BGP local export proof

Base integration: `ebda72a045adbfcf8ee525a5ebb622eea758b74a`.
Cloud remains on frozen source `3d0951e84aa58ce78dcc6238bd2ecaf7d3f38fd9`.
No deployment, route relabel, daemon adoption or qualification override occurs
in this candidate.

Actual cloud HA has two established IKEv2/installed ESP-in-UDP children, SAD4,
owned XFRM links, but no managed BGP process checkpoint, learned route or
application readiness. Bounded node diagnostics repeatedly report
`bgp_apply/session_start`. Native local-export input receipt SHA256 is
`25add546aa108764ca8f53de763cd810a8d09bbb2441f1b7b286051612383963`.

Before any directory/process checkpoint, generic FRR startup runs its strict
local export probe. That probe rejects the actual assigned `10.70.0.2/32` and
explicit approved `10.70.0.0/24 via 10.70.0.1` route with protocol242: only
kernel/static/boot are accepted and the gateway must belong to an assigned
address subnet. The existing GCP runtime environment inspector independently
proves this specific /32/routed topology. The captured route regression
preserves generic refusal and demonstrates the explicit proof boundary.

The new named proof-aware start method requires a nonnil proof for cloned exact
Config.LocalPrefixes. Default start/observer methods retain the generic probe.
Only validated GCP HA contract3 selects the new method. It snapshots the actual
immutable allocation, engines, process config and Apply environment, and reruns
ObserveLocalExports before starting FRR. This private observation mode reuses
the same complete bounded inventories, strict source/gateway/route checks and
namespace/reread stability as Observe, while additionally requiring an exact
local-prefix cover with kernel/static/boot or explicit242 protocol. Named and
numeric grammar is bounded; missing, dynamic, unknown, null and malformed
protocols refuse. Ordinary Observe is unchanged.

Package qualification, peer reachability, process checkpoint/identity, child
supervision, RIB reconciliation, route ownership and full guard proof remain
mandatory. Source tests model command I/O using captured key-free routes and
exercise the real inspector/parser. They do not establish live FRR or Google
BGP readiness; that requires the reviewed candidate's normal deployment and
fresh real evidence.

Checks:
- Captured generic local-probe refusal; exact GCP inspector/export boundary PASS.
- GCP export/protocol/cancellation/immutable-config and inherited native-shape
  tests: race PASS bgp1.609s/ipsec1.811s.
- Independent focused review race: bgp1.521s/ipsec1.619s, source review PASS.
- Full suites PASS: bgp0.567s/ipsec42.723s/fqdnrpc0.543s.
- Linux AMD64 and ARM64 agent builds PASS. AMD64 SHA256
  `4de727867eaea2d9287920dbedf4d3c67249c93b463d8a0d0e4f577ca4062755`;
  ARM64 `313db76ff8684b0ebb643bb201b7035571f4e95b8f28331fcf8c43e6b7373160`.
- Linux AMD64 managed-FRR and IPsec native test binaries compile PASS.
