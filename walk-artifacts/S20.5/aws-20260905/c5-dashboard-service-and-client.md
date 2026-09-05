# Dashboard cluster/service setup and managed-client continuation

2026-09-05, immutable candidate `61ecc5fec4e5a971faaf9b1c65ccdc7b3b4cd8c1`.
User reported matching desktop installation; installed macOS bundle version
independently verified `0.0.0-walk.sha61ecc5fec4e5a971faaf9b1c65ccdc7b`.

Normal signed-in dashboard flow completed:

- Created Site `S20.5 AWS EKS sandbox`; bound A3 and B2.
- Registered `s205-aws-eks`, AWS/EKS, initially A3 connector, verified actual
  EKS Service CIDR `172.20.0.0/16`, non-overlapping VIP `100.96.0.0/24`,
  DNS zone `s205.internal.tunnex.app`, allocated DNS VIP `100.96.0.2`.
- Configured A3/B2 pool with priorities 100/90; enabled organization HA
  availability and separately requested fenced HA for this pool. Readback
  was `bootstrap_pending`, NOT yet accepted as fenced or failover proof.
- Inventory initially unavailable after registration, then normal reports
  converged to VERIFIED REPORT. Stale report selection refreshed without
  bypass. Used discovered namespace `tunnex-s205-workloads`, Service
  `s205-private-nginx`, only TCP8080; no manual exposure submitted.
- Exposed VIP `100.96.0.3`; service FQDN
  `s205-private-nginx.tunnex-s205-workloads.svc.s205-aws-eks.s205.internal.tunnex.app`.
- Created exact user `Control Plane Admin` to this Kubernetes Service rule;
  confirmed enabling enforcement from previously open-mesh state.

Desktop displayed Connected but no handshake/received bytes, and first VIP
HTTP request timed out. Read-only CP device inventory proved the sole device
`01a06c09-8ff9-7c78-9569-245c6844312e` was still homed on retired demo gateway
`01a06c02-0566-7d45-9e4d-07140d75dee5`. Normal dashboard Move devices selected
A3, returned **1 moved, 0 require configuration re-import**. Device address
remains allocated; old gateway is not revoked by transfer. No key copying,
manual client state edits, or re-enrollment workaround was performed.

Private-service wire success, managed-client reconnection, fenced authority
and HA failover remain unproven at this checkpoint. No completed walk leg or
merge readiness is inferred from configuration alone.

## Actual client wire success

At 16:07:59.975Z through 16:08:00.436Z, six fresh HTTP requests from the
local laptop succeeded: three to `http://100.96.0.3:8080`, three to the full
service FQDN on port8080. All returned HTTP200 and exact body
`S20.5_PRIVATE_SERVICE_OK`. No hosts override, direct Pod tunnel, or proxy
substitute was used. Desktop showed a real handshake and received bytes.

Important identity qualification: subsequent authoritative CP read showed
original device `01a06c09-8ff9-7c78-9569-245c6844312e` revoked and a new active
device `01a0724f-fbe8-76c4-8ee0-ac2bf1a6a515` homed on A3. The UI transfer
result above is historical; do NOT claim that the final successful client
session preserved the original device identity or proved crash recovery.

## HA prerequisite surfaced

HA remains `bootstrap_pending`, reason `base_authority_pending`. CP logs
repeated `handoff bootstrap plan refused`. Source
`apps/api/internal/nodes/handoff_bootstrap_plan_source.go` explicitly requires
an active same-site edge hub outside the connector pool: it skips pool members
when selecting EdgeWGPublicKey and refuses if none exists. The two current
same-site gateways are both pool members, so this topology cannot bootstrap
the implemented fenced handoff. A separate same-site edge gateway is needed;
the already allocated third worker can host it without another EC2 machine.
This prerequisite must be dispositioned before changing the endpoint topology;
no manual promotion or authority record edit is permitted.
