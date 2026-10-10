# GCP-0 isolated cloud lab

Verified 2026-10-10 through the corrected human-provided bastion.

- Bastion: `cyberking9560@34.131.23.179`, host `bastion-host`, existing default VPC; preserve it.
- Project: `project-0048836f-6ba1-4a14-8da`; billing enabled; Compute API enabled. DNS API not enabled in initial inventory.
- Region: `asia-south2`, matching bastion zone `asia-south2-b`.
- Initial inventory: existing `default` auto VPC and bastion only; no HA VPN gateway or Cloud Router in returned inventory.
- Ownership prefix: `tn-gcps2s-20261010`; label `tunnex-lab=gcp-s2s-20261010`, `managed-by=tunnex-development` where resource supports labels; otherwise exact unique resource name plus description and ledger.

## Planned resources

| Role | Owned resource | Range / details |
| --- | --- | --- |
| Local Site | peer custom VPC/subnet | `10.70.0.0/24`, regional dynamic routing, VM IP forwarding |
| HA remote Site | HA custom VPC/subnet | `10.80.0.0/24`, regional routing, Cloud Router ASN 64514 |
| Classic remote Site | Classic custom VPC/subnet | `10.81.0.0/24`, route-based static tunnel and exact return routes |
| Peer | fixed IPv4 address and lab gateway VM | Peer ASN 65010, no cloud credentials on gateway; dedicated forwarding/SSH rules |
| HA provider | HA VPN gateway, external peer and two tunnels | Explicit cloud interface mapping; BGP /30s from actual configured link-local pairs |
| Classic provider | target VPN gateway/address/forwarding rules/tunnel | One tunnel; do not reuse HA identity or AWS slot count |
| Traffic evidence | local behind-host and remote test VMs | private TCP/UDP and DNS/application paths; no public application ingress |
| DNS | Cloud DNS private zone and inbound server policy | DNS inbound IPs from API; UDP/TCP53 and return routes explicitly tested |

## Safety and cleanup ownership

All cloud operations execute via SSH on the designated bastion. Do not modify default VPC/bastion, project settings unrelated to lab, existing firewall/routes or IAM. Lab services may be enabled as needed. Keep PSKs/SSH keys in private bastion state, never in committed receipts/ledger. Use no cloud service account on traffic/gateway machines unless a demonstrated test dependency requires it.

Record exact names, locations, create status and observed identifiers in a key-free ledger. Existing same-name resources must match ownership/plan before reuse. Cleanup in dependency order: tests/CP stop; DNS records/policy/zone; Classic static routes/tunnel/forwarding rules/target gateway; HA BGP peers/interfaces/tunnels/external peer/gateway/router; VMs/firewalls/static IPs/subnets/VPCs. Teardown is scoped to exact ledger resources and held until human has inspected the lab. Reconciliation/delete failure is recorded, never handled with broad cleanup.

Implementation, local acceptance, live qualification and production publication remain separate. No live acceptance has passed at this checkpoint.
