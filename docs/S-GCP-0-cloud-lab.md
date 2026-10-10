# GCP-0 isolated cloud lab

Initial inventory and owned resource creation were recorded on 2026-10-10 through the corrected human-provided bastion. Subsequent SSH access is blocked; this document does not assert current cloud health or successful VPN/DNS traffic.

- Bastion: `cyberking9560@34.131.23.179`, host `bastion-host`, existing default VPC; preserve it.
- Project: `project-0048836f-6ba1-4a14-8da`; billing enabled; Compute API enabled. DNS API not enabled in initial inventory.
- Region: `asia-south2`, matching bastion zone `asia-south2-b`.
- Initial inventory: existing `default` auto VPC and bastion only; no HA VPN gateway or Cloud Router in returned inventory.
- Ownership prefix: `tn-gcps2s-20261010`; label `tunnex-lab=gcp-s2s-20261010`, `managed-by=tunnex-development` where resource supports labels; otherwise exact unique resource name plus description and ledger.

## Created topology and intended qualification

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

## Creation checkpoint and SSH incident

The [integration epic](EPIC-gcp-site-to-site.md#qualification-checkpoint--2026-10-10) records 39 owned resources created in this project/region: separate peer, HA and Classic VPCs, Cloud Router, two HA tunnels, one Classic tunnel, private targets and a Cloud DNS inbound policy. Initial “DNS API not enabled” above describes the earlier inventory, not a claim about the later creation state. The last observed key-free ownership ledger is `/home/cyberking9560/tn-gcps2s-20261010/resource-ledger.json` on the bastion, inspected before the SSH incident. It has not been reread since the public-key refusal; the path and count are last-observed evidence, not current verification. Project number was `947644326305`. Resource creation is distinct from SA establishment, BGP/routing readiness, application packets and Cloud DNS answers. None of those cloud traffic acceptance checks is verified.

After the generated lab SSH public key was moved from project metadata to the four owned VM metadata entries and that exact project key was removed, the existing Mac-to-bastion login began refusing public-key authentication. The user was informed and asked to restore access through Console. This records the observed sequence; it does not establish a complete authentication root cause or guarantee that reverting metadata alone restores access. Private key material and metadata payloads are omitted.

Cloud execution is paused at the designated SSH boundary. No local gcloud/API fallback is used. Existing owned resources are retained for inspection; no broad teardown or modification of unrelated infrastructure is authorized by this checkpoint. Successful isolated Docker emulator tests in the [local control-plane receipt](../tests/gcp-s2s-local/CONTROL-PLANE-ACCEPTANCE-20261010.md) are separate from this cloud lab and do not resolve the SSH blocker.

## Safety and cleanup ownership

All cloud operations execute via SSH on the designated bastion. Do not modify default VPC/bastion, project settings unrelated to lab, existing firewall/routes or IAM. Lab services may be enabled as needed. Keep PSKs/SSH keys in private bastion state, never in committed receipts/ledger. Use no cloud service account on traffic/gateway machines unless a demonstrated test dependency requires it.

Record exact names, locations, create status and observed identifiers in a key-free ledger. Existing same-name resources must match ownership/plan before reuse. Cleanup in dependency order: tests/CP stop; DNS records/policy/zone; Classic static routes/tunnel/forwarding rules/target gateway; HA BGP peers/interfaces/tunnels/external peer/gateway/router; VMs/firewalls/static IPs/subnets/VPCs. Teardown is scoped to exact ledger resources and held until human has inspected the lab. Reconciliation/delete failure is recorded, never handled with broad cleanup.

Implementation, local acceptance, live qualification and production publication remain separate. No live acceptance has passed at this checkpoint.
