# EPIC — Azure site-to-site VPN

Date: 2026-10-10. Integration branch: `azure-s2s`.
Worktree: `/Users/pawangupta/.codex/worktrees/65f0/tunnex`.
Status: four-profile implementation and focused local qualification passed; owned cloud gateway enrolled; live Azure tunnel acceptance pending.

## Contract and boundaries

Reuse main `8d344e30` through clean GCP shared integration `625ff213`, which includes AWS BGP/static/DNS/lifecycle foundations and the reviewed normalized PSK correction. No older AWS snapshot replaces newer main. GCP migrations 0222–0224 and AWS 0214–0221 are present; Azure 0225 onward reserved with sibling owners. Node journal envelope is 16 MiB; native/per-guard material remains 1 MiB.

Explicit profiles encode active-active (two independent public peers) and active-standby (one peer), each with BGP or static IPv4. Route-based IKEv2, custom AES256/SHA256/DHGroup14 and ESP AES256/SHA256/PFS2048 policy is required. Azure BGP uses one shared local APIPA /32 across both gateway instances, with independent Azure peers in 169.254.21.0–169.254.22.255 reached by exact per-interface /32 routes. One local-network-gateway/connection means one shared PSK across active-active tunnels. The initial distinct-/30 draft was corrected before live deployment; non-APIPA combinations remain explicitly unsupported until independently implemented and qualified. Azure initiates no APIPA BGP session; Tunnex must initiate. Basic/policy-based/BGP combinations fail clearly. Applied, SA established, routing ready and application reachable remain distinct.

Azure commands run only through `ssh ubuntu@104.211.219.1`. Verified configured user account: sole enabled Azure subscription 1; Owner subscription role; Microsoft.Network registered; existing southindia demo/bastion resources remain untouched. Newly owned lab resources require exact ownership tags and isolated resource group. South India regional core quota is 4, with 2 used by existing resources; the one-core B1ms SKU was refused for Central India capacity. Two minimum suitable D2s_v5 lab VMs were created: peer in Central India (to avoid the South India 3-public-IP limit) and private target in South India, each within verified regional four-core quotas. Never expose PSKs, tokens, private keys, raw journals or secret logs.

All Git work stays local. Provider, runtime and UI agents use `/private/tmp/azure-s2s-{provider,runtime,ui}` on separate branches. Sibling worktrees are read-only. Local compose/project and available ports must be isolated from AWS/GCP. No remote push, PR, main merge or publication.

## Stories

| Story | Scope | Shared reuse | Azure-specific change | Dependency | Acceptance | Status |
| --- | --- | --- | --- | --- | --- | --- |
| AZ-S2S-0 | Inventory/contracts/compatibility | Actual AWS/GCP source audit and ownership | SKU, route-based IKE, BGP/static, ASN/APIPA/topology contract | None | Official contract and inventory; unsupported cases refused | In progress; SSH/account/inventory verified |
| AZ-S2S-1 | Provider/API/storage | CAS, revisions, RBAC, licence, encrypted PSK storage | Four profiles, per-peer endpoints/inside/ASN validation, additive schema | 0 | Disabled save, tenancy/roles/CAS, backward-compatible AWS/GCP | Implemented; focused API/DB and four-profile normal HTTP passed |
| AZ-S2S-2 | Import/config generation | Existing validated per-peer material and masked config | Explicit reviewed Azure input/policy contract, safe import/generation | 1 | Independent peers, invalid settings refused, stored configuration accurate | Implemented; focused API/DB and four-profile normal HTTP passed |
| AZ-S2S-3 | Shared runtime | IPsec/XFRM/strongSwan/FRR, guards/leases/journal | Profile/capability/version adapter and cardinality | 1–2 | Daemon capabilities, fail-closed apply and owned cleanup | Implemented; focused native/runtime passed; live forwarding pending |
| AZ-S2S-4 | Routing/BGP/security | Exact prefix filters, limits/recovery, per-prefix selection | Azure initiation and ASN/inside peers | 3 | No default/subprefix/local/WAN leak; actual accepted/installed routes | Implemented; focused native/runtime passed; live forwarding pending |
| AZ-S2S-5 | Static support | Existing static routes/guards/expiry/recreation | Azure supported static topology and policy | 3 | One/two-peer static traffic, disabled settings, expiry/recovery | In progress |
| AZ-S2S-6 | Telemetry/truthful health | SA/BGP/route observation and freshness | Azure provider admission/status capability | 3–5 | Never UP from apply/fixture; IPsec/BGP/routes/app separate | In progress |
| AZ-S2S-7 | UI/UX | Existing Site-to-site theme, forms, tables/health | Azure creation/import/details and topology validation | 1–6 | Admin/member, responsive, independent per-tunnel truth | Implemented; owner/mobile browser passed; other roles/import ongoing |
| AZ-S2S-8 | DNS/customer application | Conditional forwarding/zone profiles/lease policy | Private Resolver inbound endpoint and linked private zone guidance | 4–5 | UDP/TCP53, CNAME/NXDOMAIN/TC fallback, failover/expiry/negative, private FQDN→app | UI/DNS agent active; live pending |
| AZ-S2S-9 | Lifecycle/reliability | Restore journal, disable/delete/recreate, rotation/CAS/roles | Azure provider/cardinality restoration | 3–8 | Genuine restart, fresh/existing TCP/UDP, PSK maintenance and finalized cleanup | Implemented; native component restart/cleanup passed; genuine live restart pending |
| AZ-S2S-10 | Owned Azure E2E | Common unchanged test evidence only with coverage proof | Real Azure gateway identity, failover downtime, MTU/DNS/app receipts | 0–9 | Source/build/resource bound key-free evidence, both directions; local/live/blocked separate | Live pending |

## Official references

- [Azure BGP constraints](https://learn.microsoft.com/en-us/azure/vpn-gateway/configure-bgp)
- [BGP configuration and APIPA](https://learn.microsoft.com/en-us/azure/vpn-gateway/bgp-howto)
- [Custom IPsec/IKE policy](https://learn.microsoft.com/en-us/azure/vpn-gateway/ipsec-ike-policy-howto)
- [Active-active gateways](https://learn.microsoft.com/en-us/azure/vpn-gateway/active-active-portal)
- [DNS Private Resolver](https://learn.microsoft.com/en-us/azure/dns/dns-private-resolver-overview)

The private resolver inbound IP is reached through approved VPN routes and linked private DNS zones. Dedicated delegated endpoint subnets are /28 or larger; do not forward from outside Azure to 168.63.129.16 or copy managed load-balancer IPs. DNS permission is separate from application permission. No public/WAN fallback.

## Evidence rules

Implemented, local-pass, live-pass, blocked and unsupported are independent labels. Do not declare 11/11 from tests or resource creation. Keep exact source/build hashes and resource ownership in redacted receipts. Genuine Azure tunnel traffic, continuous failover measurement, lifecycle, prefix negatives and MTU/DNS/application acceptance remain necessary. Re-run broad suites only for new source changes or unresolved concerns.

## Owned lab checkpoint

Resource group `tunnex-azure-s2s-20261010`, owner tag `azure-s2s-01a12505`. Managed gateway `azure-vpn` VpnGw1AZ active-active and both VMs succeeded. Private HTTP/UDP target service is active. Owned peer native gateway enrolled and bound through normal APIs; real local route is 10.232.1.0/24 on eth0. Tagged resolver and first inbound endpoint exist; DNS provisioning continues. No IPsec/BGP/application/DNS live acceptance yet. Existing `demo` and `NetworkWatcherRG` resources remain untouched.

## Actual API boundary regressions

Genuine node enrollment exposed a dropped `ipsec_azure_version` in the API heartbeat sink. Local commit `19b80238` preserves and validates the reported value through storage and eligibility; authenticated HTTP regression passes without capability seeding. Shared GCP status decoder correction `d50ee448` adds transport/cardinality metadata; Azure followup `3a451571` permits standby BGP with exact-zero inactive slots. Authenticated report-to-persisted-status regressions cover Azure standby BGP and Classic compatibility. Owned cloud CP runs this corrected source; this proves admission/reporting, not Azure SA or traffic.
