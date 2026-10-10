# Azure site-to-site DNS and application qualification

Status: implementation and test plan only. No Azure live acceptance is asserted by this document or by receipt-checker fixtures.

## Reuse and Azure contract

Reuse the existing private DNS resolver profiles, most-specific suffix selection, IPsec connection/revision/source binding, policy evaluation, TCP/UDP transport, lease guards, mailbox freshness and FQDN answer generation. The existing `azure` provider hint is presentation metadata; it does not create an Azure resolver or authorize traffic. Keep ordinary DNS and application permissions separate.

For customer-to-Azure private resolution, configure conditional forwarding for each approved private namespace to the Azure DNS Private Resolver **inbound endpoint private IP**. Link the private zone to the resolver's VNet and provide an approved VPN route and return path. Do not target Azure's platform IP `168.63.129.16` from outside Azure. A custom forwarder inside Azure is a separate customer configuration, not evidence of managed Private Resolver acceptance.

Inbound endpoints require a dedicated subnet delegated to `Microsoft.Network/dnsResolvers`; Microsoft recommends at least /28. Do not place customer workloads in that subnet. A stable inbound endpoint IP can be allocated statically. An outbound endpoint plus forwarding ruleset is needed when Azure must resolve customer namespaces; it is not required solely for customer-to-Azure private resolution. Resolve private service/LB names at runtime and apply the returned approved private addresses; do not copy managed service IPs into static configuration.

Sources checked 2026-10-10:

- [Custom IKE/IPsec policy combinations and supported SKUs](https://learn.microsoft.com/en-us/azure/vpn-gateway/ipsec-ike-policy-howto)
- [DNS Private Resolver overview](https://learn.microsoft.com/en-us/azure/dns/dns-private-resolver-overview)
- [Endpoints and rulesets](https://learn.microsoft.com/en-us/azure/dns/private-resolver-endpoints-rulesets)
- [Hybrid DNS deployment guidance](https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/azure-best-practices/dns-for-on-premises-and-azure-resources)
- [Hybrid DNS troubleshooting, including the outside-VNet platform-IP constraint](https://learn.microsoft.com/en-us/troubleshoot/azure/dns/troubleshoot-azure-dns-private-resolver-hybrid-resolution-failure)

## Owned live topology and evidence

The lead provisions and inventories the smallest owned test lab through the designated Azure bastion. Record subscription/tenant, resource group, location, resource IDs and ownership tags in sanitized evidence. Run no Azure CLI locally. Preserve bastion access and unrelated resources. The lab should include a linked private zone, inbound endpoint, private application endpoint and explicit approved prefixes for the resolver and application. If a managed private LB/private service cannot be afforded or authorized, record that specific acceptance case as blocked rather than substituting a hosts-file entry or public DNS.

Record the tested source commit, binary hashes, runtime image, profile, tunnel topology, current CP configuration revision, Azure public/BGP peer identities, exact resolver IPs/private suffixes and approved routes. Evidence must contain timestamps and actual observed packets/results, with keys, tokens and PSKs removed. A receipt checker only verifies coverage names and artifact hashes; technical and secret review are still required.

## Qualification matrix

| Check | Required observed behavior |
|---|---|
| DNS UDP and TCP 53 | Allowed client/source resolves the approved private zone over the selected VPN path; UDP and TCP return packets traverse that path. |
| A, CNAME, NXDOMAIN | Private A answer is within approved prefixes; CNAME chain resolves using the approved namespace rules; nonexistent name returns genuine NXDOMAIN. |
| Large and truncated answers | Demonstrate real large/truncated UDP response and successful TCP retry across the tunnel, including lower-MTU conditions. Fixture-only proof remains local. |
| Resolver failover | With two owned reachable inbound resolver IPs in one profile, fail the selected endpoint and observe the permitted second endpoint; no cross-profile/public fallback. Record capability/resource limitations if only one endpoint is available. |
| Lease expiry and tunnel loss | DNS and both fresh/existing application flows lose access on enforced expiry/unavailable transport. No protected-zone request or response reaches WAN/public DNS. Recovery requires current valid ownership/configuration. |
| Security negatives | Unauthorized source, unapproved suffix, resolver outside approved ranges, stale configuration revision, disabled/deleted tunnel and denied application port fail closed. |
| Application flow | Query the actual customer private service/LB FQDN, then establish fresh TCP/UDP application traffic by that name. Re-resolve changed DNS without copying managed LB addresses. Record DNS success separately from application success. |
| Ordinary LAN option | Existing office resolver forwards the private suffix directly to inbound endpoint through the approved route; authorize that resolver source on DNS and application policies. Gateway WireGuard DNS listener does not imply a LAN-facing listener. |
| Azure-to-customer DNS option | When included, use outbound endpoint + forwarding ruleset for the customer namespace and verify the VPN return route and customer resolver ACLs. |

Some response semantics, such as controlled truncation, may require an owned custom authoritative server in addition to the managed resolver. Its coverage must be identified separately; it does not prove that Azure Private Resolver produced the same response.

## Profile-specific receipt gate

Use `python3 deploy/ipsec/check_azure_walk.py RECEIPT.json`. Four pending templates cover active-active/active-standby and static/BGP profiles. All require `live-azure`; AWS/GCP/emulator receipts are rejected. Standby coverage does not certify two-peer failover. BGP coverage additionally requires exact import/export/default/subprefix/prefix-limit selection and APIPA initiation evidence; static coverage requires exact route/selector and return-path proof. Never replace pending checks with pass based on a successful JSON/hash check.
