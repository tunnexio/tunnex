# Azure provider contract v1

This is a bounded Tunnex configuration contract, not proof that a gateway or application is reachable. The four explicit profiles preserve Azure topology:

| Profile | Peers | Routing |
| --- | ---: | --- |
| `azure-active-active-bgp-ipv4-v1` | 2 | BGP |
| `azure-active-active-static-ipv4-v1` | 2 | Static |
| `azure-active-standby-bgp-ipv4-v1` | 1 | BGP |
| `azure-active-standby-static-ipv4-v1` | 1 | Static |

Azure must use a route-based gateway with IKEv2 and a custom policy: IKE AES256/SHA256/DHGroup14; IPsec AES256/SHA256/PFS2048. Basic, policy-based traffic selectors, NAT rules, and other policies are explicitly unsupported. Supported SKUs are VpnGw1 through VpnGw5 and their AZ equivalents. Inputs describe the actual configured cloud contract; the API does not discover or attest it.

The required `azure` object is:

```json
{"gateway_sku":"VpnGw1AZ","vpn_type":"RouteBased","ike_version":2,"custom_policy":"aes256-sha256-dh14-pfs2048","use_policy_based_traffic_selectors":false,"nat_enabled":false}
```

Import accepts **Tunnex Azure JSON** with the `IPsecConfigurationCheckInput` OpenAPI shape, at most 64 KiB. It is not a parser for Azure ARM exports, downloadable VPN device scripts or arbitrary command text. Fields are `profile_id`, `azure`, `mode`, `customer_outside_address`, `local_prefixes`, `remote_prefixes`, optional `bgp`, and `tunnels`. Each tunnel includes `outside_address`, `inside_cidr`, `customer_inside_address`, `cloud_inside_address`, and a write-only `psk`. Secrets remain input only and are absent from stored-configuration readback and per-peer settings generation.

BGP uses one explicit local APIPA loopback `/32` shared across active-active peers, with independently routed Azure APIPA peer `/32` addresses. The Azure address must be within 169.254.21.0–169.254.22.255. General GatewaySubnet/non-APIPA peers are unsupported in v1. Tunnex initiates APIPA BGP because Azure does not initiate these sessions. Local/remote ASNs must differ; Azure's default remote ASN 65515 is valid, but it cannot be used for Tunnex's local ASN. Public and 32-bit ASNs are admitted subject to reserved-number validation.

Static inside `/30` pairs are **local Tunnex interface allocations**, not Azure-assigned addresses. They support the existing shared XFRM/runtime ownership contract. Static active-active can reuse qualified shared recovery version1; standby has one real active slot and an exact-zero inactive slot, without a fabricated second SA, secret or peer.

Per-peer settings generation returns endpoint and BGP addresses plus the exact policy names above. It contains no PSKs, shell commands or provisioning authority. Active-active peers share one Local Network Gateway and one Azure connection: both slots must use the same local BGP address and the same PSK. The distinct outside and Azure BGP addresses come from the two gateway instances. Azure connection PSKs must be entered to match the actual Azure connection; the configuration does not claim to validate a key against Azure.

Both providers retain the shared range locks, encrypted secrets, revisions/CAS, RBAC/licence checks, approved prefix enforcement, runtime delivery ownership and freshness-based status. Migration0225 adds only Azure contract metadata and provider-aware guards to existing storage. Rollback refuses existing Azure connection history rather than deleting it.

Sources checked 2026-10-10:

- [Configure BGP](https://learn.microsoft.com/en-us/azure/vpn-gateway/configure-bgp)
- [VPN Gateway FAQ and reserved ASNs](https://learn.microsoft.com/en-us/azure/vpn-gateway/vpn-gateway-vpn-faq)
- [Custom IPsec/IKE policy](https://learn.microsoft.com/en-us/azure/vpn-gateway/vpn-gateway-ipsecikepolicy-rm-powershell)
- [Active-active VPN gateways](https://learn.microsoft.com/en-us/azure/vpn-gateway/about-active-active-gateways)

Implementation, local verification, actual Azure tunnel qualification and production readiness are separate evidence states.
