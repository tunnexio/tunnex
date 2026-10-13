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

## Customer setup and operating guide

### Prepare the two ends

Use an owner or administrator account and enable IPsec in **Settings → Features** with an eligible licence. Select an active gateway attached to the intended Site and approve its local network ranges before creating a connection. Check those ranges, the Azure VNet/subnets, tunnel interface allocations, organization VPN pools and gateway container networks for overlap. Record the actual customer public IP, Azure gateway SKU, topology, routing mode, peer public IPs and remote ranges; Tunnex does not discover these values from Azure.

In Azure, configure a supported route-based VPN Gateway and the custom IKE/IPsec policy described above. Configure the Local Network Gateway with the customer's actual public IP and local ranges, and create the matching Azure connection. Keep the shared key in your normal secret store. For active-active, use the two actual gateway instance public IPs and one shared connection key. For BGP, use the same customer APIPA `/32` on both Tunnex slots, distinct Azure APIPA peers, different local and remote ASNs, and an explicit maximum-prefix limit. Azure's APIPA constraints and session initiation behavior are documented in [Configure BGP](https://learn.microsoft.com/en-us/azure/vpn-gateway/configure-bgp).

Allow the required IKE/IPsec transport at both ends and provide return routes for the approved local ranges. Permit the workload's application ports separately. For static routing, enter only the intended remote ranges; the local Tunnex inside `/30` values are interface allocations and must not be presented as Azure-assigned tunnel addresses. Choose the profile that matches the actual Azure gateway: active-standby has one Tunnex peer slot.

### Save, review and enable

1. Open **Site-to-site**, create an IPsec connection and choose Azure. Enter a name, the **Local network**, **Gateway**, approved local ranges, **Customer public IP**, remote ranges, profile and actual **Azure VPN Gateway SKU**.
2. Enter the addresses and shared key under **Next: tunnels**. Alternatively, select **Import Tunnex Azure JSON** after selecting the network and gateway. Import performs configuration preflight and fills a draft; it does not save or enable a connection. Imported local ranges must already belong to this Site's approved ranges.
3. Review the topology, ranges, policy and BGP settings. For active-active, enter the same actual Azure connection PSK in both password fields. Select **Save disabled connection**. Save performs a fresh gateway readiness check and configuration preflight before creating the disabled record.
4. Open the saved connection's **Stored Azure gateway contract** and, if useful, **Download nonsecret Azure settings review**. Compare its endpoints, topology and policy with Azure. The downloaded review omits PSKs and is not a complete import file.
5. After the Azure side and return routing are ready, use the connection's **Enable** action. Check current per-tunnel health and, for BGP, peer sessions and accepted routes. An **Applied** state confirms configuration application; verify actual workload traffic before treating the connection as usable.

Tunnex import JSON contains write-only `psk` fields and is a secret-bearing file. Use manual entry if you do not want the key in a file. Shared keys must meet the configuration validator's 8–64-byte requirement and match Azure; successful preflight does not authenticate a key against the remote gateway. Keep keys out of downloaded reviews, tickets and screenshots.

If Save reports an unknown result, use **Retry save** in that existing dialog. It reconciles the original connection ID before another attempt. If an intent or key update cannot be confirmed, follow the displayed refresh instruction and inspect the stored record before attempting another change.

### Reach Azure private DNS

Create or identify an Azure DNS Private Resolver inbound endpoint reachable through this VPN. Link the required private DNS zones to the resolver VNet. Azure requires a dedicated endpoint subnet delegated to `Microsoft.Network/dnsResolvers`, with a size between `/28` and `/24`; use the actual inbound private IPs, not an outbound endpoint, as forwarding destinations. See [Azure DNS Private Resolver overview](https://learn.microsoft.com/en-us/azure/dns/dns-private-resolver-overview).

Ensure the inbound IPs fall within the connection's approved remote ranges, Azure has return routes to the DNS source, and access policies permit that source to those endpoints on UDP **and** TCP port 53. Choose the path that matches your clients:

- **Existing office DNS:** retain the office resolver and add a conditional forwarder for the Azure private zone to the inbound endpoint IPs. Authorize the office DNS server's actual source address across the tunnel.
- **Tunnex gateway proxy:** in **Private DNS resolvers**, select the Site and Gateway, configure a profile with **Provider** Azure, the exact **DNS zone suffixes**, **DNS transport path** Site-to-site IPsec, the enabled **IPsec connection**, and **Gateway DNS source IPv4**. That source must be owned by this gateway within an approved local range. Enter the inbound endpoints on port 53, then activate the profiles. Configure supported WireGuard clients to use the gateway's WireGuard-facing DNS address for those zones and grant those clients explicit DNS access.

The gateway proxy does not create an office LAN DNS listener. Profiles select the most-specific configured zone suffix and do not fall back to another profile when a private resolver fails. DNS access and application access are separate permissions. FQDN application enforcement requires the corresponding feature and a genuine eligible licence or trial; resolving a name does not grant access to its IPs or ports.

### Check service behavior

Run these checks from an explicitly authorized client, using the actual workload and resolver addresses. Retain timestamps, connection/configuration revisions and nonsecret results so that a stale health report cannot be mistaken for a current test.

| Check | Evidence to retain |
| --- | --- |
| Direct private-IP access | Successful TCP and UDP exchanges on authorized ports, with the original permitted source observed at the workload; refusal from an ungranted source. |
| Ordinary application grant expiry and recovery | After an ordinary private-IP grant expires or is revoked, both new and existing TCP/UDP flows lose access. A genuine replacement grant restores authorized traffic. Test this independently of DNS resolution and FQDN address-lease expiry. |
| Private DNS | Expected A/CNAME results, NXDOMAIN handling and a large UDP response that can complete through TCP retry; public names still use the client's normal resolver. |
| FQDN application grant | Fresh resolution and successful authorized traffic, followed by refusal when the grant is revoked or its permitted address lease expires. Check existing TCP/UDP flows as well as new flows. |
| Profile health and routing | The expected one or two peer slots, current SA health and, for BGP, established peers and only approved remote routes. |
| MTU and large transfers | Test large TCP/UDP exchanges in both directions at the intended reduced tunnel MTU. Record DF/ICMP path-MTU feedback and the TCP SYN/SYN-ACK MSS on the selected tunnel interface; successful small packets alone do not prove these checks. Restore the original MTU and record the final routing and traffic state. |
| Peer recovery | During a planned maintenance window, test the profile's supported peer failure and restoration, return routing and representative application traffic. Measure interruption and recovery on new and existing TCP/UDP flows. Restore the original configuration and record the final state. |
| Gateway restart and key maintenance | Test a planned gateway restart using fresh connections and the original TCP sockets/UDP flows. Check automatic CHILD and IKE renewal separately, with successful traffic through each transition. Test a coordinated two-sided PSK change separately; record recovery time and the final cleanup state. |

These are acceptance checks to perform in the customer's environment. A local UI test, stored configuration, successful DNS answer or applied runtime state does not establish that all of them passed on Azure.

Current owned Azure qualification, reviewed 2026-10-13, covers active-active BGP forwarding and filtering, active-active static traffic in both directions, and bounded forward static MTU1280 continuity. Active-standby routing/traffic, ordinary grant expiry/recovery, sustained private DNS and encrypted FQDN application access, restart/key-maintenance continuity, reverse reduced-MTU/DF/PMTU/MSS and peer-fault recovery remain open. Do not assume those behaviors are ready for a customer rollout from the completed checks. See the [current story status](evidence/azure-s2s-20261010/azure-story-wise-status-20261012.json) for their individual scope.

### Maintain and troubleshoot

To rotate keys, disable the connection and wait for pending cleanup to finish. Select **Rotate tunnel keys**, enter **Azure connection new PSK**, and use **Save new keys**. Tunnex applies the shared key to the Azure slots and keeps the connection disabled. Update the matching Azure connection key separately, then enable and repeat the health and workload checks. Tunnex does not update Azure's key automatically.

Use this order when service access fails:

| Observation | Check next |
| --- | --- |
| Save or Enable is unavailable | Licence/feature state, account permissions, active gateway ownership, approved ranges and fresh profile-specific gateway support. |
| Applied, but no current SA | Matching peer IPs, actual shared key, IKE/IPsec policy and transport reachability at both ends. |
| SA is current, but BGP or workload traffic fails | APIPA addresses and ASNs, accepted routes/maximum-prefix limit, Azure return routes, workload rules and explicit access grants. |
| Private DNS fails | Resolver zone links, inbound endpoint IPs, suffix selection, selected connection revision, source ownership and UDP/TCP 53 permission. Test resolver access separately from application access. |
| A name resolves, but its application fails | The application's port and grant, freshness of the permitted resolved addresses, and the workload's return path. |
| Removal still reports cleanup or retained guard | Inspect the displayed cleanup state. Deletion can retain safety ownership and reserved ranges; it is not proof that all remote resources or local ownership have been released. |

For support, share the nonsecret settings review, current tunnel/routing status, exact test timestamps and relevant error codes. Review logs for secrets before sharing them. Remove Azure resources only through your normal cloud ownership process after the Tunnex connection's removal and cleanup state have been checked.
