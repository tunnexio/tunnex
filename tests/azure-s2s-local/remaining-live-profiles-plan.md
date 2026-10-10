Source-only reviewed plan for the three remaining Azure profiles. No calls below have been executed by this agent. The existing active-active BGP source configuration is in `activate-live.py`; its public IP values are historical and MUST be rediscovered after any gateway change. This plan makes no assertion about current readiness.

1. Qualify active-active static first, retaining the existing two-instance gateway and existing target VM. Then perform one separately reviewed active-active → active-standby gateway change; qualify standby BGP and standby static on its actual single endpoint. Do not represent an active-active gateway with a standby profile merely by dropping one tunnel.
2. Before each transition use `lifecycle-live.py read` under the normal UID1000 owner. Save fresh typed status. Disable through its fresh revision CAS and wait for actual normal cleanup acknowledgement. `disabled` intent or a timeout is insufficient: require cleanup `not_required`/`retained_guard`, no pending cleanup, and independently observed absent SAD/SPD, tunnel interfaces and remote routes while retaining required deny guards. Refusal/restart failures remain separate evidence. Never bypass a pending cleanup or fabricate acknowledgement/capability.
3. Delete the old Tunnex connection through the exact normal API below and wait for its finalization before creating the next profile. Use a NEW connection UUID and exactly one/two new tunnel UUIDs for a different profile. Rebind only the same explicitly owned Site/gateway and approved real LAN prefix. Revoke/review old connection-bound DNS/FQDN path grants before changing the path; create only exact replacement grants through the normal APIs. Existing application target remains `10.231.1.4`, LAN principal `10.233.10.2`, authorized LAN prefix `10.233.10.0/24`; no blanket allow or new VM is needed.

Normal API calls use the reviewed `activate-live.Client`, owner login, org slug `azure-s2s-local`, exact private setup IDs and fresh GET revision. `P=/api/v1/organizations/{owned_org}/ipsec`, `C=P/connections/{owned_connection}`. Private request bodies containing PSKs must never be printed. Headers for intent/delete are `If-Match: "<fresh desired_revision>"`; rotation CAS is in its BODY.

| Operation | Exact call and request | Required observation |
| --- | --- | --- |
| Validate | `POST P/configuration-check`, configuration below | 200 validates shape only; not live readiness |
| Create | `POST P/connections`, `{id,name,site_id,gateway_node_id,tunnel_ids,configuration}` | Disabled creation, owned binding; read configuration's **top-level** `profile_id` and nested nonsecret `configuration` |
| Enable | `PUT C/intent`, `{intent:"enabled"}`, fresh If-Match | Successor revision, real normal status acknowledgement, actual packets |
| Disable | `PUT C/intent`, `{intent:"disabled"}`, fresh If-Match | Successor revision and genuine completed cleanup as above |
| Rotate | `POST C/rotate-psks`, `{expected_desired_revision:R,tunnels:[{tunnel_id:T,psk:PRIVATE},...]}` | AA MUST include BOTH active IDs and the SAME 8–64 character control-free key atomically; standby exactly one; stale CAS refuses |
| Delete | `DELETE C`, fresh If-Match, no body | Tombstone/finalization and actual withdrawal; do not equate initial200 with completed cleanup |
| Same-profile recreate | After finalization `POST P/connections` with the saved exact IDs and original immutable binding/configuration | Normal recreation supported only with original topology/profile/binding; verify new desired revision, fresh status, secrets absent readback |

Build configurations locally in memory from rediscovered public endpoints, never append manifest-only transport fields to HTTP input. The HTTP tunnel array has actual cardinality; the producer pads the inactive runtime slot itself.

```python
# Plan template only: real endpoints, observed SKU, and PSK come from owned inputs.
azure = dict(gateway_sku=observed_sku, vpn_type='RouteBased', ike_version=2,
             custom_policy='aes256-sha256-dh14-pfs2048',
             use_policy_based_traffic_selectors=False, nat_enabled=False)
config = dict(profile_id=profile, azure=azure, mode='ipv4-'+routing,
              customer_outside_address=observed_peer_public_ip,
              local_prefixes=['10.233.10.0/24'], remote_prefixes=['10.231.0.0/16'],
              tunnels=[])
for i, outside in enumerate(observed_azure_public_ips):
    if routing == 'static':
        # Tunnex local dummy pairs, NOT Azure APIPA assignments; verify unreserved.
        tunnel = dict(outside_address=outside, inside_cidr=f'169.254.{70+i}.0/30',
                      customer_inside_address=f'169.254.{70+i}.1',
                      cloud_inside_address=f'169.254.{70+i}.2', psk=private_psk)
    else:
        tunnel = dict(outside_address=outside, inside_cidr='169.254.10.1/32',
                      customer_inside_address='169.254.10.1',
                      cloud_inside_address=observed_azure_apipa[i], psk=private_psk)
    config['tunnels'].append(tunnel)
if routing == 'bgp':
    config['bgp'] = dict(local_asn=65000, remote_asn=observed_azure_asn,
                         router_id='10.233.10.1', maximum_prefixes=8)
```

| Next profile | Actual Azure layout | HTTP tunnels/BGP |
| --- | --- | --- |
| `azure-active-active-static-ipv4-v1` | `activeActive=true`, two observed public IP configs; same one LNG/connection | Two local dummy /30 pairs, common PSK; no `bgp` key |
| `azure-active-standby-bgp-ipv4-v1` | `activeActive=false`, one observed public IP config and one observed custom Azure APIPA | One shared-local /32 tunnel, one real cloud APIPA and `bgp` |
| `azure-active-standby-static-ipv4-v1` | Same verified standby layout | One local dummy /30 pair, no `bgp` key |

Owned Azure discovery/mutation plan: root runs only through the authorized bastion. Resolve exact subscription, RG `tunnex-azure-s2s-20261010`, owner tag `azure-s2s-01a12505`. Discover the actual connection, its `virtualNetworkGateway1.id` and `localNetworkGateway2.id`; do not assume names. Require each exact ID is in this owned RG/subscription and each resource's owner tag matches. Recheck immediately before every mutation; missing tags or multiple matches stop. Project only IDs/tags, `activeActive`, SKU, `vpnType`, provisioning state, IP-configuration→public-IP IDs, custom BGP APIPA/ASN, connection BGP flag, selectors, NAT-rule IDs and custom policy. Do not print an unfiltered connection response or retrieve `shared-key show`.

After those checks, minimal active-active static Azure updates are:

```sh
# Reviewed placeholders populated from exact owned discovery; root alone executes.
az network local-gateway update --ids "$owned_lng_id" \
  --local-address-prefixes 10.233.10.0/24 -o none
az network vpn-connection update --ids "$owned_connection_id" \
  --enable-bgp false --use-policy-based-traffic-selectors false -o none
```

Keep gateway custom APIPA/ASN settings for rollback; static disables BGP on the connection. Re-read exact policy: IKE AES256/SHA256/DHGroup14; IPsec AES256/SHA256/PFS2048, RouteBased/IKEv2, no NAT. One Azure connection supplies the common PSK for both active-active tunnels. Use the existing reviewed private Azure shared-key updater or a private `az rest --body @0600file` request; never interpolate a key into shell command arguments/history/output. Rotation against the normal API uses the same new key across both IDs. Actual Azure CLI supports `vpn-connection shared-key update`, but secure key transport must be reviewed before execution.

Standby conversion is a longer gateway operation, not part of the minimal static test. Preserve the unused public-IP resource for rollback. From the captured actual gateway document identify the second IP configuration index/name and retain the first; reviewed CLI generic update is `az network vnet-gateway update --ids "$owned_gateway_id" --set activeActive=false --remove ipConfigurations <exact_second_index> -o none`. Recheck the installed CLI help and exact request before execution. Wait for successful provisioning; read actual remaining public endpoint and BGP custom APIPA instead of reusing stale two-instance values. For standby BGP enable BGP on the owned connection and verify LNG ASN65000/peer169.254.10.1 plus actual cloud ASN/APIPA; for standby static disable connection BGP and retain exact LAN static prefix. Do not delete the gateway, public IP, target, or unrelated resource as part of this plan.

Per-profile observations: normal role authorization owner/admin success and member403; exact tunnel count/zero inactive runtime slot; actual target HTTP8080 and UDP8081 fresh/persistent packets from authorized `.2` with source preservation; `.3` must remain denied using the existing bounded probe. Capture disable withdrawal, enable recovery and same-profile delete/recreate. Active-active static needs selected-slot failover/restart evidence independently; standby has one active tunnel and no two-tunnel failover claim.

Bad-PSK qualification: choose a private syntactically valid wrong key, rotate both AA IDs atomically (or standby single ID) on the normal API while leaving the Azure key unchanged. Existing established SAs can continue until actual rekey/re-establishment; do not call an immediate success/failure proof. Under the separately authorized controlled connection reset/rekey, record actual tunnel/app failure; restore a new synchronized Azure+Tunnex key through the reviewed private paths and record convergence. Invalid-length, single-slot-AA, unequal-AA, stale-CAS negative requests must refuse without revision change. Keep wrong keys/private outputs out of evidence.

Prefix-negative qualification has distinct layers: configuration-check tests canonical/invalid/default/overlap input; creation tests an unapproved local prefix and conflicting remote reservation while remaining disabled. These are control-plane tests. BGP maximum-prefix/allowlist rejection needs a real owned additional advertised prefix and actual accepted/rejected/installed counts, route absence and packet denial; static profiles do not have BGP rejection. Do not grant or fabricate an unowned prefix. Narrow `.3` app denial is principal policy evidence, not remote-prefix rejection proof. Any live additional-prefix experiment needs an explicit bounded owned namespace/route and reviewed advertisement before execution.

Primary references verified 2026-10-10: [connection CLI](https://learn.microsoft.com/en-us/cli/azure/network/vpn-connection?view=azure-cli-latest), [local gateway CLI](https://learn.microsoft.com/en-us/cli/azure/network/local-gateway?view=azure-cli-latest), [virtual network gateway CLI](https://learn.microsoft.com/en-us/cli/azure/network/vnet-gateway?view=azure-cli-latest), [mode conversion](https://learn.microsoft.com/en-us/azure/vpn-gateway/gateway-change-active-active), [custom BGP APIPA](https://learn.microsoft.com/en-us/azure/vpn-gateway/configure-bgp). CLI command shapes are documented; actual owned-resource mutation and resulting topology are not yet proved by this plan.
