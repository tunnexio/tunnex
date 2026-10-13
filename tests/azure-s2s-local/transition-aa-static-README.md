`transition-aa-static.py` performs only normal API operations against fixed localhost48083. Run as the normal UID1000 account owning mode0700 `.runtime`; root controls Azure changes separately through the authorized bastion. It accepts only the existing owned AA BGP profile, exact Site/gateway binding, LAN10.233.10/24 and remote10.231/16. It copies actual observed public endpoints and nested Azure metadata from nonsecret provider readback, assigns local dummy169.25470/71 /30 pairs, and requires one private common PSK.

Run separate reviewed phases:

```sh
python3 tests/azure-s2s-local/transition-aa-static.py read --private-root PRIVATE
python3 tests/azure-s2s-local/transition-aa-static.py disable --private-root PRIVATE
# Read until genuine normal cleanup is settled; root independently verifies withdrawal.
python3 tests/azure-s2s-local/transition-aa-static.py delete --private-root PRIVATE
# Read until prior tombstone finalized_at is present. Root aligns owned Azure
# connection BGPfalse/static LNG prefix and synchronized common PSK separately.
python3 tests/azure-s2s-local/transition-aa-static.py create-static --private-root PRIVATE --psk-file PRIVATE_KEY_FILE
python3 tests/azure-s2s-local/transition-aa-static.py enable --private-root PRIVATE
python3 tests/azure-s2s-local/transition-aa-static.py read --private-root PRIVATE
```

Fresh If-Match CAS guards intent/delete. Creation requires a genuinely finalized disabled prior connection with no pending cleanup. The helper saves prior binding/configuration privately before deletion and new UUIDs privately BEFORE creation so an ambiguous response cannot cause duplicate allocation. It never auto-retries creation or bypasses an allocated target404: root must inspect that ambiguous result before a reviewed recovery. It uses a new profile/connection identity and exactly two new tunnel UUIDs. Private phase receipts contain only typed connection/runtime projections; no keys/config bodies are printed. Deleted connections are read as tombstones without runtime probes; historical Site/gateway binding is verified after finalization.

The helper's state is `azure-static-transition.json`. It does not overwrite `azure-live-activation.json`; that file remains the prior allocation for historical helpers. Root must review/rebind any other qualification helper to the new saved target IDs and exact current configuration revision, including connection-bound DNS paths. No grants, routes, cloud settings, capability/status seeds, or packet probes are changed by this helper. Enable/status alone does not establish target packet readiness. Use the existing real LAN probes independently after Azure alignment. This implementation covers AA static only; standby conversion remains separately reviewed.

The same source now supports `--profile azure-active-standby-bgp-ipv4-v1` and `--profile azure-active-standby-static-ipv4-v1` with phase `create-profile`. Every creation, including AA static, additionally requires `--gateway-discovery-file PRIVATE_DISCOVERY`. Discovery must be fresh (≤15min), show the actual matching AA/standby mode, exact endpoint count and matching connection BGP flag, observed SKU, owned Azure IDs, peer outside address, and for BGP actual Azure APIPA/ASN plus LNG peer/ASN. The helper cannot convert an AA topology to standby by dropping a slot. No caller-supplied endpoint override exists.

For standby's first phase use `--prior-allocation-file PRIVATE_CURRENT_ALLOCATION`, a UID1000-owned private `{id,tunnel_ids}` record identifying the actual currently active prior connection. This is required instead of silently reusing the original BGP allocation. Each profile has its own fixed transition state file. Keep the same `--profile` for read/disable/delete/create-profile/enable. After separately reviewed actual Azure standby conversion and successful provisioning, run fresh discovery before creating exactly one new tunnel UUID. New static uses one dummy /30; new BGP uses actual one Azure APIPA and shared local169.25410.1/32. Existing cleanup/CAS/finalization/ambiguity guards remain.

`deploy/azure/discover-owned-profile.py` is a separate reviewed **bastion-only** CLI source. `discover` is read-only. `aa-static` mutates only the exact owned LNG address-prefix list and connection BGP/selectors, then requires readback; it never changes gateway mode, keys, custom policy, VMs, grants or public-IP allocations. Run only after root's explicit review of the current qualification window:

```sh
python3 deploy/azure/discover-owned-profile.py discover \
  --subscription EXACT_OWNED_SUBSCRIPTION_UUID --connection-id EXACT_OWNED_ARM_CONNECTION_ID \
  --output NEW_PRIVATE_DISCOVERY_JSON
# Separately authorized AA-static change, same exact ID arguments:
python3 deploy/azure/discover-owned-profile.py aa-static \
  --subscription EXACT_OWNED_SUBSCRIPTION_UUID --connection-id EXACT_OWNED_ARM_CONNECTION_ID \
  --output NEW_PRIVATE_STATIC_DISCOVERY_JSON
```

It requires current CLI account subscription, exact RG/owner tags on RG/connection/gateway/LNG/public IPs, exact connection resource bindings and GatewaySubnet of owned azure-vnet, successful provisioning, supported RouteBased SKU, IKEv2/no-NAT/selectorsfalse/exact custom policy and actual endpoint cardinality. It rechecks owned binding before each mutation. CLI read queries exclude shared keys; mutation outputs project only resource ID; stderr and raw responses are suppressed. Saved metadata output is mode0600 under the executing user's ownership; use UID1000 for consumption by the normal API helper. Missing ownership or unsupported shape refuses rather than broadening acceptance. Source/tests are local qualification, not proof of deployed CLI compatibility or Azure topology readiness.

The bastion discovery entry point refuses unless the actual hostname is exactly `bastion-host` and the supplied/current subscription is exactly `34e2f259-b462-40bf-8f4a-06a3930d99e6`. Normal profile creation also enforces that same subscription in the discovery input. Before any CLI call/mutation the output parent must be owned by the executing UID, mode0700, with no symlink ancestors, and the output must be a new nonsymlink filename. An operation timeout remains a refused/ambiguous result requiring inspection; there is no automatic mutation retry.
