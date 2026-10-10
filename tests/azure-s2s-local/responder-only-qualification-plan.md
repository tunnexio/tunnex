# Owned Azure ResponderOnly qualification plan

Source-only plan. Execute only on `bastion-host` after root reviews normal disabled revision 15 cleanup acknowledgement, retained deny, native owned SA/policy/interface/route absence, and no pending cleanup. This document does not establish current readiness. Do not enable revision 16 before the Azure update and its complete readback settle.

The local managed strongSwan 6.1.0 investigation reproduced duplicate IKEs under simultaneous initiation; `unique=replace` plus connection interface IDs failed prevention. The live Azure causal initiation sequence remains unclassified. Default-mode qualification is unresolved; ResponderOnly is a bounded owned qualification condition, not a new profile or a general Default-mode support claim. Keep exact selector/cardinality validation unchanged.

## Verified property and CLI shape

ARM `properties.connectionMode` accepts `Default`, `InitiatorOnly`, `ResponderOnly`. Current `az network vpn-connection update` documentation lists generic `--set`; it does **not** list a dedicated `--connection-mode` option. Use the modeled CLI property `--set connectionMode=ResponderOnly`, with exact ID and subscription. Verify the installed bastion CLI help supports `--set` before execution. If property update is refused, stop; do not substitute an unreviewed whole-object ARM PUT or blindly retry.

Primary sources checked 2026-10-10:

- [Azure connection-mode semantics](https://learn.microsoft.com/en-us/azure/vpn-gateway/vpn-gateway-about-vpn-gateway-settings#connection-modes): applies only to route-based IKEv2 initial establishment; either party can still initiate rekeys.
- [Azure CLI update reference](https://learn.microsoft.com/en-us/cli/azure/network/vpn-connection?view=azure-cli-latest#az-network-vpn-connection-update): generic `--set` and `--ids`/`--subscription`.
- [ARM connection Create Or Update](https://learn.microsoft.com/en-us/rest/api/network-gateway/virtual-network-gateway-connections/create-or-update?view=rest-network-gateway-2025-09-01): exact `properties.connectionMode` enum.

## Minimal private bastion wrapper design

Reuse `deploy/azure/discover-owned-profile.py` via an explicit local import. Its `discover`, `resource_id`, `owned`, `az`, and `output_preflight` implement the existing ownership boundaries. A future reviewed executable should:

1. Before **any** Azure CLI call, require hostname `bastion-host`, exact subscription `34e2f259-b462-40bf-8f4a-06a3930d99e6`, and a new output filename under a current-UID, mode-0700, nonsymlink private parent. Never relax output ownership.
2. Read the exact connection ARM ID from the existing private owned discovery allocation, checking its file UID/mode/no-symlink metadata. Require the exact RG `tunnex-azure-s2s-20261010` and owner tag `azure-s2s-01a12505`. Bind expected gateway and LNG IDs from that same reviewed allocation; never infer another connection from a list.
3. Call existing `discover(subscription, connection_id)` to revalidate current account subscription, RG/connection/gateway/LNG/PIP owner tags, resource IDs, RouteBased/IKEv2/custom policy, no NAT, selector flag false, actual AA topology and provisioning Succeeded. Compare returned gateway/LNG IDs to the private expected IDs.
4. Read a **bounded projection only** using `vpn-connection show --ids <exact-id> --subscription <exact-subscription> --query '{id:id,owner:tags.owner,mode:connectionMode,state:provisioningState,gateway:virtualNetworkGateway1.id,lng:localNetworkGateway2.id,selectors:usePolicyBasedTrafficSelectors,trafficSelectors:trafficSelectorPolicies}'`. Require owned exact identity/bindings, Succeeded, selector flag false, and an empty/null custom selector list. Record prior mode privately, only if it is exactly Default or ResponderOnly; refuse any other/missing mode.
5. Recheck exact discovery/binding immediately before the single mutation. If mode is already ResponderOnly, perform readback without mutation. Otherwise issue only:

   `az network vpn-connection update --ids <exact-owned-connection-id> --subscription 34e2f259-b462-40bf-8f4a-06a3930d99e6 --set connectionMode=ResponderOnly --query id --only-show-errors -o json`

   Capture stdout/stderr privately through the existing bounded `az` wrapper; do not print command response objects or errors. Match returned ID. The wrapper timeout is 180 seconds. Timeout/failure is an ambiguous operation requiring fresh read-only inspection, not a mutation retry.
6. Re-read the bounded projection and full existing discovery. Require mode ResponderOnly, provisioning Succeeded, unchanged exact gateway/LNG bindings, owner tags, custom policy, BGP flag, selector flag and empty custom selector list. A pending provisioning state is not acceptance. Save only allowlisted before/after mode, timestamp, IDs, subscription/owner, and provisioning state through O_EXCL/O_NOFOLLOW mode-0600 output. Do not retrieve/write shared keys.
7. Root separately invokes the existing normal lifecycle enable with fresh CAS and observes strict native cardinality/selectors, BGP/routes, packet source preservation and DNS enforcement. ResponderOnly readback is not tunnel health or application reachability.

Do not combine this operation with gateway topology changes, PSK updates, custom selector changes, native termination, or CP schema edits. Reverse-mode restoration, if later requested, needs its own disabled-cleanup boundary and reviewed exact Default update. Remaining AA/AS profile qualification must record the mode used explicitly.

## Reviewed wrapper input contract

`deploy/azure/set-owned-responder-only.py --discovery <private-existing-discovery.json> --cleanup <fresh-azure-lifecycle-read-or-disable.json> --native <fresh-native-absence.json> --native-sha256 <exact-file-sha256> --output <new-private-mode-readback.json>` is source only until root executes. All input/output parents must be current-UID 0700 with no symlink ancestors; inputs must be nonsymlink current-UID 0600 regular files. Transfer separately owned root/Ubuntu projections into the reviewed executing identity's private directory rather than relaxing ownership checks.

The discovery uses the existing version-1 discovery schema and binds specifically to `tunnex-connection`, `azure-vpn`, and `tunnex-local`. Cleanup uses the actual normal lifecycle helper output: `observed_at`, `phase` read/disable, `cleanup_readback_settled:true`, and `connection` containing the exact current connection UUID, revision 15, desired_intent disabled, application_state not_applied, cleanup_state retained_guard. Both cleanup and native observations must be no older than 60 seconds and not future-dated; cleanup pending is refused. Normal API cleanup state is the acknowledged cleanup projection, not a packet-health assertion.

Root supplies a separate projection of **actual independent native observations**, never invented from API status: `{version:1,kind:"owned_native_cleanup_absence",observed_at:<UTC timestamp>,connection_id:"9bfa4090-d3ca-4a8e-9ef9-3b41bd91fe99",desired_revision:15,guard_retained:true,azure_connection_id:<exact ARM ID>,owned_ike:0,owned_children:0,owned_sad:0,owned_spd:0,owned_interfaces:0,owned_routes:0}`. The exact byte SHA256 is mandatory. Counts describe owned objects; daemon socket bypass policies are not owned application policies. The wrapper rechecks freshness immediately before mutation after cloud reads. It performs no normal API mutation, native deletion, key retrieval or blind Azure mutation retry. These files are evidence inputs to the owned qualification wrapper, not general runtime authority.
