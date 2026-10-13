# Owned unapproved-prefix resource helper

Source-only executable: `deploy/azure/qualify-owned-unapproved-prefix.py`. No live/cloud calls have been made for this implementation. Keep current primary qualification ARM Default and normal connection30 unchanged. No max-prefix or profile-transition operation exists in this helper.

Run later only on `bastion-host` as the identity owning a nonsymlink0700 private directory. All existing input/state files must be owned0600 regular files. First review the current normal API configuration, Site/overlay/DNS/connection ranges, owned cloud routes/peerings and candidate nonuse. Save a freshly observed merged projection from those actual reads, not manufactured status:

```json
{
  "version": 1,
  "kind": "owned_prefix_range_review",
  "observed_at": "ACTUAL_FRESH_UTC_TIME",
  "subscription": "34e2f259-b462-40bf-8f4a-06a3930d99e6",
  "resource_group": "tunnex-azure-s2s-20261010",
  "owner": "azure-s2s-01a12505",
  "vnet_id": "/subscriptions/34e2f259-b462-40bf-8f4a-06a3930d99e6/resourceGroups/tunnex-azure-s2s-20261010/providers/Microsoft.Network/virtualNetworks/azure-vnet",
  "candidate": "10.235.77.0/24",
  "normal_connection": {
    "id": "9bfa4090-d3ca-4a8e-9ef9-3b41bd91fe99",
    "desired_revision": 30,
    "desired_intent": "enabled",
    "application_state": "applied",
    "profile_id": "azure-active-active-bgp-ipv4-v1",
    "remote_prefixes": ["10.231.0.0/16"],
    "maximum_prefixes": 8
  },
  "ranges": ["ACTUAL_CANONICAL_EXISTING_IPV4_RANGES_FROM_REVIEW"]
}
```

The shown candidate remains UNVERIFIED unused; the timestamp/range list are placeholders and are rejected literally. This projection is a reviewed owned qualification input, not runtime authority. Prepare and add require fresh≤60s evidence; refresh actual normal reads before add, especially after slow discovery. The helper independently lists owned RG VNet and LNG prefix ranges and rejects overlap/foreign ownership. It does not claim those lists include every external route; root's range review must cover normal CP and owned peering/route sources.

Later phase commands (private filenames only):

```sh
python3 deploy/azure/qualify-owned-unapproved-prefix.py prepare --state PRIVATE/experiment.json --range-review PRIVATE/fresh-range-review.json
python3 deploy/azure/qualify-owned-unapproved-prefix.py add --state PRIVATE/experiment.json --range-review PRIVATE/new-fresh-range-review.json
python3 deploy/azure/qualify-owned-unapproved-prefix.py read --state PRIVATE/experiment.json
python3 deploy/azure/qualify-owned-unapproved-prefix.py restore --state PRIVATE/experiment.json
```

Optional `--candidate` requires an exact private reviewed unused10/8 /24; use the same candidate for every phase. The helper validates exact subscription/RG/owner and the existing AA BGP gateway/LNG/connection, preserving Default/selectorsfalse/empty custom selectors. It captures the whole nonsecret VNet object privately, preserving **every** property except the intended addressPrefixes list; only recursive ARM etags are excluded from comparison. Unknown properties, subnets/NSG/delegation/route/NAT associations, DNS and peering differences refuse mutation rather than being silently discarded.

It independently snapshots and compares the existing owned private LB `azure-private-app-lb`, resolver `azure-resolver`, actual inbound1/2 resources, private zone `azure-s2s.test`, every zone record set and VNet link. These are read-only; no DNS/LB/subnet/grant update is exposed. State contains private resource metadata and DNS record values; export only typed output/hashes, never the state object.

The single Azure mutation is `vnet update --address-prefixes` with ALL original prefixes plus only the candidate; restoration supplies the exact original list. Existing resource properties are re-read immediately before and after; the helper does not pretend CLI operations are ETag CAS. It reserves/fsyncs state before mutation. Failure/timeout retains add_sent/restore_sent: use `reconcile` for a fresh read-only original/added classification. Add is never automatically repeated. Restore can safely no-op if fresh exact original state is observed; an ambiguous restore still showing added is refused, requiring root review rather than another blind mutation.

Readback is a resource observation, NOT proof of advertisement, rejected prefix, packet denial or continuity. Root must separately observe actual Azure advertisement and managed FRR receipt/rejection, exact strict Up/cardinality/selectors, no route/permission for the unapproved prefix, and restored baseline packets. If the gateway never advertises the prefix, acceptance remains unproven. Current DNS timeouts/no grant remain unresolved and must not be relabeled successful by this helper. Restore original prefixes and independently prove genuine withdrawal before closing the window.

Offline tests mock cloud commands only and cover positive addition/restoration, before-mutation reservation, full/unknown-property preservation, DNS/LB/subnet changes, stale/overlapping review, foreign owner/summarization refusal and no blind retry. They are not cloud acceptance.
