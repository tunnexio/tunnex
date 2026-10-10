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
