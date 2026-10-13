This is a cleanup-only recovery recipe after genuine externally supervised reboot of the owned peer VM. It is distinct from active process restart and from apply restoration. The assembler never stops a VM, changes a journal, removes native objects or grants traffic. The product still validates the receipt and performs two independent absence passes.

Keep the connection normally disabled at its current cleanup revision. Stop the owned node before taking a root-owned 0600 immutable journal snapshot; preserve the original mounted journal and old refused container. Record the snapshot SHA256, actual old host boot ID, actual host `/etc/machine-id`, gateway owner ID and actual external reboot request timestamp. Require the current unfinished entry's recorded `Restoration.BootID` to match that actual old boot. A missing old boot record is a refusal, not permission to infer it.

The external bastion must execute the separately authorized real VM reboot, then observe the same machine ID, a different kernel boot ID, and actual reboot completion. Keep the node stopped after reboot. Start the control plane, owned namespace anchor and real LAN before the node. Obtain the current cleanup delivery using normal node mTLS GET `/agent/ipsec/connections/<connection-id>/cleanup?desired_revision=<current-cleanup-revision>` and retain its exact response bytes privately. No synthetic API delivery is accepted.

External proof JSON uses these exact field names:

```json
{
  "Version": 1,
  "Kind": "supervisor-confirmed-owned-vm-reboot",
  "OwnerID": "actual gateway UUID",
  "MachineID": "actual host machine ID, 32 lowercase hex digits",
  "OldBootID": "actual pre-reboot UUID matching persisted Restoration.BootID",
  "NewBootID": "actual post-reboot UUID",
  "StoppedJournalSHA256": "SHA256 of exact stopped snapshot bytes",
  "CleanupSHA256": "SHA256 of exact fresh normal cleanup response bytes",
  "RequestedAt": "actual UTC RFC3339Nano reboot request time",
  "CompletedAt": "actual UTC RFC3339Nano external completion observation"
}
```

This proof is a privileged supervisor attestation. The tool cannot cryptographically authenticate the bastion or remote cloud lifecycle. Root must independently review its real evidence; private file ownership alone does not make invented observations authentic. The tool independently binds actual current machine/boot/network namespace, persisted old boot, unchanged snapshot, current cleanup ID/revision/digest and all covered lineage. It rejects unchanged boot, stale evidence older than 15 minutes, future completion, namespace equality, unrecorded old boot, changed input and unknown fields.

Run the source-built Linux CLI as root in the new gateway's network namespace while retaining the peer host mount namespace (so `/etc/machine-id` is the host identity):

```sh
nsenter -t "$OWNED_ANCHOR_PID" -n -- /private/path/ipsec-reset-cleanup-receipt \
  -journal /private/path/stopped-journal.json \
  -cleanup /private/path/current-normal-cleanup.json \
  -proof /private/path/actual-supervisor-reboot-proof.json \
  -output-dir /actual/persisted/node-state/ipsec
```

All three inputs must be absolute regular root-owned 0600 files with no symlink components. Output directory must already be root-owned 0700. It exclusively creates `reset-cleanup-<actual-cleanup-ID>.json`; an existing receipt causes refusal. It does not update the journal. Assemble within the evidence time bound; do not adjust timestamps to evade expiry.

Start the node normally. Require normal cleanup acknowledgement and all covered records retained as refusal, native owned SAD/SPD/link/route absence, current boot/namespace receipt binding, and the original identities/history preserved. Only then normally enable and qualify fresh actual SAs/BGP/DNS/client traffic. Test the graceful node-only restart separately with a 45-second Docker stop grace, unchanged anchor/boot/netns, clean daemon supervisor artifact census and fresh actual traffic/status. No active-restart success is implied by reboot cleanup success.
