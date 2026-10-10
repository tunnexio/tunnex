# Owned target/client host-key recovery review

Status: SOURCE ONLY. No metadata update, reset, guest command, new key or trust change executed. Three exact owned instances in project project-0048836f-6ba1-4a14-8da / asia-south2-b:

| Instance | Instance ID | Private IP |
|---|---|---|
| tn-gcps2s-20261010-local-client | 4751969643435150303 | 10.70.0.10 |
| tn-gcps2s-20261010-ha-target | 7595462031766211538 | 10.80.0.10 |
| tn-gcps2s-20261010-classic-target | 139156170322758560 | 10.81.0.10 |

Authenticated Google API identity checks succeeded. Existing serial port 1 output has no host fingerprints/public-key candidates; hostkeys/ guest attributes are absent. Existing bastion known_hosts has no pinned alias for these IDs. No listener or SSH readiness claim follows from instance RUNNING.

Google documentation requires enabling guest attributes before first boot for automatic host-key publication: https://docs.cloud.google.com/solutions/connecting-securely . Legacy guest-agent primary source https://github.com/GoogleCloudPlatform/guest-agent/blob/main/google_guest_agent/instance_setup.go lines169-203 invokes generateSSHKeys only when metadata instance ID differs from the saved ID. Lines244-274 generate temporary keys, replace original key files, then publish. This establishes neither unchanged-ID reset republishing nor metadata-watch republishing of existing keys. The actual installed agent version is presently unverified because trusted SSH is unavailable. Do not remove the saved ID, regenerate host keys or assume a reset publishes them.

Candidate metadata-only step, AFTER separate review/authorization and only on these three instances, from the designated bastion:

```
gcloud compute instances describe EXACT_NAME --project=project-0048836f-6ba1-4a14-8da --zone=asia-south2-b --format=json
gcloud compute instances add-metadata EXACT_NAME --project=project-0048836f-6ba1-4a14-8da --zone=asia-south2-b --metadata=enable-guest-attributes=true
gcloud compute instances get-guest-attributes EXACT_NAME --project=project-0048836f-6ba1-4a14-8da --zone=asia-south2-b --query-path=hostkeys/ --format=json
```

Before any authorized update: reverify exact instance ID/private IP/network and owned ledger. Privately capture complete metadata and fingerprint in mode0600 under an exclusive owned mode0700 directory; emit only metadata key names, SHA256 of canonical complete metadata, and ownership booleans. Preserve SSH keys, startup/shutdown scripts and all other items byte-for-byte. Use current Compute setMetadata fingerprint for compare-and-set; stale fingerprint must refuse, never blindly replay or replace items. The add-metadata command is illustrative; any executable wrapper must preserve the captured items and refuse drift. Re-read full metadata privately and require every preexisting key/value unchanged except enable-guest-attributes. No project-level setting, gateway, bastion or colleague instance changes.

A reset is NOT currently recommended or evidence-supported as host-key recovery. If installed-agent-specific primary source later proves existing-key publication on startup, obtain separate authorization for genuine fixture VM reset; verify no workloads beyond owned test fixtures and assess preserved startup scripts before reset. Normal reset command would be `gcloud compute instances reset EXACT_NAME --project=project-0048836f-6ba1-4a14-8da --zone=asia-south2-b`; it is not authorized by this plan. Record instance ID unchanged, boot/operation receipt and authenticated public key fingerprints only, then independently compare public ssh-keyscan fingerprints to authenticated guest attributes before exclusive separate alias pinning. Never accept scan-only trust, change auth credentials or alter existing known_hosts.

If existing agent cannot publish unchanged keys, stop and choose a separately reviewed authenticated guest-execution or disk public-key extraction procedure. No such additional mechanism is authorized here. Do not use reset/recreation/key regeneration as an inferred shortcut.
