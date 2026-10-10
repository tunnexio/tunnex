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

## Authenticated serial append alternative — separate review only

Raw serial CLI verification used get-serial-port-output EXACT_NAME --port=1 --start=0 with no --format. Populated stdout was157775/161662/156130 bytes(client/HA/Classic), each contained2kernel,21boot,76guestagent markers and0fingerprint/publickey candidates. This rules out an empty contents projection. Next-read offsets were157774/161661/156123.

A minimal alternative source is deploy/ipsec/gcp-owned-hostkey-serial-publication.py. It reads ONLY existing root-owned /etc/ssh/ssh_host_ed25519_key.pub with O_NOFOLLOW, validates exact ed25519 public wire structure, confirms exact instance ID against Google metadata, reads actual boot UUID and emits a unique attempt/instance/boot/public-key/fingerprint marker on /dev/ttyS0. No private keys, SSH auth keys, key generation, guest attributes or instance ID files are touched. Source compile and synthetic existing-public-key/alternate/malformed/symlink tests pass.

Before execution, review a wrapper that captures entire original metadata privately and SHA256s its canonical items and complete startup script. Require inline original startup-script and refuse startup-script-url/other ambiguity unless explicitly reviewed; append invocation after original contents without rewriting them. Store the public helper source through a quoted literal/heredoc in the appended segment, use exact expected instance ID and new UUID attempt, and setMetadata with exact current fingerprint plus preserved original items. Verify all other metadata identical. Changes require separate approval. Then genuine reset ONLY exact owned fixture VM, wait bounded Google operation completion, privately read serial from captured offset, and accept only exact attempt/ID plus independently observed newboot. Extract the existing public key and compare ssh-keyscan fingerprint before separate exclusive pinned alias file. An original startup failure or exit preventing appended publication remains a refusal; do not bypass it. Preserve originals privately for exact CAS restoration after acceptance. This plan does not execute updates/resets, approve a wrapper, or assert no other guest workloads before source/metadata inspection.
