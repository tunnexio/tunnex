# Reviewed owned Azure restart plan

These are peer-host operations for lead review/execution, not cloud provisioning commands. Require hostname `tunnex-peer`, exact `tunnex.owner=azure-s2s-01a12505` on every affected container, the verified current image/binary, and the existing private enrollment/state mount. Never rewrite a journal, seed capabilities, substitute a receipt, or remove refusal guards manually.

## Immediate safest proof: disable, cleanup, recreate, re-enable

1. Keep continuous probes running from the real client namespace (`10.233.10.2`). Save fresh normal API status and the current desired revision. Use normal owner API CAS intent `disabled`, then observe denied traffic, actual cleanup completion and acknowledgments for all current delivery duties. Keep the connection record and IDs; do not DELETE/tombstone the connection if it will be re-enabled. “Cleanup finalized” here means delivery cleanup is acknowledged, not connection deletion.
2. Verify the owned daemon, BGP processes, XFRM interfaces/states/policies, application routes and permit grants have completed their normal cleanup. Inspect only typed/key-free observations or the existing cleanup APIs. Keep private journal bytes intact, including retained histories. A failed/uncertain cleanup blocks recreation; do not manually clear it.
3. Stop/remove only the reviewed gateway container after completed cleanup. Preserve the exact state mount and node identity. Create the owned network anchor below and recreate the real LAN in its namespace **before** starting the gateway agent. Reuse the exact reviewed gateway environment, image and mounts, changing only its network mode to the anchor.
4. Wait for genuine native static/BGP/Azure eligibility from normal heartbeats. Enable the same connection with its fresh desired-revision CAS. Require both actual IKE/child SAs and BGP peers healthy, a permitted installed route, fresh status sequence and real forwarded TCP/UDP/DNS/source-preservation proof.

Report this honestly as disable/cleanup/recreate/re-enable qualification. It is a real node process/container replacement, but it does not prove recovery of active forwarding across a process crash.

## Prepare an anchor for subsequent genuine active node restart

The anchor must own the bridge endpoint and UDP publishing from its creation. Merely joining the current gateway namespace with a helper process before stopping the original bridge owner does not prove preservation: Docker can tear down the owner's networking endpoint. Do not migrate a currently active journal by changing its namespace fields.

After normal disabled cleanup, a reviewed anchor creation has this shape (use the already verified locally available image; no pull):

```sh
sudo docker run -d --name tunnex-azure-cloud-netns \
  --label tunnex.owner=azure-s2s-01a12505 \
  --network tunnex-azure-cloud --network-alias gateway-underlay \
  --cap-drop ALL --read-only --security-opt no-new-privileges \
  --sysctl net.ipv4.ip_forward=1 \
  -p 500:500/udp -p 4500:4500/udp \
  --entrypoint /bin/sh "$VERIFIED_NATIVE_IMAGE" -c 'exec sleep infinity'
```

Check that this exact owned name does not already refer to another object and that ports are free after the old gateway stops. Install the existing real gateway-end veth/address `10.233.10.1/24` into the anchor namespace; preserve/recreate the actual client-end namespace/address `10.233.10.2/24` and default route. Do not add a fabricated reachability route. The gateway container's reviewed recreation arguments use:

```text
--network container:tunnex-azure-cloud-netns
--cap-add NET_ADMIN --cap-add NET_RAW
--device /dev/net/tun:/dev/net/tun
```

UDP ports and `ip_forward` belong on the anchor, not the network-sharing gateway. Preserve normal API `http://api:8080`, agent API `https://api:8443`, server name `tunnex-control`, configured public identity, private credentials, root-owned executable and durable state. Do not print Docker environment/configuration or add a second charon. Docker's shared namespace must retain the owned bridge's actual DNS configuration; verify normal API resolution rather than overriding it.

Once normally enabled and healthy, record the anchor and gateway netns inode plus kernel boot ID using `readlink /proc/self/ns/net` and `/proc/sys/kernel/random/boot_id` inside each. They must agree before restart. Record full container IDs privately, the key-free runtime epoch/generation if available via a typed observer, desired revision, selected slot, report sequence and normal packet baseline.

For the genuine active process restart, keep the anchor running and use `docker restart` **only on the network-sharing gateway**. Do not restart/remove the anchor. Its bridge endpoint and LAN remain alive. The node bootstrap must restore durable refusal before forwarding and revalidate existing cleanup duties; normal current receipts/new lease authority remain mandatory. Existing charon/FRR children must terminate with the old node/container; the new node must not adopt them or signal arbitrary PIDs from journal records.

After restart require: unchanged anchor/gateway netns and kernel boot ID; new node process identity; exact enrollment/site binding and journal continuity; no fabricated permit during outage; genuine fresh capability/lease/status; correct current-versus-retained history; both peers healthy and actual forwarded traffic/source preserved. Measure loss and recovery time. If it refuses, retain all evidence and diagnose the exact stage—do not remove the journal, force capability or manufacture stop evidence.

## Later genuine owned peer host reboot

A host reboot necessarily changes kernel boot identity and destroys its old namespaces. It cannot preserve an active netns inode. Existing runtime restoration supports this explicitly through recorded prior boot, `kernel-boot-change`, new allocation generation, two-pass native absence checks and a fresh authorized recovery lease. It preserves the retired entry/history; it does not silently edit the old namespace. Verify that the actual applied entry recorded its old boot before testing; use a reviewed typed observer or private exact-entry inspection, never print its raw journal.

Before reboot, establish reviewed startup ordering: control-plane dependencies, network anchor, real client/LAN topology, then gateway agent. A bare Docker restart policy is insufficient proof that the LAN is installed before the first native preflight. Preserve all exact state/enrollment mounts and source identity, and capture key-free old boot/namespace plus private exact state evidence. Keep the independent application-side observation and bastion access available.

After the separately authorized host reboot, require new boot ID, original persisted node/connection identity, old epoch retained, explicit restoration lineage/new generation, two-pass kernel/daemon absence and fresh native qualification/lease. Require refusal before activation, fresh status rather than stale preboot success, both actual SAs/BGP peers, restored managed DNS and real client traffic. If the same-boot namespace changes instead, the kernel-boot-change proof is unavailable: the existing exact stopped-runtime receipt contract requires genuine empty-cgroup/no-old-namespace-holder evidence. An anchor intentionally keeping that old namespace alive cannot satisfy that receipt. Stop and diagnose rather than forge it.

A reboot proof remains pending until the actual native restoration lineage and packets have been observed. Normal disable/cleanup before reboot is a valid, lower-risk distinct lifecycle test if active restoration has not been qualified.

The real owned peer now has `owned-boot.sh` / `owned-boot.service` installed under uniquely owned system paths. It validates every affected container's owner label, starts CP dependencies before anchor, then builds the real LAN and starts the private UI. An owned root-only marker keeps the gateway stopped for genuine reset-cleanup assembly. The original bastion and target startup configuration are untouched. A stopped node source6e53e071 with45-second grace was observed exit0/OOMfalse, `agent_stopped`, no shutdown-incomplete, and only `supervisor.lock` remaining in its daemon run directory. This is live joined-daemon cleanup proof, not full active traffic restart acceptance.

Actual reboot on 2026-10-10: external bastion requested 11:58:33Z and observed completion 12:01:18Z, same machine ID, new boot ID and unchanged stopped journal. Ubuntu cleared `/tmp`; the API bind-mounted binary vanished and Docker created an empty directory. Restoring the exact API source revision `3a451571` recovered control-plane health. Startup now restores that binary from owned durable storage before starting containers. The genuine cleanup-only receipt assembler (`d77b104c`) accepted fresh normal mTLS cleanup revision 5 and actual reboot evidence. This is not successful lifecycle recovery: node `6e53e071` refuses saved-refusal startup, normal cleanup remains pending and traffic remains disabled. Actual SAD/SPD/XFRM-link/remote-route absence is separately recorded in `docs/evidence/azure-s2s-20261010/genuine-reboot-recovery.json`.

Startup metadata identifies namespace inode reuse: a historical retained-refusal entry's allocation namespace equals the new namespace although its recorded boot differs. The current pending-cleanup allocation namespace differs. The prefix denial table was restored before startup refusal. Investigate boot-aware BGP startup cleanup before accepting any recovery; do not erase history or native state.
